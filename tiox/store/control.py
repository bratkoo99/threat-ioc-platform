"""
Control-plane store: endpoints, incidents, and the event index.

Scope note. This is the *control plane* — configuration, workflow state, and
alerts. It is NOT the event lake. Phase 1 puts the lake in ClickHouse; this file
stays small and transactional on purpose. Events are stored here too, but only so
that Phase 0 is testable end to end before a lake exists. `EventStore` has a
distinct interface so the ClickHouse implementation can drop in without callers
noticing.

Why SQLite and not the current incidents.json: the existing code rewrites the whole
file on every write with no locking, so two agents reporting concurrently lose
data. This is ACID, and the DDL is written to be portable to Postgres so Phase 1
is a driver swap rather than a rewrite.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from tiox.schemas.event import SCHEMA_VERSION, Event, iso

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id            TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL,
    ip            TEXT,
    os            TEXT,
    version       TEXT,
    status        TEXT NOT NULL DEFAULT 'unknown',
    last_seen     TEXT,
    registered    TEXT,
    scan_count    INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    connector     TEXT,
    extra         TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    status      TEXT NOT NULL DEFAULT 'open',
    source      TEXT,
    type        TEXT,
    details     TEXT,
    created     TEXT,
    updated     TEXT,
    event_id    TEXT
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    text        TEXT NOT NULL,
    author      TEXT,
    ts          TEXT NOT NULL
);

-- Control-plane events. In Phase 1 this moves to ClickHouse; the columns here
-- mirror what the lake needs so the migration is mechanical.
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    ingest_ts  TEXT NOT NULL,
    source     TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    host       TEXT,
    user       TEXT,
    title      TEXT,
    rule_id    TEXT,
    tlp        TEXT,
    raw        TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    dedupe_key TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events (type);
CREATE INDEX IF NOT EXISTS idx_events_sev      ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_host     ON events (host);
CREATE INDEX IF NOT EXISTS idx_events_rule     ON events (rule_id);

-- The pivot table. One row per (entity_type, entity_value); this is what makes
-- "show me everything about this hash" a single indexed query.
CREATE TABLE IF NOT EXISTS event_entities (
    event_id    TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_value, event_id)
);

CREATE INDEX IF NOT EXISTS idx_ent_lookup ON event_entities (entity_type, entity_value);

-- Content fingerprint: makes re-ingest of the same observation a no-op. event_id
-- alone cannot do this because it is a random UUID minted at normalize time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedupe ON events (dedupe_key);
"""

# Postgres equivalent, kept in-repo so the Phase 1 swap is a reviewed diff rather
# than a rewrite from memory. Not exercised by the test suite.
POSTGRES_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY, hostname TEXT NOT NULL, ip TEXT, os TEXT, version TEXT,
    status TEXT NOT NULL DEFAULT 'unknown', last_seen TEXT, registered TEXT,
    scan_count INTEGER NOT NULL DEFAULT 0, threats_found INTEGER NOT NULL DEFAULT 0,
    connector TEXT, extra JSONB
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', source TEXT, type TEXT, details JSONB,
    created TIMESTAMPTZ, updated TIMESTAMPTZ, event_id TEXT
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    text TEXT NOT NULL, author TEXT, ts TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id UUID PRIMARY KEY, ts TIMESTAMPTZ NOT NULL, ingest_ts TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, host TEXT, "user" TEXT,
    title TEXT, rule_id TEXT, tlp TEXT, raw JSONB NOT NULL, schema_version TEXT NOT NULL, dedupe_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedupe ON events (dedupe_key);

CREATE TABLE IF NOT EXISTS event_entities (
    event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL, entity_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ent_lookup ON event_entities (entity_type, entity_value);
"""


class StoreError(RuntimeError):
    pass


class ControlPlane:
    """Endpoints, incidents, and event persistence. Thread-safe per connection."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        # check_same_thread=False + an explicit lock: the SSE handlers and the
        # scan thread both touch this, which is exactly the race the JSON store lost.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.execute(
                "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()

    @property
    def schema_version(self) -> str:
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        return row["value"] if row else "unknown"

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "ControlPlane":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ================= endpoints =================

    def upsert_endpoint(self, ep: dict[str, Any]) -> str:
        """
        Insert or refresh an endpoint, keyed on (hostname, ip).

        Returns the server-issued id, which may differ from ep["id"]: the legacy
        migration passes historical ids in, but a new registration gets a
        fresh EP-xxxx so two agents can never collide on a client-chosen one.
        """
        now = iso()
        with self._tx() as c:
            existing = c.execute(
                "SELECT id FROM endpoints WHERE hostname = ? AND (ip IS ? OR ip = ?)",
                (ep.get("hostname"), ep.get("ip"), ep.get("ip")),
            ).fetchone()
            if existing:
                eid = existing["id"]
                c.execute(
                    """UPDATE endpoints SET ip=?, os=?, version=?, status=?, last_seen=?,
                       connector=?, extra=? WHERE id=?""",
                    (
                        ep.get("ip"), ep.get("os"), ep.get("version"),
                        ep.get("status", "online"), now,
                        ep.get("connector"), json.dumps(ep.get("extra") or {}), eid,
                    ),
                )
                return eid
            seq = c.execute("SELECT COUNT(*) AS n FROM endpoints").fetchone()["n"]
            # The id is always server-issued. The legacy JSON path passed in the
            # client's own id, which meant two agents could claim the same EP-xxxx
            # and a re-registration silently renumbered rows.
            eid = f"EP-{seq + 1:04d}"
            c.execute(
                """INSERT INTO endpoints (id, hostname, ip, os, version, status,
                   last_seen, registered, connector, extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid, ep.get("hostname", "unknown"), ep.get("ip"), ep.get("os"),
                    ep.get("version", "1.0"), ep.get("status", "online"), now, now,
                    ep.get("connector"), json.dumps(ep.get("extra") or {}),
                ),
            )
            return eid

    def touch_endpoint(self, endpoint_id: str, ip: str | None = None) -> bool:
        with self._tx() as c:
            cur = c.execute(
                "UPDATE endpoints SET last_seen=?, status='online', ip=COALESCE(?, ip) WHERE id=?",
                (iso(), ip, endpoint_id),
            )
            return cur.rowcount > 0

    def increment_scan(self, endpoint_id: str, threats: int = 0) -> None:
        with self._tx() as c:
            c.execute(
                """UPDATE endpoints SET scan_count = scan_count + 1,
                   threats_found = threats_found + ?,
                   last_seen = ? WHERE id = ?""",
                (threats, iso(), endpoint_id),
            )

    def list_endpoints(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM endpoints ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM endpoints WHERE id=?", (endpoint_id,)).fetchone()
        return dict(row) if row else None

    def get_endpoint_by_host(self, hostname: str) -> dict[str, Any] | None:
        """
        Look up an endpoint by hostname alone.

        Needed because upsert_endpoint keys on (hostname, ip): a host that
        changes address -- DHCP lease, laptop on a new network -- looks new under
        a composite key, and would file a second "new endpoint" incident for a
        machine the analyst has already seen.
        """
        if not hostname:
            return None
        row = self._conn.execute(
            "SELECT * FROM endpoints WHERE hostname = ? ORDER BY registered LIMIT 1",
            (hostname.strip(),),
        ).fetchone()
        return dict(row) if row else None

    # ================= incidents =================

    def create_incident(self, inc: dict[str, Any], event_id: str | None = None) -> dict[str, Any]:
        """
        Insert an incident. Idempotent on id, so a legacy replay or a retried
        request cannot duplicate history.

        `event_id` links the incident to the event that caused it. It is
        backfilled afterwards when the caller learns the id later (the operator
        path creates the incident first, then ingests), because requiring the
        caller to know the event id up front loses the link silently.
        """
        now = iso()
        with self._tx() as c:
            seq = c.execute("SELECT COUNT(*) AS n FROM incidents").fetchone()["n"]
            inc_id = inc.get("id") or f"INC-{seq + 1:04d}"
            if c.execute("SELECT 1 FROM incidents WHERE id=?", (inc_id,)).fetchone():
                existing = self.get_incident(inc_id) or {}
                if event_id and not existing.get("event_id"):
                    self.link_incident_event(inc_id, event_id)
                    existing = self.get_incident(inc_id) or existing
                return existing
            c.execute(
                """INSERT INTO incidents (id, title, description, severity, status, source,
                   type, details, created, updated, event_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    inc_id, inc.get("title", "Untitled"), inc.get("description", ""),
                    inc.get("severity", "medium"), inc.get("status", "open"),
                    inc.get("source"), inc.get("type"),
                    json.dumps(inc.get("details") or {}),
                    inc.get("created") or now, now, event_id,
                ),
            )
            return self.get_incident(inc_id) or {}

    def link_incident_event(self, inc_id: str, event_id: str) -> bool:
        """Attach an event to an existing incident. No-op if already linked."""
        with self._tx() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE id=?", (inc_id,)).fetchone():
                return False
            c.execute(
                "UPDATE incidents SET event_id=COALESCE(event_id, ?), updated=? WHERE id=?",
                (event_id, iso(), inc_id),
            )
        return True

    def update_incident(self, inc_id: str, status: str | None = None, note: str | None = None) -> bool:
        with self._tx() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE id=?", (inc_id,)).fetchone():
                return False
            now = iso()
            if status:
                c.execute("UPDATE incidents SET status=?, updated=? WHERE id=?", (status, now, inc_id))
            if note:
                c.execute(
                    "INSERT INTO incident_notes (incident_id, text, ts) VALUES (?,?,?)",
                    (inc_id, note, now),
                )
                c.execute("UPDATE incidents SET updated=? WHERE id=?", (now, inc_id))
            return True

    def get_incident(self, inc_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["details"] = json.loads(d.get("details") or "{}")
        d["notes"] = [
            dict(n) for n in self._conn.execute(
                "SELECT text, ts FROM incident_notes WHERE incident_id=? ORDER BY ts", (inc_id,)
            ).fetchall()
        ]
        return d

    def list_incidents(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """
        List incidents, newest first, each with its notes.

        Notes are joined in rather than left to a per-row follow-up query. The
        dashboard renders a list of incidents with their notes, and loading them
        lazily meant the list view silently showed no notes at all.
        """
        if status:
            rows = self._conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY created DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY created DESC LIMIT ?", (limit,)
            ).fetchall()
        ids = [r["id"] for r in rows]
        notes_by_inc: dict[str, list[dict[str, Any]]] = {}
        if ids:
            # SQLite has no array bind, so chunk the IN clause. 400 keeps us well
            # under the 999-variable default limit.
            for chunk_start in range(0, len(ids), 400):
                chunk = ids[chunk_start:chunk_start + 400]
                marks = ",".join("?" * len(chunk))
                for n in self._conn.execute(
                    f"SELECT incident_id, text, author, ts FROM incident_notes "
                    f"WHERE incident_id IN ({marks}) ORDER BY ts",
                    chunk,
                ).fetchall():
                    notes_by_inc.setdefault(n["incident_id"], []).append(
                        {"text": n["text"], "author": n["author"], "time": n["ts"]}
                    )
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.get("details") or "{}")
            d["notes"] = notes_by_inc.get(d["id"], [])
            out.append(d)
        return out

    def incident_counts(self) -> dict[str, int]:
        row = self._conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open,
                      SUM(CASE WHEN status='open' AND severity='critical' THEN 1 ELSE 0 END) AS critical
               FROM incidents"""
        ).fetchone()
        return {k: int(row[k] or 0) for k in ("total", "open", "critical")}

    # ================= events =================

    def insert_event(self, ev: Event) -> bool:
        """
        Insert an event and its entity rows. Returns False if it was a duplicate.

        Dedupe is on the content fingerprint, not event_id: a retried agent POST
        or a re-run of an unchanged scan produces a fresh UUID for the same
        observation, and storing it twice would inflate every count downstream.
        """
        d = ev.to_dict()
        dedupe = ev.dedupe_key()
        with self._tx() as c:
            seen = c.execute(
                "SELECT event_id FROM events WHERE dedupe_key=?", (dedupe,)
            ).fetchone()
            if seen:
                return False
            c.execute(
                """INSERT OR IGNORE INTO events (event_id, ts, ingest_ts, source, type,
                   severity, host, user, title, rule_id, tlp, raw, schema_version, dedupe_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    d["event_id"], d["ts"], d["ingest_ts"], d["source"], d["type"],
                    d["severity"], d.get("host"), d.get("user"), d.get("title"),
                    d.get("rule_id"), d.get("tlp"), json.dumps(d.get("raw") or {}),
                    d.get("schema_version", SCHEMA_VERSION), dedupe,
                ),
            )
            for etype, values in (d.get("entities") or {}).items():
                for val in values:
                    c.execute(
                        "INSERT OR IGNORE INTO event_entities (event_id, entity_type, entity_value) VALUES (?,?,?)",
                        (d["event_id"], etype, val),
                    )
            return True

    def insert_events(self, events: list[Event]) -> tuple[int, int]:
        """Bulk insert. Returns (inserted, duplicates)."""
        inserted = sum(1 for e in events if self.insert_event(e))
        return inserted, len(events) - inserted

    def find_by_entity(self, entity_type: str, entity_value: str, limit: int = 200) -> list[dict[str, Any]]:
        """The pivot query: everything ever seen for one entity value."""
        value = entity_value.lower()
        rows = self._conn.execute(
            """SELECT e.* FROM events e
               JOIN event_entities ee ON ee.event_id = e.event_id
               WHERE ee.entity_type = ? AND ee.entity_value = ?
               ORDER BY e.ts DESC LIMIT ?""",
            (entity_type, value, limit),
        ).fetchall()
        return [self._row_to_event_dict(r) for r in rows]

    def count_by_entity(self, entity_type: str, entity_value: str) -> int:
        row = self._conn.execute(
            """SELECT COUNT(DISTINCT event_id) AS n FROM event_entities
               WHERE entity_type=? AND entity_value=?""",
            (entity_type, entity_value.lower()),
        ).fetchone()
        return int(row["n"])

    def query_events(
        self,
        type: str | None = None,
        severity: str | None = None,
        host: str | None = None,
        source: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Time-range-aware query. The UI's global time filter maps onto this."""
        where: list[str] = []
        params: list[Any] = []
        for col, val in (("type", type), ("severity", severity), ("host", host), ("source", source)):
            if val:
                where.append(f"{col} = ?")
                params.append(val)
        if since:
            where.append("ts >= ?")
            params.append(since)
        if until:
            where.append("ts <= ?")
            params.append(until)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM events{clause} ORDER BY ts DESC LIMIT ?", params
        ).fetchall()
        return [self._row_to_event_dict(r) for r in rows]

    def event_stats(self, since: str | None = None) -> dict[str, Any]:
        params: list[Any] = []
        clause = ""
        if since:
            clause = " WHERE ts >= ?"
            params.append(since)
        row = self._conn.execute(
            f"""SELECT COUNT(*) AS total,
                       SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) AS high,
                       COUNT(DISTINCT host) AS hosts,
                       COUNT(DISTINCT source) AS sources
                FROM events{clause}""",
            params,
        ).fetchone()
        return {k: int(row[k] or 0) for k in ("total", "high", "hosts", "sources")}

    @staticmethod
    def _row_to_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["raw"] = json.loads(d.get("raw") or "{}")
        return d
