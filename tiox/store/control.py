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
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from tiox.schemas.event import (
    SCHEMA_VERSION,
    Event,
    iso,
    severity_at_least,
)

def _parse_iso(value: Any) -> datetime | None:
    """Parse an ISO timestamp, tolerating the Z suffix and a missing zone."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    # A naive stamp is compared against an aware `now`, which raises. Assume UTC:
    # the platform writes everything in UTC, so the only naive values are legacy.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _incident_row(row: sqlite3.Row) -> dict[str, Any]:
    """Shape an incidents row, parsing the JSON columns back into objects."""
    d = dict(row)
    for key in ("details", "correlation_components"):
        if key in d:
            try:
                d[key] = json.loads(d.get(key) or ("{}" if key == "details" else "{}"))
            except (json.JSONDecodeError, TypeError):
                d[key] = {}
    return d


RULE_MODES = ("log", "alert")


def _normalise_mode(value: Any) -> str:
    """
    Coerce a rule mode to a known value, defaulting to 'log'.

    Defaulting to 'log' rather than 'alert' is deliberate: an unrecognised mode
    must not be able to open incidents. A detection that pages someone by
    accident because of a typo is worse than one that stays quiet.
    """
    v = str(value or "").strip().lower()
    return v if v in RULE_MODES else "log"


def _rule_row(row: sqlite3.Row) -> dict[str, Any]:
    """Shape a custom_rules row: tree and techniques come back as objects."""
    d = dict(row)
    d["enabled"] = bool(d.get("enabled"))
    for key in ("tree", "techniques"):
        try:
            d[key] = json.loads(d.get(key) or ("{}" if key == "tree" else "[]"))
        except (json.JSONDecodeError, TypeError):
            d[key] = {} if key == "tree" else []
    return d


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    """Shape a scans row for the API: a short display id alongside the UUID."""
    d = dict(row)
    d["label"] = f"scan-{d['seq']:04d}"
    return d


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
    event_id    TEXT,
    -- The custom rule that opened this incident, when one did. Lets the tuning
    -- view attribute an incident to a rule without inferring it from a title.
    rule_id     TEXT
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
    dedupe_key TEXT NOT NULL,
    techniques TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events (type);
CREATE INDEX IF NOT EXISTS idx_events_sev      ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_host     ON events (host);
CREATE INDEX IF NOT EXISTS idx_events_rule     ON events (rule_id);

-- Scan runs. Every scan gets a durable id so its findings can be traced back to
-- a specific invocation -- "which run found this file?" and "re-run exactly what
-- was run on Tuesday" are both unanswerable without it.
--
-- A single mutable scan_state dict, which is what this replaces, can only ever
-- describe the most recent scan: the previous run's counts, path and timing are
-- overwritten, so scan history does not exist.
CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    seq           INTEGER NOT NULL,        -- 1-based run number, human-facing
    started_ts    TEXT NOT NULL,
    ended_ts      TEXT,
    status        TEXT NOT NULL DEFAULT 'running',  -- running|completed|error
    scan_path     TEXT,
    initiated_by  TEXT,                    -- 'local' or an endpoint_id
    host          TEXT,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    dirs_scanned  INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    errors        INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER,
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON scans (started_ts);
CREATE INDEX IF NOT EXISTS idx_scans_host    ON scans (host);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans (status);

-- Custom detection rules authored in the UI. The tree is stored as JSON: it is
-- a document that is read whole, written whole, and validated as a unit, so
-- normalising it into relational tables would buy nothing and cost a join on
-- every evaluation.
CREATE TABLE IF NOT EXISTS custom_rules (
    rule_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    techniques  TEXT NOT NULL DEFAULT '[]',
    tree        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    author      TEXT,
    created_ts  TEXT NOT NULL,
    updated_ts  TEXT NOT NULL,
    last_run_ts TEXT,
    last_hits   INTEGER NOT NULL DEFAULT 0,
    hits_total  INTEGER NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL DEFAULT 'log',
    false_positives INTEGER NOT NULL DEFAULT 0,
    incidents_opened INTEGER NOT NULL DEFAULT 0
);

-- mode: 'log' records a threat_hit event; 'alert' also opens an incident.
-- Per rule, not global, because "this rule must not page anyone" and "this rule
-- must page someone" are different tools. 'log' is the default so a new rule
-- cannot flood a queue on its first day; promoting to 'alert' is deliberate.
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON custom_rules (enabled);

-- The findings of a scan, linked to the events they produced. Kept separate from
-- the scan row so a scan with thousands of hits does not bloat the summary.
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id  TEXT NOT NULL,
    file_path   TEXT,
    file_hash   TEXT,
    family      TEXT,
    rule_id     TEXT,
    severity    TEXT,
    techniques  TEXT NOT NULL DEFAULT '[]',
    event_id    TEXT,                     -- the threat_hit event, when ingested
    PRIMARY KEY (scan_id, finding_id)
);

-- An incident's evidence set. The old `incidents.event_id` column can reference
-- exactly one event, which is why one incident per event was the only option
-- before this. Correlated incidents need the whole set, and the UI needs to walk
-- it in order.
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id    TEXT NOT NULL,
    linked_ts   TEXT NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_incev_event ON incident_events (event_id);

-- Suppression: a rule an analyst has marked as noise stops opening incidents for
-- a period. Distinct from `enabled`, which is authored; this is a response to
-- observed behaviour. Deleting a rule loses its tuning history, so the noisy
-- cases get a time-boxed mute instead.
CREATE TABLE IF NOT EXISTS rule_suppressions (
    rule_id      TEXT PRIMARY KEY,
    suppressed_until TEXT NOT NULL,
    reason       TEXT,
    created_ts   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings (file_hash);
CREATE INDEX IF NOT EXISTS idx_findings_event ON scan_findings (event_id);

-- ATT&CK techniques are stored as a JSON array on the event *and* as rows here.
-- The column keeps the event self-describing when read back; this table is what
-- makes "which hosts hit T1486 this week" a single indexed GROUP BY instead of a
-- JSON scan.
CREATE TABLE IF NOT EXISTS event_techniques (
    event_id     TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_tech_lookup ON event_techniques (technique_id);

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
    title TEXT, rule_id TEXT, tlp TEXT, raw JSONB NOT NULL, schema_version TEXT NOT NULL,
    dedupe_key TEXT NOT NULL, techniques JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedupe ON events (dedupe_key);

CREATE TABLE IF NOT EXISTS event_techniques (
    event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_tech_lookup ON event_techniques (technique_id);

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
            self._migrate()
            self._conn.execute(
                "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()

    def _migrate(self) -> None:
        """
        Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so a new
        column has to be added separately. SQLite has no "ADD COLUMN IF NOT
        EXISTS", so the column list is checked first -- and init_schema runs on
        every start, so this has to be idempotent.
        """
        additions = (
            ("incidents", "rule_id", "TEXT"),
            ("incidents", "correlation_key", "TEXT"),
            ("incidents", "correlation_components", "TEXT"),
            ("custom_rules", "mode", "TEXT NOT NULL DEFAULT 'log'"),
            ("custom_rules", "false_positives", "INTEGER NOT NULL DEFAULT 0"),
            ("custom_rules", "incidents_opened", "INTEGER NOT NULL DEFAULT 0"),
        )
        for table, column, decl in additions:
            cols = {
                r["name"] for r in
                self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if not cols:
                continue  # table absent in this build; nothing to migrate
            if column not in cols:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    @property
    def investigations(self):
        """
        Aggregation queries over the lake.

        A property rather than a stored attribute so it always shares the live
        connection, and lazy so importing the store does not import the query
        module (which imports ATT&CK metadata) for a caller that never queries.
        """
        if getattr(self, "_investigations", None) is None:
            from tiox.store.investigations import Investigations

            self._investigations = Investigations(self)
        return self._investigations

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

    # ------------------------------------------------------------------ scans

    def start_scan(
        self,
        scan_path: str,
        initiated_by: str = "local",
        host: str | None = None,
    ) -> dict[str, Any]:
        """
        Open a scan run and return its record.

        The id is a UUID so it is unique across restarts, hosts, and concurrent
        invocations; `seq` is a separate human-facing counter, because an analyst
        comparing two runs wants "scan #14", not a UUID.
        """
        scan_id = str(uuid.uuid4())
        started = iso()
        with self._tx() as c:
            row = c.execute("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM scans").fetchone()
            seq = int(row["n"])
            c.execute(
                """INSERT INTO scans (scan_id, seq, started_ts, status, scan_path,
                                     initiated_by, host)
                   VALUES (?, ?, ?, 'running', ?, ?, ?)""",
                (scan_id, seq, started, scan_path, initiated_by, host),
            )
        # Return the same shape get_scan() will later return, label included.
        # Returning a narrower dict here meant the caller read record["label"],
        # got a KeyError, and the scan thread died before doing any work --
        # leaving a scan stuck at "running" forever.
        created = self.get_scan(scan_id)
        if created is None:  # pragma: no cover -- the row was just written
            raise RuntimeError(f"scan {scan_id} vanished after write")
        return created

    def update_scan(self, scan_id: str, /, **fields: Any) -> bool:
        """
        Update a run's counters. Whitelisted so a caller cannot set scan_id.

        scan_id is positional-only: as a normal parameter it would collide with a
        caller passing scan_id= in the update dict, raising TypeError instead of
        silently ignoring the attempt.
        """
        allowed = {
            "status", "ended_ts", "files_scanned", "dirs_scanned",
            "threats_found", "errors", "duration_ms", "error",
        }
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return False
        clause = ", ".join(f"{k} = ?" for k in sets)
        with self._tx() as c:
            cur = c.execute(
                f"UPDATE scans SET {clause} WHERE scan_id = ?",
                (*sets.values(), scan_id),
            )
            return cur.rowcount > 0

    def finish_scan(self, scan_id: str, status: str = "completed", **fields: Any) -> bool:
        ended = iso()
        started = self.get_scan(scan_id)
        duration = None
        if started:
            try:
                duration = int(
                    (datetime.fromisoformat(ended) - datetime.fromisoformat(started["started_ts"]))
                    .total_seconds() * 1000
                )
            except (TypeError, ValueError):
                duration = None
        return self.update_scan(
            scan_id, status=status, ended_ts=ended, duration_ms=duration, **fields
        )

    def record_finding(self, scan_id: str, finding: dict[str, Any]) -> str:
        """
        Store one scan hit, and return its finding id.

        A finding is tied to a file, not to an occurrence: the same malicious
        file seen twice in one scan is one finding with a count, which is what
        makes "how many copies of this are on disk" answerable.
        """
        finding_id = str(uuid.uuid4())
        techniques = finding.get("techniques") or []
        with self._tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO scan_findings
                     (scan_id, finding_id, file_path, file_hash, family, rule_id,
                      severity, techniques, event_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, finding_id,
                    finding.get("file_path"), finding.get("file_hash"),
                    finding.get("family"), finding.get("rule_id"),
                    finding.get("severity"), json.dumps(techniques),
                    finding.get("event_id"),
                ),
            )
        return finding_id

    def link_finding_event(self, scan_id: str, file_hash: str, event_id: str) -> int:
        """Tie a finding to the event it produced, so a click reaches the event."""
        with self._tx() as c:
            cur = c.execute(
                "UPDATE scan_findings SET event_id = ? WHERE scan_id = ? AND file_hash = ?",
                (event_id, scan_id, file_hash),
            )
            return cur.rowcount

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return _scan_row(row) if row else None

    def list_scans(
        self,
        host: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM scans WHERE 1=1"
        args: list[Any] = []
        if host:
            sql += " AND host = ?"
            args.append(host)
        if status:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [_scan_row(r) for r in rows]

    def scan_findings(self, scan_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scan_findings WHERE scan_id = ? LIMIT ?",
                (scan_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["techniques"] = json.loads(d.get("techniques") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["techniques"] = []
            out.append(d)
        return out

    def scan_stats(self) -> dict[str, Any]:
        """Totals for the dashboard tiles. Reads the scans table, not counters."""
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*)                        AS total,
                          COALESCE(SUM(threats_found), 0) AS threats,
                          COALESCE(SUM(errors), 0)       AS errors,
                          COALESCE(SUM(files_scanned),0) AS files,
                          COALESCE(SUM(duration_ms), 0)  AS duration_ms,
                          COUNT(DISTINCT host)           AS hosts
                   FROM scans"""
            ).fetchone()
        out = dict(row)
        runs = out["total"] or 0
        out["avg_duration_ms"] = int(out.pop("duration_ms") / runs) if runs else 0
        out["last_scan"] = None
        latest = self.list_scans(limit=1)
        if latest:
            out["last_scan"] = latest[0]
        return out

    # ---------------------------------------------------------- correlation

    def create_correlated_incident(
        self, inc: dict[str, Any], event_id: str | None = None
    ) -> dict[str, Any]:
        """
        Open an incident with a correlation key and its first event.

        The key and its human-readable components are stored together: the digest
        groups, the components explain, and an analyst looking at a queue needs
        the second without reverse-engineering the first.
        """
        created = self.create_incident(inc, event_id=event_id)
        if event_id and created.get("id"):
            self.attach_incident_event(created["id"], event_id)
        return created

    def find_correlated_incident(
        self, key: str, since: str
    ) -> dict[str, Any] | None:
        """
        An open incident with this key, created at or after `since`.

        Only `open` and `investigating` match. A resolved incident that reopens on
        the next hit loses the resolution history and the effort spent on the
        first occurrence, which is worse than a duplicate.
        """
        with self._lock:
            row = self._conn.execute(
                """SELECT * FROM incidents
                    WHERE correlation_key = ?
                      AND status IN ('open', 'investigating')
                      AND (created >= ? OR updated >= ?)
                    ORDER BY created DESC LIMIT 1""",
                (key, since, since),
            ).fetchone()
        return _incident_row(row) if row else None

    def attach_incident_event(self, incident_id: str, event_id: str | None) -> bool:
        """
        Add an event to an incident's evidence set.

        Idempotent: the same event joining twice is one link, so a replayed feed
        cannot inflate the event count an analyst reads.
        """
        if not incident_id or not event_id:
            return False
        with self._tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id, linked_ts) "
                "VALUES (?, ?, ?)",
                (incident_id, event_id, iso()),
            )
            return cur.rowcount > 0

    def incident_events(self, incident_id: str) -> list[dict[str, Any]]:
        """The incident's evidence, oldest first, so it reads as a timeline."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT e.*, ie.linked_ts FROM incident_events ie
                   JOIN events e ON e.event_id = ie.event_id
                   WHERE ie.incident_id = ?
                   ORDER BY e.ts ASC""",
                (incident_id,),
            ).fetchall()
        return [self._row_to_event_dict(r) for r in rows]

    def incident_event_count(self, incident_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM incident_events WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return int(row["n"])

    def promote_incident_severity(self, incident_id: str, severity: str) -> bool:
        """
        Raise an incident's severity to the highest member severity.

        Max, never average: fifty low-severity hits must not dilute one critical
        hit. Returns True when the severity actually changed, so the caller can
        record that it was promoted.
        """
        current = self.get_incident(incident_id)
        if not current:
            return False
        if not severity_at_least(severity, current.get("severity", "medium")):
            return False
        with self._tx() as c:
            c.execute(
                "UPDATE incidents SET severity = ?, updated = ? WHERE id = ?",
                (str(severity), iso(), incident_id),
            )
        return True

    def merge_incident_components(self, incident_id: str, components: dict[str, str]) -> None:
        """
        Widen an incident's recorded component set.

        The second host to hit the same key is the information that turns "a
        detection" into "a spread", and it is only visible because the incident
        outlives the first event that created it.
        """
        existing = self.get_incident(incident_id) or {}
        current = existing.get("correlation_components") or {}
        merged = dict(current)
        for name, value in (components or {}).items():
            if not value:
                continue
            have = {v for v in str(current.get(name, "")).split(",") if v}
            add = {v for v in str(value).split(",") if v}
            if add:
                merged[name] = ",".join(sorted(have | add))
        if merged == current:
            return
        with self._tx() as c:
            c.execute(
                "UPDATE incidents SET correlation_components = ?, updated = ? WHERE id = ?",
                (json.dumps(merged), iso(), incident_id),
            )

    # ---------------------------------------------------------- suppression

    def suppress_rule(self, rule_id: str, minutes: int = 1440,
                      reason: str | None = None) -> bool:
        """
        Mute a rule for a period, without disabling or deleting it.

        Time-boxed on purpose. An analyst who says "this is noise today" should
        not have to remember to unmute it in a week, and an unbounded mute is
        indistinguishable from a disabled rule.
        """
        until = (datetime.now() + timedelta(minutes=max(1, minutes))).isoformat()
        with self._tx() as c:
            c.execute(
                """INSERT INTO rule_suppressions (rule_id, suppressed_until, reason, created_ts)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(rule_id) DO UPDATE SET
                       suppressed_until = excluded.suppressed_until,
                       reason = excluded.reason""",
                (rule_id, until, reason, iso()),
            )
        return True

    def unsuppress_rule(self, rule_id: str) -> bool:
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM rule_suppressions WHERE rule_id = ?", (rule_id,))
            return cur.rowcount > 0

    def is_rule_suppressed(self, rule_id: str) -> bool:
        if not rule_id:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT suppressed_until FROM rule_suppressions WHERE rule_id = ?",
                (rule_id,),
            ).fetchone()
        if not row:
            return False
        until = _parse_iso(row["suppressed_until"])
        return bool(until and until > datetime.now(until.tzinfo))

    def list_suppressions(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM rule_suppressions ORDER BY suppressed_until DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------- custom rules

    def save_rule(self, rule: dict[str, Any], rule_id: str | None = None) -> dict[str, Any]:
        """
        Create or update a custom rule.

        The tree is validated before it is stored, so a rule that can never fire
        is rejected at save time rather than discovered as silence weeks later.
        """
        from tiox.rules.engine import validate

        tree = rule.get("tree")
        if not isinstance(tree, dict):
            raise ValueError("rule needs a tree object")
        problems = validate(tree)
        if problems:
            raise ValueError("; ".join(problems))

        now = iso()
        rid = rule_id or str(uuid.uuid4())
        techniques = json.dumps(rule.get("techniques") or [])
        name = (rule.get("name") or "untitled").strip() or "untitled"

        existing = self.get_rule(rid)
        if existing:
            with self._tx() as c:
                c.execute(
                    """UPDATE custom_rules
                       SET name = ?, description = ?, severity = ?, techniques = ?,
                           tree = ?, enabled = ?, mode = ?, updated_ts = ?
                       WHERE rule_id = ?""",
                    (name, rule.get("description", ""), rule.get("severity", "medium"),
                     techniques, json.dumps(tree), 1 if rule.get("enabled", True) else 0,
                     _normalise_mode(rule.get("mode")), now, rid),
                )
        else:
            with self._tx() as c:
                c.execute(
                    """INSERT INTO custom_rules
                         (rule_id, name, description, severity, techniques, tree,
                          enabled, author, created_ts, updated_ts, mode)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (rid, name, rule.get("description", ""),
                     rule.get("severity", "medium"), techniques, json.dumps(tree),
                     1 if rule.get("enabled", True) else 0,
                     rule.get("author"), now, now,
                     _normalise_mode(rule.get("mode"))),
                )
        saved = self.get_rule(rid)
        if saved is None:  # pragma: no cover -- the row was just written
            raise RuntimeError(f"rule {rid} vanished after write")
        return saved

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM custom_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
        return _rule_row(row) if row else None

    def list_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM custom_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY name"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [_rule_row(r) for r in rows]

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        with self._tx() as c:
            cur = c.execute(
                "UPDATE custom_rules SET enabled = ?, updated_ts = ? WHERE rule_id = ?",
                (1 if enabled else 0, iso(), rule_id),
            )
            return cur.rowcount > 0

    def delete_rule(self, rule_id: str) -> bool:
        with self._tx() as c:
            cur = c.execute("DELETE FROM custom_rules WHERE rule_id = ?", (rule_id,))
            return cur.rowcount > 0

    def record_rule_incidents(self, rule_id: str, opened: int) -> None:
        """
        Count incidents a rule actually opened.

        Separate from hits because the two diverge sharply: a rule that fires a
        hundred times inside one correlation window produces a single incident.
        Ranking on raw hits would call that the noisiest rule on the platform.
        """
        with self._tx() as c:
            c.execute(
                "UPDATE custom_rules SET incidents_opened = incidents_opened + ? "
                "WHERE rule_id = ?",
                (opened, rule_id),
            )

    def record_rule_false_positive(self, rule_id: str, count: int = 1) -> None:
        """
        Note that a rule produced work an analyst rejected.

        A count, not a flag: one analyst dismissing a hit says little about a
        rule, and a rule that is quietly one bad morning away from being deleted
        is a rule nobody trusts.
        """
        with self._tx() as c:
            c.execute(
                "UPDATE custom_rules SET false_positives = false_positives + ? "
                "WHERE rule_id = ?",
                (count, rule_id),
            )

    def rule_effectiveness(self, since: str | None = None) -> list[dict[str, Any]]:
        """
        Per-rule tuning signal: hits, incidents, false positives, and a rank.

        Advisory only. Nothing here disables anything -- a detection that
        vanishes without explanation is the failure mode this whole phase exists
        to prevent. The numbers are there so an analyst can decide.
        """
        since = since or iso()
        with self._lock:
            rows = self._conn.execute(
                """SELECT r.rule_id, r.name, r.severity, r.mode, r.enabled,
                          r.hits_total, r.incidents_opened, r.false_positives,
                          r.last_run_ts,
                          (SELECT COUNT(DISTINCT i.id)
                             FROM incidents i
                            WHERE i.rule_id = r.rule_id
                              AND i.created >= ?) AS window_incidents
                     FROM custom_rules r
                    ORDER BY r.hits_total DESC""",
                (since,),
            ).fetchall()

        out = []
        for r in rows:
            hits = int(r["hits_total"] or 0)
            incidents = int(r["incidents_opened"] or 0)
            fps = int(r["false_positives"] or 0)
            # Yield = how much of the rule's output was worth an analyst's time.
            # A rule with zero hits has no evidence either way, so it is neither
            # promoted nor demoted.
            if hits == 0:
                precision = None
                grade = "untested"
            else:
                precision = round(max(0.0, (incidents - fps) / hits), 3)
                if fps > incidents and fps > 0:
                    grade = "noisy"
                elif incidents == 0:
                    grade = "quiet"
                elif precision >= 0.5:
                    grade = "productive"
                else:
                    grade = "marginal"
            out.append({
                "rule_id": r["rule_id"],
                "name": r["name"],
                "severity": r["severity"],
                "mode": r["mode"],
                "enabled": bool(r["enabled"]),
                "hits": hits,
                "incidents": incidents,
                "false_positives": fps,
                "precision": precision,
                "grade": grade,
                "last_run_ts": r["last_run_ts"],
            })

        # Most productive first, untested last.
        order = {"productive": 0, "marginal": 1, "noisy": 2, "quiet": 3,
                 "untested": 4}
        out.sort(key=lambda x: (order.get(x["grade"], 9), -(x["incidents"] or 0)))
        return out

    def record_rule_run(self, rule_id: str, hits: int) -> None:
        with self._tx() as c:
            c.execute(
                """UPDATE custom_rules
                   SET last_run_ts = ?, last_hits = ?, hits_total = hits_total + ?
                   WHERE rule_id = ?""",
                (iso(), hits, hits, rule_id),
            )

    def scans_for_event(self, event_id: str) -> list[dict[str, Any]]:
        """Which scan produced this event. The reverse of the finding link."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT s.* FROM scans s
                   JOIN scan_findings f ON f.scan_id = s.scan_id
                   WHERE f.event_id = ? ORDER BY s.seq DESC""",
                (event_id,),
            ).fetchall()
        return [_scan_row(r) for r in rows]

    def increment_scan(self, endpoint_id: str, threats: int = 0) -> None:
        """
        Bump an endpoint's scan counters.

        Kept as a per-endpoint lifetime tally for the inventory view. The scans
        table is the authoritative run history -- this only exists so a view that
        asks "how many scans has this host reported" does not have to aggregate
        every run.
        """
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
                   type, details, created, updated, event_id, rule_id,
                   correlation_key, correlation_components)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    inc_id, inc.get("title", "Untitled"), inc.get("description", ""),
                    inc.get("severity", "medium"), inc.get("status", "open"),
                    inc.get("source"), inc.get("type"),
                    json.dumps(inc.get("details") or {}),
                    inc.get("created") or now, now, event_id,
                    inc.get("rule_id"),
                    inc.get("correlation_key"),
                    json.dumps(inc.get("correlation_components") or {}),
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
        # _incident_row parses the JSON columns; get_incident used to do its own
        # json.loads, which left correlation_components a raw string and made
        # merge_incident_components re-parse a string on every join.
        d = _incident_row(row)
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
                   severity, host, user, title, rule_id, tlp, raw, schema_version,
                   dedupe_key, techniques)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    d["event_id"], d["ts"], d["ingest_ts"], d["source"], d["type"],
                    d["severity"], d.get("host"), d.get("user"), d.get("title"),
                    d.get("rule_id"), d.get("tlp"), json.dumps(d.get("raw") or {}),
                    d.get("schema_version", SCHEMA_VERSION), dedupe,
                    json.dumps(d.get("techniques") or []),
                ),
            )
            for tid in d.get("techniques") or []:
                c.execute(
                    "INSERT OR IGNORE INTO event_techniques (event_id, technique_id) VALUES (?,?)",
                    (d["event_id"], tid),
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

    def entities_for_events(self, event_ids: list[str]) -> dict[str, dict[str, list[str]]]:
        """
        Entities for a set of events, as {event_id: {type: [values]}}.

        Batched and chunked because the UI needs the pivot targets alongside
        each row, and issuing one query per row would be N+1 on every table
        render.
        """
        out: dict[str, dict[str, list[str]]] = {}
        ids = [e for e in event_ids if e]
        if not ids:
            return out
        conn = self._conn
        # 400 stays under SQLite's default 999-variable limit.
        for start in range(0, len(ids), 400):
            chunk = ids[start:start + 400]
            marks = ",".join("?" * len(chunk))
            for row in conn.execute(
                f"SELECT event_id, entity_type, entity_value FROM event_entities "
                f"WHERE event_id IN ({marks})",
                chunk,
            ).fetchall():
                out.setdefault(row["event_id"], {}).setdefault(
                    row["entity_type"], []
                ).append(row["entity_value"])
        return out

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
        try:
            d["techniques"] = json.loads(d.get("techniques") or "[]")
        except json.JSONDecodeError:
            d["techniques"] = []
        return d
