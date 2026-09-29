"""
Investigation queries.

`query_events` and `find_by_entity` answer "show me matching rows". A hunter's
real questions are aggregations: how far did this spread, what keeps coming back,
what have we not seen in a week. Those are what this module adds.

Every function here is a plain SQL GROUP BY over indexed columns. That is
deliberate: it keeps the whole investigation surface inside SQLite, and
`ControlPlane` already isolates storage behind a class, so the same calls port to
ClickHouse later by changing the dialect rather than the callers.

Time windows are always optional and always applied server-side. Nothing here
fetches everything and filters in Python.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from tiox.schemas.event import iso

# Where a time filter is needed but not supplied.
_ALL_TIME = "9999-12-31T23:59:59+00:00"


def _since(since: str | None) -> str:
    return since or _ALL_TIME


def parse_window(value: str | None, default_hours: int = 24) -> tuple[str | None, str | None]:
    """
    Accept either an explicit ISO `since`, or a shorthand like "24h" / "7d".

    The shorthand is what the UI's time picker sends, so keeping the parsing here
    means one place defines what "last 7 days" means.
    """
    if not value:
        now = datetime.now(timezone.utc)
        return iso(now - timedelta(hours=default_hours)), iso(now)
    v = str(value).strip().lower()
    if v in ("all", "any"):
        return None, None
    if v == "":
        # An explicit empty `window=` means the caller sent nothing useful, so
        # fall through to the default rather than silently querying all time.
        now = datetime.now(timezone.utc)
        return iso(now - timedelta(hours=default_hours)), iso(now)
    # ISO timestamp: a date ("2026-01-01") or a full stamp.
    if "t" in v or v.endswith("z") or re.match(r"^\d{4}-\d{2}-\d{2}", v):
        try:
            # The Z suffix is the most common ISO form in the wild, and
            # fromisoformat only learned to accept it in Python 3.11. Replacing it
            # explicitly keeps the UI's datetime-local value working on 3.10.
            dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("z") else v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return iso(dt), None
        except ValueError:
            pass
    # shorthand
    units = {"m": 1 / 60, "h": 1, "d": 24, "w": 168}
    if v and v[-1] in units and v[:-1].replace(".", "", 1).isdigit():
        n = float(v[:-1])
        hours = n * units[v[-1]]
        now = datetime.now(timezone.utc)
        return iso(now - timedelta(hours=hours)), iso(now)
    # bare number = hours
    try:
        hours = float(v)
    except ValueError:
        # Unrecognised input must not become "all time": a garbled window that
        # silently widens the query is how a 24h view turns into a full-lake scan.
        now = datetime.now(timezone.utc)
        return iso(now - timedelta(hours=default_hours)), iso(now)
    now = datetime.now(timezone.utc)
    return iso(now - timedelta(hours=hours)), iso(now)


class Investigations:
    """
    Aggregations over the event lake.

    Instantiated per store so it can share the connection and the lock, rather
    than reaching for module-level state.
    """

    def __init__(self, store) -> None:
        self._store = store

    # ---------- internals ----------

    def _conn(self) -> sqlite3.Connection:
        return self._store._conn

    def _time_clause(self, since: str | None = None, until: str | None = None,
                     alias: str = "e") -> tuple[str, list[Any]]:
        where, params = [], []
        if since:
            where.append(f"{alias}.ts >= ?")
            params.append(since)
        if until:
            where.append(f"{alias}.ts <= ?")
            params.append(until)
        return (" AND ".join(where), params)

    # ---------- spread: "how far did this get?" ----------

    def entity_spread(self, entity_type: str, entity_value: str,
                      since: str | None = None) -> dict[str, Any]:
        """
        How widely one indicator is distributed.

        The single most useful question about an IOC: one host is a curiosity,
        forty hosts is an incident. Returns host count, first/last seen, the
        hosts themselves, and the families that hit it.
        """
        value = (entity_value or "").lower()
        conn = self._conn()
        clause, params = self._time_clause(since)

        row = conn.execute(
            f"""SELECT COUNT(DISTINCT e.event_id) AS events,
                       COUNT(DISTINCT e.host)      AS hosts,
                       COUNT(DISTINCT e.source)    AS sources,
                       MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
                FROM events e
                JOIN event_entities ee ON ee.event_id = e.event_id
                WHERE ee.entity_type = ? AND ee.entity_value = ?{_and(clause)}""",
            [entity_type, value, *params],
        ).fetchone()

        hosts = [
            dict(r) for r in conn.execute(
                f"""SELECT e.host AS host, COUNT(*) AS events,
                           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
                    FROM events e
                    JOIN event_entities ee ON ee.event_id = e.event_id
                    WHERE ee.entity_type = ? AND ee.entity_value = ?{_and(clause)}
                    GROUP BY e.host
                    ORDER BY events DESC""",
                [entity_type, value, *params],
            ).fetchall()
        ]

        families = [
            r["family"] for r in conn.execute(
                f"""SELECT DISTINCT json_extract(e.raw, '$.family') AS family
                    FROM events e
                    JOIN event_entities ee ON ee.event_id = e.event_id
                    WHERE ee.entity_type = ? AND ee.entity_value = ?{_and(clause)}
                      AND json_extract(e.raw, '$.family') IS NOT NULL""",
                [entity_type, value, *params],
            ).fetchall()
        ]

        return {
            "entity": {"type": entity_type, "value": value},
            "events": int(row["events"] or 0),
            "host_count": int(row["hosts"] or 0),
            "source_count": int(row["sources"] or 0),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "hosts": hosts,
            "families": sorted(f for f in families if f),
        }

    # ---------- what keeps coming back ----------

    def top_entities(self, entity_type: str = "file_hash", since: str | None = None,
                     limit: int = 20) -> list[dict[str, Any]]:
        """
        Most frequent entity values of a type, with their host spread.

        Frequency alone is noisy (a hash on one host seen 200 times is one
        problem), so host_count is included and sortable -- that is what
        distinguishes a campaign from a loop.
        """
        clause, params = self._time_clause(since)
        rows = self._conn().execute(
            f"""SELECT ee.entity_value AS value,
                       COUNT(DISTINCT e.event_id) AS events,
                       COUNT(DISTINCT e.host)      AS hosts,
                       MAX(e.severity)             AS worst_severity,
                       MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
                FROM events e
                JOIN event_entities ee ON ee.event_id = e.event_id
                WHERE ee.entity_type = ?{_and(clause)}
                GROUP BY ee.entity_value
                ORDER BY hosts DESC, events DESC
                LIMIT ?""",
            [entity_type, *params, max(1, min(limit, 200))],
        ).fetchall()
        return [dict(r) for r in rows]

    def entity_first_last_seen(self, entity_type: str, since: str | None = None,
                               limit: int = 100) -> list[dict[str, Any]]:
        """First/last sighting per entity value -- the "when did this start?" view."""
        clause, params = self._time_clause(since)
        rows = self._conn().execute(
            f"""SELECT ee.entity_value AS value,
                       COUNT(DISTINCT e.event_id) AS events,
                       MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
                FROM events e
                JOIN event_entities ee ON ee.event_id = e.event_id
                WHERE ee.entity_type = ?{_and(clause)}
                GROUP BY ee.entity_value
                ORDER BY first_seen ASC
                LIMIT ?""",
            [entity_type, *params, max(1, min(limit, 500))],
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------- timeline ----------

    def timeline(self, since: str | None = None, until: str | None = None,
                 bucket: str = "hour", entity_type: str | None = None,
                 entity_value: str | None = None) -> list[dict[str, Any]]:
        """
        Event counts bucketed over time, for a sparkline or a hunt timeline.

        `bucket` accepts SQLite's strftime formats, e.g. "%Y-%m-%dT%H:00" for
        hourly. Done in SQL because pulling every event into Python to bin it
        would not survive a real dataset.
        """
        fmt = {
            "minute": "%Y-%m-%dT%H:%M",
            "hour": "%Y-%m-%dT%H:00",
            "day": "%Y-%m-%d",
            "week": "%Y-W%W",
            "month": "%Y-%m",
        }.get(bucket, "%Y-%m-%dT%H:00")

        clause, params = self._time_clause(since, until)
        join = ""
        extra: list[Any] = []
        if entity_type and entity_value:
            join = ("JOIN event_entities ee ON ee.event_id = e.event_id "
                    "AND ee.entity_type = ? AND ee.entity_value = ?")
            extra = [entity_type, (entity_value or "").lower()]

        rows = self._conn().execute(
            f"""SELECT strftime('{fmt}', e.ts) AS bucket,
                       COUNT(*) AS events,
                       SUM(CASE WHEN e.severity IN ('high','critical') THEN 1 ELSE 0 END) AS high
                FROM events e
                {join}
                WHERE 1=1{_and(clause)}
                GROUP BY bucket
                ORDER BY bucket""",
            [*extra, *params],
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------- ATT&CK ----------

    def technique_breakdown(self, since: str | None = None) -> list[dict[str, Any]]:
        """
        Every technique seen, with event and host counts.

        The report an analyst builds a case from: which techniques this
        environment has actually shown, not which ones are in the catalog.
        """
        clause, params = self._time_clause(since)
        rows = self._conn().execute(
            f"""SELECT et.technique_id AS technique,
                       COUNT(DISTINCT e.event_id) AS events,
                       COUNT(DISTINCT e.host)      AS hosts,
                       MAX(e.severity)             AS worst_severity
                FROM event_techniques et
                JOIN events e ON e.event_id = et.event_id
                WHERE 1=1{_and(clause)}
                GROUP BY et.technique_id
                ORDER BY events DESC""",
            params,
        ).fetchall()

        from tiox.schemas import attack

        out = []
        for r in rows:
            d = dict(r)
            meta = attack.get(d["technique"])
            d["name"] = meta.name if meta else "Unknown technique"
            d["tactic"] = meta.tactic if meta else "unknown"
            d["url"] = meta.url if meta else None
            out.append(d)
        return out

    def technique_hosts(self, technique_id: str, since: str | None = None) -> list[dict[str, Any]]:
        """Which hosts produced a given technique."""
        clause, params = self._time_clause(since)
        rows = self._conn().execute(
            f"""SELECT e.host AS host, COUNT(DISTINCT e.event_id) AS events,
                       MAX(e.severity) AS worst_severity,
                       MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
                FROM event_techniques et
                JOIN events e ON e.event_id = et.event_id
                WHERE et.technique_id = ?{_and(clause)} AND e.host IS NOT NULL
                GROUP BY e.host
                ORDER BY events DESC""",
            [technique_id, *params],
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------- estate ----------

    def stale_endpoints(self, days: int = 7) -> list[dict[str, Any]]:
        """
        Endpoints that have not reported recently.

        Answers "what is our blind spot?". Uses last_seen rather than event
        activity, because a healthy idle host should not look compromised --
        only absent.
        """
        cutoff = iso(datetime.now(timezone.utc) - timedelta(days=max(1, days)))
        rows = self._conn().execute(
            """SELECT id, hostname, ip, os, status, last_seen, registered
               FROM endpoints
               WHERE last_seen IS NULL OR last_seen < ?
               ORDER BY last_seen ASC""",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def host_summary(self, since: str | None = None) -> list[dict[str, Any]]:
        """
        Per-host rollup: events, high-severity count, techniques hit, last seen.

        This is the endpoint page's data source, and the thing that makes the
        fleet legible at a glance rather than one incident at a time.
        """
        clause, params = self._time_clause(since)
        tech_join = ("LEFT JOIN (SELECT event_id, GROUP_CONCAT(technique_id) AS techniques"
                     " FROM event_techniques GROUP BY event_id) t"
                     " ON t.event_id = e.event_id")
        rows = self._conn().execute(
            f"""SELECT e.host AS host,
                       COUNT(DISTINCT e.event_id) AS events,
                       SUM(CASE WHEN e.severity IN ('high','critical') THEN 1 ELSE 0 END) AS high,
                       COUNT(DISTINCT e.source) AS sources,
                       MAX(e.ts) AS last_seen,
                       MIN(e.ts) AS first_seen
                FROM events e
                {tech_join}
                WHERE e.host IS NOT NULL{_and(clause)}
                GROUP BY e.host
                ORDER BY high DESC, events DESC""",
            params,
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            techs = self._conn().execute(
                """SELECT DISTINCT et.technique_id FROM event_techniques et
                   JOIN events e ON e.event_id = et.event_id
                   WHERE e.host = ?""",
                (d["host"],),
            ).fetchall()
            d["techniques"] = sorted(t["technique_id"] for t in techs)
            out.append(d)
        return out

    def rule_breakdown(self, since: str | None = None) -> list[dict[str, Any]]:
        """Which detection rules are firing, and how often. Feeds rule tuning."""
        clause, params = self._time_clause(since)
        rows = self._conn().execute(
            f"""SELECT rule_id, COUNT(*) AS events,
                       COUNT(DISTINCT host) AS hosts,
                       MAX(severity) AS worst_severity,
                       MIN(ts) AS first_seen, MAX(ts) AS last_seen
                FROM events e
                WHERE rule_id IS NOT NULL{_and(clause)}
                GROUP BY rule_id
                ORDER BY events DESC""",
            params,
        ).fetchall()

        from tiox.schemas import attack

        out = []
        for r in rows:
            d = dict(r)
            rule = d["rule_id"] or ""
            d["techniques"] = attack.techniques_for_rule(rule)
            # Ask the ATT&CK module whether this is a genuine coverage gap, rather
            # than re-deciding here. Duplicating the rule meant an operational
            # rule like "system.operator.INC-0001" was reported as unmapped by
            # this query while unmapped_rules() correctly ignored it.
            d["unmapped"] = rule in attack.unmapped_rules([rule])
            out.append(d)
        return out


def _and(clause: str) -> str:
    """
    Prefix a time clause with AND.

    Every query composing one must already have a WHERE, or the result reads
    "... AND x = ? e.ts >= ?" -- a syntax error that only appears when a time
    window is actually supplied, so it hides until someone touches the time
    picker.
    """
    return f" AND {clause}" if clause else ""
