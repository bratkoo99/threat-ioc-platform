"""
Ingest pipeline: native payload -> connector -> canonical events -> store.

One function, `ingest`, is the only path into the lake. Everything upstream of it
(agent HTTP handlers, feed pollers, future cloud connectors) is a producer; the
pipeline owns normalization, dedupe, and persistence. That is the seam that keeps
connectors pure.

The pipeline is also where the legacy JSON store gets retired: `migrate_legacy`
replays incidents.json and inventory.json through the same connector code, so
historical data enters the lake with the same normalization as new data and can
be re-normalized by fixing the connector later.
"""

from __future__ import annotations

import logging
from typing import Any

from tiox.connectors.base import Connector, ConnectorError
from tiox.connectors.registry import get as get_connector
from tiox.schemas.event import Event
from tiox.store.control import ControlPlane

log = logging.getLogger(__name__)


class IngestResult:
    __slots__ = ("inserted", "duplicates", "events", "errors")

    def __init__(self) -> None:
        self.inserted = 0
        self.duplicates = 0
        self.events: list[Event] = []
        self.errors: list[str] = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "normalized": len(self.events),
            "errors": self.errors,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<IngestResult inserted={self.inserted} duplicates={self.duplicates} "
            f"errors={len(self.errors)}>"
        )


def ingest(
    store: ControlPlane,
    payload: dict[str, Any],
    source: str,
    context: dict[str, Any] | None = None,
    connector: Connector | None = None,
) -> IngestResult:
    """
    Normalize one native payload and persist the resulting events.

    A connector that raises is an ingest failure, not a platform failure: the
    error is recorded and returned, and the caller decides whether to retry. This
    keeps one malformed feed from taking down the agent path.
    """
    result = IngestResult()
    conn = connector or get_connector(source)
    try:
        events = conn.normalize(payload, context or {})
    except ConnectorError as exc:
        log.warning("connector %s failed: %s", source, exc)
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # a buggy connector must not kill the pipeline
        log.exception("connector %s raised unexpectedly", source)
        result.errors.append(f"{type(exc).__name__}: {exc}")
        return result

    for ev in events:
        result.events.append(ev)
        try:
            if store.insert_event(ev):
                result.inserted += 1
            else:
                result.duplicates += 1
        except Exception as exc:
            log.exception("failed to store event %s", ev.event_id)
            result.errors.append(f"store: {exc}")
    return result


def migrate_legacy(
    store: ControlPlane,
    incidents: list[dict[str, Any]] | None = None,
    inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Replay the pre-Phase-0 JSON stores into the control plane and the lake.

    Incidents become `incident` events carrying their original id in
    raw.legacy_incident_id, so the migration is idempotent and a re-run does not
    duplicate history. Endpoints are upserted by hostname, which is what the old
    code effectively did (it just tracked a running count, so re-registration
    created duplicate rows — that bug does not survive the move).
    """
    from tiox.connectors.agent import normalize_incident

    summary = {"endpoints": 0, "incidents": 0, "events": 0, "duplicates": 0, "errors": []}

    for ep in (inventory or {}).get("endpoints", []):
        try:
            store.upsert_endpoint({
                "id": ep.get("id"),
                "hostname": ep.get("hostname", "unknown"),
                "ip": ep.get("ip"),
                "os": ep.get("os"),
                "version": ep.get("version"),
                "status": ep.get("status", "unknown"),
                "connector": "agent",
                "extra": {"registered": ep.get("registered"), "legacy": True},
            })
            summary["endpoints"] += 1
        except Exception as exc:
            summary["errors"].append(f"endpoint {ep.get('hostname')}: {exc}")

    for inc in incidents or []:
        try:
            events = normalize_incident(inc)
            if not events:
                continue
            inserted, dupes = store.insert_events(events)
            summary["events"] += inserted
            summary["duplicates"] += dupes
            ev = events[0]
            store.create_incident(inc, event_id=ev.event_id)
            summary["incidents"] += 1
        except Exception as exc:
            log.exception("failed to migrate incident %s", inc.get("id"))
            summary["errors"].append(f"incident {inc.get('id')}: {exc}")

    return summary
