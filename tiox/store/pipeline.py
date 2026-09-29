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
from typing import TYPE_CHECKING, Any

from tiox.connectors.base import Connector, ConnectorError
from tiox.connectors.registry import get as get_connector
from tiox.schemas.event import Event
from tiox.store.control import ControlPlane

if TYPE_CHECKING:  # pragma: no cover -- import cycle broken at runtime
    from tiox.detection import DetectionEngine

log = logging.getLogger(__name__)

# One engine for the process. It caches the enabled rule set, and rebuilding
# that on every payload would re-read and re-validate every rule for every event
# batch. A save_rule call must invalidate it -- see invalidate_detection().
_ENGINE: "DetectionEngine | None" = None


def get_detection_engine(store: ControlPlane) -> "DetectionEngine":
    """
    The process-wide engine, rebuilt if the store it is bound to has changed.

    The engine caches both the rule set and the store it read them from. A test
    (or a future reconfiguration) that swaps the store would otherwise leave the
    engine querying the previous one -- which, once that store is closed, means
    every detection silently stops and only a logged exception says why.
    """
    global _ENGINE
    if _ENGINE is None or _ENGINE.store is not store:
        from tiox.detection import DetectionEngine

        _ENGINE = DetectionEngine(store)
    return _ENGINE


def invalidate_detection() -> None:
    """
    Drop the cached rule set after a rule is saved, enabled, or deleted.

    Without this a rule edit would not take effect until the process restarted,
    and an analyst who enables a rule and immediately tests it would see it not
    fire -- and conclude the engine is broken.
    """
    if _ENGINE is not None:
        _ENGINE.invalidate()


class IngestResult:
    __slots__ = ("inserted", "duplicates", "events", "errors",
                 "detections", "detection_events")

    def __init__(self) -> None:
        self.inserted = 0
        self.duplicates = 0
        self.events: list[Event] = []
        self.errors: list[str] = []
        # Custom-rule hits produced while ingesting this payload, and the
        # threat_hit events built from them. Reported separately from `events`
        # so a caller can tell an observation from a detection of one.
        self.detections: list[dict[str, Any]] = []
        self.detection_events: list[Event] = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "normalized": len(self.events),
            "detections": len(self.detection_events),
            "errors": self.errors,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<IngestResult inserted={self.inserted} duplicates={self.duplicates} "
            f"detections={len(self.detection_events)} errors={len(self.errors)}>"
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

    engine = get_detection_engine(store)

    for ev in events:
        result.events.append(ev)
        try:
            is_new = store.insert_event(ev)
        except Exception as exc:
            log.exception("failed to store event %s", ev.event_id)
            result.errors.append(f"store: {exc}")
            continue

        if is_new:
            result.inserted += 1
        else:
            result.duplicates += 1

        # Detection runs only on events that were actually new. Re-evaluating a
        # duplicate would double-count a rule's hits every time a feed replays,
        # and would re-open incidents for observations already accounted for.
        #
        # This has to key off is_new, not off the counters: the previous version
        # incremented `duplicates` in an else branch and then fell through to
        # detection anyway, so a replayed feed produced a fresh threat_hit every
        # time -- the exact inflation the check exists to prevent.
        if not is_new or not should_detect(ev):
            continue

        # A rule hit is itself a threat_hit event. Running the rules over it would
        # let a rule that matches on "type is threat_hit" fire on its own
        # output, and a broad rule would then amplify its own hits without end.
        try:
            detection_events, hits = engine.process(ev)
        except Exception:
            # Detection is additive: a broken rule must degrade to no detection,
            # never to a failed ingest of data that arrived fine.
            log.exception("detection failed for event %s", ev.event_id)
            result.errors.append(f"detection: {ev.event_id}")
            continue

        if not detection_events:
            continue

        result.detections.extend(hits)
        for det in detection_events:
            try:
                if store.insert_event(det):
                    result.inserted += 1
                else:
                    result.duplicates += 1
                result.detection_events.append(det)
            except Exception as exc:
                log.exception("failed to store detection %s", det.event_id)
                result.errors.append(f"store detection: {exc}")

    # Counters are written once per payload, not once per event, so the tuning
    # view reflects this batch rather than every intermediate state.
    if result.detections:
        try:
            engine.record_outcome(result.detections)
        except Exception:  # pragma: no cover -- counters are not load-bearing
            log.exception("could not record rule outcomes")

    return result


def should_detect(event: Event) -> bool:
    """
    Whether a rule should be offered this event.

    Two exclusions, both about signal rather than safety. A heartbeat every
    thirty seconds across fifty hosts is twenty-eight thousand events a day, and
    evaluating rules over all of them to find nothing is a real cost for no
    benefit. And a detection of a detection is a feedback loop.
    """
    if event.type == "agent_status":
        return False
    if (event.rule_id or "").startswith("custom:"):
        return False
    return True


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
