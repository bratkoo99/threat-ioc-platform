"""
System connector.

Platform-generated records (manual incidents, triage actions) are not a data
source with a native format -- they are born canonical. This connector exists so
`ingest_event(..., source="system")` has a real target instead of logging
"unknown connector" and silently dropping the record.

Kept separate from the agent connector so `Event.source` stays meaningful: a
pivot can then distinguish "an endpoint said this" from "an operator said this",
which matters for trust when the two disagree.
"""

from __future__ import annotations

from typing import Any

from tiox.connectors.base import Connector
from tiox.schemas.event import (
    EntityType,
    Event,
    EventType,
    Severity,
    merge_entities,
)

_EVENT_TYPE_MAP = {
    "incident": EventType.INCIDENT,
    "alert": EventType.ALERT,
    "agent": EventType.AGENT_STATUS,
    "malware": EventType.THREAT_HIT,
}


def normalize_severity(value: Any, default: Severity = Severity.MEDIUM) -> Severity:
    return {
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "crit": Severity.CRITICAL,
    }.get(str(value or "").strip().lower(), default)


class SystemConnector(Connector):
    """Normalizes operator-created records into events."""

    NAME = "system"
    SCHEMA_VER = "1"

    def normalize(self, payload: dict[str, Any], context: dict[str, Any] | None = None
                  ) -> list[Event]:
        context = context or {}
        if not isinstance(payload, dict):
            from tiox.connectors.base import ConnectorError

            raise ConnectorError(f"system payload must be an object, got {type(payload)}")

        # A bare incident record with nothing identifying it is not worth storing.
        if not (payload.get("title") or payload.get("id") or payload.get("description")):
            return []

        itype = _EVENT_TYPE_MAP.get(
            str(payload.get("type") or "incident").strip().lower(), EventType.INCIDENT
        )
        severity = normalize_severity(payload.get("severity"))
        raw = dict(payload)

        entities: dict[str, list[str]] = {}
        host = payload.get("host") or context.get("hostname")
        if host:
            entities[EntityType.HOST.value] = [str(host)]
        user = payload.get("user")
        if user:
            entities[EntityType.USER.value] = [str(user)]

        ev = Event(
            type=itype.value,
            source=self.NAME,
            severity=severity.value,
            host=host,
            user=user,
            entities=merge_entities(entities),
            title=str(payload.get("title") or payload.get("id") or "System record")[:512],
            description=str(payload.get("description") or ""),
            rule_id="system.operator",
            raw=raw,
            tags=["system", itype.value],
        )
        # A manually created incident is a distinct act from a machine finding,
        # so the incident id is part of identity. Two operators filing "Suspicious
        # activity" must not collapse into one event.
        inc_id = str(payload.get("id") or "").strip()
        if inc_id:
            ev.rule_id = f"system.operator.{inc_id}"
        ev.raw["operator_recorded"] = True
        return [ev]
