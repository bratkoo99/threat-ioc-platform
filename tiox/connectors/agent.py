"""
Endpoint agent connector.

Adapts the payloads produced by the existing agent (`web_ui_server.py`'s
`/api/agent/*` handlers and the generated bash agent) onto canonical events. This
is the reference implementation of a connector: when you write the EDR or STIX
connectors later, copy its shape, not its content.

Mapping notes, all of which are deliberate:

  * The agent's `type` field is one of two strings, "Filename pattern" or
    "Known malicious hash". Hash hits outrank name hits for severity, which is
    what the current web server already does in `add_incident` calls. That
    precedence is preserved here rather than reinvented, so historical and new
    alerts stay comparable.

  * The agent emits `datetime.now().isoformat()`, which is NAIVE local time with
    no offset. That is a real defect in the existing code: a scan from a host in
    a different timezone lands in the lake at the wrong instant, and the whole
    point of the lake is ordering. The adapter treats naive stamps as UTC and
    records the ambiguity in `raw` so a later fix can re-normalize correctly
    instead of silently keeping wrong data. Phase 0 does not change the agent's
    output format, because that would require redeploying every agent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from tiox.connectors.base import Connector, ConnectorError
from tiox.schemas.event import (
    EntityType,
    Event,
    EventType,
    Severity,
    host_entities,
    merge_entities,
)

# Agent's `type` string -> (severity, rule_id). Hash match is a confirmed
# malicious artifact; name match is a heuristic lead.
_THREAT_TYPE_MAP: dict[str, tuple[Severity, str]] = {
    "Known malicious hash": (Severity.CRITICAL, "builtin.hash_exact"),
    "Filename pattern": (Severity.HIGH, "builtin.filename_pattern"),
}

# A name match and a hash match on the same file is one event, not two.
_TYPE_PRECEDENCE = ["Known malicious hash", "Filename pattern"]

_EVENT_TYPE_MAP: dict[str, EventType] = {
    "file": EventType.FILE,
    "process": EventType.PROCESS,
    "network_conn": EventType.NETWORK_CONN,
    "dns": EventType.DNS,
    "auth": EventType.AUTH,
    "registry": EventType.REGISTRY,
    "threat_hit": EventType.THREAT_HIT,
    "alert": EventType.ALERT,
    "incident": EventType.INCIDENT,
    "agent_status": EventType.AGENT_STATUS,
}

_SEVERITY_ALIASES = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
}


def parse_agent_ts(value: Any) -> tuple[str, bool, bool]:
    """
    Parse an agent timestamp into an ISO-8601 UTC string.

    Returns (iso_string, was_naive, was_derived). `was_naive` means the source
    sent a local-time stamp with no offset; `was_derived` means there was no
    stamp at all and we used ingest time. Both are recorded on the event so the
    assumption stays auditable and dedupe knows not to trust the instant.
    """
    if not value:
        return datetime.now(timezone.utc).isoformat(), True, True
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConnectorError(f"unparseable agent timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc).isoformat(), True, False
    return dt.astimezone(timezone.utc).isoformat(), False, False


def normalize_severity(value: Any, default: Severity = Severity.INFO) -> Severity:
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), default)


class AgentConnector(Connector):
    """Normalizes agent scan hits, endpoint registration, and heartbeats."""

    NAME = "agent"
    SCHEMA_VER = "1"  # the /api/agent/* payload shape as it exists today

    def normalize(
        self, payload: dict[str, Any], context: dict[str, Any] | None = None
    ) -> list[Event]:
        context = context or {}
        if not isinstance(payload, dict):
            raise ConnectorError(f"agent payload must be an object, got {type(payload)}")

        # Route by shape rather than by an explicit envelope, so payloads emitted
        # by different agent versions all land somewhere sensible.
        if "threats" in payload:
            return self._scan_report(payload, context)
        if "hostname" in payload and "scan_count" not in payload:
            return self._registration(payload)
        if "agent_id" in payload and len(payload) <= 3:
            return self._heartbeat(payload, context)
        if "hash" in payload or "file" in payload:
            return [self._threat(payload, context)]
        return []

    # ---------- individual shapes ----------

    def _registration(self, payload: dict[str, Any]) -> list[Event]:
        """
        Endpoint registration.

        The time is the registration event, not an observation of anything, so
        the source supplies no `ts` and we mark it derived. Without that marker a
        re-registration got a fresh `now()` and a new fingerprint, so the lake
        filled with duplicate "this host exists" records -- four registrations of
        one host produced four events plus four registration incidents.
        """
        hostname = (payload.get("hostname") or "unknown").strip()
        ip = (payload.get("ip") or "").strip()
        _, _, derived = parse_agent_ts(payload.get("ts"))
        ev = self._event(
            type=EventType.AGENT_STATUS.value,
            severity=Severity.INFO.value,
            host=hostname,
            entities=merge_entities(
                host_entities(hostname, ip or None),
                {"host": [hostname]},
            ),
            title=f"Agent registered: {hostname}",
            description=f"Endpoint {hostname} ({ip or 'no ip'}) registered",
            rule_id="agent.register",
            raw=dict(payload),
            tags=["agent", "registration"],
        )
        if derived:
            ev.raw["_ts_derived"] = True
        return [ev]

    def _heartbeat(self, payload: dict[str, Any], context: dict[str, Any]) -> list[Event]:
        agent_id = payload.get("agent_id")
        hostname = context.get("hostname") or payload.get("hostname")
        ip = (payload.get("ip") or "").strip()
        ts, naive, derived = parse_agent_ts(payload.get("ts") or context.get("ts"))
        ev = self._event(
            type=EventType.AGENT_STATUS.value,
            ts=ts,
            severity=Severity.INFO.value,
            host=hostname,
            entities=merge_entities(
                host_entities(hostname, ip or None),
                {"host": [hostname]} if hostname else None,
            ),
            title=f"Agent heartbeat: {agent_id}",
            description=f"Agent {agent_id} reported from {ip or 'unknown ip'}",
            rule_id="agent.heartbeat",
            raw=dict(payload),
            tags=["agent", "heartbeat"],
        )
        if naive:
            ev.raw["_ts_assumed_utc"] = True
        if derived:
            ev.raw["_ts_derived"] = True
        return [ev]

    def _scan_report(self, payload: dict[str, Any], context: dict[str, Any]) -> list[Event]:
        """A full scan result: summary counts plus any threats found."""
        events: list[Event] = []
        hostname = context.get("hostname") or payload.get("hostname")
        ts, naive, derived = parse_agent_ts(payload.get("end_time") or payload.get("start_time"))
        ep = context.get("endpoint") or {}
        ip = ep.get("ip") or payload.get("ip")

        summary = self._event(
            type=EventType.AGENT_STATUS.value,
            ts=ts,
            severity=Severity.INFO.value,
            host=hostname,
            entities=merge_entities(host_entities(hostname, ip or None)),
            title=(
                f"Scan completed on {hostname}: "
                f"{payload.get('threats_found', 0)} threat(s)"
            ),
            description=(
                f"{payload.get('files_scanned', 0)} files, "
                f"{payload.get('dirs_scanned', 0)} dirs, "
                f"{payload.get('errors', 0)} errors in "
                f"{payload.get('scan_time', 0)}s"
            ),
            rule_id="agent.scan_complete",
            raw={k: v for k, v in payload.items() if k != "threats"},
            tags=["agent", "scan"],
        )
        if naive:
            summary.raw["_ts_assumed_utc"] = True
        if derived:
            summary.raw["_ts_derived"] = True
        events.append(summary)

        for threat in self._safe_iter(payload.get("threats")):
            if isinstance(threat, dict):
                ev = self._threat(threat, {**context, "hostname": hostname, "ts": ts})
                if ev is not None:
                    events.append(ev)
        return events

    def _threat(self, threat: dict[str, Any], context: dict[str, Any]) -> Event | None:
        path = (threat.get("file") or "").strip()
        sha256 = (threat.get("hash") or "").strip()
        if not path and not sha256:
            return None

        # A file can match both a name pattern and a hash. One event, highest
        # severity wins, and the losing match is preserved in raw for the analyst.
        match_type = self._winning_match(threat)
        severity, rule_id = _THREAT_TYPE_MAP.get(
            match_type, (Severity.MEDIUM, "builtin.unknown")
        )

        family = (threat.get("family") or "Unknown").strip()
        details = (threat.get("details") or "").strip()
        path_l = path.lower()
        basename = path_l.rsplit("/", 1)[-1] if path_l else ""

        entities: dict[str, list[str]] = {}
        if sha256:
            entities[EntityType.FILE_HASH.value] = [sha256.lower()]
        if path:
            entities[EntityType.FILE_PATH.value] = [path]
            if basename:
                entities[EntityType.FILE_NAME.value] = [basename]

        ts = context.get("ts")
        if not ts:
            ts, naive, derived = parse_agent_ts(threat.get("time"))
        else:
            naive, derived = False, False

        ev = self._event(
            type=EventType.THREAT_HIT.value,
            ts=ts,
            severity=severity.value,
            host=context.get("hostname"),
            entities=merge_entities(
                entities,
                host_entities(
                    context.get("hostname"),
                    (context.get("endpoint") or {}).get("ip"),
                ),
            ),
            title=f"Threat: {family}",
            description=details or f"{match_type} match for {basename or path}",
            rule_id=rule_id,
            raw=dict(threat),
            tags=["agent", "threat", family.lower()],
        )
        if naive:
            ev.raw["_ts_assumed_utc"] = True
        if derived:
            ev.raw["_ts_derived"] = True
        if match_type != (threat.get("type") or "").strip():
            ev.raw["_superseded_match"] = threat.get("type")
        return ev

    @staticmethod
    def _winning_match(threat: dict[str, Any]) -> str:
        """Pick the strongest match type present on this threat."""
        reported = (threat.get("type") or "").strip()
        if reported in _THREAT_TYPE_MAP:
            return reported
        for candidate in _TYPE_PRECEDENCE:
            if candidate == reported:
                return reported
        # Unknown/absent `type`: infer from what data we do have.
        if (threat.get("hash") or "").strip():
            return "Known malicious hash"
        return "Filename pattern"


def normalize_incident(incident: dict[str, Any], context: dict[str, Any] | None = None) -> list[Event]:
    """
    Convert an incident from the existing incidents.json store into events.

    Kept as a function rather than a Connector method because incidents are
    platform-generated, not a data source. It exists so the migration can replay
    historical incidents into the lake instead of losing them.
    """
    context = context or {}
    if not incident.get("id") and not incident.get("title"):
        return []
    severity = normalize_severity(incident.get("severity"), Severity.MEDIUM)
    ts, naive, derived = parse_agent_ts(incident.get("created"))
    inc_id = (incident.get("id") or "").strip()
    ev = Event(
        type=EventType.INCIDENT.value,
        ts=ts,
        source=incident.get("source") or "system",
        severity=severity.value,
        title=(incident.get("title") or "Incident")[:512],
        description=incident.get("description") or "",
        # The legacy id is part of the fingerprint via rule_id. Two incidents can
        # share a title, a source, and have no timestamp of their own, which would
        # otherwise collapse them into one event during migration.
        rule_id=f"legacy.incident.{inc_id}" if inc_id else "legacy.incident",
        raw=dict(incident),
        tags=["legacy", "incident"],
    )
    ev.raw["legacy_incident_id"] = inc_id or incident.get("id")
    if naive:
        ev.raw["_ts_assumed_utc"] = True
    if derived:
        ev.raw["_ts_derived"] = True
    if incident.get("status"):
        ev.tags.append(f"status:{incident['status']}")
    return [ev]
