"""
Correlation: one incident, not one per event.

Phase 0 and 1 produced exactly one incident per event. A file seen fifty times
produced fifty incidents, and a hash on five hosts produced five -- so the
analyst's actual question, "how far did this spread", was not answerable, because
the spread was not an object anywhere.

This module groups. Events that agree on a correlation key and fall inside a time
window join an existing incident rather than opening a new one.

Three decisions worth stating, because each one trades something real.

**The key is not event identity.** A file hash is the pivot. Grouping by
`(technique, host, hash)` answers "this hash, on these hosts, in this window".
Grouping by event would answer nothing.

**The window is a window.** A ransomware campaign a week old and one happening
now are different incidents, even with an identical key. The window is what
separates them.

**Severity is the maximum, never an average.** Fifty low-severity hits averaging
against one critical hit would let a background of noise dilute the finding. An
analyst opens a critical incident because something critical is in it.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from tiox.schemas.event import Severity, severity_at_least

log = logging.getLogger("tiox.correlation")

# A rule in "log" mode never reaches this layer: it records a threat_hit event
# and stops. Correlation is only reached from mode="alert".
DEFAULT_WINDOW_MINUTES = 60

# The window may not be tuned beyond these bounds without an incident becoming
# either meaningless (1 minute, so a scan's own events do not merge into one) or
# unbounded (7 days, so "correlated" stops meaning anything).
MIN_WINDOW_MINUTES = 5
MAX_WINDOW_MINUTES = 7 * 24 * 60


def correlation_key(
    event: dict[str, Any],
    *,
    scope: Iterable[str] = ("technique", "host"),
) -> str:
    """
    The grouping key for an event.

    `scope` names the fields that must agree. The default deliberately does NOT
    include the file hash: two different malicious files detected by the same
    rule on the same host are one problem ("this host is compromised"), and
    splitting them by hash hides the host as the common factor. A caller that
    wants per-file grouping passes the hash in `scope`.

    Hashed rather than joined so the key is a fixed-width token safe to use as a
    database index and safe to log.
    """
    parts: list[str] = []
    for name in scope:
        if name == "technique":
            techs = event.get("techniques") or []
            parts.append("tech=" + ",".join(sorted(t for t in techs if t)))
        elif name == "host":
            parts.append("host=" + (event.get("host") or "").lower())
        elif name == "rule_id":
            parts.append("rule=" + (event.get("rule_id") or ""))
        elif name in ("file_hash", "ip", "domain", "process", "user", "file_path"):
            values = (event.get("entities") or {}).get(name) or []
            parts.append(f"{name}=" + ",".join(sorted(str(v) for v in values)))
        else:
            parts.append(f"{name}=" + str(event.get(name) or ""))
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def key_components(
    event: dict[str, Any], *, scope: Iterable[str] = ("technique", "host")
) -> dict[str, str]:
    """
    The human-readable parts of a key.

    Stored alongside the hash so an incident can explain what grouped it without
    the analyst having to reverse a digest.
    """
    out: dict[str, str] = {}
    for name in scope:
        if name == "technique":
            techs = event.get("techniques") or []
            out["technique"] = ",".join(sorted(t for t in techs if t))
        elif name == "host":
            out["host"] = (event.get("host") or "").lower()
        elif name == "rule_id":
            out["rule_id"] = event.get("rule_id") or ""
        else:
            values = (event.get("entities") or {}).get(name) or []
            out[name] = ",".join(sorted(str(v) for v in values))
    return out


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def clamp_window(minutes: Any) -> int:
    """
    Coerce a window to a usable number of minutes.

    A bad window must not become an unbounded one. An analyst typing 0 (or a
    config defaulting to None) would otherwise correlate every event with the
    same key into a single incident forever, which is the exact failure
    correlation exists to prevent.
    """
    try:
        n = int(minutes)
    except (TypeError, ValueError):
        return DEFAULT_WINDOW_MINUTES
    return max(MIN_WINDOW_MINUTES, min(MAX_WINDOW_MINUTES, n))


class Correlator:
    """
    Joins detections into incidents.

    Holds no state between calls beyond the store: whether an event joins an
    existing incident is a question about the database (is there an open
    incident with this key inside the window?), not about this process. That
    matters because incidents outlive any single ingest request, and a stateful
    correlator would reset on restart and re-open incidents it had already
    opened.
    """

    def __init__(self, store, *, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> None:
        self.store = store
        self.window_minutes = clamp_window(window_minutes)

    # ------------------------------------------------------------------ keys

    def find_open(self, key: str, window_minutes: int | None = None) -> dict[str, Any] | None:
        """
        An open incident with this key, created inside the window.

        Closed incidents never match. A resolved incident that reopens on the next
        hit is worse than a new one: it loses the resolution history and the
        time spent on the first occurrence.
        """
        minutes = clamp_window(window_minutes or self.window_minutes)
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        return self.store.find_correlated_incident(key, since)

    # ------------------------------------------------------------- incidents

    def correlate(self, event: dict[str, Any], hits: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Fold a detection into an incident, opening or joining as needed.

        `event` is the stored threat_hit event; `hits` are the rule hits that
        produced it. Only `alert`-mode rules reach this layer -- a `log` rule
        records its event and returns without an incident.
        """
        alerting = [h for h in hits if h.get("mode") == "alert"]
        if not alerting:
            return {"action": "none", "reason": "no alert-mode rule fired"}

        # Suppression: a rule an analyst has marked as noise stops opening
        # incidents for a period, without being disabled or deleted. A rule that
        # is merely quiet still opens them.
        suppressed = [
            h for h in alerting
            if self.store.is_rule_suppressed(h["rule"].get("rule_id", ""))
        ]
        active = [h for h in alerting if h not in suppressed]
        if suppressed and not active:
            return {
                "action": "suppressed",
                "reason": "rule is suppressed",
                "rule_ids": [h["rule_id"] for h in suppressed],
            }

        key = correlation_key(event)
        components = key_components(event)
        existing = self.find_open(key)

        if existing:
            return self._join(existing, event, active, components)
        return self._open(event, active, key, components)

    def _open(
        self,
        event: dict[str, Any],
        hits: list[dict[str, Any]],
        key: str,
        components: dict[str, str],
    ) -> dict[str, Any]:
        primary = hits[0]
        title = self._title(event, primary)
        incident = self.store.create_correlated_incident({
            "title": title,
            "description": self._describe(event, primary, hits),
            "severity": event.get("severity", "medium"),
            "status": "open",
            "type": "correlation",
            "source": event.get("host") or event.get("source"),
            "correlation_key": key,
            "correlation_components": components,
            "rule_id": (primary.get("rule") or {}).get("rule_id"),
            "details": {
                "rules": [h["name"] for h in hits],
                "rule_ids": [h["rule_id"] for h in hits],
                "first_event": event.get("event_id"),
            },
        }, event_id=event.get("event_id"))
        return {
            "action": "opened",
            "incident": incident,
            "incident_id": incident.get("id"),
        }

    def _join(
        self,
        incident: dict[str, Any],
        event: dict[str, Any],
        hits: list[dict[str, Any]],
        components: dict[str, str],
    ) -> dict[str, Any]:
        self.store.attach_incident_event(incident["id"], event.get("event_id"))
        promoted = self.store.promote_incident_severity(
            incident["id"], event.get("severity", "medium"))
        # Widen the recorded component set: a second host hitting the same key is
        # exactly the information the analyst needs, and it is only visible
        # because the incident outlives the first event.
        self.store.merge_incident_components(
            incident["id"], components)
        return {
            "action": "joined",
            "incident": self.store.get_incident(incident["id"]) or incident,
            "incident_id": incident["id"],
            "severity_promoted": promoted,
        }

    # ---------------------------------------------------------------- wording

    def _title(self, event: dict[str, Any], hit: dict[str, Any]) -> str:
        name = hit.get("name") or "Detection"
        host = event.get("host")
        techs = event.get("techniques") or []
        if host and techs:
            return f"{name} on {host} ({techs[0]})"
        if host:
            return f"{name} on {host}"
        if techs:
            return f"{name} ({techs[0]})"
        return name

    def _describe(
        self, event: dict[str, Any], hit: dict[str, Any], hits: list[dict[str, Any]]
    ) -> str:
        parts = [hit.get("reason") or "matched"]
        others = [h["name"] for h in hits[1:]]
        if others:
            parts.append("also matched: " + ", ".join(others))
        if event.get("host"):
            parts.append(f"host {event['host']}")
        return "; ".join(p for p in parts if p)
