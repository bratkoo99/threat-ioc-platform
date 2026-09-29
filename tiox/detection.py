"""
Detection: rules in the execution path.

Phase 1 shipped a rule engine with exactly one caller -- the dry-run endpoint an
analyst uses while writing a rule. A rule could be authored, validated, saved,
displayed, and test-fired, and then never evaluate against real data. This module
is the missing link: it offers ingested events to the enabled rules and turns
hits into attributed threat events.

Two decisions shape everything here.

**Attribution is the point.** A hit becomes a `threat_hit` event carrying
`rule_id = custom:<uuid>`. That is what makes "this rule is noise" a fact about
data rather than an opinion, and it is what the tuning feedback in Phase 2 reads.

**A broken rule must not break ingest.** A rule that raises is logged and skipped.
A detection that degrades to no detection is a gap; a detection that takes down
the feed is an outage. The asymmetry is not a preference.
"""

from __future__ import annotations

import logging
from typing import Any

from tiox.schemas.event import Event
from tiox.schemas.attack import techniques_for_rule
from tiox.rules.engine import Evaluator, RuleError, validate

log = logging.getLogger("tiox.detection")

RULE_PREFIX = "custom:"

# Reused across a single ingest() call so a rule tree is validated once, not once
# per event. A batch of fifty events would otherwise re-validate the same JSON
# fifty times.
_MAX_RULES_EVALUATED = 500


def rule_id_of(rule: dict[str, Any]) -> str:
    """The stored id, in the form it is written onto events."""
    return f"{RULE_PREFIX}{rule.get('rule_id', 'unknown')}"


def _bare_rule_id(value: str) -> str:
    return (value or "").removeprefix(RULE_PREFIX)


class DetectionEngine:
    """
    Evaluates custom rules against events.

    Rules are loaded once and cached, because they change on the order of once a
    week while events arrive continuously. The cache is invalidated explicitly on
    save rather than by a timestamp check per event, so a rule edit takes effect
    immediately rather than whenever a poll happens to notice.
    """

    def __init__(self, store) -> None:
        self.store = store
        self._rules: list[dict[str, Any]] | None = None

    # ------------------------------------------------------------------ rules

    def invalidate(self) -> None:
        """Drop the cached rule set. Call after a rule is saved or deleted."""
        self._rules = None

    def rules(self) -> list[dict[str, Any]]:
        if self._rules is None:
            try:
                loaded: list[dict[str, Any]] = list(
                    self.store.list_rules(enabled_only=True)
                )
            except Exception:  # pragma: no cover -- store failure
                log.exception("could not load custom rules")
                loaded = []
            self._rules = loaded
        return self._rules

    def loadable_rules(self) -> list[dict[str, Any]]:
        """
        Enabled rules whose tree actually validates.

        A rule that fails validation is dropped here rather than at evaluation
        time, so one broken rule cannot cost an evaluation round-trip per event.
        The reason is logged: a rule silently not running is the failure mode this
        whole module exists to eliminate.
        """
        out = []
        for rule in self.rules():
            problems = validate(rule.get("tree") or {})
            if problems:
                log.warning(
                    "skipping custom rule %r (%s): %s",
                    rule.get("name"), rule.get("rule_id"), "; ".join(problems),
                )
                continue
            if rule.get("mode") == "disabled":
                continue
            out.append(rule)
        return out

    # -------------------------------------------------------------- evaluation

    def evaluate(self, event: Event) -> list[dict[str, Any]]:
        """
        All rules that fire on this event.

        Returns a list of hits rather than the first one: two rules matching the
        same event is a stronger signal, and collapsing them would hide that.
        """
        as_dict = event_to_dict(event)
        hits: list[dict[str, Any]] = []

        for rule in self.loadable_rules()[:_MAX_RULES_EVALUATED]:
            try:
                rule_hits = Evaluator().run_rule(rule, [as_dict])
            except RuleError as exc:
                # validate() already ran in loadable_rules, so this is a rule
                # that only fails on this particular event.
                log.warning("rule %s failed on event %s: %s",
                            rule.get("name"), event.event_id, exc)
                continue
            except Exception:
                log.exception("rule %s raised unexpectedly", rule.get("name"))
                continue

            for hit in rule_hits:
                hits.append({
                    "rule": rule,
                    "rule_id": rule_id_of(rule),
                    "name": rule.get("name"),
                    "severity": hit.severity or rule.get("severity", "medium"),
                    "techniques": list(hit.techniques or rule.get("techniques") or []),
                    "reason": hit.reason,
                    "group_key": hit.group_key,
                    "mode": rule.get("mode", "log"),
                })

        return hits

    def process(self, event: Event) -> tuple[list[Event], list[dict[str, Any]]]:
        """
        Evaluate one event and build the threat events its hits imply.

        Returns (new_events, hits). The caller decides what to persist and whether
        to open incidents, because ingestion and incident creation have different
        failure semantics: an event that fails to store is retryable, an incident
        that fails to open is not.
        """
        hits = self.evaluate(event)
        if not hits:
            return [], []

        made: list[Event] = []
        for hit in hits:
            # A rule's own `techniques` list wins. Falling back to the ATT&CK
            # module only covers the built-in rule ids, so for a custom rule it
            # contributes nothing -- which is correct: a custom rule tags
            # whatever its author declared.
            techniques = list(hit["techniques"] or []) or list(
                techniques_for_rule(hit["rule_id"])
            )
            made.append(build_threat_event(event, hit, techniques))
        return made, hits

    def record_outcome(
        self,
        hits: list[dict[str, Any]],
        *,
        opened: int = 0,
        opened_by_rule: dict[str, int] | None = None,
    ) -> None:
        """
        Persist per-rule counters for the tuning view.

        `opened_by_rule` is how many incidents *each* rule actually opened. The
        older single `opened` total is not usable for this: with two rules firing
        on one event and one incident opened, attributing that incident to both
        rules would report a log-mode rule as having opened an incident, which is
        exactly the behaviour per-rule mode exists to prevent. The `opened`
        argument is kept for callers that genuinely have one rule in play.
        """
        by_rule: dict[str, int] = {}
        for hit in hits:
            by_rule[hit["rule_id"]] = by_rule.get(hit["rule_id"], 0) + 1

        for rule_id, count in by_rule.items():
            bare = _bare_rule_id(rule_id)
            if opened_by_rule is not None:
                opened_count = opened_by_rule.get(rule_id, 0)
            else:
                opened_count = opened if len(by_rule) == 1 else 0
            try:
                self.store.record_rule_run(bare, count)
                if opened_count:
                    self.store.record_rule_incidents(bare, opened_count)
            except Exception:  # pragma: no cover -- counters are not load-bearing
                log.exception("could not record outcome for rule %s", rule_id)


def event_to_dict(event: Event) -> dict[str, Any]:
    """
    An event as the rules engine reads it.

    The engine works on plain dicts with an `entities` map; the lake stores the
    same data columnar. This is the single conversion point, so a rule written
    against one shape keeps working if the storage moves.
    """
    return {
        "event_id": event.event_id,
        "ts": event.ts,
        "type": event.type,
        "severity": event.severity,
        "host": event.host,
        "user": event.user,
        "title": event.title,
        "rule_id": event.rule_id,
        "source": event.source,
        "techniques": list(event.techniques or []),
        "entities": {k: list(v) for k, v in (event.entities or {}).items()},
        "raw": dict(event.raw or {}),
    }


def build_threat_event(
    source_event: Event, hit: dict[str, Any], techniques: list[str]
) -> Event:
    """
    The `threat_hit` event a rule hit implies.

    It keeps the source event's entities and host, so a pivot from a hit reaches
    the same hash, IP, or path the underlying observation carried. A detection
    that loses its entities is a detection nobody can investigate.
    """
    rule = hit.get("rule") or {}
    reason = hit.get("reason") or "matched"
    title = f"Rule hit: {hit.get('name') or rule.get('name') or 'custom rule'}"

    payload = {
        "title": title,
        "description": reason,
        "severity": hit.get("severity", "medium"),
        "host": source_event.host,
        "user": source_event.user,
        "rule_id": hit["rule_id"],
        "technique": ",".join(techniques) if techniques else None,
        "source_event_id": source_event.event_id,
        "rule_name": hit.get("name"),
        "rule_mode": hit.get("mode", "log"),
        "match_reason": reason,
        "group_key": hit.get("group_key"),
        "rule_id_bare": _bare_rule_id(hit["rule_id"]),
    }
    # Carry the triggering event's raw fields up, so a rule can test a field that
    # is not part of the canonical event (file_size, protocol, and so on).
    payload.update({
        k: v for k, v in (source_event.raw or {}).items()
        if k not in ("title", "description", "severity")
    })

    return Event(
        type="threat_hit",
        severity=hit.get("severity", "medium"),
        host=source_event.host,
        user=source_event.user,
        title=title,
        rule_id=hit["rule_id"],
        techniques=techniques,
        source=f"rule:{source_event.source}",
        raw=payload,
        entities=source_event.entities,
    )
