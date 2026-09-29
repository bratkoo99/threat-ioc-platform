"""
Custom detection rules, as building blocks.

Modelled on IBM QRadar's rule model because that model survives contact with real
analysts: a rule is a *tree of typed tests*, each node either examines one event
or combines the result of its children. You can see what a rule does, reorder
the parts, and reason about whether a threshold is right, without reading code.

    rule := node

    leaf node:   {"kind": "match", "field": "file_path", "op": "contains",
                  "value": "\\\\Temp\\\\"}
    test node:   {"kind": "test", "op": "and", "children": [node, node, ...]}
    count node:  {"kind": "threshold", "field": "source_ip",
                  "op": "gte", "value": 20, "window_minutes": 5,
                  "group_by": "user"}

Evaluation returns matches with the context that triggered them, because a
detection you cannot inspect is a detection you cannot tune.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# --------------------------------------------------------------------------
# Fields a rule may test. An allowlist rather than a free string: a rule naming a
# field that does not exist would silently never fire, and a rule that can only
# fire silently is worse than a rule that errors.
# --------------------------------------------------------------------------
FIELDS: dict[str, str] = {
    "type": "Event type (threat_hit, dns, network_conn, auth, ...)",
    "severity": "Severity (info, low, medium, high, critical)",
    "host": "Reporting host",
    "user": "User account",
    "title": "Event title",
    "rule_id": "Rule that produced the event",
    "source": "Ingest source (agent, system)",
    "technique": "ATT&CK technique id",
    "process": "Process name",
    "file_path": "Full file path",
    "file_name": "File name",
    "file_hash": "SHA-256 of the file",
    "file_size": "File size in bytes",
    "domain": "Domain contacted",
    "ip": "IP address",
    "url": "URL",
    "port": "Destination port",
    "protocol": "Protocol (tcp, udp)",
}

COMPARISONS: dict[str, str] = {
    "equals": "is exactly",
    "not_equals": "is not",
    "contains": "contains",
    "not_contains": "does not contain",
    "starts_with": "starts with",
    "ends_with": "ends with",
    "matches": "matches regex",
    "glob": "matches glob (* and ?)",
    "in": "is one of (comma-separated)",
    "not_in": "is none of (comma-separated)",
    "gt": "is greater than",
    "gte": "is at least",
    "lt": "is less than",
    "lte": "is at most",
    "exists": "is present",
    "missing": "is absent",
    "ip_in_cidr": "is inside CIDR",
    "private_ip": "is a private address",
    "public_ip": "is a public address",
}

BOOL_OPS = {"and", "or", "not"}


class RuleError(ValueError):
    """A rule is malformed. Surfaced to the author, not swallowed."""


# --------------------------------------------------------------------------
# Value extraction
# --------------------------------------------------------------------------


def extract(event: dict[str, Any], fieldname: str) -> Any:
    """
    Pull a field out of an event, including the entity table.

    Entities are stored as lists (one event can carry several IPs), so a scalar
    test matches if *any* value matches. That is the behaviour an analyst expects
    from "source_ip matches 10.0.0.5".
    """
    if fieldname in ("technique", "techniques"):
        return event.get("techniques") or []
    ents = event.get("entities") or {}
    if fieldname in ents:
        return ents[fieldname]
    if fieldname in event:
        return event[fieldname]
    # A few conveniences: nested raw fields like raw.family
    raw = event.get("raw")
    if isinstance(raw, dict) and fieldname in raw:
        return raw[fieldname]
    return None


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def _to_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _as_ip(v: Any):
    try:
        return ipaddress.ip_address(str(v).strip())
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------
# Leaf comparison
# --------------------------------------------------------------------------


def compare(op: str, actual: Any, expected: Any) -> bool:
    """
    Apply one comparison.

    Each op is total: an incomparable value (a number test against a string)
    returns False rather than raising, because a single odd event must not abort
    evaluation of a rule over a whole time window.
    """
    if op == "exists":
        return actual is not None and actual != [] and actual != ""
    if op == "missing":
        return actual is None or actual == [] or actual == ""

    if op == "ip_in_cidr":
        want = ipaddress.ip_network(str(expected).strip(), strict=False)
        return any(_in_net(x, want) for x in _as_list(actual))
    if op == "private_ip":
        ips = [i for i in (_as_ip(x) for x in _as_list(actual)) if i]
        return bool(ips) and all(i.is_private for i in ips)
    if op == "public_ip":
        ips = [i for i in (_as_ip(x) for x in _as_list(actual)) if i]
        return bool(ips) and all(not i.is_private for i in ips)

    if op == "matches":
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regex {expected!r}: {exc}") from exc
        return any(rx.search(str(x)) for x in _as_list(actual))

    if op == "glob":
        return any(fnmatch.fnmatch(str(x).lower(), str(expected).lower())
                   for x in _as_list(actual))

    if op in ("in", "not_in"):
        allowed = {s.strip().lower() for s in str(expected).split(",") if s.strip()}
        got = {str(x).strip().lower() for x in _as_list(actual)}
        return bool(got & allowed) if op == "in" else not (got & allowed)

    if op in ("gt", "gte", "lt", "lte"):
        a, b = _to_number(actual), _to_number(expected)
        if a is None or b is None:
            return False
        return {
            "gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b,
        }[op]

    text = str(expected)
    vals = [str(x) for x in _as_list(actual)]
    # Every text operator is case-insensitive. Half of them being case-sensitive
    # is the worst outcome: "host equals WKS-01" against "wks-01" produces a rule
    # that validates, saves, runs, and never fires.
    if op == "equals":
        return any(v.lower() == text.lower() for v in vals)
    if op == "not_equals":
        return not any(v.lower() == text.lower() for v in vals)
    if op == "contains":
        return any(text.lower() in v.lower() for v in vals)
    if op == "not_contains":
        return not any(text.lower() in v.lower() for v in vals)
    if op == "starts_with":
        return any(v.lower().startswith(text.lower()) for v in vals)
    if op == "ends_with":
        return any(v.lower().endswith(text.lower()) for v in vals)
    raise RuleError(f"unknown operator {op!r}")


def _in_net(value: Any, net: ipaddress._BaseNetwork) -> bool:
    ip = _as_ip(value)
    return bool(ip and ip in net)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def validate(node: dict[str, Any], *, depth: int = 0) -> list[str]:
    """
    Return a list of problems. Empty means valid.

    Warnings are reported as strings rather than raised so an author can save a
    work-in-progress rule -- but an unknown field or operator is a hard error,
    because that rule can never fire and would look healthy.
    """
    problems: list[str] = []
    if depth > 12:
        return ["rule nests deeper than 12 levels; likely a cycle"]

    if not isinstance(node, dict):
        return [f"node must be an object, got {type(node).__name__}"]

    kind = node.get("kind")

    if kind == "match":
        fieldname = node.get("field")
        op = node.get("op")
        if not fieldname:
            problems.append("match node needs a field")
        elif fieldname not in FIELDS:
            problems.append(
                f"unknown field {fieldname!r}; known fields: {', '.join(sorted(FIELDS))}"
            )
        if not op:
            problems.append("match node needs an operator")
        elif op not in COMPARISONS:
            problems.append(
                f"unknown operator {op!r}; known: {', '.join(sorted(COMPARISONS))}"
            )
        if op in ("equals", "not_equals", "contains", "not_contains", "starts_with",
                  "ends_with", "matches", "glob", "in", "not_in", "gt", "gte",
                  "lt", "lte", "ip_in_cidr") and node.get("value") in (None, ""):
            problems.append(f"operator {op!r} needs a value")
        if op == "matches":
            try:
                re.compile(str(node.get("value") or ""))
            except re.error as exc:
                problems.append(f"invalid regex: {exc}")

    elif kind in ("test", "threshold"):
        op = node.get("op", "and")
        if kind == "test":
            if op not in BOOL_OPS:
                problems.append(f"test op must be one of {sorted(BOOL_OPS)}, got {op!r}")
            children = node.get("children") or []
            if not isinstance(children, list):
                problems.append("children must be a list")
                children = []
            if len(children) < 2 and op in ("and", "or"):
                problems.append(f"{op!r} with fewer than 2 children is pointless")
            for i, child in enumerate(children):
                for p in validate(child, depth=depth + 1):
                    problems.append(f"child {i}: {p}")

        else:  # threshold
            fieldname = node.get("field")
            if not fieldname:
                problems.append("threshold needs a field")
            elif fieldname not in FIELDS:
                problems.append(
                    f"unknown field {fieldname!r}; known fields: {', '.join(sorted(FIELDS))}"
                )
            cop = node.get("op", "gte")
            if cop not in COMPARISONS:
                problems.append(f"unknown comparison {cop!r}")
            if cop not in ("exists", "missing"):
                raw_val = node.get("value")
                if raw_val is None or _to_number(raw_val) is None:
                    problems.append(f"threshold value {raw_val!r} is not a number")
            wm = node.get("window_minutes")
            if wm is not None:
                try:
                    if int(wm) <= 0:
                        problems.append("window_minutes must be positive")
                except (TypeError, ValueError):
                    problems.append("window_minutes must be a number")
            gb = node.get("group_by")
            if gb and gb not in FIELDS:
                problems.append(f"unknown group_by field {gb!r}")
            for i, child in enumerate(node.get("children") or []):
                for p in validate(child, depth=depth + 1):
                    problems.append(f"child {i}: {p}")

    else:
        problems.append(f"unknown node kind {kind!r}; use match, test, or threshold")

    # A threshold counts events, so it is meaningless inside a boolean tree:
    # OR(threshold, match) has no per-event truth value. Saying so is better
    # than evaluating it as a single-event comparison and quietly under-firing.
    if kind == "test" and node.get("op") in ("and", "or", "not"):
        for i, child in enumerate(node.get("children") or []):
            if isinstance(child, dict) and child.get("kind") == "threshold":
                problems.append(
                    f"child {i}: a threshold cannot sit inside an "
                    f"{node['op']!r} -- thresholds count a set of events, so "
                    f"make it the rule's top-level node, or use a match test"
                )
    return problems


def explain(node: dict[str, Any], indent: int = 0) -> str:
    """Render a rule as indented text, so the author can read it back."""
    pad = "  " * indent
    kind = node.get("kind")
    if kind == "match":
        f = node.get("field")
        op = node.get("op")
        desc = COMPARISONS.get(op, op)
        val = node.get("value")
        tail = f" {val!r}" if val not in (None, "") else ""
        return f"{pad}IF {f} {desc}{tail}"
    if kind == "test":
        label = {"and": "ALL of", "or": "ANY of", "not": "NOT"}.get(node.get("op", "and"), "ALL of")
        lines = [f"{pad}{label}:"]
        for c in node.get("children") or []:
            lines.append(explain(c, indent + 1))
        return "\n".join(lines)
    if kind == "threshold":
        f = node.get("field")
        cop = node.get("op", "gte")
        desc = COMPARISONS.get(cop, cop)
        wm = node.get("window_minutes")
        gb = node.get("group_by")
        head = f"{pad}COUNT {f} {desc} {node.get('value')}"
        if wm:
            head += f" within {wm}m"
        if gb:
            head += f", per {gb}"
        lines = [head]
        for c in node.get("children") or []:
            lines.append(explain(c, indent + 1))
        return "\n".join(lines)
    return f"{pad}(unrecognised node {kind!r})"


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


@dataclass
class Hit:
    """One rule firing, with enough context to judge whether it should have."""

    rule_id: str
    rule_name: str
    severity: str
    techniques: list[str]
    matched_events: list[dict[str, Any]]
    reason: str
    group_key: str | None = None
    score: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "matched_events": self.matched_events,
            "reason": self.reason,
            "group_key": self.group_key,
            "score": self.score,
            **({"extra": self.extra} if self.extra else {}),
        }


class Evaluator:
    """
    Runs rules over a set of events.

    Events are supplied already-windowed by the caller. The evaluator does not
    know about time except for thresholds, which need a window to count within;
    that window is declared on the node and applied to timestamps the events
    carry. Keeping the window on the node (rather than hidden in the caller) is
    what makes a rule self-describing when exported.
    """

    def __init__(self, max_matches_per_rule: int = 200) -> None:
        self.max_matches = max_matches_per_rule

    # -- leaf -------------------------------------------------------------

    def _test_leaf(self, node: dict[str, Any], ev: dict[str, Any]) -> bool:
        actual = extract(ev, node["field"])
        if node["op"] == "not":
            return not self._test_leaf(node["children"][0], ev)
        return compare(node["op"], actual, node.get("value"))

    def _test_node(self, node: dict[str, Any], ev: dict[str, Any]) -> bool:
        op = node.get("op", "and")
        kind = node.get("kind")
        # Children of a threshold are usually `match` leaves, not `test` nodes.
        # Dispatch on kind first, so a leaf is never read as a boolean tree.
        if kind == "match":
            return self._test_leaf(node, ev)
        kids = node.get("children") or []
        if op == "and":
            return all(self._test_node(c, ev) for c in kids)
        if op == "or":
            return any(self._test_node(c, ev) for c in kids)
        if op == "not":
            return not self._test_node(kids[0], ev) if kids else False
        raise RuleError(f"unknown test op {op!r}")

    def matches_event(self, node: dict[str, Any], ev: dict[str, Any]) -> bool:
        kind = node.get("kind")
        if kind == "match":
            return self._test_leaf(node, ev)
        if kind == "test":
            return self._test_node(node, ev)
        if kind == "threshold":
            # A threshold is not a per-event predicate: it is satisfied by the
            # *set*. Asked about a single event, the only meaningful reading is
            # "does this event qualify toward the threshold", which is what the
            # children decide. This matters when a threshold is nested in a
            # boolean tree: a rule reading OR(threshold, match) would otherwise
            # raise, because there is no count for one event.
            kids = node.get("children") or []
            if not kids:
                fieldname = node.get("field")
                if not fieldname:
                    raise RuleError("threshold node needs a field")
                return compare(node.get("op", "gte"), extract(ev, fieldname),
                               node.get("value"))
            return all(self._test_node(c, ev) for c in kids)
        raise RuleError(f"unknown node kind {kind!r}")

    # -- thresholds -------------------------------------------------------

    def _threshold_groups(
        self, node: dict[str, Any], events: list[dict[str, Any]]
    ) -> list[tuple[str, list[dict[str, Any]]]]:
        """Bucket qualifying events by the node's group_by key."""
        kids = node.get("children") or []
        qualifiers = [
            e for e in events
            if all(self._test_node(c, e) for c in kids) if kids
        ] or ([] if kids else list(events))

        gb = node.get("group_by")
        window = node.get("window_minutes")

        groups: dict[str, list[dict[str, Any]]] = {}
        for e in qualifiers:
            if gb:
                vals = _as_list(extract(e, gb))
                key = str(vals[0]) if vals else "(none)"
            else:
                key = "(all)"
            groups.setdefault(key, []).append(e)

        if not window:
            return sorted(groups.items())

        # Sliding window: for each qualifying event, take everything in the
        # preceding N minutes within the same group and keep the largest burst.
        from datetime import datetime, timedelta

        def _ts(e: dict[str, Any]) -> datetime | None:
            try:
                return datetime.fromisoformat(str(e.get("ts")).replace("Z", "+00:00"))
            except (TypeError, ValueError):
                return None

        span = timedelta(minutes=int(window))
        out: list[tuple[str, list[dict[str, Any]]]] = []
        for key, evs in groups.items():
            best: list[dict[str, Any]] = []
            for anchor in evs:
                t0 = _ts(anchor)
                if t0 is None:
                    cand = list(evs)
                else:
                    # A missing timestamp must not compare against a datetime:
                    # _ts() returns None for those, and None <= datetime raises.
                    cand = []
                    for e in evs:
                        te = _ts(e)
                        if te is not None and t0 - span <= te <= t0 + span:
                            cand.append(e)
                if len(cand) > len(best):
                    best = cand
            if best:
                out.append((key, best))
        return sorted(out, key=lambda kv: -len(kv[1]))

    # -- rules ------------------------------------------------------------

    def run_rule(self, rule: dict[str, Any], events: list[dict[str, Any]]) -> list[Hit]:
        """Evaluate one rule; may return many hits (one per threshold group)."""
        problems = validate(rule.get("tree") or {})
        if problems:
            raise RuleError("; ".join(problems))

        node = rule["tree"]
        hits: list[Hit] = []
        name = rule.get("name") or rule.get("id") or "rule"

        def _mk(sev: str, techs: list[str], evs: list[dict], reason: str,
                group: str | None = None) -> Hit:
            return Hit(
                rule_id=rule.get("id", "custom"),
                rule_name=name,
                severity=sev or rule.get("severity", "medium"),
                techniques=techs or list(rule.get("techniques") or []),
                matched_events=evs[:20],
                reason=reason,
                group_key=group,
            )

        if node.get("kind") == "threshold":
            cop = node.get("op", "gte")
            try:
                threshold = float(node.get("value"))
            except (TypeError, ValueError):
                raise RuleError(f"threshold value {node.get('value')!r} is not a number")
            fieldname = node.get("field")
            if not fieldname:
                raise RuleError("threshold node needs a field")
            for key, evs in self._threshold_groups(node, events):
                vals = [extract(e, fieldname) for e in evs]
                # count distinct values, not events: 20 packets to one IP is
                # 1 destination, and 20 destinations is a sweep.
                distinct = len({str(v) for v in _as_flat(vals)})
                count = distinct if node.get("count_distinct", True) else len(evs)
                if not compare(cop, count, threshold):
                    continue
                wm = node.get("window_minutes")
                reason = (
                    f"{count} distinct {fieldname} in "
                    f"{'a ' + str(wm) + '-minute window' if wm else 'the window'}"
                    + (f" for {key}" if key and key != '(all)' else "")
                )
                hits.append(_mk(node.get("severity", rule.get("severity", "medium")),
                                node.get("techniques") or [], evs, reason, key))
                if len(hits) >= self.max_matches:
                    break
            return hits

        matched = [e for e in events if self.matches_event(node, e)]
        if matched:
            hits.append(_mk(rule.get("severity", "medium"), rule.get("techniques") or [],
                            matched, f"{len(matched)} event(s) matched"))
        return hits

    def run(self, rules: Iterable[dict[str, Any]], events: list[dict[str, Any]]) -> list[Hit]:
        """
        Run many rules. A malformed rule is skipped, not fatal.

        One bad rule must not stop the others: a rule engine that halts on the
        first syntax error is a rule engine nobody trusts.
        """
        hits: list[Hit] = []
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            try:
                hits.extend(self.run_rule(rule, events))
            except RuleError:
                continue
        return hits


def _as_flat(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    for v in values:
        if isinstance(v, (list, tuple, set)):
            out.extend(v)
        else:
            out.append(v)
    return out
