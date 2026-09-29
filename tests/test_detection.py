"""
Detection-in-the-path tests.

The Phase 1 rule engine had exactly one caller: the dry-run endpoint. These tests
exist because the failure that matters here is silence. A rule that stops firing
raises nothing, reports nothing, and looks identical to an environment with
nothing to detect.

Four properties are pinned:

1. Rules actually run on ingest, and attribute their hits to themselves.
2. A rule cannot break ingest. A broken detection must degrade to no detection.
3. Detection cannot feed itself -- a rule matching `threat_hit` must not fire on
   the threat_hit events another rule produced.
4. Per-rule mode is honoured: `log` records, `alert` is what the correlation
   layer keys off.
"""

from __future__ import annotations

import unittest
from typing import Any

from tiox.connectors.base import Connector
from tiox.detection import (
    RULE_PREFIX,
    DetectionEngine,
    build_threat_event,
    event_to_dict,
    rule_id_of,
)
from tiox.schemas.event import Event
from tiox.store import pipeline
from tiox.store.control import ControlPlane


class ProcConnector(Connector):
    """
    Emits one process event per payload.

    The agent connector only handles scan hits, registrations, and heartbeats, so
    process telemetry has no producer yet. This stands in for the EDR connector
    that Phase 3 will add, and keeps the detection tests independent of it.
    """

    NAME = "proc"
    SCHEMA_VER = "1"

    def normalize(self, payload, context=None):
        context = context or {}
        entities: dict[str, list[str]] = {"process": [payload["proc"]]}
        if payload.get("path"):
            entities["file_path"] = [payload["path"]]
        return [Event(
            type="process",
            host=context.get("hostname") or payload.get("host"),
            user=payload.get("user"),
            title=f"process started: {payload['proc']}",
            entities=entities,
            source="edr",
        )]


class _Replay(Connector):
    """Returns a fixed event, so a test can re-ingest it verbatim."""

    NAME = "proc"
    SCHEMA_VER = "1"

    def __init__(self, event: Event) -> None:
        self.fixed_event = event

    def normalize(self, payload, context=None) -> list[Event]:
        return [self.fixed_event]


def lolbin_rule(name="Temp LOLBin", mode="log", **over) -> dict[str, Any]:
    return {
        "name": name,
        "severity": "critical",
        "techniques": ["T1059.001"],
        "mode": mode,
        "tree": {"kind": "test", "op": "and", "children": [
            {"kind": "match", "field": "process", "op": "equals",
             "value": "rundll32.exe"},
            {"kind": "match", "field": "file_path", "op": "contains",
             "value": "Temp"},
        ]},
        **over,
    }


class DetectionTestCase(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane()
        self.store.init_schema()
        # The engine is a process-wide singleton that caches the rule set, and
        # it caches the *store* too. Each test gets a fresh in-memory database,
        # so an engine left over from a previous test would evaluate against a
        # closed store and silently find no rules -- every detection assertion
        # would fail for a reason that has nothing to do with detection.
        pipeline.invalidate_detection()
        pipeline._ENGINE = None
        self.conn = ProcConnector()

    def tearDown(self):
        pipeline.invalidate_detection()
        pipeline._ENGINE = None
        self.store.close()

    def save(self, spec: dict[str, Any]) -> dict[str, Any]:
        saved = self.store.save_rule(spec)
        pipeline.invalidate_detection()
        return saved

    def feed(self, **payload) -> Any:
        return pipeline.ingest(self.store, payload, source="proc",
                               connector=self.conn)


class TestRulesRunOnIngest(DetectionTestCase):
    def test_a_matching_event_produces_a_detection(self):
        self.save(lolbin_rule())
        res = self.feed(proc="rundll32.exe",
                        path=r"C:\Users\a\AppData\Local\Temp\a.dll", host="wks-1")
        self.assertEqual(len(res.detections), 1)
        self.assertEqual(len(res.detection_events), 1)

    def test_a_non_matching_event_produces_nothing(self):
        self.save(lolbin_rule())
        res = self.feed(proc="notepad.exe",
                        path=r"C:\Users\a\Documents\a.txt", host="wks-1")
        self.assertEqual(res.detections, [])
        self.assertEqual(res.detection_events, [])

    def test_the_hit_is_attributed_to_the_rule(self):
        """Attribution is what makes "this rule is noise" a fact, not an opinion."""
        rule = self.save(lolbin_rule())
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        hit = res.detections[0]
        self.assertEqual(hit["rule_id"], f"{RULE_PREFIX}{rule['rule_id']}")
        self.assertEqual(hit["name"], "Temp LOLBin")
        # And the attribution is on the event, where a query can find it.
        self.assertEqual(res.detection_events[0].rule_id, hit["rule_id"])

    def test_the_detection_carries_the_rule_severity_and_techniques(self):
        self.save(lolbin_rule(severity="critical", techniques=["T1059.001"]))
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        ev = res.detection_events[0]
        self.assertEqual(ev.severity, "critical")
        self.assertEqual(ev.techniques, ["T1059.001"])

    def test_the_detection_keeps_the_source_entities(self):
        """A detection that loses its entities cannot be investigated."""
        self.save(lolbin_rule())
        res = self.feed(proc="rundll32.exe",
                        path=r"C:\Temp\important.dll", host="wks-1")
        ev = res.detection_events[0]
        self.assertIn("rundll32.exe", ev.entities.get("process", []))
        self.assertTrue(any("important.dll" in p
                            for p in ev.entities.get("file_path", [])))

    def test_the_detection_points_back_at_its_source_event(self):
        self.save(lolbin_rule())
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        ev = res.detection_events[0]
        self.assertTrue(ev.raw.get("source_event_id"))
        # And the id resolves to a real event in the lake, so a click on the
        # detection reaches the observation that caused it.
        stored = self.store.query_events(limit=50)
        ids = {e["event_id"] for e in stored}
        self.assertIn(ev.raw["source_event_id"], ids,
                      "source_event_id must resolve to a stored event")

    def test_two_rules_matching_one_event_both_fire(self):
        """Collapsing them would hide that two independent rules agree."""
        self.save(lolbin_rule("AnyProcess", tree={
            "kind": "match", "field": "type", "op": "equals", "value": "process"}))
        self.save(lolbin_rule("EvilProc", tree={
            "kind": "match", "field": "process", "op": "equals",
            "value": "rundll32.exe"}))
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        self.assertEqual(
            sorted(h["name"] for h in res.detections), ["AnyProcess", "EvilProc"])

    def test_a_disabled_rule_does_not_run(self):
        rule = self.save(lolbin_rule())
        self.store.set_rule_enabled(rule["rule_id"], False)
        pipeline.invalidate_detection()
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        self.assertEqual(res.detections, [])

    def test_detection_is_reported_separately_from_ingest(self):
        """A caller must be able to tell an observation from a detection."""
        self.save(lolbin_rule())
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        d = res.as_dict()
        self.assertEqual(d["normalized"], 1)
        self.assertEqual(d["detections"], 1)


class TestNoFeedbackLoop(DetectionTestCase):
    def test_a_rule_matching_threat_hit_does_not_fire_on_its_own_output(self):
        """
        A rule that matches `threat_hit` would otherwise fire on the events
        another rule produced, and a broad rule would amplify its own output
        without end.
        """
        self.save(lolbin_rule("Real", tree={
            "kind": "match", "field": "process", "op": "equals",
            "value": "rundll32.exe"}))
        self.save(lolbin_rule("Amplifier", tree={
            "kind": "match", "field": "type", "op": "equals",
            "value": "threat_hit"}))
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="wks-1")
        self.assertEqual(
            sorted(h["name"] for h in res.detections), ["Real"],
            "the amplifier fired on a detection, so detection feeds itself")
        self.assertEqual(len(res.detection_events), 1)

    def test_heartbeats_are_not_offered_to_rules(self):
        """
        A heartbeat every 30s across 50 hosts is ~28k events a day, all
        evaluated to find nothing.
        """
        self.save(lolbin_rule("AnyType", tree={
            "kind": "match", "field": "type", "op": "exists", "value": None}))
        pipeline.invalidate_detection()

        class Beat(Connector):
            NAME = "beat"
            SCHEMA_VER = "1"

            def normalize(self, payload, context=None):
                return [Event(type="agent_status", title="heartbeat")]

        res = pipeline.ingest(self.store, {"n": 1}, source="beat", connector=Beat())
        self.assertEqual(res.detections, [], "a heartbeat triggered a detection")

    def test_a_duplicate_event_does_not_re_evaluate(self):
        """
        An at-least-once feed must not double-count a rule's hits.

        The connector stamps a fresh `ts` per call, so feeding the same payload
        twice is legitimately two observations. A real replay is the *same*
        event arriving twice, which the store dedupes -- and the pipeline must
        then skip detection, or every replay inflates the count that the tuning
        view ranks rules by.
        """
        self.save(lolbin_rule())
        # The same Event instance, already stored. A replay is the identical
        # observation arriving twice, not a second observation that looks alike --
        # and the connector stamps a fresh ts on every call, so re-normalising
        # the same payload would produce a legitimately different event.
        original = Event(
            type="process", host="w1", title="process started: rundll32.exe",
            entities={"process": ["rundll32.exe"],
                      "file_path": [r"C:\Temp\dup.dll"]},
            source="edr",
        )
        self.assertTrue(self.store.insert_event(original), "first insert is new")

        res = pipeline.ingest(
            self.store, {}, source="proc", connector=_Replay(original))
        self.assertEqual(res.inserted, 0, "the replay should be deduplicated")
        self.assertEqual(
            res.detections, [],
            "a deduplicated event was re-evaluated, inflating the hit count")


class TestABrokenRuleCannotBreakIngest(DetectionTestCase):
    def test_a_rule_that_raises_is_skipped(self):
        import tiox.detection as det

        self.save(lolbin_rule())
        real = det.Evaluator.run_rule

        def boom(self, rule, events):
            raise det.RuleError("rule exploded")

        det.Evaluator.run_rule = boom
        try:
            res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="w1")
        finally:
            det.Evaluator.run_rule = real
        self.assertGreaterEqual(res.inserted, 1, "the observation was lost")
        self.assertEqual(res.detections, [])

    def test_an_unexpected_error_is_also_survivable(self):
        """A MemoryError from a rule must not take the feed down either."""
        import tiox.detection as det

        self.save(lolbin_rule())
        real = det.Evaluator.run_rule

        def kaboom(self, rule, events):
            raise MemoryError("something deep broke")

        det.Evaluator.run_rule = kaboom
        try:
            res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="w1")
        finally:
            det.Evaluator.run_rule = real
        self.assertGreaterEqual(res.inserted, 1)

    def test_a_store_that_cannot_list_rules_yields_no_detections(self):
        class BadStore:
            def list_rules(self, enabled_only=False):
                raise RuntimeError("db down")

        self.assertEqual(DetectionEngine(BadStore()).rules(), [])

    def test_a_rule_whose_tree_no_longer_validates_is_dropped(self):
        """
        Schema drift, or a hand-edited database. The rule must be skipped
        loudly, not evaluated into nonsense.
        """
        rule = self.save(lolbin_rule())
        self.store._conn.execute(
            "UPDATE custom_rules SET tree = '{\"kind\":\"bogus\"}' WHERE rule_id = ?",
            (rule["rule_id"],))
        self.store._conn.commit()
        engine = DetectionEngine(self.store)
        self.assertEqual(engine.loadable_rules(), [])
        # And ingest still works.
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="w1")
        self.assertGreaterEqual(res.inserted, 1)

    def test_an_invalid_rule_cannot_be_saved_at_all(self):
        """A rule that could never fire is refused, not stored and ignored."""
        with self.assertRaises(ValueError):
            self.store.save_rule({"name": "bad", "tree": {
                "kind": "match", "field": "no_such_field", "op": "equals",
                "value": "x"}})


class TestPerRuleMode(DetectionTestCase):
    def test_mode_defaults_to_log(self):
        """A new rule must not be able to open incidents on its first day."""
        rule = self.store.save_rule(lolbin_rule())
        self.assertEqual(rule["mode"], "log")

    def test_an_unrecognised_mode_is_coerced_to_log(self):
        """A typo must not escalate a rule to paging someone."""
        rule = self.store.save_rule(lolbin_rule(mode="PAGE-EVERYONE"))
        self.assertEqual(rule["mode"], "log")

    def test_alert_mode_round_trips(self):
        rule = self.store.save_rule(lolbin_rule(mode="alert"))
        self.assertEqual(self.store.get_rule(rule["rule_id"])["mode"], "alert")

    def test_mode_survives_a_save(self):
        rule = self.store.save_rule(lolbin_rule(mode="alert"))
        again = self.store.save_rule(
            {**lolbin_rule(mode="alert"), "name": "renamed"},
            rule_id=rule["rule_id"])
        self.assertEqual(again["mode"], "alert")

    def test_the_hit_reports_its_mode(self):
        """The correlation layer keys off mode, so the hit must carry it."""
        self.save(lolbin_rule(mode="alert"))
        res = self.feed(proc="rundll32.exe", path=r"C:\Temp\a.dll", host="w1")
        self.assertEqual(res.detections[0]["mode"], "alert")

        self.save(lolbin_rule("log-rule", mode="log", tree={
            "kind": "match", "field": "type", "op": "equals", "value": "process"}))
        res2 = self.feed(proc="second.exe", path=r"C:\Temp\b.dll", host="w1")
        modes = {h["name"]: h["mode"] for h in res2.detections}
        self.assertEqual(modes.get("log-rule"), "log")

    def test_mode_is_migrated_onto_an_existing_database(self):
        """A Phase 1 database has no mode column; init must add it."""
        import sqlite3
        import tempfile
        import os
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "old.db")
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE custom_rules (
                    rule_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
                    severity TEXT NOT NULL DEFAULT 'medium',
                    techniques TEXT NOT NULL DEFAULT '[]', tree TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, author TEXT,
                    created_ts TEXT NOT NULL, updated_ts TEXT NOT NULL,
                    last_run_ts TEXT, last_hits INTEGER NOT NULL DEFAULT 0,
                    hits_total INTEGER NOT NULL DEFAULT 0);
                INSERT INTO custom_rules (rule_id, name, tree, created_ts, updated_ts)
                VALUES ('old-1', 'legacy', '{"kind":"match","field":"host",
                    "op":"equals","value":"x"}', 't', 't');
            """)
            conn.commit()
            conn.close()

            store = ControlPlane(path)
            store.init_schema()
            self.assertEqual(store.get_rule("old-1")["mode"], "log")
            # Idempotent: init runs on every start.
            store.init_schema()
            store.init_schema()
            self.assertEqual(store.get_rule("old-1")["mode"], "log")
            store.close()


class TestRuleCounters(DetectionTestCase):
    def test_hits_are_counted_per_rule(self):
        self.save(lolbin_rule())
        for i in range(3):
            self.feed(proc="rundll32.exe", path=fr"C:\Temp\{i}.dll", host="w1")
        stats = {r["name"]: r for r in self.store.rule_effectiveness()}
        self.assertEqual(stats["Temp LOLBin"]["hits"], 3)

    def test_a_rule_that_never_fired_is_untested_not_bad(self):
        """
        Zero hits is no evidence either way. Grading it 'noisy' would push an
        analyst to delete a rule that has simply not seen its condition.
        """
        self.save(lolbin_rule())
        rows = self.store.rule_effectiveness()
        self.assertEqual(rows[0]["grade"], "untested")
        self.assertIsNone(rows[0]["precision"])

    def test_rule_cache_is_invalidated_on_demand(self):
        rule = self.save(lolbin_rule())
        engine = DetectionEngine(self.store)
        self.assertEqual(len(engine.rules()), 1)
        self.store.set_rule_enabled(rule["rule_id"], False)
        pipeline.invalidate_detection()
        self.assertEqual(
            len(DetectionEngine(self.store).rules()), 0,
            "a stale cache meant a rule edit had no effect until restart")


class TestEventConversion(unittest.TestCase):
    def test_event_to_dict_exposes_what_rules_read(self):
        ev = Event(type="process", host="h", severity="high",
                   entities={"process": ["a"], "ip": ["1.1.1.1"]})
        d = event_to_dict(ev)
        self.assertEqual(d["type"], "process")
        self.assertEqual(d["entities"]["process"], ["a"])
        self.assertEqual(d["severity"], "high")

    def test_entity_lists_are_copied_not_shared(self):
        """A rule mutating the dict must not corrupt the stored event."""
        ev = Event(type="process", entities={"ip": ["1.1.1.1"]})
        d = event_to_dict(ev)
        d["entities"]["ip"].append("9.9.9.9")
        self.assertEqual(ev.entities["ip"], ["1.1.1.1"])

    def test_rule_id_prefixing_is_reversible(self):
        self.assertEqual(rule_id_of({"rule_id": "abc"}), "custom:abc")
        from tiox.detection import _bare_rule_id
        self.assertEqual(_bare_rule_id("custom:abc"), "abc")


if __name__ == "__main__":
    unittest.main()
