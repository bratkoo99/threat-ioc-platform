"""
Custom rule engine and scan-identity tests.

Two things are being pinned here:

1. Detection logic. A rule that stops firing is a silent failure -- there is no
   error, just silence -- so every operator and every threshold semantic gets a
   positive test and a negative one.

2. Scan identity. Scans used to live in a single mutable dict, so a second run
   erased the first. These assert a run keeps its id from start to finish, and
   that its findings stay attached to it.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from tiox.rules.engine import (
    COMPARISONS,
    FIELDS,
    Evaluator,
    RuleError,
    compare,
    explain,
    validate,
)
from tiox.store.control import ControlPlane

BASE = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def ev(**kw) -> dict:
    """One event, with the fields the rules read."""
    offset = kw.pop("off", 0)
    e = {
        "ts": (BASE + timedelta(seconds=offset)).isoformat(),
        "type": "network_conn",
        "severity": "info",
        "host": "wks-01",
        "user": "alice",
        "source": "agent",
        "title": "connection",
        "rule_id": None,
        "techniques": [],
        "entities": {},
    }
    e.update(kw)
    return e


def leaf(field: str, op: str, value=None) -> dict:
    return {"kind": "match", "field": field, "op": op, "value": value}


class TestCompare(unittest.TestCase):
    def test_text_operators_are_case_insensitive(self):
        self.assertTrue(compare("contains", "Windows/System32", "system32"))
        self.assertTrue(compare("equals", "WKS-01", "wks-01"))

    def test_scalar_test_matches_any_value_in_a_list(self):
        # One event can carry several IPs; "ip equals X" must not require the
        # list to be exactly [X].
        self.assertTrue(compare("equals", ["1.1.1.1", "2.2.2.2"], "2.2.2.2"))
        self.assertFalse(compare("equals", ["1.1.1.1", "2.2.2.2"], "3.3.3.3"))

    def test_missing_value_is_not_a_match(self):
        self.assertFalse(compare("contains", None, "x"))
        self.assertTrue(compare("exists", None, None) is False)
        self.assertTrue(compare("missing", None, None) is True)

    def test_numeric_comparison_against_a_string_is_false_not_an_error(self):
        # One odd event must not abort evaluation of a whole window.
        self.assertFalse(compare("gt", "not-a-number", 5))
        self.assertTrue(compare("gt", "10", 5))

    def test_cidr_and_scope_helpers(self):
        self.assertTrue(compare("ip_in_cidr", "10.1.2.3", "10.0.0.0/8"))
        self.assertFalse(compare("ip_in_cidr", "8.8.8.8", "10.0.0.0/8"))
        self.assertTrue(compare("private_ip", "192.168.1.1", None))
        self.assertTrue(compare("public_ip", "8.8.8.8", None))
        # A CIDR boundary error must be reported, not silently treated as no match.
        with self.assertRaises(ValueError):
            compare("ip_in_cidr", "10.1.1.1", "not-a-network")

    def test_in_and_not_in(self):
        self.assertTrue(compare("in", "critical", "critical, high"))
        self.assertFalse(compare("not_in", "critical", "critical, high"))
        self.assertTrue(compare("not_in", "low", "critical, high"))

    def test_glob_and_regex(self):
        self.assertTrue(compare("glob", "cmd.exe", "*.exe"))
        # The path uses Windows separators, because that is what the rule
        # targets; a POSIX path has no backslash to match.
        self.assertTrue(compare("matches", r"C:\Users\a\AppData\Local\Temp\evil.EXE",
                                r"\\Temp\\.*\.exe$"))
        with self.assertRaises(RuleError):
            compare("matches", "x", "[unclosed")

    def test_unknown_operator_raises(self):
        with self.assertRaises(RuleError):
            compare("frobnicates", "x", "y")


class TestValidate(unittest.TestCase):
    def test_unknown_field_is_reported(self):
        problems = validate(leaf("colour", "equals", "red"))
        self.assertTrue(any("unknown field" in p for p in problems))

    def test_unknown_operator_is_reported(self):
        problems = validate(leaf("host", "sounds_like", "x"))
        self.assertTrue(any("unknown operator" in p for p in problems))

    def test_missing_value_is_reported(self):
        self.assertTrue(validate(leaf("host", "contains", "")))

    def test_valid_leaf_has_no_problems(self):
        self.assertEqual(validate(leaf("host", "contains", "wks")), [])

    def test_threshold_needs_a_number(self):
        bad = {"kind": "threshold", "field": "ip", "op": "gte", "value": "many"}
        self.assertTrue(any("not a number" in p for p in validate(bad)))

    def test_bad_regex_is_caught_before_saving(self):
        self.assertTrue(validate(leaf("file_path", "matches", "[unclosed")))

    def test_threshold_inside_a_boolean_tree_is_rejected(self):
        # A threshold counts a set, so it has no per-event truth value. Accepting
        # it would mean silently under-firing.
        tree = {"kind": "test", "op": "or", "children": [
            {"kind": "threshold", "field": "ip", "op": "gte", "value": 5},
            leaf("host", "equals", "wks-01"),
        ]}
        self.assertTrue(any("cannot sit inside" in p for p in validate(tree)))

    def test_unknown_kind_is_reported(self):
        self.assertTrue(validate({"kind": "wat"}))

    def test_runaway_nesting_is_rejected(self):
        node = leaf("host", "equals", "x")
        for _ in range(20):
            node = {"kind": "test", "op": "and", "children": [node, leaf("host", "equals", "y")]}
        self.assertTrue(validate(node))


class TestExplain(unittest.TestCase):
    def test_reads_back_as_english(self):
        tree = {"kind": "test", "op": "and", "children": [
            leaf("file_path", "contains", "AppData"),
            {"kind": "test", "op": "or", "children": [
                leaf("process", "equals", "rundll32.exe"),
                leaf("process", "equals", "powershell.exe"),
            ]},
        ]}
        out = explain(tree)
        self.assertIn("ALL of", out)
        self.assertIn("file_path contains 'AppData'", out)
        self.assertIn("ANY of", out)
        self.assertIn("rundll32.exe", out)

    def test_threshold_mentions_window_and_group(self):
        out = explain({"kind": "threshold", "field": "ip", "op": "gte",
                       "value": 20, "window_minutes": 5, "group_by": "host"})
        self.assertIn("20", out)
        self.assertIn("5m", out)
        self.assertIn("host", out)


class TestMatchRules(unittest.TestCase):
    def setUp(self):
        self.ev = Evaluator()

    def test_and_requires_every_child(self):
        rule = {"id": "r", "name": "Temp exe", "tree": {
            "kind": "test", "op": "and", "children": [
                leaf("file_path", "contains", "AppData"),
                leaf("file_path", "ends_with", ".exe"),
            ]}}
        self.assertEqual(len(self.ev.run_rule(rule, [
            ev(type="process", entities={"file_path": ["C:/Users/a/AppData/Temp/x.exe"]}),
        ])), 1)
        self.assertEqual(len(self.ev.run_rule(rule, [
            ev(type="process", entities={"file_path": ["C:/Users/a/AppData/Temp/notes.txt"]}),
        ])), 0)

    def test_not_inverts(self):
        rule = {"id": "r", "name": "not svchost", "tree": {
            "kind": "test", "op": "not", "children": [leaf("process", "equals", "svchost.exe")]}}
        self.assertEqual(len(self.ev.run_rule(rule, [ev(process="explorer.exe")])), 1)
        self.assertEqual(len(self.ev.run_rule(rule, [ev(process="svchost.exe")])), 0)

    def test_entity_fields_are_searched(self):
        rule = {"id": "r", "name": "known bad hash", "tree": leaf("file_hash", "equals", "abc123")}
        self.assertEqual(len(self.ev.run_rule(rule, [
            ev(type="threat_hit", entities={"file_hash": ["abc123"]}),
        ])), 1)

    def test_technique_is_a_first_class_field(self):
        rule = {"id": "r", "name": "ransomware", "tree": leaf("technique", "equals", "T1486")}
        self.assertEqual(len(self.ev.run_rule(rule, [ev(techniques=["T1486"])])), 1)
        self.assertEqual(len(self.ev.run_rule(rule, [ev(techniques=["T1078"])])), 0)

    def test_a_malformed_rule_raises_when_run_directly(self):
        with self.assertRaises(RuleError):
            self.ev.run_rule({"id": "r", "name": "x",
                              "tree": leaf("nonexistent_field", "equals", "y")}, [ev()])

    def test_one_bad_rule_does_not_stop_the_others(self):
        bad = {"id": "bad", "name": "bad", "tree": leaf("ghost", "equals", "x")}
        good = {"id": "good", "name": "good", "tree": leaf("host", "equals", "wks-01")}
        hits = self.ev.run([bad, good], [ev()])
        self.assertEqual([h.rule_id for h in hits], ["good"])

    def test_disabled_rules_do_not_run(self):
        rule = {"id": "r", "name": "off", "enabled": False,
                "tree": leaf("host", "equals", "wks-01")}
        self.assertEqual(self.ev.run([rule], [ev()]), [])


class TestThresholdRules(unittest.TestCase):
    def setUp(self):
        self.ev = Evaluator()
        self.sweep = {
            "id": "r_sweep", "name": "Outbound sweep", "severity": "high",
            "tree": {
                "kind": "threshold", "field": "ip", "op": "gte", "value": 20,
                "window_minutes": 5, "group_by": "host",
                "children": [leaf("type", "equals", "network_conn")],
            },
        }

    def test_fires_on_many_distinct_values_in_the_window(self):
        events = [ev(entities={"ip": [f"10.0.0.{i}"]}, off=i) for i in range(1, 26)]
        hits = self.ev.run_rule(self.sweep, events)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].group_key, "wks-01")
        self.assertIn("25 distinct ip", hits[0].reason)

    def test_counts_distinct_values_not_events(self):
        # 30 events to one destination is traffic, not a sweep. Counting events
        # here is the classic false-positive generator.
        events = [ev(entities={"ip": ["10.0.0.1"]}, off=i) for i in range(30)]
        self.assertEqual(len(self.ev.run_rule(self.sweep, events)), 0)

    def test_values_outside_the_window_do_not_count(self):
        events = [ev(entities={"ip": [f"10.0.0.{i}"]}, off=i * 60) for i in range(1, 26)]
        self.assertEqual(len(self.ev.run_rule(self.sweep, events)), 0)

    def test_window_is_measured_per_group(self):
        # 12 on one host and 12 on another must not add up to 24 on either.
        events = []
        for i in range(12):
            events.append(ev(host="wks-01", entities={"ip": [f"10.0.0.{i}"]}, off=i))
            events.append(ev(host="wks-02", entities={"ip": [f"10.1.0.{i}"]}, off=i))
        self.assertEqual(len(self.ev.run_rule(self.sweep, events)), 0)

    def test_children_filter_which_events_count(self):
        events = [ev(type="dns", entities={"ip": [f"10.0.0.{i}"]}, off=i) for i in range(30)]
        self.assertEqual(len(self.ev.run_rule(self.sweep, events)), 0)

    def test_events_without_a_timestamp_do_not_crash(self):
        # The sliding window compares timestamps; a missing one must be skipped,
        # not raise and take the whole rule down.
        events = [ev(entities={"ip": [f"10.0.0.{i}"]}, off=i) for i in range(1, 26)]
        for e in events[:5]:
            e.pop("ts", None)
        self.assertIsInstance(self.ev.run_rule(self.sweep, events), list)


class TestRuleStore(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane()
        self.store.init_schema()
        self.tree = {"kind": "test", "op": "and", "children": [
            leaf("file_path", "contains", "Temp"),
            leaf("file_path", "ends_with", ".exe"),
        ]}

    def tearDown(self):
        self.store.close()

    def test_save_and_read_back(self):
        saved = self.store.save_rule({"name": "Temp exe", "tree": self.tree})
        self.assertEqual(saved["name"], "Temp exe")
        self.assertTrue(saved["enabled"])
        # The tree must survive the JSON round-trip as structure, not a string.
        self.assertEqual(saved["tree"], self.tree)
        self.assertEqual(self.store.get_rule(saved["rule_id"])["tree"], self.tree)

    def test_invalid_rule_is_refused_at_save_time(self):
        with self.assertRaises(ValueError):
            self.store.save_rule({"name": "bad", "tree": leaf("nope", "equals", "x")})

    def test_toggle_does_not_erase_the_rule(self):
        saved = self.store.save_rule({"name": "Temp exe", "tree": self.tree})
        self.store.set_rule_enabled(saved["rule_id"], False)
        after = self.store.get_rule(saved["rule_id"])
        self.assertFalse(after["enabled"])
        self.assertEqual(after["tree"], self.tree, "toggling must not drop the rule body")

    def test_update_preserves_the_id(self):
        saved = self.store.save_rule({"name": "v1", "tree": self.tree})
        again = self.store.save_rule({"name": "v2", "tree": self.tree}, rule_id=saved["rule_id"])
        self.assertEqual(again["rule_id"], saved["rule_id"])
        self.assertEqual(again["name"], "v2")
        self.assertEqual(len(self.store.list_rules()), 1)

    def test_delete(self):
        saved = self.store.save_rule({"name": "temp", "tree": self.tree})
        self.assertTrue(self.store.delete_rule(saved["rule_id"]))
        self.assertIsNone(self.store.get_rule(saved["rule_id"]))
        self.assertFalse(self.store.delete_rule(saved["rule_id"]))

    def test_techniques_round_trip(self):
        saved = self.store.save_rule({
            "name": "ransom", "tree": self.tree, "techniques": ["T1486", "T1485"]})
        self.assertEqual(self.store.get_rule(saved["rule_id"])["techniques"],
                         ["T1486", "T1485"])


class TestScanIdentity(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane()
        self.store.init_schema()

    def tearDown(self):
        self.store.close()

    def test_each_scan_gets_a_distinct_id(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        b = self.store.start_scan("/tmp", "local", "h1")
        self.assertNotEqual(a["scan_id"], b["scan_id"])
        self.assertEqual(a["seq"], 1)
        self.assertEqual(b["seq"], 2)

    def test_a_second_scan_does_not_erase_the_first(self):
        # This is the regression: scan_state was one global dict, so history
        # could not exist.
        a = self.store.start_scan("/etc", "local", "h1")
        self.store.finish_scan(a["scan_id"], "completed", files_scanned=10, threats_found=1)
        b = self.store.start_scan("/var", "local", "h1")
        self.store.finish_scan(b["scan_id"], "completed", files_scanned=20, threats_found=0)

        scans = self.store.list_scans()
        self.assertEqual(len(scans), 2)
        by_id = {s["scan_id"]: s for s in scans}
        self.assertEqual(by_id[a["scan_id"]]["files_scanned"], 10)
        self.assertEqual(by_id[b["scan_id"]]["files_scanned"], 20)
        self.assertEqual(by_id[a["scan_id"]]["scan_path"], "/etc")

    def test_seq_survives_a_reopen(self):
        # seq is MAX(seq)+1 in the same table, so opening a second store on the
        # same file must continue the sequence rather than restart at 1.
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "lake.db")
            first = ControlPlane(path)
            first.init_schema()
            a = first.start_scan("/tmp", "local", "h1")
            first.finish_scan(a["scan_id"])
            self.assertEqual(a["seq"], 1)
            first.close()

            second = ControlPlane(path)
            second.init_schema()
            b = second.start_scan("/tmp", "local", "h1")
            self.assertEqual(b["seq"], 2, "seq must continue across a reopen")
            second.close()

    def test_finishing_records_duration_and_status(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.finish_scan(a["scan_id"], "completed", files_scanned=5)
        done = self.store.get_scan(a["scan_id"])
        self.assertEqual(done["status"], "completed")
        self.assertIsNotNone(done["ended_ts"])
        self.assertIsNotNone(done["duration_ms"])

    def test_error_status_is_distinct_from_completed(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.finish_scan(a["scan_id"], "error", error="scanner missing")
        self.assertEqual(self.store.get_scan(a["scan_id"])["status"], "error")

    def test_start_scan_returns_the_label(self):
        """
        start_scan() must return the same shape get_scan() returns.

        It used to return a hand-built dict without `label`, so the scan thread
        raised KeyError on the first scan and the record stayed "running" forever
        -- no output, no error visible in the UI, just a permanently busy scan.
        """
        rec = self.store.start_scan("/tmp", "local", "h1")
        self.assertIn("label", rec)
        self.assertEqual(rec["label"], "scan-0001")
        # And it must match what a later read produces.
        self.assertEqual(rec, self.store.get_scan(rec["scan_id"]))

    def test_start_scan_keys_match_get_scan_keys(self):
        rec = self.store.start_scan("/tmp", "local", "h1")
        self.assertEqual(set(rec), set(self.store.get_scan(rec["scan_id"])))

    def test_update_scan_cannot_change_the_id(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.update_scan(a["scan_id"], scan_id="hijacked", files_scanned=1)
        self.assertEqual(self.store.get_scan(a["scan_id"])["scan_id"], a["scan_id"])
        self.assertIsNone(self.store.get_scan("hijacked"))

    def test_findings_stay_attached_to_their_scan(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        b = self.store.start_scan("/var", "local", "h1")
        self.store.record_finding(a["scan_id"], {
            "file_path": "/tmp/evil.exe", "file_hash": "aa" * 32, "family": "Test",
            "severity": "high", "event_id": "ev-1"})
        self.store.record_finding(b["scan_id"], {
            "file_path": "/var/other.exe", "file_hash": "bb" * 32, "family": "Other"})

        self.assertEqual(len(self.store.scan_findings(a["scan_id"])), 1)
        self.assertEqual(len(self.store.scan_findings(b["scan_id"])), 1)
        self.assertEqual(self.store.scan_findings(a["scan_id"])[0]["file_hash"], "aa" * 32)

    def test_scan_stats_aggregate_runs(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.finish_scan(a["scan_id"], "completed", threats_found=2, files_scanned=100)
        b = self.store.start_scan("/var", "local", "h2")
        self.store.finish_scan(b["scan_id"], "completed", threats_found=3, files_scanned=200)
        stats = self.store.scan_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["threats"], 5)
        self.assertEqual(stats["files"], 300)
        self.assertEqual(stats["hosts"], 2)
        self.assertEqual(stats["last_scan"]["scan_id"], b["scan_id"])

    def test_scans_for_event_traces_back_to_the_run(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.record_finding(a["scan_id"], {
            "file_path": "/tmp/evil.exe", "file_hash": "cc" * 32, "event_id": "ev-9"})
        found = self.store.scans_for_event("ev-9")
        self.assertEqual([s["scan_id"] for s in found], [a["scan_id"]])

    def test_filtering_by_host_and_status(self):
        a = self.store.start_scan("/tmp", "local", "h1")
        self.store.start_scan("/var", "local", "h2")
        self.store.finish_scan(a["scan_id"], "completed")
        self.assertEqual(len(self.store.list_scans(host="h1")), 1)
        self.assertEqual(len(self.store.list_scans(status="running")), 1)
        self.assertEqual(len(self.store.list_scans(status="completed")), 1)


if __name__ == "__main__":
    unittest.main()
