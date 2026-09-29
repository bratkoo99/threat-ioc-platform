"""
Phase 1 backend tests: ATT&CK tagging and investigation aggregations.

Covers the two things this phase adds behind the API:
  1. every detection carries MITRE technique ids, and unmapped rules are visible
  2. the aggregation queries answer hunter questions (spread, frequency,
     timeline, technique coverage, stale estate)

Run:  python3 -m unittest tests.test_investigations -v
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tiox.connectors.agent import AgentConnector
from tiox.schemas import attack
from tiox.schemas.event import Event, EventType, Severity
from tiox.store.control import ControlPlane
from tiox.store.investigations import Investigations, parse_window

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
T0 = "2026-09-01T00:00:00+00:00"


# ============================ ATT&CK catalog ============================


class TestTechniqueCatalog(unittest.TestCase):
    def test_verified_technique_ids_resolve(self):
        """Spot-check ids against attack.mitre.org, including a sub-technique."""
        for tid, name in (
            ("T1486", "Data Encrypted for Impact"),
            ("T1485", "Data Destruction"),
            ("T1485.001", "Lifecycle-Triggered Deletion"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1003", "OS Credential Dumping"),
        ):
            t = attack.get(tid)
            self.assertIsNotNone(t, f"{tid} missing from catalog")
            self.assertEqual(t.name, name)

    def test_subtechnique_url_is_correct_format(self):
        self.assertEqual(attack.get("T1485.001").url,
                         "https://attack.mitre.org/techniques/T1485/001/")

    def test_unknown_technique_returns_none(self):
        self.assertIsNone(attack.get("T9999"))

    def test_id_validation(self):
        for good in ("T1486", "t1486", "T1485.001"):
            self.assertTrue(attack.is_valid(good), good)
        for bad in ("", "1486", "T148", "T14861", "attack", "T1486.1234", None):
            self.assertFalse(attack.is_valid(bad), repr(bad))

    def test_every_catalog_entry_has_metadata(self):
        for t in attack.catalog():
            self.assertTrue(t["name"])
            self.assertTrue(t["tactic"])
            self.assertTrue(t["url"].startswith("https://attack.mitre.org/"))

    def test_no_catalog_entry_is_its_own_unknown(self):
        """catalog() must not emit entries that get() cannot resolve."""
        catalog_ids = {t["id"] for t in attack.catalog()}
        self.assertEqual(catalog_ids, set(attack.TECHNIQUES))

    def test_tactics_listed(self):
        self.assertIn("impact", attack.tactics())
        self.assertIn("credential-access", attack.tactics())


class TestTechniqueMapping(unittest.TestCase):
    def test_hash_match_maps_to_encryption(self):
        self.assertEqual(attack.techniques_for_rule("builtin.hash_exact"), ["T1486"])

    def test_operational_rules_are_not_technique_tagged(self):
        """An agent heartbeat is not adversary behaviour. Tagging it would
        pollute every technique-level report."""
        for rule in ("agent.register", "agent.heartbeat", "agent.scan_complete",
                     "system.operator"):
            self.assertEqual(attack.techniques_for_rule(rule), [], rule)

    def test_family_fallback(self):
        self.assertEqual(attack.techniques_for_family("BlackBasta"), ["T1486"])
        self.assertEqual(attack.techniques_for_family("  mimikatz  "), ["T1003"])
        self.assertEqual(attack.techniques_for_family("unknown-family"), [])

    def test_rule_wins_over_family(self):
        self.assertEqual(
            attack.techniques_for_event("builtin.hash_exact", "RansomNote"), ["T1486"]
        )

    def test_family_used_when_rule_unmapped(self):
        self.assertEqual(
            attack.techniques_for_event("some.new.rule", "LockBit"), ["T1486"]
        )

    def test_unmapped_rules_are_reported(self):
        self.assertEqual(attack.unmapped_rules(["builtin.hash_exact"]), [])
        self.assertIn("mystery.rule", attack.unmapped_rules(["mystery.rule"]))
        self.assertEqual(
            attack.unmapped_rules(["agent.heartbeat"]),
            [],
            "an intentionally unmapped operational rule is not a coverage gap",
        )


class TestEventTechniqueField(unittest.TestCase):
    def test_techniques_persist_on_the_event(self):
        ev = Event(source="agent", type="threat_hit", techniques=["T1486", "t1003"])
        self.assertEqual(ev.techniques, ["T1003", "T1486"])

    def test_invalid_technique_ids_are_dropped_not_fatal(self):
        ev = Event(source="agent", type="alert",
                   techniques=["T1486", "nonsense", "", "T9999999"])
        self.assertEqual(ev.techniques, ["T1486"])

    def test_malformed_technique_list_does_not_lose_the_event(self):
        """A typo in a rule mapping must not discard the detection itself."""
        ev = Event(source="agent", type="threat_hit", rule_id="builtin.hash_exact",
                   techniques=["T1486", "oops"])
        self.assertEqual(ev.rule_id, "builtin.hash_exact")
        self.assertEqual(ev.techniques, ["T1486"])

    def test_connector_tags_automatically(self):
        """Connectors must not have to remember to tag."""
        ac = AgentConnector()
        evs = ac.normalize({
            "file": "/tmp/a.lockbit", "type": "Filename pattern",
            "family": "LockBit", "hash": "",
        })
        self.assertEqual(evs[0].techniques, ["T1486"])

    def test_connector_does_not_tag_operational_events(self):
        ac = AgentConnector()
        evs = ac.normalize({"hostname": "h1", "ip": "10.0.0.1"})
        self.assertEqual(evs[0].rule_id, "agent.register")
        self.assertEqual(evs[0].techniques, [])

    def test_technique_survives_round_trip(self):
        ev = Event(source="agent", type="threat_hit", techniques=["T1486"])
        self.assertEqual(Event.from_dict(ev.to_dict()).techniques, ["T1486"])


# ============================ time window parsing ============================


class TestParseWindow(unittest.TestCase):
    def test_shorthand_units(self):
        for text, hours in (("30m", 0.5), ("24h", 24), ("7d", 168), ("2w", 336)):
            since, until = parse_window(text)
            self.assertIsNotNone(since, text)
            self.assertIsNotNone(until, text)
            delta = (datetime.fromisoformat(until) - datetime.fromisoformat(since))
            self.assertAlmostEqual(delta.total_seconds() / 3600, hours, places=1,
                                   msg=text)

    def test_all_time(self):
        """`window=all` means no bound, so a query can reach the whole lake."""
        self.assertEqual(parse_window("all"), (None, None))
        self.assertEqual(parse_window("any"), (None, None))

    def test_empty_value_falls_back_to_default_not_all_time(self):
        """An explicit empty `window=` must not silently widen the query to
        everything, which is what an accidental `?window=` would otherwise do."""
        since, until = parse_window("", default_hours=24)
        self.assertIsNotNone(since)
        delta = datetime.fromisoformat(until) - datetime.fromisoformat(since)
        self.assertAlmostEqual(delta.total_seconds() / 3600, 24, places=1)

    def test_default_when_absent(self):
        since, until = parse_window(None, default_hours=48)
        delta = datetime.fromisoformat(until) - datetime.fromisoformat(since)
        self.assertAlmostEqual(delta.total_seconds() / 3600, 48, places=1)

    def test_iso_timestamp(self):
        since, until = parse_window("2026-01-01T00:00:00Z")
        self.assertTrue(since.startswith("2026-01-01"))
        self.assertIsNone(until)

    def test_bare_number_is_hours(self):
        since, until = parse_window("6")
        delta = datetime.fromisoformat(until) - datetime.fromisoformat(since)
        self.assertAlmostEqual(delta.total_seconds() / 3600, 6, places=1)

    def test_garbage_falls_back_to_default(self):
        since, until = parse_window("last tuesday-ish", default_hours=24)
        self.assertIsNotNone(since)


# ============================ aggregations ============================


class TestInvestigations(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane(":memory:")
        self.inv = self.store.investigations
        self.now = datetime.now(timezone.utc)
        self.conn = AgentConnector()

    def tearDown(self):
        self.store.close()

    def _threat(self, host, sha, hours_ago=1, family="BlackBasta", rule_hash=True):
        payload = {
            "file": f"/tmp/{sha[:8]}.bin",
            "type": "Known malicious hash" if rule_hash else "Filename pattern",
            "family": family, "details": "d",
            "hash": sha if rule_hash else "",
            "time": (self.now - timedelta(hours=hours_ago)).isoformat(),
        }
        evs = self.conn.normalize(payload, context={"hostname": host})
        for e in evs:
            e.host = host
            self.store.insert_event(e)
        return evs[0]

    # ---------- spread ----------

    def test_entity_spread_counts_distinct_hosts(self):
        """One host seeing a hash many times is one problem; 40 hosts is an
        incident. Host count is the number that matters."""
        # Distinct times so the observations are genuinely distinct events rather
        # than dedupe-collapsed: the dedupe behaviour has its own test.
        for i in range(5):
            self._threat("h1", SHA_A, hours_ago=i + 1)
        self._threat("h2", SHA_A, hours_ago=10)
        self._threat("h3", SHA_A, hours_ago=20)
        spread = self.inv.entity_spread("file_hash", SHA_A)
        self.assertEqual(spread["host_count"], 3)
        self.assertEqual(spread["events"], 7)
        self.assertEqual({h["host"] for h in spread["hosts"]}, {"h1", "h2", "h3"})

    def test_repeated_identical_observation_is_deduped_not_multiplied(self):
        """Five byte-identical reports of one file are one fact."""
        for _ in range(5):
            self._threat("h1", SHA_A, hours_ago=1)
        self.assertEqual(self.inv.entity_spread("file_hash", SHA_A)["events"], 1)

    def test_entity_spread_is_case_insensitive(self):
        self._threat("h1", SHA_A)
        self.assertEqual(self.inv.entity_spread("file_hash", SHA_A.upper())["host_count"], 1)

    def test_entity_spread_reports_families(self):
        self._threat("h1", SHA_A, family="BlackBasta")
        self._threat("h2", SHA_A, family="LockBit")
        self.assertEqual(
            sorted(self.inv.entity_spread("file_hash", SHA_A)["families"]),
            ["BlackBasta", "LockBit"],
        )

    def test_entity_spread_on_unseen_value_is_empty(self):
        spread = self.inv.entity_spread("file_hash", SHA_C)
        self.assertEqual(spread["host_count"], 0)
        self.assertEqual(spread["events"], 0)
        self.assertIsNone(spread["first_seen"])

    def test_entity_spread_respects_time_window(self):
        self._threat("recent", SHA_A, hours_ago=1)
        self._threat("old", SHA_A, hours_ago=72 * 24)
        since = (self.now - timedelta(hours=24)).isoformat()
        self.assertEqual(self.inv.entity_spread("file_hash", SHA_A, since)["host_count"], 1)

    # ---------- frequency ----------

    def test_top_entities_ranks_by_host_spread(self):
        """A hash on 1 host seen 50 times must not outrank one on 5 hosts."""
        for i in range(50):
            self._threat("solo", SHA_A, hours_ago=(i % 40) + 1)
        for i, host in enumerate(["a", "b", "c", "d", "e"]):
            self._threat(host, SHA_B, hours_ago=i + 1)
        top = self.inv.top_entities("file_hash")
        self.assertEqual(top[0]["value"], SHA_B)
        self.assertEqual(top[0]["hosts"], 5)
        self.assertEqual(top[1]["value"], SHA_A)
        self.assertEqual(top[1]["hosts"], 1)

    def test_top_entities_respects_limit(self):
        for i in range(5):
            self._threat(f"h{i}", f"{i:064x}")
        self.assertEqual(len(self.inv.top_entities("file_hash", limit=3)), 3)

    def test_entity_first_last_seen(self):
        self._threat("h1", SHA_A, hours_ago=48)
        self._threat("h1", SHA_A, hours_ago=1)
        rows = {r["value"]: r for r in self.inv.entity_first_last_seen("file_hash")}
        self.assertEqual(rows[SHA_A]["events"], 2)
        self.assertLess(rows[SHA_A]["first_seen"], rows[SHA_A]["last_seen"])

    # ---------- timeline ----------

    def test_timeline_buckets_hourly(self):
        self._threat("h1", SHA_A, hours_ago=0)
        self._threat("h2", SHA_B, hours_ago=1)
        buckets = self.inv.timeline(bucket="hour")
        self.assertGreaterEqual(len(buckets), 2)
        self.assertEqual(sum(b["events"] for b in buckets), 2)

    def test_timeline_counts_high_severity_separately(self):
        self._threat("h1", SHA_A)  # critical
        buckets = self.inv.timeline(bucket="day")
        self.assertEqual(sum(b["high"] for b in buckets), 1)

    def test_timeline_can_scope_to_one_entity(self):
        self._threat("h1", SHA_A, hours_ago=0)
        self._threat("h2", SHA_B, hours_ago=1)
        scoped = self.inv.timeline(bucket="hour", entity_type="file_hash",
                                   entity_value=SHA_A)
        self.assertEqual(sum(b["events"] for b in scoped), 1)

    # ---------- ATT&CK ----------

    def test_technique_breakdown_resolves_metadata(self):
        self._threat("h1", SHA_A)
        rows = self.inv.technique_breakdown()
        t1486 = next(r for r in rows if r["technique"] == "T1486")
        self.assertEqual(t1486["name"], "Data Encrypted for Impact")
        self.assertEqual(t1486["tactic"], "impact")
        self.assertEqual(t1486["hosts"], 1)
        self.assertTrue(t1486["url"].startswith("https://attack.mitre.org/"))

    def test_technique_hosts(self):
        self._threat("h1", SHA_A)
        self._threat("h2", SHA_A)
        hosts = self.inv.technique_hosts("T1486")
        self.assertEqual({h["host"] for h in hosts}, {"h1", "h2"})

    def test_operational_events_do_not_appear_in_attack_report(self):
        """A lake full of heartbeats must not produce an ATT&CK report."""
        ac = self.conn
        for _ in range(3):
            for e in ac.normalize({"hostname": "h", "ip": "10.0.0.1"}):
                self.store.insert_event(e)
        self.assertEqual(self.inv.technique_breakdown(), [])

    def test_rule_breakdown_flags_unmapped(self):
        self._threat("h1", SHA_A)                      # builtin.hash_exact -> mapped
        self.store.insert_event(Event(source="agent", type="alert",
                                      rule_id="mystery.rule"))
        rows = {r["rule_id"]: r for r in self.inv.rule_breakdown()}
        self.assertFalse(rows["builtin.hash_exact"]["unmapped"])
        self.assertTrue(rows["mystery.rule"]["unmapped"])
        self.assertEqual(rows["builtin.hash_exact"]["techniques"], ["T1486"])

    def test_rule_breakdown_agrees_with_the_attack_module(self):
        """
        rule_breakdown used to compute `unmapped` with its own check, so
        "system.operator.INC-0001" was reported as a coverage gap by this query
        while unmapped_rules() correctly ignored it. Two answers to one question
        is how a tuning view starts lying.
        """
        for rule in ("agent.register", "system.operator.INC-0001",
                     "legacy.incident.INC-0002", "builtin.hash_exact",
                     "mystery.rule"):
            self.store.insert_event(Event(source="agent", type="alert", rule_id=rule))
        for row in self.inv.rule_breakdown():
            expected = row["rule_id"] in attack.unmapped_rules([row["rule_id"]])
            self.assertEqual(row["unmapped"], expected,
                             f"{row['rule_id']}: breakdown says {row['unmapped']}, "
                             f"attack module says {expected}")

    def test_operational_rules_do_not_count_as_coverage_gaps(self):
        """A lake full of heartbeats must not report 20 unmapped rules."""
        for _ in range(5):
            for e in self.conn.normalize({"hostname": "h", "ip": "10.0.0.1"}):
                self.store.insert_event(e)
        self.assertEqual([r for r in self.inv.rule_breakdown() if r["unmapped"]], [])

    # ---------- estate ----------

    def test_stale_endpoints(self):
        recent = self.store.upsert_endpoint({"hostname": "fresh", "ip": "10.0.0.1"})
        old = self.store.upsert_endpoint({"hostname": "ancient", "ip": "10.0.0.2"})
        with self.store._tx() as c:
            c.execute("UPDATE endpoints SET last_seen = ? WHERE id = ?",
                      ((self.now - timedelta(days=30)).isoformat(), old))
        stale = self.inv.stale_endpoints(days=7)
        names = {e["hostname"] for e in stale}
        self.assertIn("ancient", names)
        self.assertNotIn("fresh", names)
        self.assertNotIn(recent, {e["id"] for e in stale})

    def test_host_summary_includes_techniques(self):
        self._threat("h1", SHA_A)
        self._threat("h2", SHA_B)
        rows = {r["host"]: r for r in self.inv.host_summary()}
        self.assertEqual(rows["h1"]["techniques"], ["T1486"])
        self.assertEqual(rows["h1"]["high"], 1)

    def test_every_query_survives_a_time_window(self):
        """
        Regression guard for a real bug: two queries omitted the AND before the
        time clause, producing "... x = ? e.ts >= ?". That is a syntax error only
        when a window is supplied, so it stayed hidden until the time picker
        existed. Every query must be exercised with and without one.
        """
        self._threat("h1", SHA_A)
        self._threat("h2", SHA_B, hours_ago=48)
        since = (self.now - timedelta(hours=24)).isoformat()
        calls = {
            "entity_spread": lambda s: self.inv.entity_spread("file_hash", SHA_A, s),
            "top_entities": lambda s: self.inv.top_entities("file_hash", s),
            "first_last_seen": lambda s: self.inv.entity_first_last_seen("file_hash", s),
            "timeline": lambda s: self.inv.timeline(s, None, "hour"),
            "timeline_scoped": lambda s: self.inv.timeline(
                s, None, "hour", "file_hash", SHA_A),
            "technique_breakdown": lambda s: self.inv.technique_breakdown(s),
            "technique_hosts": lambda s: self.inv.technique_hosts("T1486", s),
            "host_summary": lambda s: self.inv.host_summary(s),
            "rule_breakdown": lambda s: self.inv.rule_breakdown(s),
            "stale_endpoints": lambda s: self.inv.stale_endpoints(7),
        }
        for name, fn in calls.items():
            for label, window in (("no window", None), ("with window", since)):
                with self.subTest(query=name, case=label):
                    fn(window)  # must not raise

    def test_time_window_actually_narrows_results(self):
        """Not just "does not crash" -- the window must exclude older events."""
        self._threat("fresh", SHA_A, hours_ago=1)
        self._threat("stale", SHA_B, hours_ago=72)
        since = (self.now - timedelta(hours=24)).isoformat()
        hosts = {r["host"] for r in self.inv.host_summary(since)}
        self.assertIn("fresh", hosts)
        self.assertNotIn("stale", hosts)

    def test_host_summary_ignores_hostless_events(self):
        self.store.insert_event(Event(source="agent", type="alert", host=None))
        self.assertEqual(self.inv.host_summary(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
