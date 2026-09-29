"""
Correlation tests.

Before this, one event produced one incident. A file seen fifty times produced
fifty incidents, and a hash on five hosts produced five -- so "how far did this
spread" was not answerable, because the spread was not an object anywhere.

These pin the properties that make the spread answerable:

1. Related events join one incident; unrelated ones do not.
2. Severity is the maximum of the members, never an average.
3. Per-rule mode is respected: a log-mode rule opens no incident.
4. A resolved incident does not absorb new hits.
5. Suppression mutes a rule without disabling it.

They also pin the traps: an unbounded window, an unparseable timestamp, and a
window of zero all have to degrade to something sane rather than to "one
incident forever".
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from tiox.correlation import (
    DEFAULT_WINDOW_MINUTES,
    MAX_WINDOW_MINUTES,
    MIN_WINDOW_MINUTES,
    Correlator,
    clamp_window,
    correlation_key,
    key_components,
)
from tiox.store.control import ControlPlane


def detection(
    *,
    host: str = "wks-1",
    techniques=("T1486",),
    severity: str = "high",
    event_id: str | None = None,
    entities: dict | None = None,
) -> dict:
    return {
        "event_id": event_id or f"ev-{host}-{'-'.join(techniques)}-{severity}",
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "severity": severity,
        "type": "threat_hit",
        "source": "rule:agent",
        "rule_id": "custom:abc",
        "techniques": list(techniques),
        "entities": entities or {"ip": ["1.2.3.4"]},
    }


def hit(name="Ransom", *, mode="alert", rule_id="abc", reason="matched"):
    return {
        "name": name,
        "rule_id": f"custom:{rule_id}",
        "mode": mode,
        "reason": reason,
        "rule": {"rule_id": rule_id, "name": name},
        "severity": "high",
        "techniques": ["T1486"],
    }


class CorrelationTestCase(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane()
        self.store.init_schema()
        self.c = Correlator(self.store)

    def tearDown(self):
        self.store.close()


class TestWindowClamping(unittest.TestCase):
    def test_a_zero_window_does_not_correlate_everything_forever(self):
        """
        Window 0 would mean "join everything ever", which is the exact failure
        correlation exists to prevent.
        """
        self.assertEqual(clamp_window(0), MIN_WINDOW_MINUTES)

    def test_garbage_falls_back_to_the_default(self):
        for bad in (None, "", "soon", [], {}):
            self.assertEqual(clamp_window(bad), DEFAULT_WINDOW_MINUTES, bad)

    def test_an_absurd_window_is_capped(self):
        self.assertEqual(clamp_window(10**9), MAX_WINDOW_MINUTES)

    def test_a_sensible_window_passes_through(self):
        self.assertEqual(clamp_window(30), 30)


class TestKeys(unittest.TestCase):
    def test_same_host_and_technique_produce_the_same_key(self):
        a = correlation_key(detection())
        b = correlation_key(detection(severity="critical"))
        self.assertEqual(a, b, "severity must not affect grouping")

    def test_different_hosts_produce_different_keys(self):
        self.assertNotEqual(
            correlation_key(detection(host="a")),
            correlation_key(detection(host="b")),
        )

    def test_different_techniques_produce_different_keys(self):
        self.assertNotEqual(
            correlation_key(detection(techniques=("T1486",))),
            correlation_key(detection(techniques=("T1059",))),
        )

    def test_the_key_does_not_depend_on_entity_values_by_default(self):
        """
        Two different malicious files on one host are one problem: the host is
        compromised. Splitting by hash hides the host as the common factor.
        """
        a = correlation_key(detection(entities={"file_hash": ["aa" * 32]}))
        b = correlation_key(detection(entities={"file_hash": ["bb" * 32]}))
        self.assertEqual(a, b)

    def test_a_hash_scope_can_be_asked_for_explicitly(self):
        a = correlation_key(detection(entities={"file_hash": ["aa" * 32]}),
                            scope=("technique", "host", "file_hash"))
        b = correlation_key(detection(entities={"file_hash": ["bb" * 32]}),
                            scope=("technique", "host", "file_hash"))
        self.assertNotEqual(a, b)

    def test_host_case_does_not_split_a_group(self):
        self.assertEqual(
            correlation_key(detection(host="WKS-1")),
            correlation_key(detection(host="wks-1")),
        )

    def test_components_explain_the_key(self):
        comps = key_components(detection(host="wks-9", techniques=("T1486", "T1485")))
        self.assertEqual(comps["host"], "wks-9")
        self.assertEqual(comps["technique"], "T1485,T1486")

    def test_a_missing_host_does_not_crash_the_key(self):
        self.assertIsInstance(correlation_key(detection(host="")), str)


class TestCorrelate(CorrelationTestCase):
    def test_a_log_rule_opens_nothing(self):
        out = self.c.correlate(detection(), [hit(mode="log")])
        self.assertEqual(out["action"], "none")
        self.assertEqual(self.store.incident_counts()["total"], 0)

    def test_an_alert_rule_opens_one(self):
        out = self.c.correlate(detection(), [hit()])
        self.assertEqual(out["action"], "opened")
        self.assertEqual(self.store.incident_counts()["total"], 1)

    def test_the_same_key_joins_the_existing_incident(self):
        first = self.c.correlate(detection(), [hit()])
        second = self.c.correlate(detection(event_id="ev-2"), [hit()])
        self.assertEqual(second["action"], "joined")
        self.assertEqual(second["incident_id"], first["incident_id"])
        self.assertEqual(self.store.incident_counts()["total"], 1)

    def test_many_hits_on_one_key_produce_one_incident(self):
        """The whole point: a file seen fifty times is one incident."""
        for i in range(50):
            self.c.correlate(detection(event_id=f"ev-{i}"), [hit()])
        self.assertEqual(self.store.incident_counts()["total"], 1)
        self.assertEqual(
            self.store.incident_event_count(self.store.list_incidents()[0]["id"]), 50)

    def test_different_hosts_are_different_incidents(self):
        self.c.correlate(detection(host="a"), [hit()])
        out = self.c.correlate(detection(host="b", event_id="x"), [hit()])
        self.assertEqual(out["action"], "opened")
        self.assertEqual(self.store.incident_counts()["total"], 2)

    def test_an_empty_event_id_does_not_create_a_link(self):
        """A link with no event is worse than no link: it looks like evidence."""
        ev = detection()
        ev["event_id"] = ""
        out = self.c.correlate(ev, [hit()])
        self.assertEqual(out["action"], "opened")
        self.assertEqual(
            self.store.incident_event_count(out["incident_id"]), 0)

    def test_attaching_the_same_event_twice_is_one_link(self):
        first = self.c.correlate(detection(), [hit()])
        self.c.correlate(detection(), [hit()])  # same event_id
        self.assertEqual(
            self.store.incident_event_count(first["incident_id"]), 1)

    def test_a_suppressed_rule_opens_nothing(self):
        self.store.suppress_rule("abc", minutes=60)
        out = self.c.correlate(detection(), [hit()])
        self.assertEqual(out["action"], "suppressed")
        self.assertEqual(self.store.incident_counts()["total"], 0)

    def test_suppression_only_applies_to_the_named_rule(self):
        self.store.suppress_rule("other", minutes=60)
        out = self.c.correlate(detection(), [hit()])
        self.assertEqual(out["action"], "opened")

    def test_one_unsuppressed_rule_still_alerts(self):
        """A mute on one rule must not silence a second that is not muted."""
        self.store.suppress_rule("abc", minutes=60)
        out = self.c.correlate(detection(), [hit(mode="alert", rule_id="abc"),
                                             hit(name="Other", mode="alert",
                                                 rule_id="live")])
        self.assertEqual(out["action"], "opened")


class TestSeverityAggregation(CorrelationTestCase):
    def test_severity_rises_to_the_highest_member(self):
        """
        Max, never average. Fifty low-severity hits must not dilute the one
        critical hit an analyst needs to see.
        """
        first = self.c.correlate(detection(severity="low"), [hit()])
        inc_id = first["incident_id"]
        out = self.c.correlate(detection(severity="critical", event_id="ev-c"),
                               [hit()])
        self.assertTrue(out.get("severity_promoted"))
        self.assertEqual(self.store.get_incident(inc_id)["severity"], "critical")

    def test_a_lower_severity_never_demotes(self):
        first = self.c.correlate(detection(severity="critical"), [hit()])
        inc_id = first["incident_id"]
        out = self.c.correlate(detection(severity="low", event_id="ev-l"),
                               [hit()])
        self.assertFalse(out.get("severity_promoted"))
        self.assertEqual(self.store.get_incident(inc_id)["severity"], "critical")

    def test_promotion_reports_whether_it_changed_anything(self):
        out = self.c.correlate(detection(severity="critical"), [hit()])
        self.c.correlate(detection(severity="critical", event_id="ev-2"), [hit()])
        again = self.c.correlate(
            detection(severity="critical", event_id="ev-3"), [hit()])
        self.assertFalse(again.get("severity_promoted"),
                         "an unchanged severity was reported as promoted")


class TestResolvedIncidents(CorrelationTestCase):
    def test_a_resolved_incident_does_not_absorb_new_hits(self):
        """
        Reopening a resolved incident loses the resolution history and the
        effort spent on the first occurrence. A duplicate is cheaper.
        """
        first = self.c.correlate(detection(), [hit()])
        self.store.update_incident(first["incident_id"], status="resolved")
        out = self.c.correlate(detection(event_id="ev-2"), [hit()])
        self.assertEqual(out["action"], "opened")
        self.assertNotEqual(out["incident_id"], first["incident_id"])
        self.assertEqual(self.store.incident_counts()["total"], 2)

    def test_an_investigating_incident_still_absorbs(self):
        first = self.c.correlate(detection(), [hit()])
        self.store.update_incident(first["incident_id"],
                                   status="investigating")
        out = self.c.correlate(detection(event_id="ev-2"), [hit()])
        self.assertEqual(out["action"], "joined")

    def test_an_incident_older_than_the_window_does_not_absorb(self):
        """A campaign last week and one happening now are different problems."""
        first = self.c.correlate(detection(), [hit()])
        # Age both stamps: the window is tested on `updated`, because every join
        # bumps it and a `created`-only check would pass forever.
        old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        self.store._conn.execute(
            "UPDATE incidents SET created = ?, updated = ? WHERE id = ?",
            (old, old, first["incident_id"]))
        self.store._conn.commit()
        out = self.c.correlate(detection(event_id="ev-2"), [hit()])
        self.assertEqual(out["action"], "opened")


class TestIncidentEvidence(CorrelationTestCase):
    def test_evidence_reads_oldest_first(self):
        for i in range(3):
            ev = detection(event_id=f"ev-{i}")
            ev["ts"] = (datetime.now(timezone.utc)
                        - timedelta(minutes=10 - i)).isoformat()
            self.store.insert_event(_as_event(ev))
            self.c.correlate(ev, [hit()])
        inc_id = self.store.list_incidents()[0]["id"]
        timeline = self.store.incident_events(inc_id)
        self.assertEqual(len(timeline), 3)
        self.assertEqual([e["ts"] for e in timeline],
                         sorted(e["ts"] for e in timeline))

    def test_components_record_what_grouped_the_incident(self):
        out = self.c.correlate(detection(host="wks-3", techniques=("T1486",)),
                               [hit()])
        inc = self.store.get_incident(out["incident_id"])
        self.assertEqual(inc["correlation_key"], out["incident"].get(
            "correlation_key", inc["correlation_key"]))
        self.assertEqual(inc["correlation_components"]["host"], "wks-3")
        self.assertEqual(inc["correlation_components"]["technique"], "T1486")

    def test_the_incident_records_the_rule_that_opened_it(self):
        out = self.c.correlate(detection(), [hit()])
        inc = self.store.get_incident(out["incident_id"])
        self.assertEqual(inc["rule_id"], "abc")

    def test_the_title_names_the_host_and_technique(self):
        out = self.c.correlate(
            detection(host="wks-5", techniques=("T1490",)), [hit()])
        inc = self.store.get_incident(out["incident_id"])
        self.assertIn("wks-5", inc["title"])
        self.assertIn("T1490", inc["title"])


class TestSuppressionStore(CorrelationTestCase):
    def test_suppression_is_time_boxed(self):
        self.assertFalse(self.store.is_rule_suppressed("r"))
        self.store.suppress_rule("r", minutes=60)
        self.assertTrue(self.store.is_rule_suppressed("r"))

    def test_an_expired_suppression_is_not_active(self):
        self.store.suppress_rule("r", minutes=1)
        # Force it into the past rather than sleeping.
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.store._conn.execute(
            "UPDATE rule_suppressions SET suppressed_until = ? WHERE rule_id = ?",
            (past, "r"))
        self.store._conn.commit()
        self.assertFalse(self.store.is_rule_suppressed("r"),
                         "an expired mute still silenced the rule")

    def test_unsuppress(self):
        self.store.suppress_rule("r", minutes=60)
        self.assertTrue(self.store.unsuppress_rule("r"))
        self.assertFalse(self.store.is_rule_suppressed("r"))

    def test_suppressing_twice_extends_rather_than_duplicates(self):
        self.store.suppress_rule("r", minutes=60)
        self.store.suppress_rule("r", minutes=60)
        self.assertEqual(len(self.store.list_suppressions()), 1)

    def test_an_unknown_rule_is_not_suppressed(self):
        self.assertFalse(self.store.is_rule_suppressed("never-heard-of-it"))
        self.assertFalse(self.store.is_rule_suppressed(""))

    def test_a_naive_timestamp_does_not_crash_the_check(self):
        """
        A legacy naive stamp compared against an aware now() raises. Suppression
        must degrade to "not suppressed" rather than take down correlation.
        """
        self.store._conn.execute(
            "INSERT INTO rule_suppressions (rule_id, suppressed_until, reason, created_ts) "
            "VALUES ('r', '2020-01-01 00:00:00', NULL, '2020-01-01')")
        self.store._conn.commit()
        self.assertFalse(self.store.is_rule_suppressed("r"))

    def test_a_malformed_timestamp_does_not_crash_the_check(self):
        self.store._conn.execute(
            "INSERT INTO rule_suppressions (rule_id, suppressed_until, reason, created_ts) "
            "VALUES ('r', 'not-a-date', NULL, 'x')")
        self.store._conn.commit()
        self.assertFalse(self.store.is_rule_suppressed("r"))


def _as_event(d: dict):
    from tiox.schemas.event import Event

    return Event(
        event_id=d["event_id"], ts=d["ts"], type=d["type"],
        severity=d["severity"], host=d["host"], source=d["source"],
        rule_id=d["rule_id"], techniques=d["techniques"],
        entities=d["entities"],
    )


if __name__ == "__main__":
    unittest.main()
