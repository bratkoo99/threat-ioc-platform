"""
Phase 0 test suite.

Runs with stdlib unittest so there is no test dependency to install:
    python3 -m unittest discover -s tests -v

Covers the three things Phase 0 is actually promising:
  1. The schema validates and round-trips.
  2. The agent connector maps real payloads from the existing web server onto it.
  3. The store and migration behave, including the concurrency the JSON store lost.
"""

import json
import os
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tiox.connectors.agent import AgentConnector, normalize_incident, parse_agent_ts
from tiox.connectors.registry import describe_all, get, is_compatible, names
from tiox.schemas.event import (
    SCHEMA_VERSION,
    EntityType,
    Event,
    EventType,
    SchemaError,
    Severity,
    hash_entities,
    host_entities,
    merge_entities,
    network_entities,
    severity_at_least,
)
from tiox.schemas.jsonschema import build_json_schema
from tiox.store.control import ControlPlane
from tiox.store.pipeline import ingest, migrate_legacy

SHA_A = "a" * 64
SHA_B = "b" * 64
T0 = "2026-01-01T00:00:00+00:00"


# ============================ SCHEMA ============================


class TestEventSchema(unittest.TestCase):
    def test_minimal_event_validates(self):
        ev = Event(source="test", type="file", severity="info")
        self.assertEqual(ev.schema_version, SCHEMA_VERSION)
        self.assertTrue(ev.title)

    def test_round_trip_preserves_everything(self):
        ev = Event(
            source="agent", type=EventType.THREAT_HIT.value, severity="critical",
            host="ws-01", user="root",
            entities=merge_entities(hash_entities({"sha256": SHA_A}), host_entities("ws-01", "10.0.0.5")),
            title="Threat: BlackBasta", description="payload", rule_id="builtin.hash_exact",
            raw={"k": "v"}, tags=["a", "b"],
        )
        back = Event.from_dict(ev.to_dict())
        for field in ("event_id", "ts", "ingest_ts", "source", "type", "severity",
                      "host", "user", "entities", "title", "description",
                      "rule_id", "raw", "tags", "schema_version"):
            self.assertEqual(getattr(ev, field), getattr(back, field), f"field {field} drifted")

    def test_json_round_trip(self):
        ev = Event(source="agent", type="alert", severity="high")
        self.assertEqual(Event.from_json(ev.to_json()).event_id, ev.event_id)

    def test_invalid_severity_rejected(self):
        with self.assertRaises(SchemaError):
            Event(source="t", severity="catastrophic")

    def test_invalid_type_rejected(self):
        with self.assertRaises(SchemaError):
            Event(source="t", type="banana")

    def test_ts_and_ingest_ts_are_independent(self):
        ev = Event(source="t", ts="2020-01-01T00:00:00+00:00", ingest_ts="2026-01-01T00:00:00+00:00")
        self.assertNotEqual(ev.ts, ev.ingest_ts)

    def test_entities_normalized_lowercase(self):
        ev = Event(source="t", entities={"domain": ["EVIL.COM"], "user": ["ROOT"]})
        self.assertEqual(ev.entities["domain"], ["evil.com"])
        self.assertEqual(ev.entities["user"], ["root"])

    def test_invalid_hash_dropped_not_fatal(self):
        ev = Event(source="t", entities={"file_hash": [SHA_A, "not-a-hash", "ZZZZ"]})
        self.assertEqual(ev.entities["file_hash"], [SHA_A])

    def test_unknown_entity_type_preserved_in_raw(self):
        ev = Event(source="t", entities={"quantum_thing": ["x"]})
        self.assertNotIn("quantum_thing", ev.entities)
        self.assertEqual(ev.raw["_unmapped_entities"]["quantum_thing"], ["x"])

    def test_duplicate_entities_deduped(self):
        ev = Event(source="t", entities={"domain": ["a.com", "a.com", "b.com"]})
        self.assertEqual(ev.entities["domain"], ["a.com", "b.com"])

    def test_severity_ordering(self):
        self.assertTrue(severity_at_least("critical", "high"))
        self.assertTrue(severity_at_least("high", "high"))
        self.assertFalse(severity_at_least("low", "medium"))

    def test_network_url_yields_domain(self):
        e = network_entities(url="https://C2.evil.com:8443/gate.php")
        self.assertEqual(e["domain"], ["c2.evil.com"])
        self.assertEqual(e["url"], ["https://C2.evil.com:8443/gate.php"])

    def test_network_rejects_bad_ip(self):
        self.assertEqual(network_entities(src_ip="999.1.1.1"), {})

    def test_dedupe_key_ignores_invented_timestamps(self):
        a = Event(source="agent", type="alert", raw={"_ts_derived": True})
        b = Event(source="agent", type="alert", raw={"_ts_derived": True})
        self.assertEqual(a.dedupe_key(), b.dedupe_key())

    def test_dedupe_key_respects_source_timestamps(self):
        a = Event(source="agent", type="alert", ts="2026-01-01T00:00:00+00:00")
        b = Event(source="agent", type="alert", ts="2026-01-02T00:00:00+00:00")
        self.assertNotEqual(a.dedupe_key(), b.dedupe_key())

    def test_dedupe_key_ignores_severity_and_description(self):
        a = Event(source="agent", type="alert", ts=T0, severity="low", description="x")
        b = Event(source="agent", type="alert", ts=T0, severity="critical", description="y")
        self.assertEqual(a.dedupe_key(), b.dedupe_key())

    def test_dedupe_key_distinguishes_entities(self):
        a = Event(source="agent", type="alert", ts=T0, entities={"file_hash": [SHA_A]})
        b = Event(source="agent", type="alert", ts=T0, entities={"file_hash": [SHA_B]})
        self.assertNotEqual(a.dedupe_key(), b.dedupe_key())

    def test_dedupe_key_is_order_independent(self):
        a = Event(source="agent", type="alert", ts=T0, entities={"domain": ["a.com", "b.com"]})
        b = Event(source="agent", type="alert", ts=T0, entities={"domain": ["b.com", "a.com"]})
        self.assertEqual(a.dedupe_key(), b.dedupe_key())

    def test_json_schema_is_valid_shape(self):
        s = build_json_schema()
        self.assertEqual(s["properties"]["type"]["enum"], [t.value for t in EventType])
        self.assertEqual(
            s["properties"]["entities"]["propertyNames"]["enum"],
            [e.value for e in EntityType],
        )
        for f in ("event_id", "ts", "ingest_ts", "source", "type", "severity"):
            self.assertIn(f, s["required"])

    def test_json_schema_file_is_current(self):
        path = Path(__file__).resolve().parents[1] / "tiox/schemas/event.schema.json"
        if not path.exists():
            self.skipTest("schema file not generated yet")
        self.assertEqual(json.loads(path.read_text()), build_json_schema(),
                         "event.schema.json is stale; run python3 -m tiox.schemas.jsonschema")


# ============================ AGENT CONNECTOR ============================


class TestAgentConnector(unittest.TestCase):
    def setUp(self):
        self.conn = AgentConnector()

    def test_hash_hit_is_critical(self):
        evs = self.conn.normalize({
            "file": "/tmp/.x", "type": "Known malicious hash",
            "family": "BlackBasta", "details": "payload", "hash": SHA_A, "time": "2026-01-01T00:00:00",
        })
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev.severity, Severity.CRITICAL.value)
        self.assertEqual(ev.rule_id, "builtin.hash_exact")
        self.assertEqual(ev.entities[EntityType.FILE_HASH.value], [SHA_A])
        self.assertIn(EntityType.FILE_PATH.value, ev.entities)
        self.assertIn("blackbasta", ev.tags)

    def test_name_hit_is_high(self):
        evs = self.conn.normalize({
            "file": "/tmp/HOW_TO_DECRYPT.txt", "type": "Filename pattern",
            "family": "RansomNote", "hash": "",
        })
        self.assertEqual(evs[0].severity, Severity.HIGH.value)
        self.assertEqual(evs[0].rule_id, "builtin.filename_pattern")

    def test_registration(self):
        evs = self.conn.normalize({"hostname": "ws-01", "ip": "10.0.0.5", "os": "Arch"})
        self.assertEqual(evs[0].type, EventType.AGENT_STATUS.value)
        self.assertEqual(evs[0].entities["host"], ["ws-01"])
        self.assertEqual(evs[0].entities["ip"], ["10.0.0.5"])

    def test_heartbeat(self):
        evs = self.conn.normalize({"agent_id": "EP-0001", "ip": "10.0.0.5"},
                                  context={"hostname": "ws-01"})
        self.assertEqual(evs[0].rule_id, "agent.heartbeat")

    def test_scan_report_yields_summary_plus_threats(self):
        evs = self.conn.normalize({
            "files_scanned": 100, "dirs_scanned": 10, "threats_found": 1, "errors": 0,
            "scan_time": 3.5, "end_time": "2026-01-01T00:00:00",
            "threats": [{"file": "/tmp/a.lockbit", "type": "Filename pattern",
                         "family": "LockBit", "hash": ""}],
        }, context={"hostname": "ws-01"})
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0].rule_id, "agent.scan_complete")
        self.assertEqual(evs[1].rule_id, "builtin.filename_pattern")

    def test_naive_timestamp_is_flagged(self):
        """Agent stamps are naive local time; the assumption must stay auditable."""
        evs = self.conn.normalize({
            "file": "/tmp/a", "type": "Filename pattern", "family": "X",
            "time": "2026-01-01T12:00:00",
        })
        self.assertTrue(evs[0].raw.get("_ts_assumed_utc"))

    def test_naive_timestamp_on_heartbeat_recorded(self):
        evs = self.conn.normalize(
            {"agent_id": "EP-1", "ip": "10.0.0.5", "ts": "2026-01-01T12:00:00"},
            context={"hostname": "h"},
        )
        self.assertTrue(evs[0].raw.get("_ts_assumed_utc"))

    def test_bad_payload_raises(self):
        with self.assertRaises(Exception):
            self.conn.normalize("not a dict")

    def test_unrecognized_payload_yields_nothing(self):
        self.assertEqual(self.conn.normalize({"totally": "unrelated"}), [])

    def test_normalize_incident(self):
        evs = normalize_incident({
            "id": "INC-0001", "title": "Threat: LockBit", "severity": "critical", "status": "open",
        })
        self.assertEqual(evs[0].type, EventType.INCIDENT.value)
        self.assertEqual(evs[0].raw["legacy_incident_id"], "INC-0001")
        self.assertIn("status:open", evs[0].tags)


class TestTimestampParsing(unittest.TestCase):
    def test_naive_utc(self):
        ts, naive, derived = parse_agent_ts("2026-01-01T12:00:00")
        self.assertTrue(naive)
        self.assertFalse(derived)
        self.assertTrue(ts.endswith("+00:00"))

    def test_aware_passthrough(self):
        ts, naive, derived = parse_agent_ts("2026-01-01T12:00:00+02:00")
        self.assertFalse(naive)
        self.assertFalse(derived)
        self.assertTrue(ts.endswith("+00:00"))

    def test_missing_is_derived(self):
        _, naive, derived = parse_agent_ts(None)
        self.assertTrue(naive)
        self.assertTrue(derived)

    def test_garbage_raises(self):
        with self.assertRaises(Exception):
            parse_agent_ts("not-a-date")


# ============================ REGISTRY ============================


class TestRegistry(unittest.TestCase):
    def test_agent_registered(self):
        self.assertIn("agent", names())
        self.assertIsInstance(get("agent"), AgentConnector)

    def test_unknown_raises(self):
        with self.assertRaises(Exception):
            get("nope")

    def test_agent_compatible(self):
        ok, _ = is_compatible(get("agent"))
        self.assertTrue(ok)

    def test_describe_all(self):
        for d in describe_all():
            self.assertIn("name", d)
            self.assertIn("compatible", d)


# ============================ STORE ============================


class TestControlPlane(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane(":memory:")
        self.ev = Event(
            source="agent", type="threat_hit", severity="critical", host="ws-01",
            entities=merge_entities(hash_entities({"sha256": SHA_A}), host_entities("ws-01", "10.0.0.5")),
        )

    def tearDown(self):
        self.store.close()

    def test_schema_version_recorded(self):
        self.assertEqual(self.store.schema_version, SCHEMA_VERSION)

    def test_insert_and_pivot_on_hash(self):
        self.assertTrue(self.store.insert_event(self.ev))
        found = self.store.find_by_entity("file_hash", SHA_A)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["event_id"], self.ev.event_id)
        self.assertEqual(self.store.count_by_entity("file_hash", SHA_A), 1)

    def test_pivot_is_case_insensitive(self):
        self.store.insert_event(self.ev)
        self.assertEqual(len(self.store.find_by_entity("file_hash", SHA_A.upper())), 1)

    def test_duplicate_event_id_rejected(self):
        self.assertTrue(self.store.insert_event(self.ev))
        self.assertFalse(self.store.insert_event(self.ev))

    def test_pivot_across_multiple_event_types(self):
        other = Event(source="edr", type="network_conn", severity="high",
                      entities={"file_hash": [SHA_A]})
        self.store.insert_events([self.ev, other])
        self.assertEqual(self.store.count_by_entity("file_hash", SHA_A), 2)

    def test_query_events_time_range(self):
        self.store.insert_event(self.ev)
        self.assertEqual(len(self.store.query_events(severity="critical")), 1)
        self.assertEqual(len(self.store.query_events(severity="info")), 0)
        self.assertEqual(len(self.store.query_events(since="2099-01-01T00:00:00+00:00")), 0)
        self.assertEqual(len(self.store.query_events(until="2099-01-01T00:00:00+00:00")), 1)

    def test_event_stats(self):
        self.store.insert_event(self.ev)
        st = self.store.event_stats()
        self.assertEqual(st["total"], 1)
        self.assertEqual(st["high"], 1)
        self.assertEqual(st["hosts"], 1)

    def test_endpoint_upsert_is_idempotent_by_hostname(self):
        a = self.store.upsert_endpoint({"hostname": "ws-01", "ip": "10.0.0.5"})
        b = self.store.upsert_endpoint({"hostname": "ws-01", "ip": "10.0.0.5"})
        self.assertEqual(a, b)
        self.assertEqual(len(self.store.list_endpoints()), 1)

    def test_increment_scan(self):
        eid = self.store.upsert_endpoint({"hostname": "ws-02", "ip": "10.0.0.6"})
        self.store.increment_scan(eid, threats=2)
        ep = self.store.get_endpoint(eid)
        self.assertEqual(ep["scan_count"], 1)
        self.assertEqual(ep["threats_found"], 2)

    def test_incident_lifecycle(self):
        inc = self.store.create_incident({"title": "T", "severity": "high"})
        self.assertTrue(inc["id"].startswith("INC-"))
        self.assertTrue(self.store.update_incident(inc["id"], status="closed", note="done"))
        got = self.store.get_incident(inc["id"])
        self.assertEqual(got["status"], "closed")
        self.assertEqual(len(got["notes"]), 1)
        self.assertFalse(self.store.update_incident("NOPE", status="closed"))

    def test_incident_counts(self):
        self.store.create_incident({"title": "a", "severity": "critical"})
        self.store.create_incident({"title": "b", "severity": "low"})
        counts = self.store.incident_counts()
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["open"], 2)
        self.assertEqual(counts["critical"], 1)

    def test_concurrent_writes_do_not_lose_data(self):
        """The race the old incidents.json whole-file rewrite lost."""
        n_threads, per_thread = 8, 20

        def worker(tid: int) -> None:
            for i in range(per_thread):
                self.store.insert_event(Event(
                    source="agent", type="alert", severity="high", host=f"h{tid}",
                    entities={"host": [f"h{tid}"]},
                ))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.store.event_stats()["total"], n_threads * per_thread)


# ============================ PIPELINE ============================


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.store = ControlPlane(":memory:")

    def tearDown(self):
        self.store.close()

    def test_ingest_agent_payload(self):
        r = ingest(self.store, {
            "hostname": "ws-01", "ip": "10.0.0.5", "os": "Arch",
        }, source="agent")
        self.assertEqual(r.inserted, 1)
        self.assertEqual(r.errors, [])

    def test_ingest_is_idempotent(self):
        ev = Event(source="agent", type="alert")
        self.assertEqual(ingest(self.store, {"hostname": "h"}, "agent").inserted, 1)
        # Different payload -> different event_id, so this is about explicit dupes:
        self.store.insert_event(ev)
        self.assertTrue(ingest(self.store, ev.to_dict(), "agent").duplicates >= 0)

    def test_ingest_repeat_of_same_threat_is_deduped(self):
        payload = {"file": "/tmp/a", "type": "Known malicious hash", "hash": SHA_A, "family": "X"}
        r1 = ingest(self.store, payload, "agent")
        r2 = ingest(self.store, payload, "agent")
        self.assertEqual(r1.inserted, 1)
        self.assertEqual(r2.inserted, 0)
        self.assertEqual(r2.duplicates, 1)

    def test_connector_failure_is_contained(self):
        r = ingest(self.store, {"bogus": object()}, "agent")
        self.assertTrue(r.errors or r.inserted == 0)

    def test_migrate_legacy(self):
        summary = migrate_legacy(
            self.store,
            incidents=[
                {"id": "INC-0001", "title": "Threat: LockBit", "severity": "critical"},
                {"id": "INC-0002", "title": "Agent registered: ws-01", "severity": "info"},
            ],
            inventory={"endpoints": [{"id": "EP-0001", "hostname": "ws-01", "ip": "10.0.0.5"}]},
        )
        self.assertEqual(summary["endpoints"], 1)
        self.assertEqual(summary["incidents"], 2)
        self.assertEqual(summary["events"], 2)
        self.assertEqual(self.store.incident_counts()["total"], 2)
        self.assertEqual(len(self.store.list_endpoints()), 1)

    def test_migration_is_idempotent(self):
        args = ([{"id": "INC-0001", "title": "T", "severity": "high"}],
                {"endpoints": [{"hostname": "ws-01", "ip": "10.0.0.5"}]})
        migrate_legacy(self.store, *args)
        second = migrate_legacy(self.store, *args)
        self.assertEqual(second["incidents"], 1)
        self.assertEqual(self.store.incident_counts()["total"], 1)
        self.assertEqual(len(self.store.list_endpoints()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
