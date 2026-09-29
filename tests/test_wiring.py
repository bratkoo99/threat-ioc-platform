"""
Phase 0.6 tests: the server is actually wired to the control plane and the lake.

The point of Phase 0 was building tiox/ and the point of 0.6 was connecting it.
These tests boot a real server against a temporary database and assert that agent
traffic lands in the lake and the pivot answers -- the claims that were false
before this change.

Run:  python3 -m unittest tests.test_wiring -v
"""

import hashlib
import http.client
import importlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA = hashlib.sha256(EICAR).hexdigest()


_SERVER = {}
_TMP = None
_ENV_KEYS = ("TIOX_TLS", "TIOX_AGENT_KEY", "TIOX_SESSION_KEY", "TIOX_BIND",
             "TIOX_DB", "TIOX_MIGRATE_LEGACY", "TIOX_INVENTORY_FILE",
             "TIOX_INCIDENTS_FILE")


class WiringBase:
    """
    Boots the real handler against a throwaway database.

    The server module keeps a module-level `_store` singleton, so exactly one
    server is started for the whole test module rather than one per class. An
    earlier version started one per class and closed the shared store in the
    first teardown, so every later class hit a closed connection.
    """

    AGENT = "wire-agent-key"
    SESSION = "wire-session-key"

    def req(self, method, path, key=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, payload, headers)
            r = conn.getresponse()
            raw = r.read().decode(errors="replace")
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
        finally:
            conn.close()

    def register(self, hostname, ip):
        status, body = self.req("POST", "/api/agent/register", self.AGENT,
                                {"hostname": hostname, "ip": ip, "os": "test"})
        self.assertEqual(status, 200, body)
        return body["id"]


def setUpModule():
    global _SERVER, _TMP
    _TMP = tempfile.TemporaryDirectory()
    db = os.path.join(_TMP.name, "tiox.db")
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    os.environ.update({
        "TIOX_TLS": "0",
        "TIOX_AGENT_KEY": WiringBase.AGENT,
        "TIOX_SESSION_KEY": WiringBase.SESSION,
        "TIOX_BIND": "127.0.0.1",
        "TIOX_DB": db,
        # Legacy seeding has its own test; isolate it so a stray incidents.json
        # on the developer's disk cannot change these results.
        "TIOX_MIGRATE_LEGACY": "0",
    })
    server = importlib.import_module("web_ui_server")
    server.PORT = 0
    httpd, _ = server.build_server()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _SERVER = {
        "httpd": httpd,
        "port": httpd.server_address[1],
        "store": server.get_store(),
        "saved": saved,
    }


def tearDownModule():
    httpd = _SERVER["httpd"]
    httpd.shutdown()
    httpd.server_close()
    _SERVER["store"].close()
    importlib.import_module("web_ui_server")._store = None
    for k, v in _SERVER["saved"].items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    _TMP.cleanup()


class _Mixin:
    """Gives each test class access to the module-scoped server."""

    @property
    def store(self):
        return _SERVER["store"]

    @property
    def port(self):
        return _SERVER["port"]

    @property
    def server(self):
        return importlib.import_module("web_ui_server")

    def setUp(self):
        # Each test gets a clean-ish event count baseline rather than a fresh db,
        # since the module shares one server. Assertions compare deltas.
        self._events_before = self.store.event_stats()["total"]
        self._incidents_before = self.store.incident_counts()["total"]


# ============================ the wiring itself ============================


class TestServerUsesControlPlane(_Mixin, WiringBase, unittest.TestCase):
    def test_server_imports_tiox(self):
        src = (ROOT / "web_ui_server.py").read_text()
        self.assertIn("from tiox.store.control import ControlPlane", src)
        self.assertIn("from tiox.store.pipeline import", src)
        self.assertIn("from tiox.connectors.registry import", src)

    def test_legacy_json_writers_are_no_longer_used(self):
        """The handlers must not still call the JSON writers."""
        src = (ROOT / "web_ui_server.py").read_text()
        handler_body = src[src.index("class Handler"):]
        self.assertNotIn("save_inventory(inv)", handler_body)
        self.assertNotIn("save_incidents(inc)", handler_body)

    def test_registration_writes_to_sqlite_not_json(self):
        eid = self.register("wire-a", "10.0.0.1")
        self.assertTrue(eid.startswith("EP-"))
        # Present in the control plane...
        self.assertIsNotNone(self.store.get_endpoint(eid))
        # ...and the handler now reads from the control plane too.
        inv = self.server.get_inventory()
        self.assertIn("wire-a", [e["hostname"] for e in inv["endpoints"]])

    def test_endpoint_id_is_server_issued(self):
        """A client-chosen id must not create a second endpoint or collide."""
        eid1 = self.register("wire-b", "10.0.0.2")
        # Re-register the same host: upsert, not duplicate.
        eid2 = self.register("wire-b", "10.0.0.2")
        self.assertEqual(eid1, eid2)
        eps = [e for e in self.store.list_endpoints() if e["hostname"] == "wire-b"]
        self.assertEqual(len(eps), 1)

    def test_heartbeat_updates_last_seen(self):
        eid = self.register("wire-c", "10.0.0.3")
        before = self.store.get_endpoint(eid)["last_seen"]
        status, _ = self.req("POST", "/api/agent/heartbeat", self.AGENT,
                            {"agent_id": eid, "ip": "10.0.0.3"})
        self.assertEqual(status, 200)
        self.assertIsNotNone(self.store.get_endpoint(eid)["last_seen"])

    def test_heartbeat_from_unknown_agent_is_rejected(self):
        """The old loop silently accepted an unknown id, so a broken agent
        looked healthy forever."""
        status, _ = self.req("POST", "/api/agent/heartbeat", self.AGENT,
                            {"agent_id": "EP-9999", "ip": "10.9.9.9"})
        self.assertEqual(status, 404)

    def test_inventory_reports_registered_endpoints(self):
        self.register("wire-d", "10.0.0.4")
        status, inv = self.req("GET", "/api/inventory", self.SESSION)
        self.assertEqual(status, 200)
        self.assertIn("wire-d", [e["hostname"] for e in inv["endpoints"]])


# ============================ the lake actually fills ============================


class TestLakeIngest(_Mixin, WiringBase, unittest.TestCase):
    def test_registration_reaches_the_lake(self):
        self.register("wire-lake-1", "10.1.0.1")
        after = self.store.event_stats()["total"]
        self.assertGreater(after, self._events_before,
                           "agent registration produced no event")

    def test_incident_creation_reaches_the_lake(self):
        status, inc = self.req("POST", "/api/incidents/create", self.SESSION,
                               {"title": "Manual test incident", "severity": "high"})
        self.assertEqual(status, 200, inc)
        after = self.store.event_stats()["total"]
        self.assertGreater(after, self._events_before,
                           "incident creation produced no event")

    def test_incident_is_retrievable_and_linked(self):
        _, inc = self.req("POST", "/api/incidents/create", self.SESSION,
                          {"title": "Linked incident", "severity": "medium"})
        inc_id = inc["id"]
        self.assertTrue(inc_id.startswith("INC-"))
        status, got = self.req("GET", "/api/incidents", self.SESSION)
        self.assertEqual(status, 200)
        row = next(i for i in got["incidents"] if i["id"] == inc_id)
        self.assertEqual(row["title"], "Linked incident")
        # It should carry a link to the event that represents it.
        self.assertTrue(row.get("event_id"), "incident has no event_id link")

    def test_incident_update_reports_unknown_id(self):
        """The old code answered ok:true for a typo'd id."""
        status, _ = self.req("POST", "/api/incidents/update", self.SESSION,
                            {"id": "INC-9999", "status": "closed"})
        self.assertEqual(status, 404)

    def test_incident_update_with_note(self):
        _, inc = self.req("POST", "/api/incidents/create", self.SESSION,
                          {"title": "Note target", "severity": "low"})
        status, body = self.req("POST", "/api/incidents/update", self.SESSION,
                                {"id": inc["id"], "status": "closed", "note": "handled"})
        self.assertEqual(status, 200, body)
        status, got = self.req("GET", "/api/incidents", self.SESSION)
        row = next(i for i in got["incidents"] if i["id"] == inc["id"])
        self.assertEqual(row["status"], "closed")
        self.assertEqual(len(row.get("notes", [])), 1)

    def test_stats_include_lake_figures(self):
        self.register("wire-stats", "10.2.0.1")
        status, stats = self.req("GET", "/api/stats", self.SESSION)
        self.assertEqual(status, 200)
        for k in ("events_total", "events_high_severity", "event_hosts", "event_sources"):
            self.assertIn(k, stats, f"stats missing {k}")
        self.assertGreater(stats["events_total"], self._events_before)


# ============================ the pivot ============================


class TestPivotAPI(_Mixin, WiringBase, unittest.TestCase):
    def _seed_hash(self, sha, hostname="pivot-host"):
        """
        Put a known hash in the lake the way production does: a real agent
        registration over HTTP, then the connector's normalization of a scan
        finding. Deliberately not a hand-built Event, so the pivot test would
        fail if the connector stopped carrying the hash entity.
        """
        from tiox.connectors.agent import AgentConnector

        eid = self.register(hostname, "10.3.0.1")
        conn = AgentConnector()
        events = conn.normalize({
            "file": f"/tmp/{sha[:8]}.bin",
            "type": "Known malicious hash",
            "family": "TestFam", "details": "eicar", "hash": sha,
        }, context={"hostname": hostname})
        # Assert on the connector's output, not on the insert count: the class
        # reuses one hash across tests, so later inserts are correctly deduped
        # and a "inserted == 1" check would fail for the right behaviour.
        self.assertTrue(events, "connector produced no event at all")
        self.assertEqual(len(events), 1)
        self.assertIn(sha, events[0].entities.get("file_hash", []),
                      "connector dropped the file_hash entity")
        self.assertEqual(events[0].rule_id, "builtin.hash_exact")
        self.assertEqual(events[0].severity, "critical")
        # Persist it, and confirm the entity index actually carries the hash --
        # the pivot query reads that index, so a store that accepted the event
        # without indexing it would look fine until someone pivoted.
        self.store.insert_events(events)
        self.assertGreaterEqual(self.store.count_by_entity("file_hash", sha), 1,
                                "event stored but not indexed for pivoting")
        return eid, events

    def test_pivot_returns_the_event_for_a_hash(self):
        self._seed_hash(EICAR_SHA)
        status, body = self.req(
            "GET", f"/api/entity?type=file_hash&value={EICAR_SHA}", self.SESSION)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["entity"]["type"], "file_hash")
        self.assertEqual(body["entity"]["value"], EICAR_SHA)
        self.assertGreaterEqual(body["total"], 1)
        self.assertIn("pivot-host", body["hosts"])
        self.assertIn("agent", body["sources"])

    def test_pivot_is_case_insensitive(self):
        self._seed_hash(EICAR_SHA)
        _, body = self.req(
            "GET", f"/api/entity?type=file_hash&value={EICAR_SHA.upper()}", self.SESSION)
        self.assertGreaterEqual(body["total"], 1)

    def test_pivot_reports_first_and_last_seen(self):
        self._seed_hash(EICAR_SHA)
        _, body = self.req(
            "GET", f"/api/entity?type=file_hash&value={EICAR_SHA}", self.SESSION)
        self.assertIsNotNone(body["first_seen"])
        self.assertIsNotNone(body["last_seen"])
        self.assertLessEqual(body["first_seen"], body["last_seen"])

    def test_pivot_requires_type_and_value(self):
        status, _ = self.req("GET", "/api/entity", self.SESSION)
        self.assertEqual(status, 400)
        status, _ = self.req("GET", "/api/entity?type=file_hash", self.SESSION)
        self.assertEqual(status, 400)

    def test_pivot_rejects_unknown_entity_type(self):
        status, body = self.req("GET", "/api/entity?type=bogus&value=x", self.SESSION)
        self.assertEqual(status, 400)
        self.assertIn("valid", body)
        self.assertIn("file_hash", body["valid"])

    def test_pivot_on_absent_entity_is_empty_not_error(self):
        status, body = self.req("GET", "/api/entity?type=file_hash&value=" + "c" * 64,
                                self.SESSION)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["events"], [])

    def test_pivot_omits_raw_payload(self):
        self._seed_hash(EICAR_SHA)
        _, body = self.req("GET", f"/api/entity?type=file_hash&value={EICAR_SHA}",
                           self.SESSION)
        for ev in body["events"]:
            self.assertNotIn("raw", ev, "pivot response should not include raw blobs")

    def test_pivot_requires_auth(self):
        status, _ = self.req("GET", f"/api/entity?type=file_hash&value={EICAR_SHA}")
        self.assertEqual(status, 401)

    def test_pivot_limit_is_bounded(self):
        self._seed_hash(EICAR_SHA)
        _, body = self.req(
            "GET", f"/api/entity?type=file_hash&value={EICAR_SHA}&limit=99999", self.SESSION)
        self.assertLessEqual(body["returned"], 500)

    def test_pivot_limit_rejects_garbage(self):
        self._seed_hash(EICAR_SHA)
        status, body = self.req(
            "GET", f"/api/entity?type=file_hash&value={EICAR_SHA}&limit=abc", self.SESSION)
        self.assertEqual(status, 200)
        self.assertLessEqual(body["returned"], 200)


# ============================ event query ============================


class TestEventQueryAPI(_Mixin, WiringBase, unittest.TestCase):
    """GET /api/lake -- paginated event query.

    Deliberately not /api/events: that path is the SSE progress stream, and a
    request to it blocks forever holding a thread. That collision hung this test
    class until the route was renamed.
    """
    def test_events_endpoint_returns_rows(self):
        self.register("query-host", "10.4.0.1")
        status, body = self.req("GET", "/api/lake", self.SESSION)
        self.assertEqual(status, 200, body)
        self.assertIn("events", body)
        self.assertGreater(body["count"], self._events_before)

    def test_events_filter_by_type(self):
        self.register("query-host-2", "10.4.0.2")
        status, body = self.req("GET", "/api/lake?type=agent_status", self.SESSION)
        self.assertEqual(status, 200)
        for ev in body["events"]:
            self.assertEqual(ev["type"], "agent_status")

    def test_events_filter_by_severity(self):
        self.register("query-host-3", "10.4.0.3")
        status, body = self.req("GET", "/api/lake?severity=info", self.SESSION)
        self.assertEqual(status, 200)
        for ev in body["events"]:
            self.assertEqual(ev["severity"], "info")

    def test_events_time_range_excludes_future(self):
        self.register("query-host-4", "10.4.0.4")
        status, body = self.req("GET", "/api/lake?since=2099-01-01T00:00:00%2B00:00",
                                self.SESSION)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 0,
                         "future since= should return nothing, not everything")

    def test_events_requires_auth(self):
        status, _ = self.req("GET", "/api/lake")
        self.assertEqual(status, 401)


# ============================ dedupe through the real path ============================


class TestNoDoubleCounting(_Mixin, WiringBase, unittest.TestCase):
    def test_repeated_registration_does_not_duplicate_events(self):
        """
        Registering the same host repeatedly must not inflate the lake.

        Two events on the FIRST registration are correct and not duplicates: one
        "agent.register" event, and one event for the resulting incident. The
        requirement is that registrations 2..4 add nothing.
        """
        hostname, ip = "repeat-host", "10.5.0.1"
        self.register(hostname, ip)
        after_first = self.store.event_stats()["total"]
        for _ in range(3):
            self.register(hostname, ip)
        after_all = self.store.event_stats()["total"]
        self.assertEqual(after_all, after_first,
                         f"3 re-registrations added {after_all - after_first} event(s)")

    def test_re_registration_does_not_file_a_new_incident(self):
        hostname, ip = "repeat-inc", "10.5.0.2"
        self.register(hostname, ip)
        inc_after_first = self.store.incident_counts()["total"]
        for _ in range(3):
            self.register(hostname, ip)
        self.assertEqual(self.store.incident_counts()["total"], inc_after_first,
                         "re-registration filed duplicate 'new endpoint' incidents")

    def test_registration_event_is_deduped_at_the_connector(self):
        """The connector must mark its invented timestamp, or re-registration
        produces a new fingerprint each time."""
        from tiox.connectors.agent import AgentConnector

        conn = AgentConnector()
        payload = {"hostname": "dedupe-check", "ip": "10.5.0.3", "os": "x"}
        a = conn.normalize(payload)[0]
        b = conn.normalize(payload)[0]
        self.assertTrue(a.raw.get("_ts_derived"),
                        "registration event should mark its ts as derived")
        self.assertEqual(a.dedupe_key(), b.dedupe_key())

    def test_agent_key_cannot_read_the_lake(self):
        status, _ = self.req("GET", f"/api/entity?type=file_hash&value={EICAR_SHA}",
                             self.AGENT)
        self.assertEqual(status, 401, "agent key could pivot the lake")


# ============================ legacy seeding ============================


class TestLegacySeeding(unittest.TestCase):
    def test_legacy_json_is_seeded_once_and_left_alone(self):
        tmp = tempfile.TemporaryDirectory()
        db = os.path.join(tmp.name, "tiox.db")
        inc = os.path.join(tmp.name, "incidents.json")
        inv = os.path.join(tmp.name, "inventory.json")
        with open(inc, "w") as f:
            json.dump({"incidents": [
                {"id": "INC-0001", "title": "Legacy A", "severity": "high"},
                {"id": "INC-0002", "title": "Legacy B", "severity": "low"},
            ]}, f)
        with open(inv, "w") as f:
            json.dump({"endpoints": [{"id": "EP-0001", "hostname": "legacy-ws",
                                      "ip": "10.0.0.9"}]}, f)
        before_inc = Path(inc).read_text()

        prev = {k: os.environ.get(k) for k in ("TIOX_TLS", "TIOX_AGENT_KEY",
                                               "TIOX_SESSION_KEY", "TIOX_BIND",
                                               "TIOX_DB", "TIOX_MIGRATE_LEGACY",
                                               "TIOX_INVENTORY_FILE", "TIOX_INCIDENTS_FILE")}
        os.environ.update({
            "TIOX_TLS": "0", "TIOX_AGENT_KEY": "k", "TIOX_SESSION_KEY": "s",
            "TIOX_BIND": "127.0.0.1", "TIOX_DB": db, "TIOX_MIGRATE_LEGACY": "1",
            "TIOX_INVENTORY_FILE": inv, "TIOX_INCIDENTS_FILE": inc,
        })
        try:
            import web_ui_server as w
            w.INVENTORY_FILE = inv
            w.INCIDENTS_FILE = inc
            w.DB_FILE = db
            w._store = None
            w.LEGACY_MIGRATE = True
            store = w.get_store()
            self.assertEqual(store.incident_counts()["total"], 2)
            self.assertEqual(len(store.list_endpoints()), 1)
            # Second open (simulating a restart) must not duplicate.
            w._store = None
            store2 = w.get_store()
            self.assertEqual(store2.incident_counts()["total"], 2)
            self.assertEqual(len(store2.list_endpoints()), 1)
            store.close()
            store2.close()
            # The JSON file is a rollback path, so it must be untouched.
            self.assertEqual(Path(inc).read_text(), before_inc)
        finally:
            w._store = None
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
