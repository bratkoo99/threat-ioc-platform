"""
Auth tests for web_ui_server.

These exist because the previous server had no authentication at all and the
dashboard's own JS never sent a key. The tests boot a real server on an ephemeral
port and make real requests, so a regression in the wiring (rather than just in
a helper function) fails here.

Run:  python3 -m unittest tests.test_auth -v
"""

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


class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import with TLS off and a throwaway key file so the test never touches
        # the real .agent_key, then run on an ephemeral port.
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["TIOX_TLS"] = "0"
        os.environ["TIOX_AGENT_KEY"] = "test-agent-key-0123456789"
        os.environ["TIOX_SESSION_KEY"] = "test-session-key-9876543210"
        os.environ["TIOX_BIND"] = "127.0.0.1"

        cls.server = importlib.import_module("web_ui_server")
        # Port 0 lets the OS pick, so a stale 8443 cannot collide with a real run.
        cls.server.PORT = 0
        httpd, _ = cls.server.build_server()
        cls.port = httpd.server_address[1]
        cls.httpd = httpd
        cls.thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    # ---------- helpers ----------

    def request(self, method, path, key=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, payload, headers)
            resp = conn.getresponse()
            data = resp.read().decode(errors="replace")
            return resp.status, data
        finally:
            conn.close()

    AGENT = "test-agent-key-0123456789"
    SESSION = "test-session-key-9876543210"

    # ---------- the vulnerability itself ----------

    def test_agent_key_endpoint_requires_session_key(self):
        """The old code returned the agent key to anyone who asked."""
        status, _ = self.request("GET", "/api/agent/key")
        self.assertEqual(status, 401, "agent key leaked to unauthenticated caller")

        status, _ = self.request("GET", "/api/agent/key", key=self.AGENT)
        self.assertEqual(status, 401, "agent key leaked to holder of agent key")

        status, body = self.request("GET", "/api/agent/key", key=self.SESSION)
        self.assertEqual(status, 200)
        self.assertIn("key", json.loads(body))

    def test_protected_endpoints_reject_anonymous(self):
        for path in ("/api/incidents", "/api/inventory", "/api/stats",
                     "/api/agent/key", "/api/agent/script", "/api/reports"):
            with self.subTest(path=path):
                status, _ = self.request("GET", path)
                self.assertEqual(status, 401, f"{path} served without auth")

    def test_state_mutating_posts_reject_anonymous(self):
        for path, body in (
            ("/api/scan/start", {"path": "/tmp"}),
            ("/api/incidents/create", {"title": "pwned"}),
            ("/api/incidents/update", {"id": "INC-0001", "status": "closed"}),
            ("/api/agent/register", {"hostname": "evil"}),
        ):
            with self.subTest(path=path):
                status, _ = self.request("POST", path, body=body)
                self.assertEqual(status, 401, f"{path} accepted an unauthenticated write")

    # ---------- credential separation ----------

    def test_agent_key_cannot_reach_operator_endpoints(self):
        for path in ("/api/incidents", "/api/inventory", "/api/agent/key"):
            with self.subTest(path=path):
                status, _ = self.request("GET", path, key=self.AGENT)
                self.assertEqual(status, 401, f"{path} accepted the agent key")

    def test_agent_key_works_for_agent_endpoints(self):
        status, body = self.request(
            "POST", "/api/agent/register", key=self.AGENT,
            body={"hostname": "unit-test-host", "ip": "10.1.2.3", "os": "test"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["hostname"], "unit-test-host")

    def test_session_key_works_for_operator_endpoints(self):
        status, _ = self.request("GET", "/api/incidents", key=self.SESSION)
        self.assertEqual(status, 200)

    def test_session_key_is_not_accepted_for_agent_only_surface(self):
        """The agent surface should require the agent credential specifically."""
        # /api/agent/* is agent-scoped; the session key must not substitute for it.
        status, _ = self.request(
            "POST", "/api/agent/register", key=self.SESSION,
            body={"hostname": "x"},
        )
        self.assertEqual(status, 401)

    # ---------- key handling ----------

    def test_wrong_key_rejected(self):
        status, _ = self.request("GET", "/api/incidents", key="wrong-key")
        self.assertEqual(status, 401)

    def test_empty_key_rejected(self):
        status, _ = self.request("GET", "/api/incidents", key="")
        self.assertEqual(status, 401)

    def test_prefix_of_real_key_rejected(self):
        """Guards against a non-constant-time or prefix comparison."""
        status, _ = self.request("GET", "/api/incidents", key=self.SESSION[:-1])
        self.assertEqual(status, 401)

    def test_x_api_key_header_accepted(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/api/incidents", headers={"X-API-Key": self.SESSION})
            self.assertEqual(conn.getresponse().status, 200)
        finally:
            conn.close()

    def test_public_paths_remain_reachable(self):
        """The login page and assets must load without a credential."""
        for path in ("/", "/index.html", "/api/status"):
            with self.subTest(path=path):
                status, _ = self.request("GET", path)
                self.assertEqual(status, 200, f"{path} should be public")

    def test_unknown_path_still_requires_auth(self):
        status, _ = self.request("GET", "/api/does-not-exist")
        self.assertEqual(status, 401)


class TestLoginFlow(unittest.TestCase):
    """POST /api/login exchanges the session key for a cookie the JS can rely on."""

    @classmethod
    def setUpClass(cls):
        cls._prev = {k: os.environ.get(k) for k in
                     ("TIOX_TLS", "TIOX_AGENT_KEY", "TIOX_SESSION_KEY", "TIOX_BIND")}
        os.environ["TIOX_TLS"] = "0"
        os.environ["TIOX_AGENT_KEY"] = "test-agent-key-0123456789"
        os.environ["TIOX_SESSION_KEY"] = "test-session-key-9876543210"
        os.environ["TIOX_BIND"] = "127.0.0.1"
        cls.server = importlib.import_module("web_ui_server")
        cls.server.PORT = 0
        httpd, _ = cls.server.build_server()
        cls.port = httpd.server_address[1]
        cls.httpd = httpd
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for k, v in cls._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _login(self, key):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            body = json.dumps({"key": key})
            conn.request("POST", "/api/login", body,
                         {"Content-Type": "application/json"})
            res = conn.getresponse()
            return res.status, res.getheader("Set-Cookie"), res.read()
        finally:
            conn.close()

    def _get_with_cookie(self, path, cookie):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers={"Cookie": cookie})
            res = conn.getresponse()
            return res.status
        finally:
            conn.close()

    SESSION = "test-session-key-9876543210"

    def test_login_with_correct_key_sets_cookie(self):
        status, set_cookie, _ = self._login(self.SESSION)
        self.assertEqual(status, 200)
        self.assertIn("tiox_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)

    def test_login_with_wrong_key_rejected(self):
        status, set_cookie, _ = self._login("not-the-key")
        self.assertEqual(status, 401)
        self.assertIsNone(set_cookie)

    def test_login_with_empty_key_rejected(self):
        status, _, _ = self._login("")
        self.assertEqual(status, 401)

    def test_agent_key_cannot_log_in_to_dashboard(self):
        status, _, _ = self._login("test-agent-key-0123456789")
        self.assertEqual(status, 401)

    def test_cookie_authenticates_subsequent_request(self):
        _, set_cookie, _ = self._login(self.SESSION)
        cookie = set_cookie.split(";")[0]
        self.assertEqual(self._get_with_cookie("/api/incidents", cookie), 200)

    def test_no_cookie_still_rejected(self):
        self.assertEqual(self._get_with_cookie("/api/incidents", "other=1"), 401)

    def test_logout_clears_cookie(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/api/logout", headers={
                "Authorization": f"Bearer {self.SESSION}"})
            res = conn.getresponse()
            res.read()
            self.assertEqual(res.status, 200)
            self.assertIn("Max-Age=0", res.getheader("Set-Cookie"))
        finally:
            conn.close()


class TestTlsConfiguration(unittest.TestCase):
    def test_tls_refuses_to_silently_fall_back(self):
        """Missing cert must be a hard error, not a cleartext listener on 8443."""
        prev = {k: os.environ.get(k) for k in ("TIOX_TLS", "TIOX_CERT", "TIOX_KEY", "TIOX_BIND")}
        try:
            import importlib

            os.environ["TIOX_TLS"] = "1"
            os.environ["TIOX_CERT"] = "/nonexistent/cert.pem"
            os.environ["TIOX_KEY"] = "/nonexistent/key.pem"
            os.environ["TIOX_BIND"] = "127.0.0.1"
            mod = importlib.reload(importlib.import_module("web_ui_server"))
            mod.PORT = 0
            with self.assertRaises(RuntimeError) as ctx:
                mod.build_server()
            self.assertIn("TLS is enabled", str(ctx.exception))
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            import importlib

            importlib.reload(importlib.import_module("web_ui_server"))

    def test_tls_default_is_on(self):
        """Cleartext must require an explicit opt-out, not be the default."""
        self.assertIn("TIOX_TLS", os.environ.get("_unused", "TIOX_TLS"))
        import importlib

        prev = os.environ.pop("TIOX_TLS", None)
        try:
            mod = importlib.reload(importlib.import_module("web_ui_server"))
            self.assertTrue(mod.TLS_ENABLED, "TLS must default to enabled")
        finally:
            if prev is not None:
                os.environ["TIOX_TLS"] = prev
            import importlib

            importlib.reload(importlib.import_module("web_ui_server"))


class TestKeyFilePermissions(unittest.TestCase):
    def test_generated_key_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".agent_key"
            key = self._load(p)
            mode = p.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, f"key file is {oct(mode)}, expected 0o600")
            self.assertTrue(key)

    def _load(self, path):
        # Exercise ensure_key_file directly rather than reloading the module.
        from web_ui_server import ensure_key_file

        return ensure_key_file(str(path))

    def test_existing_key_is_reused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".agent_key"
            p.write_text("preexisting-key")
            os.chmod(p, 0o600)
            from web_ui_server import ensure_key_file

            self.assertEqual(ensure_key_file(str(p)), "preexisting-key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
