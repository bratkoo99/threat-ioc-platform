#!/usr/bin/env python3
"""
IOC Scanner Web UI Server
Real-time threat scanning dashboard with SSE progress updates
Features: Scan control, Agent sync, Inventory, Incidents/Alarms
"""

import http.server
import socketserver
import subprocess
import threading
import json
import os
import sys
import time
import re
import hmac
import base64
import hashlib
import secrets
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

PORT = 8443

# --- TLS ------------------------------------------------------------------
# 8443 is conventionally HTTPS. The previous version bound that port over
# PLAINTEXT with no ssl import anywhere, so the agent key and every scan report
# crossed the network in the clear while looking encrypted. TLS is now explicit
# and on by default; the flag exists only for a loopback-only dev session.
TLS_ENABLED = os.environ.get("TIOX_TLS", "1") not in ("0", "false", "no")
CERT_FILE = os.environ.get("TIOX_CERT", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "certs", "server.pem"))
KEY_FILE = os.environ.get("TIOX_KEY", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "certs", "server.key"))
BIND_HOST = os.environ.get("TIOX_BIND", "127.0.0.1")  # not 0.0.0.0 by default
PLATFORM_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_BIN = os.path.join(PLATFORM_DIR, "ioc_scanner")
IOC_DB_DIR = os.path.join(PLATFORM_DIR, "ioc_databases")
REPORT_DIR = os.path.join(PLATFORM_DIR, "reports")
LOG_DIR = os.path.join(PLATFORM_DIR, "logs")
AGENT_KEY_FILE = os.path.join(PLATFORM_DIR, ".agent_key")
INVENTORY_FILE = os.path.join(PLATFORM_DIR, "inventory.json")
INCIDENTS_FILE = os.path.join(PLATFORM_DIR, "incidents.json")

# --- Auth ----------------------------------------------------------------
# There was no authentication anywhere in this file. GET /api/agent/key handed
# the agent key to any caller that reached the port, and every /api/* endpoint
# (scan control, incident mutation, endpoint registration) was open. Now:
#   * two credentials, so a leaked agent key cannot read the UI or mutate state
#   * constant-time comparison, so the key cannot be recovered by timing
#   * /api/agent/key is itself protected, which is the point
#   * auth is enforced on the request handler, so a new endpoint is covered by
#     default rather than by remembering to guard it

AGENT_KEY = os.environ.get("TIOX_AGENT_KEY", "")
SESSION_KEY = os.environ.get("TIOX_SESSION_KEY", "")

# Endpoints that must work before any credential exists (bootstrap only).
PUBLIC_PATHS = {"/", "/index.html", "/style.css", "/app.js", "/api/status"}

# Agent-facing endpoints authenticate with the agent key.
AGENT_PATHS = ("/api/agent/register", "/api/agent/heartbeat", "/api/agent/scan")

# Name of the browser session cookie set by /api/login.
SESSION_COOKIE = "tiox_session"
COOKIE_MAX_AGE = 28800  # 8h, matching a working day for an analyst


def ensure_key_file(path, existing=""):
    """Load a key from env or the on-disk file, generating one if needed."""
    if existing:
        return existing
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


def _const_eq(a, b):
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


AGENT_KEY = ensure_key_file(AGENT_KEY_FILE, AGENT_KEY)
SESSION_KEY = SESSION_KEY or secrets.token_urlsafe(32)

# Global scan state
scan_state = {
    "running": False,
    "files_scanned": 0,
    "dirs_scanned": 0,
    "threats_found": 0,
    "errors": 0,
    "current_file": "",
    "threats": [],
    "start_time": None,
    "end_time": None,
    "scan_path": "",
    "process": None,
    "progress": 0,
    "status": "idle"
}

# SSE clients
sse_clients = []
sse_lock = threading.Lock()


def sanitize_string(s):
    """Remove potentially dangerous characters from strings"""
    if not s:
        return ""
    # Remove null bytes
    s = s.replace('\x00', '')
    # Limit length
    return s[:256]


def validate_path(path):
    """Validate and sanitize file path"""
    if not path:
        return "/"
    # Remove null bytes
    path = path.replace('\x00', '')
    # Resolve to absolute path
    path = os.path.abspath(path)
    # Limit length
    if len(path) > 4096:
        path = path[:4096]
    return path


def load_json(path, default=None):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default if default is not None else {}


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_inventory():
    return load_json(INVENTORY_FILE, {"endpoints": [], "total": 0})


def save_inventory(inv):
    save_json(INVENTORY_FILE, inv)


def get_incidents():
    return load_json(INCIDENTS_FILE, {"incidents": [], "total": 0, "open": 0, "critical": 0})


def save_incidents(inc):
    save_json(INCIDENTS_FILE, inc)


def add_incident(incident):
    inc = get_incidents()
    incident["id"] = f"INC-{len(inc['incidents'])+1:04d}"
    incident["created"] = datetime.now().isoformat()
    incident["status"] = "open"
    inc["incidents"].insert(0, incident)
    inc["total"] = len(inc["incidents"])
    inc["open"] = sum(1 for i in inc["incidents"] if i["status"] == "open")
    inc["critical"] = sum(1 for i in inc["incidents"] if i.get("severity") == "critical" and i["status"] == "open")
    save_incidents(inc)
    return incident


def send_sse_event(event, data):
    """Send SSE event to all connected clients"""
    # Make a copy to avoid modifying the original
    data_copy = {k: v for k, v in data.items() if k != "process"}
    with sse_lock:
        dead = []
        for i, client in enumerate(sse_clients):
            try:
                client.write(f"event: {event}\n")
                client.write(f"data: {json.dumps(data_copy)}\n\n")
                client.flush()
            except Exception:
                dead.append(i)
        for i in reversed(dead):
            sse_clients.pop(i)


def parse_scanner_output(line):
    threat_match = re.match(r'\[!!!\]\s*THREAT DETECTED', line)
    if threat_match:
        scan_state["threats"].append({
            "file": "", "type": "", "family": "", "details": "", "hash": "",
            "time": datetime.now().isoformat()
        })
        scan_state["threats_found"] += 1
        return

    file_match = re.match(r'\[SCAN\]\s*(.+)', line)
    if file_match:
        scan_state["current_file"] = file_match.group(1)
        scan_state["files_scanned"] += 1
        return

    verbose_match = re.match(r'\[OK\]\s*(.+)', line)
    if verbose_match:
        scan_state["current_file"] = verbose_match.group(1)
        scan_state["files_scanned"] += 1
        return

    if scan_state["threats"]:
        last = scan_state["threats"][-1]
        if "Path:" in line:
            last["file"] = line.split("Path:", 1)[1].strip()
        elif "Match:" in line:
            last["type"] = line.split("Match:", 1)[1].strip()
        elif "Family:" in line:
            last["family"] = line.split("Family:", 1)[1].strip()
        elif "Details:" in line:
            last["details"] = line.split("Details:", 1)[1].strip()
        elif "SHA-256:" in line:
            last["hash"] = line.split("SHA-256:", 1)[1].strip()

    scanned_match = re.match(r'\s*Files scanned:\s*(\d+)', line)
    if scanned_match:
        scan_state["files_scanned"] = int(scanned_match.group(1))
    dirs_match = re.match(r'\s*Directories scanned:\s*(\d+)', line)
    if dirs_match:
        scan_state["dirs_scanned"] = int(dirs_match.group(1))
    threats_match = re.match(r'\s*Threats found:\s*(\d+)', line)
    if threats_match:
        scan_state["threats_found"] = int(threats_match.group(1))
    errors_match = re.match(r'\s*Errors:\s*(\d+)', line)
    if errors_match:
        scan_state["errors"] = int(errors_match.group(1))


def run_scan(scan_path, quick_mode=False, agent_id=None):
    global scan_state
    if scan_state["running"]:
        return False

    scan_state = {
        "running": True, "files_scanned": 0, "dirs_scanned": 0,
        "threats_found": 0, "errors": 0, "current_file": "",
        "threats": [], "start_time": datetime.now().isoformat(),
        "end_time": None, "scan_path": scan_path,
        "process": None, "progress": 0, "status": "scanning",
        "agent_id": agent_id
    }
    send_sse_event("scan_start", scan_state)

    def scan_thread():
        global scan_state
        try:
            flags = ["-v"]
            if quick_mode:
                flags = ["-Q", "-v"]
            cmd = [SCANNER_BIN] + flags + [scan_path]
            scan_state["process"] = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            for line in scan_state["process"].stdout:
                line = line.rstrip()
                parse_scanner_output(line)
                send_sse_event("progress", scan_state)
            scan_state["process"].wait()
            scan_state["status"] = "completed"
            scan_state["end_time"] = datetime.now().isoformat()
            scan_state["progress"] = 100

            # Auto-create incidents for threats
            for threat in scan_state["threats"]:
                if threat.get("file"):
                    add_incident({
                        "title": f"Threat: {threat.get('family', 'Unknown')}",
                        "description": f"Detected {threat.get('type', 'unknown match')} in {threat['file']}",
                        "severity": "critical" if threat.get("type") == "Known malicious hash" else "high",
                        "source": agent_id or "local",
                        "type": "malware",
                        "details": threat
                    })
        except Exception as e:
            scan_state["status"] = "error"
            scan_state["end_time"] = datetime.now().isoformat()
            scan_state["error"] = str(e)
        finally:
            scan_state["running"] = False
            send_sse_event("scan_complete", scan_state)

    thread = threading.Thread(target=scan_thread, daemon=True)
    thread.start()
    return True


class Handler(http.server.SimpleHTTPRequestHandler):
    # --- authentication ---

    @property
    def is_https(self):
        """True when this request arrived over TLS. Used to set Secure on cookies."""
        import ssl

        return isinstance(self.connection, ssl.SSLSocket)

    def _presented_key(self):
        """
        Extract a bearer token from the Authorization header, X-API-Key, or the
        session cookie.

        The cookie exists because EventSource cannot set request headers, so the
        dashboard's live event stream would otherwise be the one authenticated
        request with no way to carry a credential.
        """
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        if auth.lower().startswith("token "):
            return auth[6:].strip()
        hdr = self.headers.get("X-API-Key", "").strip()
        if hdr:
            return hdr
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, val = part.strip().partition("=")
            if name == SESSION_COOKIE and val:
                return val.strip()
        return ""

    def is_authorized(self, path):
        """
        Central auth gate. Called at the top of do_GET/do_POST so that a newly
        added endpoint is protected by default instead of relying on the author
        remembering to guard it. Public routes are an explicit allowlist.
        """
        if path in PUBLIC_PATHS or path == "/api/login":
            return True
        presented = self._presented_key()
        if not presented:
            return False
        if path in AGENT_PATHS:
            return _const_eq(presented, AGENT_KEY)
        # Everything else needs the session key; the agent key is not enough, so
        # a compromised endpoint cannot read the dashboard or mutate incidents.
        return _const_eq(presented, SESSION_KEY)

    def require_auth(self, path):
        if self.is_authorized(path):
            return True
        self.send_json({
            "error": "Unauthorized",
            "hint": "Send 'Authorization: Bearer <key>'. "
                    "Agent key for /api/agent/*, session key for everything else.",
        }, 401)
        return False

    def do_GET(self):
        global scan_state
        parsed = urlparse(self.path)

        if not self.require_auth(parsed.path):
            return

        if parsed.path in ("/", "/index.html"):
            self.serve_file("index.html", "text/html")
        elif parsed.path == "/api/logout":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
            )
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
        elif parsed.path == "/style.css":
            self.serve_file("style.css", "text/css")
        elif parsed.path == "/app.js":
            self.serve_file("app.js", "application/javascript")
        elif parsed.path == "/api/status":
            self.send_json(scan_state)
        elif parsed.path == "/api/events":
            self.handle_sse()
        elif parsed.path == "/api/databases":
            self.list_databases()
        elif parsed.path == "/api/reports":
            self.list_reports()
        elif parsed.path == "/api/inventory":
            self.send_json(get_inventory())
        elif parsed.path == "/api/incidents":
            self.send_json(get_incidents())
        elif parsed.path == "/api/incidents/recent":
            inc = get_incidents()
            self.send_json({"incidents": inc["incidents"][:10], "total": inc["total"]})
        elif parsed.path == "/api/agent/key":
            # Requires the session key: handing the agent key to anyone who can
            # reach the port let them register a rogue endpoint and request scans.
            # Deliver it once, to an operator who already has admin.
            self.send_json({"key": AGENT_KEY})
        elif parsed.path == "/api/agent/script":
            self.serve_agent_script(tls=TLS_ENABLED)
        elif parsed.path == "/api/stats":
            self.send_stats()
        else:
            self.send_error(404)

    def do_POST(self):
        global scan_state
        parsed = urlparse(self.path)

        if not self.require_auth(parsed.path):
            return

        if parsed.path == "/api/login":
            # Exchange the session key for a cookie. The dashboard's JS cannot set
            # headers on an EventSource, and repeatedly embedding a bearer token in
            # page JS is worse, so the browser holds a cookie instead.
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            if not _const_eq(str(data.get("key", "")), SESSION_KEY):
                self.send_json({"error": "Invalid credentials"}, 401)
                return
            secure = "; Secure" if self.is_https else ""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={SESSION_KEY}; HttpOnly; Path=/; "
                f"Max-Age={COOKIE_MAX_AGE}; SameSite=Strict{secure}",
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif parsed.path == "/api/scan/start":
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                params = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            scan_path = validate_path(params.get("path", "/"))
            quick_mode = params.get("quick", False)
            agent_id = params.get("agent_id")
            if scan_state["running"]:
                self.send_json({"error": "Scan already running"}, 409)
            else:
                success = run_scan(scan_path, quick_mode, agent_id)
                self.send_json({"started": success})

        elif parsed.path == "/api/scan/stop":
            if scan_state["running"] and scan_state["process"]:
                try:
                    scan_state["process"].terminate()
                except ProcessLookupError:
                    pass
                scan_state["running"] = False
                scan_state["status"] = "stopped"
                send_sse_event("scan_stopped", scan_state)
                self.send_json({"stopped": True})
            else:
                self.send_json({"error": "No scan running"}, 400)

        elif parsed.path == "/api/scan/reset":
            if not scan_state["running"]:
                scan_state = {
                    "running": False, "files_scanned": 0, "dirs_scanned": 0,
                    "threats_found": 0, "errors": 0, "current_file": "",
                    "threats": [], "start_time": None, "end_time": None,
                    "scan_path": "", "process": None, "progress": 0, "status": "idle"
                }
                self.send_json({"reset": True})
            else:
                self.send_json({"error": "Scan in progress"}, 409)

        elif parsed.path == "/api/agent/register":
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            inv = get_inventory()
            endpoint = {
                "id": f"EP-{len(inv['endpoints'])+1:04d}",
                "hostname": sanitize_string(data.get("hostname", "unknown")),
                "ip": sanitize_string(data.get("ip", self.client_address[0])),
                "os": sanitize_string(data.get("os", "unknown")),
                "version": sanitize_string(data.get("version", "1.0")),
                "status": "online",
                "last_seen": datetime.now().isoformat(),
                "registered": datetime.now().isoformat(),
                "scan_count": 0,
                "threats_found": 0
            }
            inv["endpoints"].append(endpoint)
            inv["total"] = len(inv["endpoints"])
            save_inventory(inv)
            add_incident({
                "title": f"Agent registered: {endpoint['hostname']}",
                "description": f"New endpoint {endpoint['hostname']} ({endpoint['ip']}) registered",
                "severity": "info",
                "source": "system",
                "type": "agent"
            })
            self.send_json(endpoint)

        elif parsed.path == "/api/agent/heartbeat":
            body = self.read_body()
            data = json.loads(body) if body else {}
            inv = get_inventory()
            for ep in inv["endpoints"]:
                if ep["id"] == data.get("agent_id"):
                    ep["last_seen"] = datetime.now().isoformat()
                    ep["status"] = "online"
                    ep["ip"] = data.get("ip", ep["ip"])
                    break
            save_inventory(inv)
            self.send_json({"ok": True})

        elif parsed.path == "/api/agent/scan":
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            agent_id = data.get("agent_id")
            inv = get_inventory()
            ep = next((e for e in inv["endpoints"] if e["id"] == agent_id), None)
            if not ep:
                self.send_json({"error": "Agent not found"}, 404)
                return
            scan_path = validate_path(data.get("path", "/"))
            quick_mode = data.get("quick", False)
            if scan_state["running"]:
                self.send_json({"error": "Scan already running"}, 409)
            else:
                success = run_scan(scan_path, quick_mode, agent_id)
                if success:
                    ep["scan_count"] = ep.get("scan_count", 0) + 1
                    save_inventory(inv)
                self.send_json({"started": success})

        elif parsed.path == "/api/incidents/update":
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            # Sanitize note
            if "note" in data:
                data["note"] = sanitize_string(data["note"])
            inc = get_incidents()
            for i in inc["incidents"]:
                if i["id"] == data.get("id"):
                    i["status"] = data.get("status", i["status"])
                    i["updated"] = datetime.now().isoformat()
                    if data.get("note"):
                        i.setdefault("notes", []).append({
                            "text": data["note"],
                            "time": datetime.now().isoformat()
                        })
                    break
            inc["open"] = sum(1 for i in inc["incidents"] if i["status"] == "open")
            inc["critical"] = sum(1 for i in inc["incidents"] if i.get("severity") == "critical" and i["status"] == "open")
            save_incidents(inc)
            self.send_json({"ok": True})

        elif parsed.path == "/api/incidents/create":
            body = self.read_body()
            if body is None:
                self.send_json({"error": "Request too large"}, 413)
                return
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            # Sanitize string inputs
            for key in ["title", "description", "source"]:
                if key in data:
                    data[key] = sanitize_string(data[key])
            inc = add_incident(data)
            send_sse_event("new_incident", inc)
            self.send_json(inc)

        else:
            self.send_error(404)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        # Limit body size to 1MB to prevent DoS
        if length > 1048576:
            return None
        return self.rfile.read(length) if length > 0 else b""

    def serve_file(self, filename, content_type):
        filepath = os.path.join(PLATFORM_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404)

    def send_json(self, data, code=200):
        # Remove non-serializable items
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k != "process"}
        response = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response)

    def handle_sse(self):
        global scan_state
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        # Was "*", which let any page on the internet open an event stream against
        # this server. Same-origin only; the dashboard is served by this host.
        self.send_header("Access-Control-Allow-Origin", f"https://{self.headers.get('Host', 'localhost')}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with sse_lock:
            sse_clients.append(self.wfile)
        try:
            # Remove non-serializable process object
            state_copy = {k: v for k, v in scan_state.items() if k != "process"}
            self.wfile.write(f"event: connected\n")
            self.wfile.write(f"data: {json.dumps(state_copy)}\n\n")
            self.wfile.flush()
            while True:
                time.sleep(1)
                self.wfile.write(f": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with sse_lock:
                if self.wfile in sse_clients:
                    sse_clients.remove(self.wfile)

    def serve_agent_script(self, tls=True):
        script = self.generate_agent_script(tls=tls)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(script))
        self.end_headers()
        self.wfile.write(script.encode())

    def generate_agent_script(self, tls=True):
        return f'''#!/usr/bin/env bash
# IOC Scanner Agent - Remote endpoint agent
# Install on servers to enable remote scanning from main platform

AGENT_KEY="{AGENT_KEY}"
SERVER_URL="${{SERVER_URL:-{'https' if tls else 'http'}://${{TIOX_HOST:-127.0.0.1}}:{PORT}}}"
AGENT_ID=""
LOG_FILE="/var/log/ioc_agent.log"
SCAN_DIR="/"
# Skip TLS verification: the platform ships a self-signed cert. Remove this
# once you have a real CA-signed cert, because with -k on there is no protection
# against an active network attacker on this hop.
CURL_OPTS="--insecure -sf"

log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}}

api() {{
    # All /api/agent/* calls carry the agent key. Without this header the server
    # returns 401; the previous agent script sent nothing and relied on the
    # server having no authentication at all.
    local path="$1"; shift
    curl $CURL_OPTS -X POST "$SERVER_URL$path" \\
        -H "Authorization: Bearer $AGENT_KEY" \\
        -H "Content-Type: application/json" \\
        "$@"
}}

get_hostname() {{
    hostname 2>/dev/null || echo "unknown"
}}

get_os() {{
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$NAME $VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    else
        uname -s -r
    fi
}}

get_ip() {{
    ip route get 1.1.1.1 2>/dev/null | awk '{{print $7; exit}}' || hostname -I | awk '{{print $1}}'
}}

register() {{
    log "Registering agent with server: $SERVER_URL"
    local payload
    payload=$(cat <<EOF
{{"hostname":"$(get_hostname)","ip":"$(get_ip)","os":"$(get_os)","version":"1.0"}}
EOF
)
    local response
    response=$(api /api/agent/register -d "$payload" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        AGENT_ID=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
        echo "$AGENT_ID" > /etc/ioc_agent.id
        log "Registered as agent: $AGENT_ID"
        return 0
    else
        log "Registration failed"
        return 1
    fi
}}

heartbeat() {{
    [ -z "$AGENT_ID" ] && return
    api /api/agent/heartbeat \\
        -d "{{\\"agent_id\\":\\"$AGENT_ID\\",\\"ip\\":\\"$(get_ip)\\"}}" \\
        --connect-timeout 5 --max-time 10 > /dev/null 2>&1 || true
}}

do_scan() {{
    local path="${{1:-/}}"
    local quick="${{2:-false}}"
    log "Starting scan of $path (quick=$quick)"
    
    local scanner="/usr/local/bin/ioc_scanner"
    if [ ! -f "$scanner" ]; then
        scanner="$(dirname "$0")/ioc_scanner"
    fi
    
    if [ ! -f "$scanner" ]; then
        log "Scanner binary not found"
        return 1
    fi
    
    local flags="-v"
    [ "$quick" = "true" ] && flags="-Q -v"
    
    local threats=0
    local scanned=0
    while IFS= read -r line; do
        if [[ "$line" == *"THREAT DETECTED"* ]]; then
            threats=$((threats + 1))
        fi
        if [[ "$line" == "[OK]"* ]] || [[ "$line" == "[SCAN]"* ]]; then
            scanned=$((scanned + 1))
        fi
    done < <($scanner $flags "$path" 2>&1)
    
    log "Scan complete: $scanned files scanned, $threats threats found"
    
    # Report results
    api /api/agent/heartbeat \\
        -d "{{\\"agent_id\\":\\"$AGENT_ID\\",\\"last_scan\\":\\"$(date -Iseconds)\\",\\"threats\\":$threats}}" \\
        --connect-timeout 5 --max-time 10 > /dev/null 2>&1 || true
}}

# Main
[ -f /etc/ioc_agent.id ] && AGENT_ID=$(cat /etc/ioc_agent.id)

case "${{1:-run}}" in
    register) register ;;
    heartbeat) heartbeat ;;
    scan) do_scan "${{2:-/}}" "${{3:-false}}" ;;
    run)
        register
        while true; do
            heartbeat
            sleep 60
        done
        ;;
    *) echo "Usage: $0 {{register|heartbeat|scan|run}}" ;;
esac
'''

    def list_databases(self):
        dbs = []
        if os.path.exists(IOC_DB_DIR):
            for f in os.listdir(IOC_DB_DIR):
                if f.endswith(".csv"):
                    filepath = os.path.join(IOC_DB_DIR, f)
                    dbs.append({
                        "name": f, "size": os.path.getsize(filepath),
                        "entries": sum(1 for _ in open(filepath)) - 1
                    })
        self.send_json(dbs)

    def list_reports(self):
        reports = []
        if os.path.exists(REPORT_DIR):
            for f in os.listdir(REPORT_DIR):
                filepath = os.path.join(REPORT_DIR, f)
                reports.append({
                    "name": f, "size": os.path.getsize(filepath),
                    "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
        self.send_json(reports)

    def send_stats(self):
        global scan_state
        inv = get_inventory()
        inc = get_incidents()
        stats = {
            "endpoints": inv.get("total", 0),
            "endpoints_online": sum(1 for e in inv.get("endpoints", []) if e["status"] == "online"),
            "incidents_total": inc.get("total", 0),
            "incidents_open": inc.get("open", 0),
            "incidents_critical": inc.get("critical", 0),
            "threats_total": sum(e.get("threats_found", 0) for e in inv.get("endpoints", [])),
            "scans_total": sum(e.get("scan_count", 0) for e in inv.get("endpoints", [])),
            "databases": len(os.listdir(IOC_DB_DIR)) if os.path.exists(IOC_DB_DIR) else 0,
            "reports": len(os.listdir(REPORT_DIR)) if os.path.exists(REPORT_DIR) else 0
        }
        self.send_json(stats)

    def log_message(self, format, *args):
        pass


class ThreadedHTTPSServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_server():
    """
    Create the server, wrapping the socket in TLS when enabled.

    Raises RuntimeError with an actionable message if TLS is on but no cert
    exists, rather than silently falling back to cleartext on port 8443.
    """
    httpd = ThreadedHTTPSServer((BIND_HOST, PORT), Handler)

    if not TLS_ENABLED:
        print("  [!] TLS DISABLED (TIOX_TLS=0) - traffic is cleartext.")
        print("      Only acceptable for a loopback dev session.")
        return httpd, False

    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        httpd.server_close()
        raise RuntimeError(
            f"TLS is enabled but no certificate found.\n"
            f"  expected cert: {CERT_FILE}\n"
            f"  expected key:  {KEY_FILE}\n\n"
            f"Generate a self-signed pair:\n"
            f"  mkdir -p {os.path.dirname(CERT_FILE)}\n"
            f"  openssl req -x509 -newkey rsa:4096 -nodes -days 365 \\\n"
            f"    -keyout {KEY_FILE} -out {CERT_FILE} \\\n"
            f"    -subj '/CN=threat-platform'\n\n"
            f"Or set TIOX_CERT / TIOX_KEY to an existing pair.\n"
            f"To run in cleartext for local dev only, set TIOX_TLS=0."
        )

    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd, True


def main():
    for d in (IOC_DB_DIR, REPORT_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)

    if not os.path.exists(SCANNER_BIN):
        print(f"[!] Scanner binary not found: {SCANNER_BIN}")
        print("[!] Compile it first: make")
        print()

    try:
        httpd, tls = build_server()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1

    scheme = "https" if tls else "http"
    with httpd:
        print("  IOC Scanner Web UI Dashboard")
        print(f"  Platform:  {PLATFORM_DIR}")
        print(f"  Binding:   {BIND_HOST}:{PORT} ({scheme})")
        print(f"  Open:      {scheme}://{BIND_HOST}:{PORT}")
        if tls:
            print("  Note:      self-signed cert -> your browser will warn once.")
        print()
        print("  Credentials (printed once; the session key is not persisted):")
        print(f"    session key: {SESSION_KEY}")
        print(f"    agent key:   {AGENT_KEY}   (.agent_key, mode 0600)")
        print()
        print("  Use:  curl -H 'Authorization: Bearer <session key>' \\")
        print("             http://<host>:<port>/api/status")
        print()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Shutting down...")
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
