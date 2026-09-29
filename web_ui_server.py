#!/usr/bin/env python3
"""
IOC Scanner Web UI Server
Real-time threat scanning dashboard with SSE progress updates
Features: Scan control, Agent sync, Inventory, Incidents/Alarms

Phase 0.6: this server now reads and writes the tiox control plane (SQLite) and
ingests every agent observation into the event lake through the connector
pipeline. The old incidents.json / inventory.json files are still read once at
startup to seed a fresh database, then left untouched as a rollback path.
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
import logging
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tiox.store.control import ControlPlane
from tiox.correlation import Correlator
from tiox.store.pipeline import (
    IngestResult,
    get_detection_engine,
    ingest,
    invalidate_detection,
    migrate_legacy,
)
from tiox.connectors.registry import get as get_connector
from tiox.schemas.event import EntityType
from tiox.schemas import attack
from tiox.store.investigations import parse_window

logging.basicConfig(
    level=os.environ.get("TIOX_LOG", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("tiox.server")

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

# --- Control plane (Phase 0.6) -------------------------------------------
# SQLite is the source of truth for endpoints, incidents, and the event lake.
# The legacy JSON files are read once at startup to seed a fresh database and
# then left alone, so rolling back means pointing TIOX_DB elsewhere and
# restoring the old helpers -- not recovering data that was overwritten.
#
# The env vars are read at call time, not import time. Reading them at import
# meant a test or an embedding program could not point the store somewhere else
# without reimporting the module, and the first caller silently won.
DB_ENV = "TIOX_DB"
MIGRATE_ENV = "TIOX_MIGRATE_LEGACY"
INVENTORY_ENV = "TIOX_INVENTORY_FILE"
INCIDENTS_ENV = "TIOX_INCIDENTS_FILE"

_store = None
_store_lock = threading.RLock()


def _env_flag(name, default=True):
    return os.environ.get(name, "1" if default else "0") not in ("0", "false", "no")


def db_path():
    return os.environ.get(DB_ENV) or os.path.join(PLATFORM_DIR, "tiox.db")


def get_store():
    """Lazily open the control plane. Deferred so importing this module for
    tests does not create a database file as a side effect."""
    global _store
    with _store_lock:
        if _store is None:
            path = db_path()
            _store = ControlPlane(path)
            log.info("control plane open: %s (schema v%s)",
                     path, _store.schema_version)
            if _env_flag(MIGRATE_ENV, True):
                _seed_from_legacy(_store)
        return _store


def _seed_from_legacy(store):
    """Import the pre-Phase-0 JSON stores once, idempotently."""
    inc_path = os.environ.get(INCIDENTS_ENV) or INCIDENTS_FILE
    inv_path = os.environ.get(INVENTORY_ENV) or INVENTORY_FILE
    incidents = {}
    inventory = {}
    try:
        if os.path.exists(inc_path):
            with open(inc_path) as f:
                incidents = json.load(f)
        if os.path.exists(inv_path):
            with open(inv_path) as f:
                inventory = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("could not read legacy JSON stores: %s", exc)
        return
    rows = incidents.get("incidents") if isinstance(incidents, dict) else None
    eps = inventory.get("endpoints") if isinstance(inventory, dict) else None
    if not rows and not eps:
        return
    summary = migrate_legacy(
        store, rows or [], inventory if isinstance(inventory, dict) else {}
    )
    log.info(
        "legacy import: %d endpoint(s), %d incident(s), %d event(s) (%d dupes skipped)",
        summary["endpoints"], summary["incidents"],
        summary["events"], summary["duplicates"],
    )

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
# Only the shell and its assets load before login. Everything else, including
# every /ui/ module, requires a credential: the view files reveal the API
# surface and the data shapes to anyone who can fetch them.
# The shell and every view module must load before login, or the page cannot
# render the login form's target app. They contain no data -- only the API
# surface and request shapes -- and every /api/ call they make is still
# authenticated. Denying them just produced a blank page after a correct login.
UI_ASSETS = {"/ui/index.html", "/ui/app.css", "/ui/core.js", "/ui/shell.js"}

PUBLIC_PATHS = {"/", "/index.html", "/api/status"} | UI_ASSETS

# Agent-facing endpoints authenticate with the agent key.
AGENT_PATHS = ("/api/agent/register", "/api/agent/heartbeat", "/api/agent/scan")

# The workbench is a directory of independent files rather than one page, so
# adding a view does not mean editing a monolith. Path traversal is rejected
# explicitly: the handler resolves under UI_DIR only.
UI_DIR = os.path.join(PLATFORM_DIR, "ui")

# Attribution for scans initiated locally (from the dashboard or the CLI)
# rather than reported by an agent.
LOCAL_SCAN_HOST = os.environ.get("TIOX_LOCAL_HOST", "platform-local")

UI_TYPES = {
".html": "text/html; charset=utf-8",
".js": "application/javascript; charset=utf-8",
".css": "text/css; charset=utf-8",
".json": "application/json; charset=utf-8",
".svg": "image/svg+xml",
".ico": "image/x-icon",
}

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


def _looks_like_window(value: str) -> bool:
    """
    Whether a time window is one we understand.

    parse_window() falls back to a default on unrecognised input, which is right
    for a UI filter and wrong for a report: a report over the wrong period is
    confidently wrong, and nobody notices until they act on it.
    """
    v = (value or "").strip().lower()
    if v in ("all", ""):
        return True
    if re.match(r"^\d+[mhd]$", v):
        return True
    # An ISO date or timestamp.
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", v))


def _hours_ago(hours: int) -> str:
    """ISO timestamp `hours` in the past, for a `since` query bound."""
    return (datetime.now() - timedelta(hours=hours)).isoformat()


def _const_eq(a, b):
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


# Populated at import for the common case, but `is_authorized` prefers the
# live values below. Resolving per request means rotating a key does not require
# a restart, and it means the process does not permanently freeze whatever
# credential happened to be in the environment when it started.
AGENT_KEY = ensure_key_file(AGENT_KEY_FILE, os.environ.get("TIOX_AGENT_KEY", ""))
SESSION_KEY = os.environ.get("TIOX_SESSION_KEY", "") or secrets.token_urlsafe(32)


def current_agent_key():
    """
    The live agent key.

    The environment is consulted on every call so a rotation takes effect
    without a restart. The module-level value is only a fallback for the
    generated-file case, where there is nothing in the environment to read.
    """
    return os.environ.get("TIOX_AGENT_KEY") or AGENT_KEY


def current_session_key():
    """
    The live session key.

    Same rationale as current_agent_key. The generated fallback is stored in
    SESSION_KEY at import, and is deliberately not regenerated per call -- a
    session key that changed on every request could never be logged in with.
    """
    return os.environ.get("TIOX_SESSION_KEY") or SESSION_KEY

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

# Set on shutdown so the SSE keepalive loops exit. Without it an open dashboard
# tab held a thread forever and server shutdown hung.
_shutdown = threading.Event()


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


# --- Control-plane backed store (Phase 0.6) --------------------------------
# These keep the exact call signatures the handlers already use, so the handler
# code did not have to change. What changed is where the data lives: SQLite with
# transactions instead of a whole-file JSON rewrite, which loses writes when two
# agents report at the same moment.


def get_inventory():
    eps = get_store().list_endpoints()
    for ep in eps:
        if ep.get("extra"):
            try:
                ep["extra"] = json.loads(ep["extra"])
            except (json.JSONDecodeError, TypeError):
                ep["extra"] = {}
    return {"endpoints": eps, "total": len(eps)}


def save_inventory(inv):
    """Retained for compatibility with any caller still using the old shape.

    The handlers below were converted to call ControlPlane directly; this exists
    only so an external script importing this module does not break on import.
    """
    log.warning("save_inventory() is a no-op: the control plane owns this data. "
                "Use store.upsert_endpoint()/touch_endpoint()/increment_scan().")


def get_incidents():
    store = get_store()
    rows = store.list_incidents(limit=1000)
    counts = store.incident_counts()
    return {
        "incidents": rows,
        "total": counts["total"],
        "open": counts["open"],
        "critical": counts["critical"],
    }


def save_incidents(inc):
    log.warning("save_incidents() is a no-op: the control plane owns this data. "
                "Use store.create_incident()/update_incident().")


def add_incident(incident, event_id=None):
    """Create an incident and link it to the event that represents it.

    The incident row is written first, then ingested, then the link is
    backfilled -- the event id does not exist until the connector has run. Doing
    it in that order is why the link survives: an earlier version tried to pass
    event_id into create_incident and it was always None, so every incident
    arrived in the lake with no pointer back to the event that caused it.
    """
    store = get_store()
    incident.setdefault("status", "open")
    incident.setdefault("created", datetime.now().isoformat())
    created = store.create_incident(incident, event_id=event_id)
    inc_id = created.get("id")
    if event_id is None and inc_id:
        r = ingest_event({**incident, "id": inc_id}, source="system")
        if r.events:
            store.link_incident_event(inc_id, r.events[0].event_id)
            created = store.get_incident(inc_id) or created
    return created


def _correlate(result, store):
    """
    Turn alert-mode detections into incidents.

    Deliberately not inside the pipeline. Event storage and incident creation have
    different failure semantics -- an event that fails to store is retryable, an
    incident that fails to open is not -- so separating them means a correlation
    bug can cost a detection but never the data that produced it.

    Returns a summary; never raises.
    """
    summary: dict[str, Any] = {
        "opened": 0, "joined": 0, "suppressed": 0, "none": 0,
        # Which rule opened which incident. A single total is not enough: with two
        # rules firing on one event, attributing the incident to both would make a
        # log-mode rule look like it paged someone, which is precisely what per-rule
        # mode exists to prevent.
        "opened_by_rule": {},
    }
    if not result.detections:
        return summary
    try:
        from tiox.detection import event_to_dict

        correlator = Correlator(store)
        by_detection: dict[str, list] = {}
        for hit in result.detections:
            # Pair by rule_id: each detection event carries exactly one rule id.
            if hit.get("rule_id"):
                by_detection.setdefault(hit["rule_id"], []).append(hit)

        for ev in result.detection_events:
            hits = by_detection.get(ev.rule_id) or []
            if not hits:
                continue
            outcome = correlator.correlate(event_to_dict(ev), hits)
            action = outcome.get("action", "none")
            if action in summary and isinstance(summary[action], int):
                summary[action] += 1
            if action == "opened":
                per = summary["opened_by_rule"]
                for h in hits:
                    per[h["rule_id"]] = per.get(h["rule_id"], 0) + 1
    except Exception:
        log.exception("correlation failed; detections are still stored")
    return summary


def ingest_event(payload, source, context=None, kind=None):
    """Normalize a native payload into canonical events and persist them.

    One funnel for every producer, so nothing can reach the store without going
    through a connector. Returns the IngestResult for logging/response bodies.
    """
    try:
        conn = get_connector(source)
    except Exception as exc:
        log.error("no connector for source %r: %s", source, exc)
        failed = IngestResult()
        failed.errors.append(f"no connector for source {source!r}: {exc}")
        return failed
    store = get_store()
    result = ingest(store, payload, source, context, connector=conn)
    if result.detections:
        summary = _correlate(result, store)
        log.info(
            "ingest %s: %d detection(s) -> %d incident(s) opened, %d joined",
            source, len(result.detections), summary.get("opened", 0),
            summary.get("joined", 0),
        )
        # Rule counters are only honest once correlation has decided how many
        # incidents were really opened, and which rule opened each one, so they
        # are written here rather than in the pipeline.
        try:
            engine = get_detection_engine(store)
            engine.record_outcome(
                result.detections,
                opened_by_rule=summary.get("opened_by_rule") or {},
            )
        except Exception:
            log.exception("could not record rule outcomes")
    if result.errors:
        log.warning("ingest %s: %d error(s): %s", source, len(result.errors), result.errors)
    else:
        log.info(
            "ingest %s: %d inserted, %d duplicate(s)",
            source, result.inserted, result.duplicates,
        )
    return result


def send_sse_event(event, data):
    """Send SSE event to all connected clients"""
    # Make a copy to avoid modifying the original
    data_copy = {k: v for k, v in data.items() if k != "process"}
    with sse_lock:
        dead = []
        for i, client in enumerate(sse_clients):
            try:
                # wfile is a binary buffer: these must be encoded. Writing str
                # raises TypeError and silently kills the live stream.
                client.write(f"event: {event}\n".encode())
                client.write(f"data: {json.dumps(data_copy)}\n\n".encode())
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


def run_scan(scan_path, quick_mode=False, agent_id=None, hash_file=None, pattern_file=None):
    global scan_state
    if scan_state["running"]:
        return False

    # Open a durable scan record before the subprocess starts. Without this the
    # run has no identity: scan_state is a single global dict, so a second scan
    # overwrites the first and the platform keeps no history at all.
    ep = get_store().get_endpoint(agent_id) if agent_id else None
    hostname = (ep or {}).get("hostname") or LOCAL_SCAN_HOST
    record = get_store().start_scan(
        scan_path=scan_path,
        initiated_by=agent_id or "local",
        host=hostname,
    )
    scan_id = record["scan_id"]

    scan_state = {
        "running": True, "files_scanned": 0, "dirs_scanned": 0,
        "threats_found": 0, "errors": 0, "current_file": "",
        "threats": [], "start_time": datetime.now().isoformat(),
        "end_time": None, "scan_path": scan_path,
        "process": None, "progress": 0, "status": "scanning",
        "agent_id": agent_id,
        # The id every event, incident, and finding from this run is tied to.
        "scan_id": scan_id,
        "scan_label": record["label"],
        "seq": record["seq"],
    }
    send_sse_event("scan_start", scan_state)

    def scan_thread():
        global scan_state
        last_persist = 0.0
        try:
            flags = ["-v"]
            if quick_mode:
                flags = ["-Q", "-v"]
            # An operator-supplied IOC file lets a scan use a threat feed the
            # scanner's built-in database does not carry. Without it the only
            # way to test a custom IOC is to edit C and rebuild.
            if hash_file:
                flags += ["-H", hash_file]
            if pattern_file:
                flags += ["-P", pattern_file]
            cmd = [SCANNER_BIN] + flags + [scan_path]
            scan_state["process"] = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            for line in scan_state["process"].stdout:
                line = line.rstrip()
                parse_scanner_output(line)
                # Persist progress as it happens. If the process is killed, the
                # run is still in the table with a partial count rather than
                # being absent, which is the difference between "stopped" and
                # "never happened".
                # Throttle the persistence. A verbose scan emits thousands of
                # lines, and a SQLite write per line holds the store lock long
                # enough to stall every other request. The final finish_scan()
                # records the true totals, so a throttled intermediate value is
                # only ever a progress hint, never the record of truth.
                now = time.monotonic()
                if now - last_persist >= 1.0:
                    last_persist = now
                    get_store().update_scan(
                        scan_id,
                        files_scanned=scan_state["files_scanned"],
                        dirs_scanned=scan_state["dirs_scanned"],
                        threats_found=scan_state["threats_found"],
                        errors=scan_state["errors"],
                    )
                send_sse_event("progress", scan_state)
            scan_state["process"].wait()
            scan_state["status"] = "completed"
            scan_state["end_time"] = datetime.now().isoformat()
            scan_state["progress"] = 100

            # Auto-create incidents for threats, and ingest the whole scan into
            # the event lake. This is the path that makes the platform a lake
            # rather than a dashboard: every scan becomes queryable events.
            payload = {k: v for k, v in scan_state.items() if k != "process"}
            ep = get_store().get_endpoint(agent_id) if agent_id else None
            # A scan started from the dashboard has no agent. Leaving host empty
            # made every per-host summary and host pivot silently empty, which
            # reads as "nothing happened" rather than "we did not attribute it".
            if ep:
                hostname = ep.get("hostname")
            else:
                hostname = LOCAL_SCAN_HOST
                payload = {**payload, "hostname": LOCAL_SCAN_HOST}
            context = {"hostname": hostname, "endpoint": ep or {}}
            result = ingest_event(payload, source="agent", context=context)

            # Link each threat incident to the event that produced it, so an
            # incident and its event share one identity rather than the incident
            # generating a second, duplicate event of its own.
            #
            # Match on the strongest identifier the threat carries: the file hash
            # when the scanner reported one, otherwise the full path. Index-based
            # fallback would be fragile -- the summary event is events[0], so
            # positional matching silently attaches incidents to the wrong row.
            threat_events = {
                ev.event_id: ev for ev in result.events
                if ev.rule_id in ("builtin.hash_exact", "builtin.filename_pattern")
            }
            by_hash = {}
            by_path = {}
            for ev in threat_events.values():
                for h in ev.entities.get("file_hash", []):
                    by_hash.setdefault(h, ev.event_id)
                for p in ev.entities.get("file_path", []):
                    by_path.setdefault(p, ev.event_id)

            for threat in scan_state["threats"]:
                if not threat.get("file"):
                    continue
                sha = (threat.get("hash") or "").strip().lower()
                linked = by_hash.get(sha) if sha else None
                if linked is None:
                    linked = by_path.get(threat["file"])
                add_incident({
                    "title": f"Threat: {threat.get('family', 'Unknown')}",
                    "description": f"Detected {threat.get('type', 'unknown match')} in {threat['file']}",
                    "severity": "critical" if threat.get("type") == "Known malicious hash" else "high",
                    "source": agent_id or "local",
                    "type": "malware",
                    "details": threat,
                }, event_id=linked)

                # Record the finding against this run, and link it to the event
                # it produced. This is what makes a click on a scan reach the
                # specific file that was found.
                store = get_store()
                sha = sha or None
                store.record_finding(scan_id, {
                    "file_path": threat["file"],
                    "file_hash": sha,
                    "family": threat.get("family"),
                    "rule_id": ("builtin.hash_exact" if threat.get("type") == "Known malicious hash"
                                else "builtin.filename_pattern"),
                    "severity": ("critical" if threat.get("type") == "Known malicious hash"
                                 else "high"),
                    "event_id": linked,
                })
                if linked and sha:
                    store.link_finding_event(scan_id, sha, linked)

            get_store().finish_scan(
                scan_id, "completed",
                files_scanned=scan_state["files_scanned"],
                dirs_scanned=scan_state["dirs_scanned"],
                threats_found=scan_state["threats_found"],
                errors=scan_state["errors"],
            )
        except Exception as e:
            scan_state["status"] = "error"
            scan_state["end_time"] = datetime.now().isoformat()
            scan_state["error"] = str(e)
            # A failed run is still a run. Recording it as an error is what
            # stops a broken scan from looking like one that found nothing.
            try:
                get_store().finish_scan(
                    scan_id, "error", error=str(e),
                    files_scanned=scan_state["files_scanned"],
                    dirs_scanned=scan_state["dirs_scanned"],
                    threats_found=scan_state["threats_found"],
                )
            except Exception:  # pragma: no cover -- never mask the original error
                pass
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
        if path.startswith("/ui/") and os.path.splitext(path)[1] in (
            ".html", ".css", ".js", ".svg", ".ico"
        ):
            # Static workbench assets. Data still requires a credential; these
            # are just the view modules, and gating them breaks the login flow.
            return True
        presented = self._presented_key()
        if not presented:
            return False
        if path in AGENT_PATHS:
            return _const_eq(presented, current_agent_key())
        # Everything else needs the session key; the agent key is not enough, so
        # a compromised endpoint cannot read the dashboard or mutate incidents.
        return _const_eq(presented, current_session_key())

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
            # The old single-page dashboard is superseded by the workbench in ui/.
            # Redirecting rather than serving both avoids two divergent UIs.
            self.serve_ui("index.html")
        elif parsed.path.startswith("/ui/"):
            self.serve_ui(parsed.path[len("/ui/"):])
        elif parsed.path == "/api/logout":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
            )
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
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
            self.send_json({"key": current_agent_key()})
        elif parsed.path == "/api/agent/script":
            self.serve_agent_script(tls=TLS_ENABLED)
        elif parsed.path == "/api/stats":
            self.send_stats()
        elif parsed.path == "/api/lake":
            # Named /api/lake, not /api/events: that path is already the SSE
            # progress stream, and a GET returning an endless stream cannot also
            # be a paginated query. Two meanings on one path is unfixable from
            # the client side.
            self.list_events(parsed)
        elif parsed.path == "/api/entity":
            self.pivot_entity(parsed)
        elif parsed.path == "/api/entity/spread":
            self.entity_spread_api(parsed)
        elif parsed.path == "/api/investigations/top":
            self.top_entities_api(parsed)
        elif parsed.path == "/api/investigations/timeline":
            self.timeline_api(parsed)
        elif parsed.path == "/api/investigations/hosts":
            self.host_summary_api(parsed)
        elif parsed.path == "/api/investigations/rules":
            self.rule_breakdown_api(parsed)
        elif parsed.path == "/api/investigations/stale":
            self.stale_endpoints_api(parsed)
        elif parsed.path == "/api/attack/techniques":
            self.attack_techniques_api(parsed)
        elif parsed.path == "/api/attack/technique":
            self.attack_technique_api(parsed)
        elif parsed.path == "/api/attack/catalog":
            self.attack_catalog()
        elif parsed.path == "/api/scans":
            self.list_scans_api(parsed)
        elif parsed.path == "/api/scan":
            self.get_scan_api(parsed)
        elif parsed.path == "/api/rules":
            self.list_rules_api(parsed)
        elif parsed.path == "/api/rules/schema":
            self.rules_schema_api()
        elif parsed.path == "/api/rules/effectiveness":
            self.rule_effectiveness_api(parsed)
        elif parsed.path == "/api/rules/suppressions":
            self.list_suppressions_api()
        elif parsed.path == "/api/reports/kinds":
            self.report_kinds_api()
        elif parsed.path == "/api/reports/generate":
            self.report_generate_api(parsed)
        elif parsed.path == "/api/reports/download":
            self.report_download_api(parsed)
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
            if not _const_eq(str(data.get("key", "")), current_session_key()):
                self.send_json({"error": "Invalid credentials"}, 401)
                return
            secure = "; Secure" if self.is_https else ""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={current_session_key()}; HttpOnly; Path=/; "
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
            hash_file = params.get("hash_file")
            pattern_file = params.get("pattern_file")
            if scan_state["running"]:
                self.send_json({"error": "Scan already running"}, 409)
            else:
                success = run_scan(scan_path, quick_mode, agent_id,
                                   hash_file, pattern_file)
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
            store = get_store()
            # Whether this is a first sighting decides both the incident and
            # whether it belongs in the lake. A re-registering agent (restart,
            # network blip) is not news; filing an incident each time buried real
            # ones under duplicates.
            is_new = store.get_endpoint_by_host(data.get("hostname", "")) is None
            endpoint_id = store.upsert_endpoint({
                "hostname": sanitize_string(data.get("hostname", "unknown")),
                "ip": sanitize_string(data.get("ip", self.client_address[0])),
                "os": sanitize_string(data.get("os", "unknown")),
                "version": sanitize_string(data.get("version", "1.0")),
                "status": "online",
                "connector": "agent",
            })
            endpoint = store.get_endpoint(endpoint_id) or {}
            # Ingest the registration itself, so endpoint lifecycle is part of the
            # lake and "when did this host first appear" is answerable.
            ingest_event(
                {"hostname": endpoint.get("hostname"), "ip": endpoint.get("ip"),
                 "os": endpoint.get("os")},
                source="agent",
            )
            if is_new:
                add_incident({
                    "title": f"Agent registered: {endpoint.get('hostname')}",
                    "description": f"New endpoint {endpoint.get('hostname')} ({endpoint.get('ip')}) registered",
                    "severity": "info",
                    "source": "system",
                    "type": "agent"
                })
            else:
                log.info("agent re-registered: %s (%s)", endpoint.get("hostname"), endpoint_id)
            self.send_json(endpoint)

        elif parsed.path == "/api/agent/heartbeat":
            body = self.read_body()
            data = json.loads(body) if body else {}
            store = get_store()
            agent_id = str(data.get("agent_id") or "")
            ip = data.get("ip")
            # A heartbeat from an unknown id is reported, not silently accepted:
            # the old code looped over endpoints and did nothing if there was no
            # match, so a misconfigured agent looked healthy.
            ep = store.get_endpoint(agent_id) if agent_id else None
            if ep:
                store.touch_endpoint(agent_id, ip)
                if data.get("threats") is not None or data.get("last_scan"):
                    ingest_event(
                        {"agent_id": agent_id, "ip": ip, "ts": data.get("last_scan")},
                        source="agent",
                        context={"hostname": ep.get("hostname")},
                    )
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "Agent not found"}, 404)

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
            agent_id = str(data.get("agent_id") or "")
            store = get_store()
            ep = store.get_endpoint(agent_id) if agent_id else None
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
                    store.increment_scan(agent_id)
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
            inc_id = str(data.get("id") or "")
            # update_incident reports whether the id existed. The old loop mutated
            # a list in memory and answered {"ok": true} regardless, so a typo'd
            # incident id looked like a successful triage.
            updated = get_store().update_incident(
                inc_id, status=data.get("status"), note=data.get("note")
            )
            if not updated:
                self.send_json({"error": "Incident not found"}, 404)
                return
            inc = get_incidents()
            for i in inc["incidents"]:
                if i["id"] == inc_id:
                    self.send_json({"ok": True, "incident": i})
                    return
            self.send_json({"ok": True})

        elif parsed.path == "/api/rules":
            self.create_rule_api(self.read_body())
        elif parsed.path == "/api/rules/test":
            self.test_rule_api(self.read_body())
        elif parsed.path == "/api/rules/suppress":
            self.suppress_rule_api(self.read_body())
        elif parsed.path == "/api/reports/generate":
            self.report_generate_api(parsed)
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

    # ==================== scans API ====================

    def list_scans_api(self, parsed):
        """Scan history. Backs the Endpoints "Scans" tile and the scan list."""
        qs = parse_qs(urlparse(self.path).query)
        store = get_store()
        try:
            limit = min(500, max(1, int(qs.get("limit", ["100"])[0])))
        except ValueError:
            limit = 100
        scans = store.list_scans(
            host=qs.get("host", [None])[0] or None,
            status=qs.get("status", [None])[0] or None,
            limit=limit,
        )
        self.send_json({"scans": scans, "stats": store.scan_stats()})

    def get_scan_api(self, parsed):
        """One scan plus its findings, so a click reaches the files it found."""
        qs = parse_qs(urlparse(self.path).query)
        scan_id = qs.get("id", [""])[0]
        if not scan_id:
            self.send_error(400)
            return
        store = get_store()
        scan = store.get_scan(scan_id)
        if not scan:
            self.send_json({"error": f"no such scan: {scan_id}"}, 404)
            return
        findings = store.scan_findings(scan_id)
        self.send_json({
            "scan": scan,
            "findings": findings,
            "events": [
                e["event_id"] for e in findings if e.get("event_id")
            ],
        })

    # ==================== custom rules API ====================

    def list_rules_api(self, parsed):
        store = get_store()
        self.send_json({"rules": store.list_rules()})

    def rules_schema_api(self):
        """
        The building blocks the UI offers.

        Served from the engine so the editor cannot drift from what actually
        evaluates: an operator dropdown built from a hardcoded list in the
        frontend would eventually accept a rule the backend rejects.
        """
        from tiox.rules.engine import COMPARISONS, FIELDS

        self.send_json({
            "fields": FIELDS,
            "operators": COMPARISONS,
            "boolean_ops": ["and", "or", "not"],
            "severities": ["critical", "high", "medium", "low", "info"],
            "node_kinds": ["match", "test", "threshold"],
        })

    def create_rule_api(self, body):
        if body is None:
            self.send_json({"error": "Request too large"}, 413)
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        try:
            saved = get_store().save_rule(data)
            # The engine caches the enabled rule set. Without this a rule the
            # analyst just created would not evaluate until the process
            # restarted, and they would conclude the engine was broken.
            invalidate_detection()
        except ValueError as exc:
            # A validation failure is the author's problem to fix, so report
            # every problem rather than the first.
            self.send_json({"error": str(exc), "kind": "validation"}, 400)
            return
        self.send_json({"rule": saved}, 201)

    def update_rule_api(self, parsed, body):
        rule_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        store = get_store()
        if not store.get_rule(rule_id):
            self.send_json({"error": f"no such rule: {rule_id}"}, 404)
            return
        if body is None:
            self.send_json({"error": "Request too large"}, 413)
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        # An enable/disable toggle sends {"enabled": bool} and nothing else, so
        # it must not be treated as a full rule replacement.
        if set(data.keys()) == {"enabled"}:
            ok = store.set_rule_enabled(rule_id, bool(data["enabled"]))
            if ok:
                invalidate_detection()
            self.send_json({"ok": ok, "rule": store.get_rule(rule_id)} if ok
                            else {"error": "not found"}, 200 if ok else 404)
            return
        try:
            saved = store.save_rule(data, rule_id=rule_id)
            invalidate_detection()
        except ValueError as exc:
            self.send_json({"error": str(exc), "kind": "validation"}, 400)
            return
        self.send_json({"rule": saved})

    def delete_rule_api(self, parsed):
        rule_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        if get_store().delete_rule(rule_id):
            invalidate_detection()
            self.send_json({"ok": True})
        else:
            self.send_json({"error": f"no such rule: {rule_id}"}, 404)

    def test_rule_api(self, body):
        """
        Dry-run a rule against recent events.

        This is the feature that makes a rule editor usable: an author needs to
        see what their rule *would* catch before enabling it, otherwise every
        new rule is a guess that either floods the queue or never fires.
        """
        if body is None:
            self.send_json({"error": "Request too large"}, 413)
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        from tiox.rules.engine import Evaluator, explain, validate

        tree = data.get("tree")
        if not isinstance(tree, dict):
            self.send_json({"error": "rule needs a tree object"}, 400)
            return

        problems = validate(tree)
        if problems:
            self.send_json({"error": "; ".join(problems), "kind": "validation",
                            "problems": problems}, 400)
            return

        hours = data.get("window_hours", 24)
        try:
            hours = min(720, max(1, int(hours)))
        except (TypeError, ValueError):
            hours = 24

        store = get_store()
        events = store.query_events(limit=500, since=_hours_ago(hours))
        rule = {
            "id": data.get("rule_id", "test"),
            "name": data.get("name", "test rule"),
            "severity": data.get("severity", "medium"),
            "techniques": data.get("techniques") or [],
            "tree": tree,
        }
        hits = Evaluator().run_rule(rule, events)
        self.send_json({
            "valid": True,
            "explanation": explain(tree),
            "events_examined": len(events),
            "hit_count": len(hits),
            "hits": [h.as_dict() for h in hits[:20]],
        })

    # ==================== reporting API ====================

    def report_kinds_api(self):
        """What can be reported, and in which formats.

        Served from the reporting module so the UI cannot offer a kind the
        backend does not implement, or a format it cannot render.
        """
        from tiox import reporting

        self.send_json({
            "kinds": [
                {"id": k, "description": v} for k, v in
                sorted(reporting.REPORT_KINDS.items())
            ],
            "formats": [
                {"id": "json", "label": "JSON", "note": "machine-readable, for other tools"},
                {"id": "xlsx", "label": "Excel", "note": "one sheet per section, filterable"},
                {"id": "txt", "label": "Plain text", "note": "for tickets and chat"},
            ],
        })

    def _report_params(self, parsed_or_qs):
        """Pull and validate the report arguments. Raises ValueError on bad input."""
        from tiox import reporting

        q = parsed_or_qs
        kind = (q.get("kind", [""])[0] or "").strip().lower()
        if kind not in reporting.REPORT_KINDS:
            raise ValueError(
                f"unknown report kind {kind!r}; known: "
                f"{', '.join(sorted(reporting.REPORT_KINDS))}"
            )
        fmt = (q.get("format", [""])[0] or "").strip().lower()
        if fmt not in reporting.FORMATS:
            raise ValueError(
                f"unsupported format {fmt!r}; choose one of: "
                f"{', '.join(reporting.FORMATS)}"
            )
        window = (q.get("window", ["24h"])[0] or "24h").strip()
        # parse_window falls back to a default on garbage, which would quietly
        # produce a report over the wrong period. Reject it instead.
        from tiox.store.investigations import parse_window
        if window not in ("all",) and not _looks_like_window(window):
            raise ValueError(
                f"unrecognised window {window!r}; use 24h, 7d, all, or an ISO timestamp"
            )
        parse_window(window)
        return {
            "kind": kind,
            "format": fmt,
            "window": window,
            "scan_id": (q.get("scan_id", [""])[0] or "").strip() or None,
            "technique": (q.get("technique", [""])[0] or "").strip() or None,
            "title": (q.get("title", [""])[0] or "").strip() or None,
        }

    def report_generate_api(self, parsed):
        """Build a report, write it, and return a descriptor (not the bytes).

        Generation is a POST: it creates a file and does work. The bytes are
        then fetched from /api/reports/download, so a report can be shared by
        URL instead of embedded in a JSON response.
        """
        from tiox import reporting

        try:
            args = self._report_params(parse_qs(parsed.query))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        try:
            doc = reporting.build_document(
                args["kind"], get_store(),
                window=args["window"],
                scan_id=args["scan_id"],
                technique=args["technique"],
                title=args["title"],
            )
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        try:
            info = reporting.render_to_file(doc, args["format"], REPORT_DIR)
        except (OSError, ValueError) as exc:
            self.send_json({"error": f"could not write the report: {exc}"}, 500)
            return
        self.send_json({"report": info}, 201)

    def report_download_api(self, parsed):
        """Serve a saved report. Path traversal is rejected, not sanitised."""
        from urllib.parse import unquote

        name = unquote(parse_qs(parsed.query).get("name", [""])[0] or "")
        if not name:
            self.send_json({"error": "'name' is required"}, 400)
            return
        # Reject rather than clean: a name that needs cleaning is a name that
        # should not have been accepted.
        if os.path.basename(name) != name or name.startswith("."):
            self.send_json({"error": "invalid report name"}, 400)
            return
        path = os.path.join(REPORT_DIR, name)
        if not os.path.isfile(path):
            self.send_json({"error": f"no such report: {name}"}, 404)
            return

        ext = os.path.splitext(name)[1].lower()
        from tiox import reporting

        content_type = {
            ".json": "application/json",
            ".xlsx": ("application/vnd.openxmlformats-officedocument."
                      "spreadsheetml.sheet"),
            ".txt": "text/plain; charset=utf-8",
        }.get(ext, "application/octet-stream")
        self.send_bytes(path, content_type, download_name=name)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if not self.require_auth(parsed.path):
            return
        if parsed.path.startswith("/api/rules/"):
            self.update_rule_api(parsed, self.read_body())
        else:
            self.send_error(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if not self.require_auth(parsed.path):
            return
        if parsed.path.startswith("/api/rules/"):
            self.delete_rule_api(parsed)
        else:
            self.send_error(404)

    def rule_effectiveness_api(self, parsed):
        """
        The tuning view's data: hits, incidents, false positives, and a grade.

        Advisory only. Nothing in this response disables anything, and the UI
        shows it that way -- a detection that disappears without explanation is
        the failure mode Phase 2 exists to prevent.
        """
        q = parse_qs(parsed.query)
        hours = 24 * 7
        if q.get("window", [""])[0] in ("24h", "7d", "30d", "all"):
            hours = {"24h": 24, "7d": 168, "30d": 720, "all": 24 * 365}[
                q.get("window", ["7d"])[0]]
        since = _hours_ago(hours)
        store = get_store()
        self.send_json({
            "rules": store.rule_effectiveness(since),
            "suppressions": store.list_suppressions(),
            "window": q.get("window", ["7d"])[0],
        })

    def list_suppressions_api(self):
        self.send_json({"suppressions": get_store().list_suppressions()})

    def suppress_rule_api(self, body):
        """
        Mute a rule for a period.

        Time-boxed, and the response states when the mute expires: an analyst who
        cannot see the end of a mute has no reason to trust that it ends.
        """
        if body is None:
            self.send_json({"error": "Request too large"}, 413)
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        rule_id = str(data.get("rule_id") or "").strip()
        store = get_store()
        if not rule_id or not store.get_rule(rule_id):
            self.send_json({"error": f"no such rule: {rule_id!r}"}, 404)
            return
        minutes = data.get("minutes", 1440)
        try:
            minutes = max(1, min(60 * 24 * 30, int(minutes)))
        except (TypeError, ValueError):
            minutes = 1440

        if data.get("action") == "unsuppress":
            store.unsuppress_rule(rule_id)
            self.send_json({"ok": True, "rule_id": rule_id, "suppressed": False})
            return

        if data.get("false_positive"):
            store.record_rule_false_positive(rule_id)
        store.suppress_rule(rule_id, minutes, data.get("reason"))
        until = (datetime.now() + timedelta(minutes=minutes)).isoformat()
        self.send_json({
            "ok": True, "rule_id": rule_id, "suppressed": True,
            "suppressed_until": until, "minutes": minutes,
        })

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        # Limit body size to 1MB to prevent DoS
        if length > 1048576:
            return None
        return self.rfile.read(length) if length > 0 else b""

    def serve_ui(self, relpath):
        """
        Serve a file from ui/, refusing anything that escapes the directory.

        The workbench is many small files rather than one page, which means the
        URL carries a path. os.path.realpath + a prefix check is what stops
        `/ui/../../etc/passwd`; join() alone would happily traverse.
        """
        relpath = (relpath or "").strip("/")
        if not relpath:
            self.send_error(404)
            return
        target = os.path.realpath(os.path.join(UI_DIR, relpath))
        root = os.path.realpath(UI_DIR)
        if target != root and not target.startswith(root + os.sep):
            log.warning("blocked UI path traversal: %r", relpath)
            self.send_error(403)
            return
        if not os.path.isfile(target):
            self.send_error(404)
            return
        ext = os.path.splitext(target)[1].lower()
        ctype = UI_TYPES.get(ext)
        if not ctype:
            self.send_error(403, "Unsupported media type")
            return
        with open(target, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(body))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

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
        """
        Server-sent events stream.

        Two bugs fixed here. The loop was `while True` with no shutdown check, so
        an open dashboard tab kept a thread alive forever and server shutdown
        hung. And the first three writes passed str to a binary buffer, raising
        TypeError before the client received the stream headers -- the live
        progress display could never have worked.
        """
        global scan_state, _shutdown
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
            state_copy = {k: v for k, v in scan_state.items() if k != "process"}
            self.wfile.write(f"event: connected\n".encode())
            self.wfile.write(f"data: {json.dumps(state_copy)}\n\n".encode())
            self.wfile.flush()
            # Bounded by the shutdown flag so shutdown() can complete.
            while not _shutdown.is_set():
                if _shutdown.wait(timeout=1.0):
                    break
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass
        finally:
            with sse_lock:
                if self.wfile in sse_clients:
                    sse_clients.remove(self.wfile)

    def send_bytes(self, path, content_type, download_name=None):
        """
        Serve a file as a download.

        The filename is echoed back as Content-Disposition. Header values cannot
        contain a newline, and a filename is user-influenced, so strip CR/LF and
        anything outside a safe set rather than trusting the caller.
        """
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self.send_error(404)
            return
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", download_name or "download")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        self.wfile.write(body)

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

AGENT_KEY="{current_agent_key()}"
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
        """
        Saved reports, newest first.

        The kind, format, and window are parsed back out of the filename rather
        than stored separately: a sidecar index is a second thing to keep in
        sync, and losing it loses the listing too.
        """
        reports = []
        if os.path.isdir(REPORT_DIR):
            for name in sorted(os.listdir(REPORT_DIR), reverse=True):
                filepath = os.path.join(REPORT_DIR, name)
                if not os.path.isfile(filepath):
                    continue
                stem, ext = os.path.splitext(name)
                parts = stem.rsplit("-", 2)
                reports.append({
                    "name": name,
                    "size": os.path.getsize(filepath),
                    "modified": datetime.fromtimestamp(
                        os.path.getmtime(filepath)).isoformat(),
                    "format": ext.lstrip("."),
                    "kind": parts[0] if len(parts) == 3 else "",
                    "window": parts[1] if len(parts) == 3 else "",
                })
        self.send_json(reports)

    def send_stats(self):
        global scan_state
        store = get_store()
        inv = get_inventory()
        inc = get_incidents()
        # Event-lake figures come from the lake, not from summing endpoint
        # counters. This is the first thing the dashboard can show that the old
        # JSON store could not answer at all.
        ev = store.event_stats()
        stats = {
            "endpoints": inv.get("total", 0),
            "endpoints_online": sum(1 for e in inv.get("endpoints", []) if e["status"] == "online"),
            "incidents_total": inc.get("total", 0),
            "incidents_open": inc.get("open", 0),
            "incidents_critical": inc.get("critical", 0),
            "threats_total": sum(e.get("threats_found", 0) or 0 for e in inv.get("endpoints", [])),
            "scans_total": sum(e.get("scan_count", 0) or 0 for e in inv.get("endpoints", [])),
            "databases": len(os.listdir(IOC_DB_DIR)) if os.path.exists(IOC_DB_DIR) else 0,
            "reports": len(os.listdir(REPORT_DIR)) if os.path.exists(REPORT_DIR) else 0,
            "events_total": ev["total"],
            "events_high_severity": ev["high"],
            "event_hosts": ev["hosts"],
            "event_sources": ev["sources"],
        }
        self.send_json(stats)

    def _clamp_limit(self, parsed, default=200, maximum=1000):
        """Bounded result size from a query string.

        parse_qs returns a list, and an unvalidated limit is an easy way to let a
        caller ask for the whole lake in one response.
        """
        try:
            raw = parse_qs(parsed.query).get("limit", [default])[0]
            n = int(raw)
        except (TypeError, ValueError):
            return default
        return max(1, min(n, maximum))

    def list_events(self, parsed):
        """Time-range-aware event query. This is what the UI's global time filter
        will drive once the workbench is built."""
        q = parse_qs(parsed.query)
        rows = get_store().query_events(
            type=(q.get("type") or [None])[0],
            severity=(q.get("severity") or [None])[0],
            host=(q.get("host") or [None])[0],
            source=(q.get("source") or [None])[0],
            since=(q.get("since") or [None])[0],
            until=(q.get("until") or [None])[0],
            limit=self._clamp_limit(parsed),
        )
        # raw can be large and the UI does not need it for a list view. The
        # entity values ARE needed, though: the table makes them clickable, and
        # a pivot target the client cannot see is not a pivot.
        store = get_store()
        entity_map = store.entities_for_events([r["event_id"] for r in rows])
        for r in rows:
            r.pop("raw", None)
            r["entities"] = entity_map.get(r["event_id"], {})
        self.send_json({"events": rows, "count": len(rows)})

    def pivot_entity(self, parsed):
        """
        The pivot: everything ever seen for one entity value, across all sources.

        GET /api/entity?type=file_hash&value=275a021b...

        This single query is the feature the whole canonical schema exists to
        support -- an analyst clicks a hash and sees its full history without
        asking each tool separately.
        """
        q = parse_qs(parsed.query)
        etype = (q.get("type") or [""])[0].strip()
        value = (q.get("value") or [""])[0].strip()
        if not etype or not value:
            self.send_json({"error": "Both 'type' and 'value' are required"}, 400)
            return
        valid = {e.value for e in EntityType}
        if etype not in valid:
            self.send_json({
                "error": f"unknown entity type {etype!r}",
                "valid": sorted(valid),
            }, 400)
            return
        store = get_store()
        rows = store.find_by_entity(etype, value, limit=self._clamp_limit(parsed, 200, 500))
        total = store.count_by_entity(etype, value)
        hosts = sorted({r.get("host") for r in rows if r.get("host")})
        sources = sorted({r.get("source") for r in rows if r.get("source")})
        entity_map = store.entities_for_events([r["event_id"] for r in rows])
        for r in rows:
            r.pop("raw", None)
            r["entities"] = entity_map.get(r["event_id"], {})
        self.send_json({
            "entity": {"type": etype, "value": value.lower()},
            "total": total,
            "returned": len(rows),
            "first_seen": rows[-1]["ts"] if rows else None,
            "last_seen": rows[0]["ts"] if rows else None,
            "hosts": hosts,
            "sources": sources,
            "events": rows,
        })

    def log_message(self, format, *args):
        pass

    # ==================== investigation API (Phase 1) ====================

    def _window(self, parsed, default_hours: int = 24) -> tuple[str | None, str | None]:
        """
        Resolve the time window from the query string.

        The UI's global time picker sends `window=24h|7d|all`, so every panel
        honours one control. Falling back to a recent default rather than "all
        time" keeps an unfiltered query from scanning the entire lake.
        """
        q = parse_qs(parsed.query)
        return parse_window((q.get("window") or [None])[0], default_hours)

    def _require_entity(self, parsed):
        q = parse_qs(parsed.query)
        etype = (q.get("type") or [""])[0].strip()
        value = (q.get("value") or [""])[0].strip()
        if not etype or not value:
            self.send_json({"error": "Both 'type' and 'value' are required"}, 400)
            return None
        valid = {e.value for e in EntityType}
        if etype not in valid:
            self.send_json({"error": f"unknown entity type {etype!r}",
                            "valid": sorted(valid)}, 400)
            return None
        return etype, value

    def entity_spread_api(self, parsed):
        """How far one indicator spread: host count, timeline, families."""
        pair = self._require_entity(parsed)
        if not pair:
            return
        etype, value = pair
        since, until = self._window(parsed)
        self.send_json(get_store().investigations.entity_spread(etype, value, since))

    def top_entities_api(self, parsed):
        """Most-seen entity values, ranked by host spread rather than raw count."""
        q = parse_qs(parsed.query)
        etype = (q.get("type") or ["file_hash"])[0]
        if etype not in {e.value for e in EntityType}:
            self.send_json({"error": f"unknown entity type {etype!r}"}, 400)
            return
        since, _ = self._window(parsed)
        rows = get_store().investigations.top_entities(
            etype, since, self._clamp_limit(parsed, 20, 200)
        )
        self.send_json({"entity_type": etype, "count": len(rows), "entities": rows})

    def timeline_api(self, parsed):
        """Event counts bucketed over time, for the sparkline."""
        q = parse_qs(parsed.query)
        bucket = (q.get("bucket") or ["hour"])[0]
        if bucket not in ("minute", "hour", "day", "week", "month"):
            self.send_json({"error": f"unknown bucket {bucket!r}",
                            "valid": ["minute", "hour", "day", "week", "month"]}, 400)
            return
        since, until = self._window(parsed, default_hours=168)
        etype = (q.get("type") or [None])[0]
        value = (q.get("value") or [None])[0]
        rows = get_store().investigations.timeline(
            since, until, bucket,
            etype if etype and value else None,
            value if etype and value else None,
        )
        self.send_json({"bucket": bucket, "since": since, "until": until,
                        "count": len(rows), "buckets": rows})

    def host_summary_api(self, parsed):
        since, _ = self._window(parsed)
        rows = get_store().investigations.host_summary(since)
        self.send_json({"count": len(rows), "hosts": rows})

    def rule_breakdown_api(self, parsed):
        since, _ = self._window(parsed)
        rows = get_store().investigations.rule_breakdown(since)
        self.send_json({"count": len(rows), "rules": rows,
                        "unmapped": sum(1 for r in rows if r["unmapped"])})

    def stale_endpoints_api(self, parsed):
        q = parse_qs(parsed.query)
        try:
            days = int((q.get("days") or ["7"])[0])
        except (TypeError, ValueError):
            days = 7
        days = max(1, min(days, 365))
        rows = get_store().investigations.stale_endpoints(days)
        self.send_json({"days": days, "count": len(rows), "endpoints": rows})

    def attack_techniques_api(self, parsed):
        """Techniques actually observed in this environment, with ATT&CK metadata."""
        since, _ = self._window(parsed, default_hours=168)
        rows = get_store().investigations.technique_breakdown(since)
        self.send_json({"count": len(rows), "techniques": rows})

    def attack_technique_api(self, parsed):
        """One technique: its metadata plus the hosts that produced it."""
        q = parse_qs(parsed.query)
        tid = (q.get("id") or [""])[0].strip().upper()
        if not tid:
            self.send_json({"error": "'id' is required"}, 400)
            return
        meta = attack.get(tid)
        if not meta:
            self.send_json({"error": f"unknown technique {tid!r}",
                            "hint": "GET /api/attack/catalog lists known techniques"},
                           404)
            return
        since, _ = self._window(parsed, default_hours=168)
        inv = get_store().investigations
        hosts = inv.technique_hosts(tid, since)
        self.send_json({"technique": meta.as_dict(), "host_count": len(hosts),
                        "hosts": hosts})

    def attack_catalog(self):
        """The curated technique catalog, plus rules that have no mapping yet."""
        from tiox.schemas.attack import unmapped_rules

        rows = get_store().investigations.rule_breakdown()
        known = [r["rule_id"] for r in rows if r["rule_id"]]
        self.send_json({
            "techniques": attack.catalog(),
            "tactics": attack.tactics(),
            "observed_rules": sorted(set(known)),
            "unmapped_rules": unmapped_rules(sorted(set(known))),
        })


def request_shutdown():
    """Signal SSE loops to exit, then stop serving. Safe to call twice."""
    _shutdown.set()


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
            _shutdown.set()
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
