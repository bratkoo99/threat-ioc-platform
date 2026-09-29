# Threat Intelligence & IOC Scanner Platform

A comprehensive security operations platform featuring a C-based IOC scanner, Python web dashboard with real-time SSE updates, agent-based endpoint monitoring, and incident management.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [Agent Deployment](#agent-deployment)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Security](#security)
- [License](#license)

## Overview

This platform provides threat hunting and IOC (Indicator of Compromise) scanning capabilities for security operations teams. It combines a high-performance C scanner for hash and pattern matching with a modern web-based dashboard for real-time monitoring and incident management.

The system is designed for:
- **SOC Analysts** — triage alarms and investigate incidents
- **Detection Engineers** — develop and tune detection rules
- **Threat Hunters** — proactively search for threats across endpoints
- **Security Architects** — design security monitoring infrastructure

## Features

### Core Scanning Engine
- SHA-256 hash matching against known threat actor databases
- Filename pattern matching for ransomware families
- CSV-based IOC database support
- Quick scan mode for rapid triage
- Full recursive directory scanning
- Custom hash and pattern scanning
- Single file analysis

### Web Dashboard
- Real-time scan progress via Server-Sent Events (SSE)
- Live file scanning activity feed
- Threat detection alerts
- Endpoint inventory management
- Incident and alarm management
- IOC database management
- Report generation and viewing
- Dark-themed EDR-style interface

### Agent System
- Lightweight agent script for remote endpoints
- Automatic registration with central server
- Heartbeat monitoring
- Remote scan execution
- Endpoint inventory collection
- Support for Linux and Windows agents

### Incident Management
- Automatic incident creation from scan threats
- Manual incident creation
- Incident severity classification
- Alarm tracking and correlation
- Incident notes and updates

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (Browser)                   │
│                   http://localhost:8443                      │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│              Python Web Server (web_ui_server.py)            │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐  │
│  │  REST   │ │   SSE    │ │   Agent   │ │   Incident   │  │
│  │  API    │ │  Stream  │ │   Sync    │ │   Manager    │  │
│  └─────────┘ └──────────┘ └───────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│               C IOC Scanner (ioc_scanner.c)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  SHA-256     │  │   Pattern    │  │   CSV Database   │  │
│  │  Hash Match  │  │   Matching   │  │   Loader         │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Required
- Python 3.6+
- GCC compiler
- OpenSSL development libraries
- Linux/macOS environment

### Optional
- curl (for agent deployment)
- ssh (for remote agent installation)

### Install Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install gcc openssl-devel python3
```

**Ubuntu/Debian:**
```bash
sudo apt install gcc libssl-dev python3
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/bratkoo99/threat-ioc-platform.git
cd threat-ioc-platform
```

2. Compile the C scanner:
```bash
make
```

3. Start the web server:
```bash
python3 web_ui_server.py
```

4. Open the dashboard:
```
http://localhost:8443
```

## Usage

### CLI Menu

Launch the interactive CLI:
```bash
./threat_platform.sh
```

Menu options:
1. **Compile Scanner** — Build the C IOC scanner
2. **Quick Scan** — Fast system scan
3. **Full Scan** — Deep recursive scan
4. **Custom Scan** — Scan with custom parameters
5. **Scan Single File** — Analyze a specific file
6. **View Research** — Display IOC research document
7. **Manage IOC Databases** — Add/edit threat databases
8. **Import IOCs** — Import indicators from CSV
9. **View Reports** — Browse scan reports
10. **Threat Intel Lookup** — Search threat intelligence
11. **Generate IOC Report** — Create detailed reports
12. **Self-Test** — Run platform diagnostics
13. **Launch Web Dashboard** — Start web UI on port 8443

### Web Dashboard

The dashboard provides:

- **Overview** — System status, active scans, recent threats
- **Scan Control** — Start/stop scans, view progress
- **Inventory** — Endpoint management and status
- **Incidents** — Alarm triage and investigation
- **Databases** — IOC database management
- **Reports** — Historical scan reports

### Agent Deployment

Deploy agents to remote endpoints:

```bash
# Download and run agent installer
curl -sL http://YOUR_SERVER:8443/api/agent/script | sudo bash -s run

# Or install manually
scp ioc_agent.sh user@remote-server:/tmp/
ssh user@remote-server "sudo bash /tmp/ioc_agent.sh install"
```

Agent configuration:
```bash
# Set custom server URL
export SERVER_URL="http://your-server:8443"
./ioc_agent.sh run
```

## Web Dashboard

### Real-Time Scanning

The dashboard uses Server-Sent Events (SSE) for real-time updates:
- Live scan progress percentage
- Files scanned counter
- Active file being scanned
- Threat detection alerts
- Scan completion status

### Incident Management

Incidents are automatically created when:
- Known threat hashes are detected
- Ransomware patterns match filenames
- Suspicious IOCs are found

Manual incident creation:
```bash
curl -X POST http://localhost:8443/api/incidents/create \
  -H "Content-Type: application/json" \
  -d '{"title":"Suspicious Activity","description":"Detected on endpoint","severity":"high","source":"manual"}'
```

## API Reference

All `/api/*` routes except `/api/status` and `/` require a credential. Use the
session key for everything, or the agent key for `/api/agent/*` only:

```bash
curl -H "Authorization: Bearer $SESSION_KEY" https://localhost:8443/api/stats
```

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/status` | public | Platform status |
| POST | `/api/login` | public | Exchange session key for a cookie |
| GET | `/api/logout` | session | Clear the session cookie |
| GET | `/api/stats` | session | Scan + event-lake statistics |
| GET | `/api/inventory` | session | Endpoint inventory |
| GET | `/api/incidents` | session | All incidents (with notes) |
| GET | `/api/incidents/recent` | session | Recent incidents |
| GET | `/api/events` | session | **SSE** progress stream (not a query) |
| GET | `/api/lake` | session | Paginated event query, filterable |
| GET | `/api/entity` | session | **The pivot**: all events for one entity |
| GET | `/api/databases` | session | IOC database files |
| GET | `/api/reports` | session | Saved scan reports |
| GET | `/api/agent/script` | session | Download the agent script |
| GET | `/api/agent/key` | session | Reveal the agent key |
| POST | `/api/scan/start` | session | Start a scan |
| POST | `/api/scan/stop` | session | Stop current scan |
| POST | `/api/scan/reset` | session | Reset scan state |
| POST | `/api/agent/register` | agent | Register endpoint |
| POST | `/api/agent/heartbeat` | agent | Endpoint heartbeat |
| POST | `/api/agent/scan` | agent | Request a scan |
| POST | `/api/incidents/create` | session | Create incident |
| POST | `/api/incidents/update` | session | Update incident status / add note |

`/api/events` is the live SSE stream and holds the connection open. The
paginated event query is `/api/lake` — a separate path, because one URL cannot
mean both an endless stream and a paged result set.

### The pivot

`GET /api/entity?type=<entity_type>&value=<value>` returns every event ever
recorded for that value, across all sources, with first/last seen, the hosts
involved, and the contributing sources. This is the query the whole canonical
schema exists to make possible: an analyst sees a hash once and immediately
knows where else it has been.

```bash
# Everything ever seen for one file hash
curl -H "Authorization: Bearer $SESSION_KEY" \
  "https://localhost:8443/api/entity?type=file_hash&value=275a021bbfb6489e..."

# Everything on one host, in a time window
curl -H "Authorization: Bearer $SESSION_KEY" \
  "https://localhost:8443/api/entity?type=host&value=web-server-01"
```

Valid `type` values: `file_hash`, `file_path`, `file_name`, `ip`, `domain`,
`url`, `process`, `registry_key`, `user`, `host`, `mutex`, `scheduled_task`,
`cert`, `email`. An unknown type returns 400 with the valid list.

### Querying the lake

`GET /api/lake` supports `type`, `severity`, `host`, `source`, `since`, `until`
(ISO-8601) and `limit` (capped at 1000):

```bash
curl -H "Authorization: Bearer $SESSION_KEY" \
  "https://localhost:8443/api/lake?type=threat_hit&severity=critical&limit=50"
```

### Example Requests

**Start a scan:**
```bash
curl -X POST https://localhost:8443/api/scan/start \
  -H "Authorization: Bearer $SESSION_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path":"/home","mode":"full"}'
```

**Register an agent:**
```bash
curl -X POST https://localhost:8443/api/agent/register \
  -H "Authorization: Bearer $AGENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-server-01","ip":"10.0.0.5","os":"Ubuntu 22.04","version":"1.0"}'
```

**Get platform status:**
```bash
curl https://localhost:8443/api/status
```

## Project Structure

```
threat-ioc-platform/
├── threat_platform.sh      # CLI menu interface
├── web_ui_server.py        # Python HTTP/SSE server (TLS + auth)
├── ioc_scanner.c           # C IOC scanner source
├── ioc_scanner             # Compiled scanner binary
├── Makefile                # Build configuration
├── index.html              # Dashboard HTML
├── style.css               # EDR-style CSS theme
├── app.js                  # Frontend JavaScript
├── ARCHITECTURE.md         # Platform design decisions
├── tiox/                   # Platform package (schema, connectors, store)
├── tests/                  # Unit + integration + e2e tests
├── data/                   # LOCAL threat intel (gitignored)
├── ioc_databases/          # IOC database files (gitignored)
├── logs/                   # Platform logs (gitignored)
├── reports/                # Scan reports (gitignored)
├── incidents.json          # Incident records (gitignored, legacy)
└── inventory.json          # Endpoint inventory (gitignored, legacy)
```

## Threat Intel Data Is Not In Git

Your indicator set is a **data file, not source**, and it is deliberately
untracked. This repo is public, so a committed IOC list would publish your
indicators — and feeds change constantly, which would mean a commit per refresh.

```bash
make ioc            # creates data/IOC-C2-Known_servers.local
```

The file it creates is gitignored along with everything else in `data/`. The CLI's
research viewer (`threat_platform.sh`) reads it from there. Point it elsewhere with
`TIOX_RESEARCH_FILE=/path/to/your/file`.

Populate it from public sources — CISA AIS, abuse.ch, MISP — or your own hunting
notes. Nothing in the scanner depends on it: the scanner's built-in hash and
pattern databases are compiled in, and external feeds are loaded at runtime with
`./ioc_scanner -H hashes.csv -P patterns.csv /path`.

## Security

### Implemented Protections

- **TLS by default** — port 8443 is genuinely encrypted, not just conventionally so. Startup fails loudly if the certificate is missing instead of silently serving cleartext. Disable only for a loopback dev session with `TIOX_TLS=0`.
- **Two-credential auth** — an agent key scoped to `/api/agent/*`, and a session key for everything else, so a compromised endpoint cannot read the dashboard or mutate incidents. Compared in constant time.
- **Protected by default** — the auth gate runs in the request handler, so a newly added endpoint is covered automatically rather than by remembering to guard it.
- **Session cookie** — `HttpOnly; SameSite=Strict`, with `Secure` added automatically over TLS. The dashboard exchanges the session key for the cookie because `EventSource` cannot set headers.
- **Binds loopback by default** — `127.0.0.1`, not `0.0.0.0`. Set `TIOX_BIND` to expose it deliberately.
- **Path Traversal Prevention** — All file paths are validated and resolved to absolute paths
- **XSS Mitigation** — Input sanitization and Content Security Policy headers
- **Request Size Limiting** — 1MB maximum request body size
- **Security Headers** — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **Input Validation** — All API inputs are validated and sanitized
- **Key material never committed** — `.agent_key` and `certs/` are gitignored; the key file is created mode 0600

### Best Practices

- Generate a certificate before first run: `make cert`
- The session key is printed at startup and **not persisted**; set `TIOX_SESSION_KEY` to pin it
- Restrict `TIOX_BIND` exposure at the firewall, not just in the app
- Regularly update IOC databases
- Review and tune detection rules to minimize false positives

### Production Deployment

For production use:
```bash
# Use a reverse proxy (nginx/caddy) for HTTPS
# Run behind a firewall
# Use systemd for service management
# Enable SELinux/AppArmor policies
```

## License

This project is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**Disclaimer:** This platform is designed for authorized security operations. Always obtain proper authorization before scanning systems you do not own.
