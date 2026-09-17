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

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Platform status |
| GET | `/api/stats` | Scan statistics |
| GET | `/api/inventory` | Endpoint inventory |
| GET | `/api/incidents` | All incidents |
| GET | `/api/incidents/recent` | Recent incidents |
| GET | `/api/events` | SSE event stream |
| POST | `/api/scan/start` | Start a scan |
| POST | `/api/scan/stop` | Stop current scan |
| POST | `/api/scan/reset` | Reset scan state |
| POST | `/api/agent/register` | Register endpoint |
| POST | `/api/incidents/create` | Create incident |
| POST | `/api/incidents/update` | Update incident |

### Example Requests

**Start a scan:**
```bash
curl -X POST http://localhost:8443/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"path":"/home","mode":"full"}'
```

**Register an agent:**
```bash
curl -X POST http://localhost:8443/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-server-01","ip":"10.0.0.5","os":"Ubuntu 22.04","version":"1.0"}'
```

**Get platform status:**
```bash
curl http://localhost:8443/api/status
```

## Project Structure

```
threat-ioc-platform/
├── threat_platform.sh      # CLI menu interface
├── web_ui_server.py        # Python HTTP/SSE server
├── ioc_scanner.c           # C IOC scanner source
├── ioc_scanner             # Compiled scanner binary
├── Makefile                # Build configuration
├── index.html              # Dashboard HTML
├── style.css               # EDR-style CSS theme
├── app.js                  # Frontend JavaScript
├── ioc_databases/          # IOC database files
├── logs/                   # Platform logs
├── reports/                # Scan reports
├── incidents.json          # Incident records
├── inventory.json          # Endpoint inventory
├── IOC-C2-Known_servers    # Known C2 server indicators
└── README.md               # This file
```

## Security

### Implemented Protections

- **Path Traversal Prevention** — All file paths are validated and resolved to absolute paths
- **XSS Mitigation** — Input sanitization and Content Security Policy headers
- **Request Size Limiting** — 1MB maximum request body size
- **Security Headers** — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **Input Validation** — All API inputs are validated and sanitized

### Best Practices

- Run the web server on a dedicated port (default: 8443)
- Use HTTPS in production (reverse proxy recommended)
- Regularly update IOC databases
- Review and tune detection rules to minimize false positives
- Restrict API access to authorized networks

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
