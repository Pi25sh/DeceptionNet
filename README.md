<div align="center">

<img src="dashboard/public/logo-badge.png" alt="DeceptionNet Logo" width="130" />

# DeceptionNet

> **Multi-service honeypot and deception platform with real-time MITRE ATT&CK mapping, AI-powered analysis, and live dashboard visualization.**  
> **Repository:** [https://github.com/Pi25sh/DeceptionNet](https://github.com/Pi25sh/DeceptionNet) | **Verified Commit:** [`3b7c0e5`](https://github.com/Pi25sh/DeceptionNet/tree/3b7c0e51c1e14de85b1d3ba8433402ff12b9902c)

</div>

DeceptionNet is an AI-orchestrated honeypot and attacker behavior profiling platform that detects, correlates, and classifies attacks in real time. It deploys realistic decoy services (SSH, FTP, SMB, HTTP) behind an isolated Docker network, forwards logs through a normalization pipeline, maps every action to [MITRE ATT&CK](https://attack.mitre.org/) techniques, generates AI-powered threat narratives, and presents the full picture on a modern live dashboard with one-click PDF reporting.

---

## Architecture

```
                          ┌─────────────────────────────────────────────────┐
                          │              deceptionnet (backend)             │
                          │                                                 │
  Attacker ──────────►┌───┴────┐    ┌──────────┐    ┌──────────────────┐   │
  (attacker)          │forwarder│───►│ core-api │───►│   ai-service     │   │
                      │(bridge) │    │ :8000    │    │ :8001 (Gemini/Cl)│   │
  ┌─────────────┐     └───┬────┘    └────┬─────┘    └──────────────────┘   │
  │ attack-target│────────┘              │                                  │
  │ :9090        │              ┌────────▼────────┐    ┌──────────────┐    │
  └─────────────┘              │   PostgreSQL    │    │  dashboard   │    │
                               │   :5433         │    │  :3000       │    │
  ┌─────────────┐              └─────────────────┘    └──────────────┘    │
  │   Cowrie    │────────┐                                                  │
  │   :2222     │        │   honeypot_net (isolated)                       │
  └─────────────┘        │   ─────────────────────                         │
                         │   No route to backend services                  │
  ┌─────────────┐        │                                                  │
  │   Dionaea   │────────┘                                                  │
  │ FTP/SMB/SIP │                                                           │
  └─────────────┘                                                           │
                          └─────────────────────────────────────────────────┘
```

### Data Flow

```
Attacker traffic
    │
    ▼
┌──────────────┐     JSON logs      ┌────────────────┐     POST /events     ┌────────────┐
│ attack-target │ ──────────────────►│ log-forwarder  │ ──────────────────► │  core-api  │
│ (vulnerable)  │     shared volume  │ (bridge node)  │     HTTP            │  :8000     │
└──────────────┘                     └────────────────┘                     └──────┬─────┘
                                                                                   │
                          ┌────────────────────────────────────────────────────────┤
                          │                                                        │
                          ▼                                                        ▼
                   ┌──────────────┐                                       ┌──────────────┐
                   │  PostgreSQL  │                                       │  ai-service  │
                   │  sessions +  │                                       │  :8001       │
                   │  events      │                                       │  Gemini/Claude  │
                   └──────┬───────┘                                       │  FAISS index │
                          │                                                └──────────────┘
                          ▼
                   ┌──────────────┐     WebSocket push
                   │  dashboard   │ ◄──────────────────
                   │  :3000       │
                   │  React/Vite  │
                   └──────────────┘
```

### Service Breakdown

| Service | Port | Description |
|---------|------|-------------|
| **attack-target** | 9090 | Deliberately vulnerable web app (SQLi, command injection, LFI, file upload) for attack lab exercises |
| **Cowrie** | 2222 | SSH/Telnet honeypot — captures login attempts, commands, file downloads |
| **Dionaea** | 21/42/5060/3478 | Multi-protocol honeypot — FTP, MSSQL, SIP, STUN captures |
| **custom-decoy** | 8080/6379/2525 | HTTP admin panel, Redis-like, SMTP decoy services |
| **log-forwarder** | — | Python tail + HTTP forwarder bridging honeypot_net → backend |
| **core-api** | 8000 | FastAPI — event ingestion, session tracking, MITRE mapping, JWT auth, PDF reports |
| **ai-service** | 8001 | Claude-powered summaries, semantic MITRE via FAISS embeddings, report narratives |
| **dashboard** | 3000 | React/Vite — live session visualization, technique tags, severity scoring |
| **PostgreSQL** | 5433 | Persistent store for sessions, events, techniques, and users |
| **Elasticsearch** | 9200 | (Optional) Log storage and full-text search |
| **attacker** | — | Throwaway host for launching attacks (`docker compose exec attacker bash`) |

---

## Quick Start

### Prerequisites

- **Docker Desktop** (with Docker Compose v2)
- **Git**
- (Optional) An [Anthropic API key](https://console.anthropic.com/) for AI-powered summaries

### 1. Clone and Configure

```bash
git clone <repo-url> deceptionnet
cd deceptionnet

# Create .env with your Anthropic API key (optional — works without it using mock responses)
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

### 2. Start the Platform

```bash
docker compose up -d --build
```

This starts all 10 services. PostgreSQL healthchecks gate the core-api startup.

### 3. Create an Admin User

```bash
docker compose exec -T core-api python create_admin.py
# Default: admin / deceptionnet
```

### 4. Access the Dashboard

Open [http://localhost:3000](http://localhost:3000) and log in:

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `deceptionnet` |

### 5. Launch an Attack Demo

```bash
# Copy attack scripts into the attacker container
docker cp attacker/scripts/hack-demo.sh deciptionnet-attacker-1:/opt/attack/scripts/
docker cp attacker/scripts/mini-pass.txt deciptionnet-attacker-1:/opt/attack/scripts/

# Run the full 3-stage attack simulation
docker compose exec attacker bash /opt/attack/scripts/hack-demo.sh
```

Watch the dashboard populate in real time with 14 attack sessions, MITRE technique tags, and severity scores.

### 6. Stop the Platform

```bash
docker compose down
```

To wipe all data (sessions, events, users) and start fresh:

```bash
docker compose down -v
```

---

## Services Deep Dive

### Core API (`core-api/`)

The central nervous system. Built with FastAPI and backed by PostgreSQL.

**Key Files:**
- `main.py` — FastAPI app, event ingestion, session management, WebSocket broadcast, JWT auth
- `mitre.py` — Rule-based MITRE ATT&CK mapping engine (32 rule specifications across 49 command signatures)
- `report.py` — PDF report generation (ReportLab with AI narratives)
- `database.py` — SQLAlchemy models (AttackSession, Event, SessionTechnique, User)
- `create_admin.py` — Admin user bootstrap script

**Endpoints:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/events` | None | Ingest honeypot event (called by forwarders) |
| `GET` | `/sessions` | JWT | List all attack sessions |
| `GET` | `/sessions/{id}` | JWT | Session detail with full event timeline |
| `GET` | `/incidents/{id}/report` | JWT | Generate and download PDF report |
| `POST` | `/api/v1/auth/login` | None | OAuth2 login → JWT token |
| `POST` | `/api/v1/auth/register` | JWT (admin) | Create new user |
| `GET` | `/api/v1/auth/me` | JWT | Current user info |
| `WS` | `/ws/live-events?token=<jwt>` | JWT | Real-time session + event push |

**Key Behaviors:**
- **Async ingestion**: `POST /events` accepts immediately; persistence runs in a background thread so bursts of traffic can't block the endpoint.
- **Session correlation**: Exact session-id match first, then fallback to `src_ip` + time window (5 min default) for cross-honeypot correlation. Only triggers for different honeypot types (e.g., Dionaea → Cowrie), never merges separate Cowrie sessions.
- **Atomic severity scoring**: `severity_score` is incremented via SQL `UPDATE ... SET score = score + weight` — safe for concurrent background tasks.
- **WebSocket broadcast**: Every ingested event is pushed to all connected dashboard clients in real time.

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://deceptionnet:deceptionnet@postgres:5432/deceptionnet` | Database connection string |
| `AI_SERVICE_URL` | `http://ai-service:8001/summarize` | AI summary endpoint |
| `SEMANTIC_MITRE_URL` | `http://ai-service:8001/api/v1/ai/semantic-mitre` | Semantic MITRE endpoint |
| `REPORT_NARRATIVE_URL` | `http://ai-service:8001/api/v1/ai/report-narrative` | Report narrative endpoint |
| `GROUNDING_CHECK_URL` | `http://ai-service:8001/api/v1/ai/grounding-check` | Grounding check endpoint |
| `SESSION_CORRELATION_WINDOW_MINUTES` | `5` | Time window for cross-honeypot correlation |
| `JWT_SECRET_KEY` | `deceptionnet-secret-change-in-production` | JWT signing key |

### AI Service (`ai-service/`)

Powered by Google Gemini 2.5 Flash (with fallback to Claude 3 Haiku) and a FAISS embeddings index for semantic MITRE mapping.

**Key Files:**
- `main.py` — FastAPI endpoints for summarization, semantic MITRE, grounding check, report narratives
- `embeddings_index.py` — FAISS vector index over MITRE ATT&CK technique descriptions

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/summarize` | Generate 2-3 sentence summary of attacker activity |
| `POST` | `/api/v1/ai/semantic-mitre` | Semantic similarity search for MITRE techniques |
| `POST` | `/api/v1/ai/grounding-check` | Verify techniques are supported by session events |
| `POST` | `/api/v1/ai/report-narrative` | Generate cohesive narrative paragraph for PDF reports |

**How It Works:**
1. On startup, builds a FAISS index from MITRE ATT&CK technique descriptions
2. When a session is requested for a report, the core-api sends the event timeline to the semantic-mitre endpoint
3. The index returns the top 15 most similar techniques with confidence scores
4. A grounding check filters out techniques not backed by actual event evidence
5. The LLM generates a professional narrative weaving together the summary and confirmed techniques

### Log Forwarder (`honeypot/forwarder.py`)

The bridge between isolated honeypot networks and the backend. Each honeypot type gets its own forwarder instance.

**Architecture:**
- Runs as a dual-network container: reads from `honeypot_net`, writes to `deceptionnet`
- Tails JSON log files from shared Docker volumes (re-opens file handles every second for Docker Desktop compatibility)
- Normalizes events from different honeypot formats (Cowrie, Dionaea, custom-decoy) into a common `EventPayload` schema
- Forwards to `POST http://core-api:8000/events` with HTTP retries

**Supported Honeypot Types:**
- **Cowrie** (`HONEYPOT_NAME=cowrie`): SSH/Telnet — login, login_failed, command, download, file_upload
- **Dionaea** (`HONEYPOT_NAME=dionaea`): SMB/FTP/HTTP — shellcode, download, login, scan, pcap, dns, sip, upnp, vnc, ftp
- **Custom-decoy** (`HONEYPOT_NAME=custom-decoy`): HTTP/Redis/SMTP — login_failed, http, redis, smtp, dns, scan

### Dashboard (`dashboard/`)

A modern, dark-themed React/Vite frontend with real-time session visualization.

**Key Features:**
- **Live sessions panel**: Session cards with IP, severity score, timestamp, and MITRE technique tags
- **WebSocket streaming**: Connects to `/ws/live-events` for instant updates — full snapshot on connect, then per-event pushes
- **JWT authentication**: Token stored in localStorage, auto-refresh on 401
- **Reconnect with exponential backoff**: Handles backend restarts gracefully
- **PDF report generation**: One-click download of incident reports

**Tech Stack:** React 18, Vite, Axios, Lucide icons, WebSocket API

### Attack Target (`attack-target/`)

A deliberately vulnerable web application simulating a real-world target (the "Vertex Bank Employee Portal").

**Vulnerabilities:**
- **SQL Injection**: Login form is vulnerable to `admin'--` and `' OR 1=1 --` bypass
- **Command Injection**: `/ping` endpoint pipes user input directly into a shell
- **Path Traversal**: `/read` endpoint allows `../` directory climbing
- **File Upload**: `/upload` endpoint accepts any file type including PHP web shells
- **Weak Passwords**: Default `admin` / `s3cr3t!` credentials

**Event Pipeline:** Writes JSONL logs to `/var/log/attack-target/target.jsonl`, shipped to core-api by `log-forwarder-target`. Session cookie pinning enables multi-step attack correlation into single high-severity sessions.

### Honeypots

**Cowrie** (SSH/Telnet honeypot):
- Emulates a Linux system with fake filesystem
- Captures all login attempts, commands, and file interactions
- Port 2222 (mapped from default SSH 22)

**Dionaea** (Multi-protocol honeypot):
- Catches malware uploads via FTP/SMB
- Emulates vulnerable services: FTP (21), MSSQL (42), SIP (5060), STUN (3478)
- Records shellcode, downloads, and protocol-specific interactions

**Custom Decoy** (Protocol gap filler):
- HTTP admin panel decoy (port 8080)
- Redis-like decoy (port 6379)
- SMTP decoy (port 2525)
- Fills protocol coverage gaps not covered by Cowrie or Dionaea

### Attacker Container

A throwaway host for launching attacks at the lab targets. Shares `honeypot_net` with the decoys (realistic "outside the DMZ" position) but has **no route** to core-api / ai-service / dashboard.

```bash
# Enter the attacker container
docker compose exec attacker bash

# Run individual attack scripts
bash /opt/attack/scripts/hydra-attack.sh       # Brute force
bash /opt/attack/scripts/hack-demo.sh          # Full 3-stage demo
bash /opt/attack/scripts/ssh-bruteforce.sh     # SSH brute force
bash /opt/attack/scripts/full-attack.sh        # Extended attack chain
```

---

## MITRE ATT&CK Coverage

DeceptionNet maps attacker behavior to **18+ MITRE ATT&CK techniques** using both rule-based and semantic similarity detection:

### Rule-Based Detection (`core-api/mitre.py`)

| Technique | Name | Trigger | Weight |
|-----------|------|---------|--------|
| T1110 | Brute Force | `login_failed` events | 0.5 |
| T1078 | Valid Accounts | Successful login | 1.0 |
| T1003.008 | OS Credential Dumping | `cat /etc/passwd`, `cat /etc/shadow` | 5.0 |
| T1048.003 | Exfiltration Over Alternative Protocol | File upload events | 3.0 |
| T1505.003 | Web Shell | `.php` file uploads | 1.0 |
| T1070 | Indicator Removal | `rm -rf`, `history -c` | 4.0 |
| T1071 | Application Layer Protocol (C2) | `nc -e`, `bash -i`, `/dev/tcp` | 4.0 |
| T1105 | Ingress Tool Transfer | `wget`, `curl`, `scp` | 3.0 |
| T1053.003 | Scheduled Task: Cron | `crontab`, `* * * * *` | 3.0 |
| T1098.004 | Account Manipulation: SSH Keys | `authorized_keys`, `ssh-keygen` | 3.0 |
| T1562.004 | Impair Defenses: Firewall | `iptables`, `ufw` | 3.0 |
| T1210 | Exploitation of Remote Services | Shellcode, SMB exploitation | 5.0 |
| T1190 | Exploit Public-Facing Application | HTTP, SIP, VNC, UPnP | 4.0 |
| T1046 | Network Service Discovery | `nmap`, `nc -z`, DNS, scan | 1.0 |
| T1033 | System Owner/User Discovery | `whoami`, `id`, `uname` | 1.0 |
| T1016 | System Network Configuration Discovery | `netstat`, `ss`, `ifconfig` | 1.0 |
| T1548.003 | Abuse Elevation: Sudo | `sudo`, `su` | 2.0 |
| T1222.002 | File Permissions Modification | `chmod +x`, `chmod 777` | 2.0 |

### Severity Scoring Formula

```
session_severity = Σ (weight of each positively detected event)
```

Only weights > 0 contribute. The score is atomically incremented via SQL to handle concurrent background threads safely.

**Example breakdown (Score 14.0 session):**
| Event | Technique | Weight |
|-------|-----------|--------|
| Login (valid creds) | T1078 | 1.0 |
| Command injection | T1071 | 4.0 |
| `cat /etc/shadow` | T1003.008 | 5.0 |
| `cat /etc/passwd` | T1033 | 1.0 |
| `sudo` | T1548.003 | 2.0 |
| File upload (shell.php) | T1048.003 | 3.0 |
| **Total** | | **14.0** |

---

## Attack Demo

The included attack simulation (`attacker/scripts/hack-demo.sh`) demonstrates all three stages of a real-world intrusion:

### Stage 1 — Credential Brute Force (T1110)
Hydra sprays the login endpoint with common passwords. Each failed guess creates a separate session (severity 0.5 each).

### Stage 2 — SQL Injection Login Bypass (T1078)
SQLi payloads bypass authentication entirely. Two separate bypass methods tested (severity 1.0 each).

### Stage 3 — Post-Compromise Kill Chain (Severity 14.0)
The attacker logs in with cracked credentials and chains four exploits:
1. **Command injection** via `/ping` → reads `/etc/shadow`
2. **Path traversal** via `/read` → reads `/etc/passwd`
3. **Web shell upload** via `/upload` → drops `shell.php`

All four steps are correlated into a **single high-severity session** via cookie pinning — exactly what a SOC analyst wants to see.

**Full walkthrough:** See [`docs/ATTACK-DEMO.md`](docs/ATTACK-DEMO.md) for step-by-step reproduction commands, every MITRE technique mapping, and the complete event ledger.

---

## Project Structure

```
deceptionnet/
├── ai-service/                 # AI-powered analysis service
│   ├── main.py                 # FastAPI endpoints (summarize, semantic-mitre, grounding-check)
│   ├── embeddings_index.py     # FAISS vector index over MITRE ATT&CK techniques
│   ├── Dockerfile
│   └── requirements.txt
├── attacker/                   # Throwaway attack host
│   ├── Dockerfile
│   └── scripts/
│       ├── hack-demo.sh        # Full 3-stage attack simulation
│       ├── hydra-attack.sh     # Brute force with Hydra
│       ├── ssh-bruteforce.sh   # SSH brute force
│       ├── full-attack.sh      # Extended attack chain
│       ├── mini-pass.txt       # Password wordlist
│       └── mini-users.txt      # Username wordlist
├── attack-target/              # Deliberately vulnerable web app
│   ├── app.py                  # Flask app (Vertex Bank Employee Portal)
│   ├── Dockerfile
│   ├── Dockerfile.forwarder    # Log forwarder for attack-target
│   └── target_forwarder.py     # Attack-target specific forwarder
├── core-api/                   # Backend API (FastAPI + PostgreSQL)
│   ├── main.py                 # Event ingestion, sessions, WebSocket, JWT auth
│   ├── mitre.py                # Rule-based MITRE ATT&CK mapping engine
│   ├── report.py               # PDF report generation
│   ├── database.py             # SQLAlchemy models
│   ├── create_admin.py         # Admin user bootstrap
│   ├── clean_db.py             # Database cleanup utilities
│   ├── Dockerfile
│   ├── requirements.txt
│   └── tests/
│       ├── test_mitre.py       # MITRE rule table tests (61 tests)
│       ├── test_scoring.py     # Severity scoring formula tests (8 tests)
│       ├── test_correlation.py # Session correlation tests (11 tests)
│       └── test_evaluation_benchmark.py # Inter-annotator Kappa, ablation, baselines, NAT (4 tests)
├── custom-decoy/               # HTTP/Redis/SMTP decoy services
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
├── dashboard/                  # React/Vite frontend
│   ├── src/
│   │   ├── App.jsx             # Main application (login, sessions, WebSocket)
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── Dockerfile
│   ├── package.json
│   └── vite.config.js
├── data/
│   └── benchmark/              # Held-out benchmark dataset and ground truth labels
│       ├── events_redacted.json
│       ├── labels_blind.json
│       ├── labels_ground_truth.json
│       ├── annotator_1_labels.json
│       └── annotator_2_labels.json
├── docs/
│   ├── ATTACK-DEMO.md          # Full attack simulation documentation
│   ├── EVALUATION_AND_REVIEWER_RESPONSE.md # Comprehensive reviewer response & metrics
│   ├── DeceptionNet_Final_Report.tex       # Full Capstone project report
│   └── DeceptionNet_Synopsis.tex           # Capstone project synopsis
├── honeypot/                   # Log forwarder (bridges honeypot_net → backend)
│   ├── forwarder.py            # Cowrie/Dionaea/decoy log normalization + forwarding
│   ├── Dockerfile.forwarder
│   └── requirements.txt
├── scripts/
│   └── compute_metrics.py      # Standalone metric computation CLI script
├── data/shots/                 # Dashboard screenshots and capture scripts
│   ├── dashboard-main.png
│   ├── capture.js              # CDP screenshot capture tool
│   └── capture-detail.js       # Detail view capture tool
├── docker-compose.yml          # Full stack orchestration (10+ services)
├── simulate_attack.py          # Python attack simulator (paramiko-based)
├── simulate.bat                # Windows attack simulation batch file
└── README.md
```

---

## Development

### Running Tests (84 passing tests)

Core API unit and benchmark tests cover the MITRE rule table (32 rules, 49 signatures), scoring formula, session correlation, inter-annotator Kappa, grounding filter ablation, baselines, and NAT boundary cases. They use an in-memory SQLite database — no Docker required.

```bash
cd core-api
pip install -r requirements-dev.txt
pytest -v
```

### Computing Benchmark Metrics & Ablation (Standalone CLI)

```bash
python scripts/compute_metrics.py
```

### Building Individual Services

```bash
# Core API
docker compose build core-api

# AI Service
docker compose build ai-service

# Dashboard
docker compose build dashboard

# Attack Target
docker compose build attack-target
```

### Database Access

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U deceptionnet -d deceptionnet

# Useful queries
SELECT id, src_ip, severity_score, honeypot FROM attack_sessions ORDER BY start_time DESC;
SELECT * FROM events WHERE session_id = 'web-...-5269b097' ORDER BY timestamp;
SELECT * FROM session_techniques WHERE session_id = 'web-...-5269b097';
```

---

## Network Isolation

DeceptionNet enforces strict network isolation between honeypots and backend services:

| Network | Containers | Purpose |
|---------|------------|---------|
| `honeypot_net` | Cowrie, Dionaea, custom-decoy, attack-target, attacker | Attacker-facing — no route to backend |
| `deceptionnet` | core-api, ai-service, dashboard, PostgreSQL, log-forwarders | Backend services — never reachable from honeypots |

Log-forwarders are the **only bridge** between the two networks. They can read honeypot logs and POST events to core-api, but honeypots themselves have no network path to the backend.

---

## Troubleshooting

### Dashboard shows "No active sessions"
- Ensure attack-target is healthy: `docker compose ps attack-target`
- Check forwarder logs: `docker compose logs log-forwarder-target`
- Verify events are reaching core-api: `curl http://localhost:8000/sessions` (needs JWT)

### PostgreSQL won't start (port 5433 already in use)
The host port is 5433 (5432 is commonly taken). Change the port mapping in `docker-compose.yml` if needed:
```yaml
ports:
  - "5434:5432"  # Use a different host port
```

### AI Service returns mock summaries
Configure your Google Gemini API key (primary) or Anthropic Claude key (fallback) in `.env`:
```bash
# Google Gemini 2.5 Flash (Primary)
echo "GEMINI_API_KEY=AIzaSy..." >> .env

# Anthropic Claude 3 Haiku (Architectural Fallback)
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

docker compose restart ai-service
```

### Log forwarder isn't picking up events
The forwarder uses `os.stat()` to detect new data, re-opening the file every second. On Docker Desktop, named volumes can have delayed propagation — the forwarder handles this by re-stat-ing rather than using a persistent file handle.

---

## Team

| Member | Responsibility |
|--------|---------------|
| Member 1 | Core API — event ingestion, session management, MITRE mapping, JWT auth, PDF reports |
| Member 2 | Honeypot forwarding — Cowrie/Dionaea log normalization, network isolation, attack-target |
| Member 3 | AI service — Claude integration, semantic MITRE (FAISS), grounding check, report narratives |
| Member 4 | Dashboard — React/Vite frontend, WebSocket streaming, live session visualization |

---

## License

This project was built for educational purposes as part of a cybersecurity coursework. All attacks run against deliberately vulnerable services inside an isolated Docker lab network — nothing targets real systems.

---

*Built with FastAPI, PostgreSQL, Google Gemini 2.5 Flash / Claude, React, Docker, and MITRE ATT&CK.*
