# DeceptionNet Claim Ledger

This document serves as the authoritative, repo-grounded Claim Ledger for DeceptionNet. Every empirical figure, software version, metric, and evaluation claim made in the manuscript is formally recorded here with its value, source file or reproducible execution command, and verification status.

## 1. Core Architecture & Grounded System Constants

| Claim ID | Claim Description | Grounded Value | Source File / Code Construct | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SYS-01** | Pinned Git Commit SHA | `c18885798469d798bd2533affad279724c4662ab` | `git rev-parse HEAD` | **Verified** |
| **SYS-02** | Core API Web Framework | FastAPI 0.109.2 | `core-api/requirements.txt:L1` (`fastapi==0.109.2`) | **Verified** |
| **SYS-03** | ORM Framework | SQLAlchemy 2.0.25 | `core-api/requirements.txt:L3` (`sqlalchemy==2.0.25`) | **Verified** |
| **SYS-04** | ASGI Server | Uvicorn 0.27.1 | `core-api/requirements.txt:L2` (`uvicorn==0.27.1`) | **Verified** |
| **SYS-05** | Production Database | PostgreSQL 16 | `docker-compose.yml:L3-L12` (`image: postgres:16`) | **Verified** |
| **SYS-06** | Test/Export Database | SQLite 3 | `core-api/database.py`, `scripts/export_docker_case_study.py` | **Verified** |
| **SYS-07** | Frontend UI Framework | React 18.2.0 | `dashboard/package.json` (`"react": "^18.2.0"`) | **Verified** |
| **SYS-08** | Frontend Build Tool | Vite 5.1.0 | `dashboard/package.json` (`"vite": "^5.1.0"`) | **Verified** |
| **SYS-09** | Frontend Iconography & Charts | Lucide-React 0.330.0, Recharts 2.15.4 | `dashboard/package.json` | **Verified** |
| **SYS-10** | Frontend Styling | Vanilla CSS (Tailwind CSS absent) | `dashboard/package.json`, `dashboard/src/index.css` | **Verified** |
| **SYS-11** | Semantic Embedding Model | `sentence-transformers/all-MiniLM-L6-v2` | `ai-service/embeddings_index.py:L14` | **Verified** |
| **SYS-12** | Vector Dimension & Index | 384 dimensions, FAISS-CPU IndexFlatIP | `ai-service/embeddings_index.py:L16-L20` | **Verified** |
| **SYS-13** | Decoy Honeypot Daemons | Cowrie (SSH/Telnet), Dionaea (SMB/FTP/HTTP), Custom Decoy (ports 16379, 2525), Attack-Target (Flask port 9090) | `docker-compose.yml` | **Verified** |

---

## 2. Rule Engine & Threat Attribution

| Claim ID | Claim Description | Grounded Value | Source File / Code Construct | Status |
| :--- | :--- | :--- | :--- | :--- |
| **RUL-01** | Command Keyword Rules Count | 16 rules | `core-api/mitre.py:MITRE_RULES` (`len(MITRE_RULES) == 16`) | **Verified** |
| **RUL-02** | Command Keyword Signatures Count | Exactly 49 signatures | `sum(len(r['keywords']) for r in MITRE_RULES) == 49` | **Verified** |
| **RUL-03** | Event-Type Normalization Rules Count | 18 rules | `core-api/mitre.py:EVENT_TYPE_RULES` (`len(EVENT_TYPE_RULES) == 18`) | **Verified** |
| **RUL-04** | Total Deterministic Rules Count | 34 rules (16 + 18) | `core-api/mitre.py` | **Verified** |
| **RUL-05** | Distinct MITRE ATT&CK Techniques | 22 techniques | Evaluated set across `MITRE_RULES` and `EVENT_TYPE_RULES` | **Verified** |
| **RUL-06** | MITRE ATT&CK Matrix Version | Version 14.1 (Enterprise) | Reference [23], `core-api/mitre.py` | **Verified** |
| **RUL-07** | Short Keyword Word Boundary | Regex `\b` for single alphabetic tokens | `core-api/mitre.py:_has_keyword` | **Verified** |
| **RUL-08** | Credential Dumping Precedence | `T1003.008` (weight 5.0) evaluated before `T1098` (weight 3.0) | `core-api/mitre.py:MITRE_RULES` order | **Verified** |
| **RUL-09** | Identity vs System Discovery | `whoami`/`id` -> `T1033` (1.0); `uname` -> `T1082` (1.0) | `core-api/mitre.py:MITRE_RULES` | **Verified** |
| **RUL-10** | Event-Type Precedence | `login_failed` (`T1110`, 0.5) evaluated before `login` (`T1078`, 1.0) | `core-api/mitre.py:EVENT_TYPE_RULES` order | **Verified** |

---

## 3. Scoring & Correlation Invariants

| Claim ID | Claim Description | Grounded Value | Source File / Code Construct | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SCO-01** | Additive Scoring Formula | `round(Severity_current + w_i, 2)` for `w_i > 0` | `core-api/scoring.py:combine_severity` | **Verified** |
| **SCO-02** | Noise Invariance | Unmapped events (`w_i == 0.0`) leave cumulative score unchanged | `core-api/scoring.py:test_severity_from_events_ignores_unmapped_commands` | **Verified** |
| **SCO-03** | Operational Severity Tiers | Low (< 1.0), Elevated (1.0–2.4), High (2.5–3.9), Critical (≥ 4.0) | `dashboard/src/utils.js:getSeverityTier` | **Verified** |
| **COR-01** | Sliding Correlation Window | 5 minutes | `core-api/main.py:SESSION_CORRELATION_WINDOW_MINUTES = 5` | **Verified** |
| **COR-02** | Intra-Honeypot Session Isolation | New session created if unseen session ID arrives from same honeypot | `core-api/main.py:get_or_create_session` | **Verified** |
| **COR-03** | Cross-Honeypot Campaign Fusion | Events from different honeypots sharing IP within 5 min attach to active session | `core-api/main.py:get_or_create_session` | **Verified** |
| **AI-01** | Lexical Grounding Threshold | Technique term token length `> 3` characters required to appear in logs | `ai-service/main.py:L95-L105` | **Verified** |
| **AI-02** | Decoupled LLM Architecture | LLMs invoked strictly post-capture for summarization; removed from live decoy socket loop | `ai-service/main.py`, `core-api/main.py` | **Verified** |
| **AI-03** | Residual Prompt Injection Risk | Post-capture summarizer still processes untrusted, attacker-controlled telemetry strings | Manuscript Section 7, `docs/DeceptionNet_Submission_Manuscript.docx` | **Verified** |

---

## 4. Test Suite Verification

| Claim ID | Test Module | Invariants Verified | Pass / Fail Count | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TST-01** | `core-api/tests/test_mitre.py` | Rule table counts, ATT&CK ID format, word boundaries, event type precedence | **61 passed**, 0 failed | **Verified** |
| **TST-02** | `core-api/tests/test_correlation.py` | Temporal bounds, cross-honeypot fusion, intra-honeypot isolation, concurrent savepoints | **12 passed**, 0 failed | **Verified** |
| **TST-03** | `core-api/tests/test_scoring.py` | Monotonic additive scoring, noise filtering, incremental vs bulk score equivalence | **9 passed**, 0 failed | **Verified** |
| **TST-04** | `core-api/tests/test_evaluation_benchmark.py` | Benchmark schema validation, representative attack sequence mapping, NAT isolation | **2 passed**, 0 failed | **Verified** |
| **TST-ALL** | **Comprehensive Test Suite** | Full backend test run executed in clean environment | **84 passed (100%)**, 0 failed (2.24s) | **Verified** |

---

## 5. Live Docker Harness Case Study (`REAL_RUN`)

| Claim ID | Case Study Metric | Grounded Value | Source File / Evidence Artifact | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CAS-01** | Provenance Execution Type | `docker_live_harness` (multi-container network execution) | `results/case_study_raw.json:provenance` | **Verified** |
| **CAS-02** | Scripted Attack Harness | `attacker/scripts/full-attack.sh` executed from `attacker` container (172.21.0.5) | `results/docker_compose_logs.txt`, `results/case_study_raw.json` | **Verified** |
| **CAS-03** | Total Ingested Events | Exactly 14 events | `results/case_study_raw.json:run_metrics.total_events`, `results/postgres_dump.sql` (14 COPY rows) | **Verified** |
| **CAS-04** | Total Sessions Created | Exactly 6 sessions | `results/case_study_raw.json:run_metrics.total_sessions`, `results/postgres_dump.sql` (6 COPY rows) | **Verified** |
| **CAS-05** | Primary Campaign Session ID | `web-172.21.0.5-364304df` | `results/case_study_raw.json:run_metrics.campaign_session_id` | **Verified** |
| **CAS-06** | Primary Campaign Event Count | Exactly 9 events | `results/case_study_raw.json:sessions[0].event_count` | **Verified** |
| **CAS-07** | Primary Campaign Final Severity | Exactly 26.0 (Critical tier) | `results/case_study_raw.json:sessions[0].severity_score`, `results/postgres_dump.sql` | **Verified** |
| **CAS-08** | Unauthenticated Sessions Count | Exactly 5 sessions (Stage 2 credential stuffing) | `results/case_study_raw.json:run_metrics.unauthenticated_sessions_count` | **Verified** |
| **CAS-09** | Unauthenticated Session Severity | Exactly 0.5 each (Low tier, `T1110 - Brute Force`) | `results/case_study_raw.json:sessions[1..5]` | **Verified** |
| **CAS-10** | Session Cookie Binding | Signed Flask session cookie pinned across Stages 1, 3, 4, 5, 6 via curl `-c`/`-b` | `attacker/scripts/full-attack.sh`, `attack-target/app.py` | **Verified** |
| **CAS-11** | Raw Container Log Stream | 1.46 MB log stream from all containers during live run | `results/docker_compose_logs.txt` (UTF-16) | **Verified** |
| **CAS-12** | Raw Database Dump | 41 KB PostgreSQL database export | `results/postgres_dump.sql` (UTF-16) | **Verified** |
| **CAS-13** | SQLite Database Replica | Committed SQLite database export | `results/case_study.db` | **Verified** |

---

## 6. Rule Table Evaluation Microbenchmark

| Claim ID | Benchmark Metric | Grounded Value | Source File / Execution Command | Status |
| :--- | :--- | :--- | :--- | :--- |
| **LAT-01** | Scope of Benchmark | Microbenchmark of rule table lookup in memory (excludes network & database time) | `scripts/benchmark_rule_latency.py` | **Verified** |
| **LAT-02** | Total Evaluations | 140,000 evaluations (10,000 iterations × 14 corpus items) | `results/rule_latency_benchmark.json:total_evaluations` | **Verified** |
| **LAT-03** | Mean Evaluation Latency | 10.56 µs (0.01056 ms) | `results/rule_latency_benchmark.json:mean_latency_us` | **Verified** |
| **LAT-04** | Median Evaluation Latency | 2.50 µs | `results/rule_latency_benchmark.json:median_latency_us` | **Verified** |
| **LAT-05** | Standard Deviation | 20.80 µs | `results/rule_latency_benchmark.json:stdev_latency_us` | **Verified** |
| **LAT-06** | 95th Percentile Latency (p95) | 34.10 µs | `results/rule_latency_benchmark.json:p95_latency_us` | **Verified** |
| **LAT-07** | 99th Percentile Latency (p99) | 58.10 µs (0.0581 ms) | `results/rule_latency_benchmark.json:p99_latency_us` | **Verified** |
| **LAT-08** | Minimum Latency | 0.20 µs | `results/rule_latency_benchmark.json:min_latency_us` | **Verified** |
| **LAT-09** | Maximum Latency | 2,170.20 µs (2.17 ms) | `results/rule_latency_benchmark.json:max_latency_us` | **Verified** |
| **LAT-10** | Benchmark Hardware: Processor | 11th Gen Intel(R) Core(TM) i5-11320H @ 3.20GHz (4 cores / 8 threads) | Machine hardware query via `Win32_Processor` | **Verified** |
| **LAT-11** | Benchmark Hardware: Memory | 8 GB RAM (7.79 GB physical RAM) | Machine hardware query via `psutil` | **Verified** |
| **LAT-12** | Benchmark Machine: OS | Microsoft Windows 11 Build 26300 | Machine OS query via `platform.platform()` | **Verified** |
| **LAT-13** | Benchmark Machine: Runtime | Python 3.14.6 (64-bit) | Machine runtime query via `platform.python_version()` | **Verified** |

---

## 7. Candid Negative Invariants & System Boundaries

| Claim ID | Limitation Description | Grounded Architectural Boundary | Status |
| :--- | :--- | :--- | :--- |
| **LIM-01** | Cross-Honeypot-Only Correlation | Intra-honeypot connections are isolated; multiple disconnected SSH probes from same IP are not linked into one campaign | **Confirmed** |
| **LIM-02** | Shared NAT / Proxy Aggregation | Distinct external hosts behind shared NAT or egress proxy are merged if within 5-min correlation window | **Confirmed** |
| **LIM-03** | Command Obfuscation Evasion | 16 keyword rules evaluate literal tokens; encoded or split commands (`c$u\a\t`, base64 pipes) yield weight 0.0 (Unmapped) | **Confirmed** |
| **LIM-04** | Gameable Lexical Grounding Filter | Technique tokens > 3 chars checked in raw logs; attacker inserting tokens into HTTP strings can force ground false techniques | **Confirmed** |
| **LIM-05** | Lab-Only Evaluation | Evaluated strictly against scripted testbed containers; no field deployment or wild internet traffic claims | **Confirmed** |
| **LIM-06** | No Baseline Comparison | No comparative throughput or detection rate benchmarks against external commercial SIEM tools | **Confirmed** |
| **LIM-07** | Prompt Injection Residual | Decoupling LLM from interactive socket loop eliminates live hijacking, but post-capture summarizer still ingests untrusted text | **Confirmed** |
