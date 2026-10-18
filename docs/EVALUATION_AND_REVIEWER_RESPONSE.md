# DeceptionNet — System Verification, Case Study & Reviewer Response Dossier

> **Repository:** [https://github.com/Pi25sh/DeceptionNet](https://github.com/Pi25sh/DeceptionNet)  
> **Target Venue:** Student Capstone Project / System Demonstration Track / Academic Workshop  
> **Evaluation Date:** October 2026  
> **Core Pipeline:** Decoupled Microservice Honeypots + Core Security Engine + React Dashboard + AI Incident Reporting  
> **Committed Run Artifact:** `results/case_study_raw.json` & `results/case_study.db`  

---

## 1. Direct Disclosure & Integrity Rectifications

In accordance with reviewer instructions and the Gravitas engineering invariants, all previously flagged synthetic metrics, unexecuted evaluation projections, and hand-written predictor assertions have been completely excised from the repository:

1. **Retraction of 21-Day Synthetic Telemetry:** All historical mentions of a "21-day deployment," "184,927 connection attempts," "42,615 sessions," and the "350-sample held-out evaluation" have been permanently removed from all repository documentation and LaTeX thesis manuscripts.
2. **Deletion of Simulated Predictors & F1 Assertions:**
   - The standalone CLI script `scripts/compute_metrics.py` has been **deleted**.
   - The artificial baseline comparison and ablation tests containing hardcoded predictor branches (`test_ablation_comparison` and `test_baselines_vs_deceptionnet`) have been **deleted**.
   - The "Computing Benchmark Metrics & Ablation" section has been **removed from README.md**.
3. **Illustrative Sample Classification:** The remaining benchmark JSON files under `data/benchmark/` (`events_redacted.json`, `labels_blind.json`, `labels_ground_truth.json`) are explicitly labeled via `data/benchmark/README.md` as an **illustrative sample dataset** provided strictly for schema contracts and format verification, with no experimental or comparative superiority claims attached.
4. **Adoption of Grounded Data Rule:** Every number, technique ID, scoring weight, and event count in the paper, documentation, and this dossier is directly copy-pasted from committed code definitions (`core-api/mitre.py`) and verified pipeline execution output (`results/case_study_raw.json`).

---

## 2. Re-Scoped Architecture & Operational Scope

DeceptionNet is an educational capstone prototype and system demonstration designed to study active cyber defense across containerized microservices:

1. **Multi-Service Decoy Infrastructure:**
   - **Cowrie:** Low-to-medium interaction SSH/Telnet decoy capturing authentication attempts, session keystrokes, and downloaded files.
   - **Dionaea:** Multi-protocol decoy exposing SMB, FTP, SIP, and HTTP endpoints to trap automated network exploitation probes.
   - **Attack-Target:** Deliberately vulnerable Web application portal (Python/Flask on port 9090) exposing realistic flaw patterns: SQL injection login bypass, unrestricted command injection, local file inclusion / path traversal, reflected XSS, and unrestricted file upload.
2. **Log Normalization & Forwarding Bridge (`honeypot/forwarder.py`):**
   - Tails raw container logs, normalizes heterogeneous schemas into a standardized event payload (`session_id`, `event_type`, `timestamp`, `src_ip`, `input`, `message`), and forwards payloads over HTTP to `core-api`.
3. **Core Security Engine (`core-api`):**
   - **Rule-Based MITRE ATT&CK Mapper (`core-api/mitre.py`):** 33 deterministic rules (16 command keyword rules spanning 50 shell signatures, and 18 protocol event-type rules, including distinct rules for `whoami`/`id` $\to$ T1033, `uname` $\to$ T1082, and `sqli` $\to$ T1190).
   - **Sliding-Window Session Correlation (`main.py:get_or_create_session`):** 5-minute sliding window correlating cross-honeypot reconnaissance by IP, with strict intra-honeypot session isolation (`honeypot != honeypot`).
   - **Monotonic Threat Severity Scoring (`mitre.py:combine_severity`):** Additive severity aggregation updating session threat levels atomically in the database (`UPDATE AttackSession SET severity_score = coalesce(severity_score, 0) + weight`).
   - **Authentication & RBAC (`main.py`):** OAuth2 Password Bearer authentication, bcrypt hashing, and JWT authorization gating REST endpoints and WebSocket channels (`/ws/live-events?token=<jwt>`).
4. **Decoupled AI Incident Reporting Engine (`ai-service` & `core-api/report.py`):**
   - Operates strictly asynchronously *after* capture. It does not sit in the interactive loop as a decoy. It compiles captured event ledgers into executive threat summaries and automated ReportLab PDF reports using Google Gemini 2.5 Flash / Claude 3 Haiku.
5. **Real-Time Operator Dashboard (`dashboard`):**
   - React 18, Vite, and WebSocket streaming client displaying live attack feeds, MITRE technique tags, session inspection drawers, and PDF report downloads.

---

## 3. Automated Test Suite Verification (84 Passing Tests)

The core logic of DeceptionNet is verified through an automated test suite executed via `pytest core-api/tests`:

```text
======================= 84 passed, 24 warnings in 2.20s =======================
```

Every test in the suite executes real functional logic against an in-memory SQLite database (with WAL mode enabled for concurrency testing):

| Test Module | Test Count | Scope & Verification Contract |
|---|---|---|
| [`test_mitre.py`](file:///d:/deciptionnet/core-api/tests/test_mitre.py) | **61 tests** | Verifies all deterministic rule specifications across command keywords and event-type rules. Validates regex word boundaries (preventing false positives on sub-tokens), case-insensitivity, and priority precedence (e.g., credential dumping `/etc/shadow` taking precedence over generic password rules; `uname` mapping strictly to T1082; `whoami`/`id` mapping strictly to T1033). |
| [`test_correlation.py`](file:///d:/deciptionnet/core-api/tests/test_correlation.py) | **12 tests** | Verifies session ingestion, exact session identifier matching, sliding-window cross-honeypot merging (5-minute window), duplicate event deduplication, database unique constraints, and **multithreaded technique deduplication** (`test_concurrent_upsert_technique_threads` testing 8 concurrent threads calling `upsert_technique` with database savepoints under WAL mode). |
| [`test_scoring.py`](file:///d:/deciptionnet/core-api/tests/test_scoring.py) | **9 tests** | Verifies additive scoring formulas, non-detection zero weighting, decimal rounding, unmapped command filtering, full attack accumulation, batch vs incremental equivalence, and **`test_harness_attack_session_score` asserting the exact cumulative score of 26.0 matching the authenticated campaign session in `results/case_study_raw.json`**. |
| [`test_evaluation_benchmark.py`](file:///d:/deciptionnet/core-api/tests/test_evaluation_benchmark.py) | **2 tests** | Validates schema integrity of the illustrative sample dataset (`test_illustrative_benchmark_sample_schema`) and verifies 5 real boundary scenarios in `get_or_create_session` (`test_correlation_cases_ground_truth`: cross-honeypot correlation, independent same-honeypot session isolation, 4m50s inside-window merge, 5m10s outside-window isolation, and NAT IP collision). |

---

## 4. Real Attack Harness Capture Case Study (7 Sessions, 15 Events, Campaign Score 26.0)

To replace all hypothetical figures, the automated attack harness (`attacker/scripts/full-attack.sh`) was executed against the running web application (`attack-target:9090`). Telemetry was processed through the real `core-api` pipeline (`get_or_create_session`, `map_event_to_mitre`, `combine_severity`, and `upsert_technique`), stored in SQLite, and committed as raw output to [`results/case_study_raw.json`](file:///d:/deciptionnet/results/case_study_raw.json) and [`results/case_study.db`](file:///d:/deciptionnet/results/case_study.db).

### 4.1 Exact Session Assignment Method
- **Authenticated Campaign Session:** The web application (`attack-target/app.py:current_sid`) pins the session ID `web-<ip>-<hex>` in a signed Flask session cookie (`session["sid"]`) upon login. When `full-attack.sh` authenticates in Stage 1 with curl's cookie jar (`-c $COOKIE_JAR`), follow-up post-exploitation requests in Stages 3–6 present the cookie (`-b $COOKIE_JAR`), binding all 9 exploited events to the **same session ID** (`web-172.21.0.100-c9a1b8e2`).
- **Unauthenticated Sessions:** In contrast, credential stuffing requests in Stage 2 and the nmap scan in Stage 7 send no cookies; each unauthenticated request is assigned a fresh random UUID session ID, yielding 5 separate brute-force sessions and 1 scan session.
- **Run Totals:** Exactly **7 sessions** created across **15 events** (1 authenticated campaign + 5 credential stuffing + 1 network scan).

### 4.2 Event Telemetry & Attribution Ledger (Authenticated Attack Campaign)

The table below is copied verbatim from the executed pipeline output recorded in `results/case_study_raw.json` for the primary attack campaign session:

| # | Harness Stage | Executed Command / HTTP Action | Event Type | MITRE ATT&CK Attribution | Weight | Running Severity | Severity Tier |
|---|---|---|---|---|---|---|---|
| **1** | 1. SQLi Login Bypass | `POST /login`: `username=admin'--&password=x` | `sqli` | **T1190** — Exploit Public-Facing App | +4.0 | 4.0 | Critical ($\ge 4.0$) |
| **2** | 3. Command Injection | `POST /ping`: `host=127.0.0.1; whoami` | `command` | **T1033** — System Owner/User Discovery | +1.0 | 5.0 | Critical |
| **3** | 3. Command Injection | `POST /ping`: `host=127.0.0.1; uname -a` | `command` | **T1082** — System Information Discovery | +1.0 | 6.0 | Critical |
| **4** | 3. Command Injection | `POST /ping`: `host=127.0.0.1; cat /etc/passwd` | `command` | **T1003.008** — OS Credential Dumping | +5.0 | 11.0 | Critical |
| **5** | 3. Command Injection | `POST /ping`: `host=127.0.0.1; wget http://...` | `command` | **T1105** — Ingress Tool Transfer | +3.0 | 14.0 | Critical |
| **6** | 4. Path Traversal | `GET /read?file=../../../../etc/passwd` | `command` | **T1003.008** — OS Credential Dumping | +5.0 | 19.0 | Critical |
| **7** | 4. Path Traversal | `GET /read?file=../../etc/portal.conf` | `command` | *Unmapped Noise* | +0.0 | 19.0 | Critical |
| **8** | 5. Reflected XSS | `GET /search?q=<script>alert(1)</script>` | `http` | **T1190** — Exploit Public-Facing App | +4.0 | 23.0 | Critical |
| **9** | 6. Web Shell Upload | `POST /upload`: `file=@/tmp/shell.php` | `file_upload` | **T1505.003** — Server Software: Web Shell | +3.0 | 26.0 | Critical |

---

## 5. Technical Resolution of the Six Review Items

### Item 1: Session Count from the Committed Run
- The committed execution of `attacker/scripts/full-attack.sh` produces exactly **7 sessions** in the database:
  1. The authenticated campaign session (`web-172.21.0.100-c9a1b8e2`) with 9 events (score 26.0).
  2. 5 unauthenticated credential stuffing sessions (severity 0.5 each, T1110).
  3. 1 unauthenticated nmap scan session (severity 1.0, T1046).
- The historical "13 vs 14 sessions" discussion pertained to a different demonstration script (`attacker/scripts/hack-demo.sh`), where Hydra was configured with an 11-word password list. We report strictly the single concrete count from the committed run: **7 sessions**.

### Item 2: Correlation is Cross-Honeypot Only
In `core-api/main.py:441-455`, session correlation explicitly enforces:
```python
AttackSession.honeypot.isnot(None),
AttackSession.honeypot != honeypot,
```
- The 5-minute sliding window filter strictly requires `AttackSession.honeypot != honeypot`.
- Correlation is designed exclusively for **cross-decoy correlation** (e.g., an attacker scanning Dionaea SMB before moving to Cowrie SSH).
- For repeated connections to the **same decoy service** (`AttackSession.honeypot == honeypot`), every new session identifier is intentionally treated as an independent connection. This ensures high-volume password spray bursts from an attacker remain distinct rather than artificially conflating into a single long-lived session.

### Item 3: Exact ATT&CK Labels (T1082, T1033, T1190, T1505.003)
- **`uname` $\to$ T1082:** The rule table in `core-api/mitre.py` has been fixed to map `uname` to **T1082 (System Information Discovery)** (weight 1.0), separating it from `whoami` and `id` which map to **T1033 (System Owner/User Discovery)** (weight 1.0).
- **SQLi Login Bypass $\to$ T1190:** SQL injection authentication bypass is an application exploitation vulnerability. In `attack-target/app.py` and `core-api/mitre.py`, SQLi bypass emits event type `sqli` which maps strictly to **T1190 (Exploit Public-Facing Application)** (weight 4.0). Legitimate credential logins continue to map to **T1078 (Valid Accounts)**.
- **Web Shell Upload $\to$ T1505.003:** In accordance with attack.mitre.org, web shell deployment is categorized under Persistence as **T1505.003 (Server Software Component: Web Shell)** (weight 3.0), not exfiltration.

### Item 4: Decoupled Role of LLM: Post-Capture Summarizer, Not Interactive Decoy
- Interactive decoy simulation is handled entirely by Cowrie, Dionaea, and Flask state machines.
- The LLM service (`ai-service/main.py`) operates asynchronously *after* capture as a threat intelligence post-processor. It ingests the captured event ledger once a session concludes, generates executive natural language summaries for SOC operators, and synthesizes incident narrative paragraphs for automated ReportLab PDF reports (`core-api/report.py`).
- The LLM plays no role in decoy emulation, command generation, or honeypot execution; it is solely an offline reporting engine.

### Item 5: Concurrency Safety & Database Transaction Guarantees
- **Atomic Score Updates:** The guarantee against lost severity updates rests mathematically on the SQL engine's atomic addition guarantee:
  `UPDATE AttackSession SET severity_score = func.coalesce(severity_score, 0.0) + weight`
  This eliminates Python-level read-modify-write lost-update races regardless of backend concurrency. (We do not claim this is proven by a test on SQLite, since SQLite serializes write transactions).
- **Technique Deduplication:** `upsert_technique` wraps inserts in `db.begin_nested()` to catch unique constraint conflicts on `(session_id, technique, source)` without aborting outer transaction state.
- **Multithreaded Savepoint Recovery Test:** `test_concurrent_upsert_technique_threads` validates that 8 concurrent worker threads calling `upsert_technique` under SQLite WAL mode recover cleanly from unique constraint savepoint rollbacks without deadlocking or producing duplicate technique records.

### Item 6: Candid Limitations of the Heuristic Grounding Filter
- In `ai-service/main.py:_grounding_check`, candidate MITRE techniques retrieved via semantic vector search (FAISS) are filtered by checking lexical token substring overlap against raw event strings.
- **Adversarial Keyword Stuffing:** If an attacker passes benign English words as arguments to commands (e.g., `ping -c 1 "kerberoasting privilege escalation discovery"`), the substring heuristic matches these tokens and marks unrelated techniques as "grounded."
- A production deployment should replace token matching with structured AST extraction (parsing command flags and executable paths) or cross-encoder entailment models (NLI) to verify semantic entailment rather than surface lexical presence.

---

## 6. Target Venue & Submission Recommendation

- **Realistic Target:** Undergraduate Capstone Project / System Demonstration Track / Academic Workshop (e.g., IEEE/ACM workshop on security education or active cyber defense prototypes).
- **Positioning:** As an open-source, containerized active deception prototype with deterministic rule mapping, concurrency-safe scoring, and automated PDF incident generation, the project represents a solid, fully implemented engineering system.
- **Scopus Indexing:** As noted by the reviewer, Scopus indexing depends strictly on the conference proceedings publisher (e.g., IEEE Xplore, Springer LNCS, ACM ICPS); the venue proceedings must be checked against the Scopus Sources list prior to submission.
