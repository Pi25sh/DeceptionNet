#!/bin/bash
# Brute-force the Cowrie SSH honeypot -> T1110 Brute Force (and, on a "win",
# the follow-up commands map to T1003.008 / T1033 / T1105 / T1070).
set -e
HOST="${COWRIE_HOST:-honeypot}"
PORT="${COWRIE_PORT:-2222}"
PASSLIST="${PASSLIST:-/opt/attack/scripts/mini-pass.txt}"

echo "[*] Brute-forcing SSH honeypot at ${HOST}:${PORT}"
hydra -L /opt/attack/scripts/mini-users.txt -P "$PASSLIST" \
  ssh://"$HOST" -s "$PORT" -t 4 -f 2>/dev/null || echo "(no creds cracked — login_failed events still logged)"

echo
echo "[*] Try an SSH session (netcat-free, plain) — Cowrie answers to almost anything:"
echo "    ssh -p $PORT root@$HOST"
