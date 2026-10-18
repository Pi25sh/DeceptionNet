"""
Custom Catch-All Decoy Service

Simulates protocol gaps not covered by Cowrie (SSH) or Dionaea (FTP/SMB/SIP):
  - HTTP admin panel with fake login form
  - Redis-like RESP protocol responses
  - SMTP banner and basic conversation

Every interaction is logged as a JSON line to /var/log/decoy/decoy.json, which
the log-forwarder tails and ships to core-api just like Cowrie/Dionaea events.
"""

import json
import os
import time
import logging
import uuid
import datetime
import threading
import socketserver

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("custom-decoy")

LOG_DIR = "/var/log/decoy"
LOG_FILE = os.path.join(LOG_DIR, "decoy.json")
os.makedirs(LOG_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Event writer — appends JSON lines for the forwarder to tail
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def write_event(event_type: str, src_ip: str, message: str, extra: dict | None = None):
    """Append a single JSON event line for the forwarder."""
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "connection": {
            "protocol": "tcp",
            "service": event_type,
            "src_ip": src_ip,
            "dst_ip": "0.0.0.0",
            "src_port": 0,
            "dst_port": 0,
        },
        "message": message,
    }
    if extra:
        event.update(extra)
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# FastAPI app — HTTP admin panel decoy
# ---------------------------------------------------------------------------
app = FastAPI(title="DeceptionNet Custom Decoy")

FAKE_ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Admin Panel</title>
<style>
  body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
         display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .card { background: #16213e; padding: 2rem; border-radius: 8px; width: 320px; box-shadow: 0 4px 24px rgba(0,0,0,.4); }
  h2 { text-align: center; margin-bottom: 1.5rem; color: #e94560; }
  input { width: 100%; padding: .6rem; margin-bottom: 1rem; border: 1px solid #0f3460;
          border-radius: 4px; background: #0f3460; color: #eee; box-sizing: border-box; }
  button { width: 100%; padding: .7rem; background: #e94560; border: none; border-radius: 4px;
           color: #fff; font-weight: bold; cursor: pointer; }
  button:hover { background: #c81e45; }
  .error { color: #e94560; text-align: center; margin-top: .5rem; font-size: .85rem; display: none; }
</style>
</head>
<body>
<div class="card">
  <h2>Admin Panel</h2>
  <form id="loginForm">
    <input type="text" id="username" placeholder="Username" required>
    <input type="password" id="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
    <div class="error" id="error">Invalid credentials. Try again.</div>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  try {
    const r = await fetch('/login', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    if (r.ok) { document.querySelector('.card').innerHTML = '<h2 style="color:#0f3460">Welcome, Admin</h2><p>Dashboard loading...</p>'; }
    else { document.getElementById('error').style.display = 'block'; }
  } catch { document.getElementById('error').style.display = 'block'; }
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def admin_panel(request: Request):
    """Fake admin login page —诱饵 for attackers scanning for web panels."""
    src_ip = request.client.host if request.client else "unknown"
    write_event("http", src_ip, f"HTTP GET / from {src_ip} — admin panel accessed")
    return HTMLResponse(content=FAKE_ADMIN_HTML)


@app.post("/login")
async def admin_login(request: Request):
    """Fake login endpoint — always rejects but logs the attempt."""
    src_ip = request.client.host if request.client else "unknown"
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = body.get("username", "")
    password = body.get("password", "")
    write_event(
        "login_failed",
        src_ip,
        f"Failed login on admin panel: {username}/{password}",
        extra={"login": {"user": username, "pass": password}},
    )
    return JSONResponse(status_code=401, content={"error": "Invalid credentials"})


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/{path:path}")
async def fake_api(request: Request, path: str):
    """Catch-all for any /api/* probing."""
    src_ip = request.client.host if request.client else "unknown"
    write_event("http", src_ip, f"HTTP {request.method} /api/{path} from {src_ip}")
    return JSONResponse(status_code=404, content={"error": "Not found"})


# ---------------------------------------------------------------------------
# Redis-like decoy (runs in a background thread on port 6379)
# ---------------------------------------------------------------------------
class RedisHandler(socketserver.BaseRequestHandler):
    """Minimal Redis-protocol decoy: responds to PING, AUTH, KEYS, GET, SET."""

    def handle(self):
        src_ip = self.client_address[0]
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
                if not data:
                    break
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.strip().decode("utf-8", errors="replace").upper()
                    if cmd.startswith("*"):
                        # RESP array — skip for simplicity, just grab next lines
                        continue
                    self._dispatch(cmd, src_ip)
            except Exception:
                break

    def _dispatch(self, cmd: str, src_ip: str):
        parts = cmd.split()
        if not parts:
            return
        command = parts[0]
        if command == "PING":
            self.request.sendall(b"+PONG\r\n")
        elif command == "AUTH":
            write_event("login_failed", src_ip, f"Redis AUTH attempt from {src_ip}")
            self.request.sendall(b"-ERR invalid password\r\n")
        elif command in ("GET", "SET", "KEYS", "INFO"):
            write_event(
                "redis",
                src_ip,
                f"Redis {command} from {src_ip}",
                extra={"redis_command": command},
            )
            if command == "INFO":
                self.request.sendall(b"$-1\r\n")
            elif command == "KEYS":
                self.request.sendall(b"*0\r\n")
            else:
                self.request.sendall(b"$-1\r\n")
        else:
            write_event("redis", src_ip, f"Redis {command} from {src_ip}")
            self.request.sendall(b"-ERR unknown command\r\n")


def start_redis_decoy():
    """Start Redis-like TCP server on port 6379 in a background thread."""
    server = socketserver.ThreadingTCPServer(("0.0.0.0", 6379), RedisHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info("Redis decoy listening on port 6379")


# ---------------------------------------------------------------------------
# SMTP-like decoy (runs in a background thread on port 25)
# ---------------------------------------------------------------------------
class SMTPHandler(socketserver.BaseRequestHandler):
    """Minimal SMTP decoy: accepts connection, logs HELO/MAIL FROM/RCPT TO."""

    def handle(self):
        src_ip = self.client_address[0]
        self.request.sendall(b"220 mail.deceptionnet.local ESMTP Decoy\r\n")
        write_event("smtp", src_ip, f"SMTP connection from {src_ip}")
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
                if not data:
                    break
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.strip().decode("utf-8", errors="replace")
                    self._dispatch(cmd, src_ip)
            except Exception:
                break

    def _dispatch(self, cmd: str, src_ip: str):
        upper = cmd.upper()
        if upper.startswith("HELO") or upper.startswith("EHLO"):
            write_event("smtp", src_ip, f"SMTP HELO from {src_ip}: {cmd}")
            self.request.sendall(b"250 Hello\r\n")
        elif upper.startswith("MAIL FROM"):
            write_event("smtp", src_ip, f"SMTP MAIL FROM from {src_ip}: {cmd}")
            self.request.sendall(b"250 OK\r\n")
        elif upper.startswith("RCPT TO"):
            write_event("smtp", src_ip, f"SMTP RCPT TO from {src_ip}: {cmd}")
            self.request.sendall(b"250 OK\r\n")
        elif upper.startswith("DATA"):
            self.request.sendall(b"354 Start mail input\r\n")
        elif upper == ".":
            write_event("smtp", src_ip, f"SMTP DATA completed from {src_ip}")
            self.request.sendall(b"250 OK\r\n")
        elif upper.startswith("QUIT"):
            self.request.sendall(b"221 Bye\r\n")
        else:
            write_event("smtp", src_ip, f"SMTP {cmd} from {src_ip}")
            self.request.sendall(b"500 Command not recognized\r\n")


def start_smtp_decoy():
    """Start SMTP-like TCP server on port 25 in a background thread."""
    server = socketserver.ThreadingTCPServer(("0.0.0.0", 25), SMTPHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info("SMTP decoy listening on port 25")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    start_redis_decoy()
    start_smtp_decoy()
    logger.info("Custom decoy service started — HTTP :8080, Redis :6379, SMTP :25")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
