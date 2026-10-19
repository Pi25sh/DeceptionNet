"""
DeceptionNet Attack Target Lab
==============================

A deliberately vulnerable web application used as a practice target to drive
REAL attack traffic into the DeceptionNet pipeline.

It mimics a small fictional organization's employee portal with a handful of
intentional vulnerabilities so that you (or a scanning/exploit tool) can attack
it with real payloads:

    /login   - SQL injection (single-quote bypass) + NO brute-force lockout
    /ping    - OS command injection (un-sanitized shell command)
    /read    - path traversal / local file inclusion
    /search  - reflected cross-site scripting (XSS)
    /upload  - unrestricted file upload

Every interaction is written as a JSON line to a log file that the log
forwarder tails and ships to core-api -- the same pipeline the Cowrie / Dionaea /
custom-decoy honeypots use. That means attacks fire the MITRE rule engine and
the AI summarizer, so sessions appear in the live dashboard just like a real
incident.

SECURITY: This app is UNSAFE BY DESIGN. Run it only inside the isolated
honeypot container (or your own throwaway lab VM). It must NEVER be exposed on
the public internet.
"""

import json
import os
import platform
import re
import shlex
import subprocess
import threading
import datetime
import uuid

from flask import Flask, request, Response, render_template_string, jsonify, session

app = Flask(__name__)
# Signs the Flask session cookie that keeps a browser connection pinned to one
# attack session after a successful login (see current_sid).
app.secret_key = os.environ.get("SECRET_KEY", "deceptionnet-attack-target-lab-secret")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_FILE = os.environ.get("TARGET_LOG_FILE", "/var/log/attack-target/target.jsonl")
# In standalone (no-docker) mode the app also ships events straight to core-api.
# In the docker-compose setup this is disabled and the separate forwarder ships them.
CORE_API_URL = os.environ.get("CORE_API_URL", "http://localhost:8000/events")
SHIP_EVENTS = os.environ.get("SHIP_EVENTS", "true").lower() == "true"

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
# Touch the log file at startup so the forwarder sees it immediately and is
# already tailing BEFORE the first attack lands. Without this, on a cold start
# the forwarder blocks in "waiting for file" and then skips the first events as
# a historical backlog, silently dropping the attack that caused you to start.
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, "a", encoding="utf-8").close()

# Simulated credential store (vulnerable "database" behind the login form).
# 'admin' is the target account an attacker wants to brute-force / inject into.
USERS = {
    "admin": "s3cr3t!",
    "jdoe": "password123",
    "alice": "ilovecats",
}

# ---------------------------------------------------------------------------
# Event writer + shipping thread
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def current_sid(src_ip):
    """Attack-session id for THIS browser connection.

    A successful login pins the id in the Flask session cookie, so follow-up
    actions (command injection, LFI, upload) land in the SAME attack session.
    That makes the dashboard show a single escalating session (T1078 login ->
    T1003.008 command exec) instead of disconnected one-shot requests.
    Requests that never logged in get a fresh one-time id.
    """
    return session.get("sid") or f"web-{src_ip}-{uuid.uuid4().hex[:8]}"


def write_target_event(event_type, src_ip, message, extra=None, input_str=None, sid=None):
    """Append one JSON event line (decoy-style) for the forwarder to tail.

    event_type is normalized so the forwarder maps it onto the core-api event
    vocabulary: login_failed / login / command / download / file_upload / http.
    """
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "connection": {
            "protocol": "http",
            "service": "http",
            "src_ip": src_ip,
            "dst_ip": "0.0.0.0",
            "src_port": 0,
            "dst_port": 9090,
        },
        "message": message,
        "session": sid or f"web-{src_ip}-{uuid.uuid4().hex[:8]}",
    }
    if input_str is not None:
        event["input"] = input_str
    if extra:
        event.update(extra)
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    if SHIP_EVENTS:
        threading.Thread(target=_ship, args=(event,), daemon=True).start()


def _ship(event):
    """Best-effort: POST the event to core-api (standalone mode only)."""
    try:
        import requests
        payload = _to_core_payload(event)
        if payload:
            requests.post(CORE_API_URL, json=payload, timeout=5)
    except Exception:
        pass


def _to_core_payload(event):
    """Translate an event line into the core-api EventPayload shape.

    Mirrors the mapping the dedicated forwarder applies -- kept here so a
    standalone run behaves identically to a dockered one.
    """
    conn = event.get("connection", {})
    src_ip = conn.get("src_ip", "unknown")
    et = event.get("event")
    msg = event.get("message", "")

    if et == "login_failed":
        login = event.get("login", {})
        return {
            "session_id": event["session"],
            "event_type": "login_failed",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "service": "http",
            "protocol": "http",
            "username": login.get("user"),
            "password": login.get("pass"),
            "message": msg,
            "honeypot": "attack-target",
        }
    if et in ("login", "sqli"):
        login = event.get("login", {})
        return {
            "session_id": event["session"],
            "event_type": et,
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "service": "http",
            "protocol": "http",
            "username": login.get("user"),
            "password": login.get("pass"),
            "message": msg,
            "honeypot": "attack-target",
        }
    if et == "command":
        return {
            "session_id": event["session"],
            "event_type": "command",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "input": event.get("input"),
            "message": msg,
            "honeypot": "attack-target",
        }
    if et == "download":
        return {
            "session_id": event["session"],
            "event_type": "download",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "url": event.get("url"),
            "outfile": event.get("outfile"),
            "message": msg,
            "honeypot": "attack-target",
        }
    if et == "file_upload":
        return {
            "session_id": event["session"],
            "event_type": "file_upload",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "message": msg,
            "honeypot": "attack-target",
        }
    if et == "http":
        return {
            "session_id": event["session"],
            "event_type": "http",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "url": event.get("url"),
            "message": msg,
            "honeypot": "attack-target",
        }
    if et == "scan":
        return {
            "session_id": event["session"],
            "event_type": "scan",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "message": msg,
            "honeypot": "attack-target",
        }
    return None


def client_ip():
    """Respect a spoofed X-Forwarded-For (realistic for proxied scanners)."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


# ---------------------------------------------------------------------------
# Helpers for the vulnerable behaviours
# ---------------------------------------------------------------------------
SQLI_BYPASS = re.compile(
    r"('|\"|\x27)\s*(or|or\s+1=1|union\s+select|--|#|;)", re.IGNORECASE
)


def login_is_valid(username, password):
    """VULNERABLE auth check.

    A real implementation would table-lookup the password. Here we mimic an
    injection-able query: any credential that could make
    ``WHERE username='<u>' AND password='<p>'`` true is accepted -- so
    classic SQLi payloads (admin' --, ' OR 1=1 --) bypass authentication.
    """
    if username in USERS and USERS[username] == password:
        return True
    # Simulated injection bypass
    if SQLI_BYPASS.search(username) or SQLI_BYPASS.search(password):
        return True
    return False


# A tiny fake filesystem the /read endpoint serves from (plus the inevitable
# path-traversal escape to /etc/passwd / application files).
FAKE_FS = {
    "/var/www/portal/README.txt": "Welcome to the Vertex Bank employee portal.",
    "/var/www/portal/config.php": "<?php $db_user='root'; /* demo */ ?>",
    "/etc/portal.conf": "db_host=10.0.0.5; db_pass=hunter2",
}


def resolve_file(fname):
    """VULNERABLE file resolution: joins the requested name onto the web root
    with no traversal guard, so ../../../../etc/passwd walks out of the root."""
    base = "/var/www/portal"
    path = os.path.normpath(os.path.join(base, fname))
    if path in FAKE_FS:
        return path, FAKE_FS[path]
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return path, fh.read()
        except Exception:
            return path, "(could not read)"
    return path, None


# ---------------------------------------------------------------------------
# UI template (dark, so it feels like the DeceptionNet dashboard)
# ---------------------------------------------------------------------------
PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Vertex Bank &mdash; Employee Portal</title>
<style>
  :root{ color-scheme: dark; }
  body{ margin:0; font-family:'Segoe UI',system-ui,Arial,sans-serif; background:#0f1420; color:#e7ecf4; }
  header{ background:#131a2b; border-bottom:1px solid #232e4d; padding:14px 28px; display:flex; align-items:center; gap:14px; }
  header .logo{ font-weight:700; font-size:18px; color:#5b8cff; }
  header .tag{ margin-left:auto; color:#7d8aa5; font-size:13px; }
  main{ max-width:860px; margin:26px auto; padding:0 20px; }
  h2{ color:#5b8cff; font-size:16px; text-transform:uppercase; letter-spacing:.06em; border-bottom:1px solid #232e4d; padding-bottom:8px;}
  .card{ background:#161d31; border:1px solid #232e4d; border-radius:10px; padding:20px 22px; margin-bottom:22px; }
  label{ display:block; margin:10px 0 4px; color:#9fb0cc; font-size:13px; }
  input[type=text],input[type=password],input[type=file],select{ width:100%; padding:10px; margin-bottom:8px; border:1px solid #2c3a63; border-radius:6px; background:#0f1420; color:#e7ecf4; box-sizing:border-box;}
  button{ background:#3a5bd9; color:#fff; border:none; padding:10px 18px; border-radius:6px; cursor:pointer; font-weight:600;}
  button:hover{ background:#4d6dff; }
  .out{ background:#0a0e18; border:1px solid #232e4d; border-radius:6px; padding:12px; margin-top:12px; font-family:ui-monospace,Consolas,monospace; font-size:13px; white-space:pre-wrap; word-break:break-all; color:#9fe8a8;}
  pre{ white-space:pre-wrap; word-break:break-all; }
  .note{ font-size:12px; color:#69748c; border-top:1px solid #232e4d; margin-top:18px; padding-top:10px;}
  table{ border-collapse:collapse; width:100%; font-size:13px;}
  th,td{ border:1px solid #232e4d; padding:8px 10px; text-align:left;}
  th{ background:#1b2440;}
</style></head><body>
<header><span class="logo">@@LOGO@@</span><span class="tag">Lab target for DeceptionNet &mdash; intentionally vulnerable</span></header>
<main>
  <div class="card"><h2>Employee Login</h2>
    <form method="post" action="/login">
      <label>Username</label><input type="text" name="username" autocomplete="off">
      <label>Password</label><input type="password" name="password">
      <button type="submit">Sign In</button>
      <div class="out" style="display:none">@LOGIN_MSG@</div>
    </form>
  </div>
  <div class="card"><h2>Network Diagnostics (ping)</h2>
    <form method="post" action="/ping">
      <label>Host / IP</label><input type="text" name="host" value="127.0.0.1">
      <button type="submit">Run Ping</button>
      <pre class="out">@PING_OUT@</pre>
    </form>
  </div>
  <div class="card"><h2>Support File Viewer</h2>
    <form method="get" action="/read">
      <label>File path</label><input type="text" name="file" value="README.txt">
      <button type="submit">Open</button>
      <pre class="out">@READ_OUT@</pre>
    </form>
  </div>
  <div class="card"><h2>Search</h2>
    <form method="get" action="/search">
      <label>Query</label><input type="text" name="q" placeholder="search the knowledge base">
      <button type="submit">Search</button>
      <div class="out">@SEARCH_OUT@</div>
    </form>
  </div>
  <div class="card"><h2>Document Upload</h2>
    <form method="post" action="/upload" enctype="multipart/form-data">
      <label>Select file</label><input type="file" name="file">
      <button type="submit">Upload</button>
      <div class="out">@UPLOAD_OUT@</div>
    </form>
  </div>
  <div class="note">
    This is a DeceptionNet attack-target. It is intentionally vulnerable so you can
    practice real payloads &mdash; SQL injection, command injection, path traversal,
    XSS, credential stuffing &mdash; and watch them light up the DeceptionNet dashboard
    as live attack sessions with MITRE ATT&amp;CK mappings and AI summaries. Do not expose it.
  </div>
</main></body></html>"""


def render(**ctx):
    page = PAGE
    for k, v in ctx.items():
        page = page.replace("@" + k + "@", v if v is not None else "")
    return page


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="", PING_OUT="",
                  READ_OUT="", SEARCH_OUT="", UPLOAD_OUT="")


@app.post("/login")
def login():
    ip = client_ip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if login_is_valid(username, password):
        sql_bypass = SQLI_BYPASS.search(username) or SQLI_BYPASS.search(password)
        # Pin this connection to one attack session so follow-up requests (that
        # carry this cookie back) escalate the SAME session on the dashboard.
        sid = current_sid(ip)
        session["sid"] = sid
        if sql_bypass:
            write_target_event(
                "sqli",
                ip,
                f"SQL injection login bypass on /login: {username} SQLi payload: {username or password}",
                extra={"login": {"user": username, "pass": password}},
                sid=sid,
            )
        else:
            write_target_event(
                "login",
                ip,
                f"Successful login on /login: {username}",
                extra={"login": {"user": username, "pass": password}},
                sid=sid,
            )
        return render(LOGO="Vertex Bank Employee Portal",
                      LOGIN_MSG=f"<p style='color:#9fe8a8'>Welcome back, {username}!</p>",
                      PING_OUT="", READ_OUT="", SEARCH_OUT="", UPLOAD_OUT="")
    else:
        # No rate limiting here -- hydra/medusa can grind away -> T1110.
        write_target_event(
            "login_failed",
            ip,
            f"Failed login on /login: {username}/{password}",
            extra={"login": {"user": username, "pass": password}},
        )
        return render(LOGO="Vertex Bank Employee Portal",
                      LOGIN_MSG="<p style='color:#ff6b6b'>Invalid credentials.</p>",
                      PING_OUT="", READ_OUT="", SEARCH_OUT="", UPLOAD_OUT="")


@app.post("/ping")
def ping():
    ip = client_ip()
    host = request.form.get("host", "127.0.0.1")

    # VULNERABLE: the input is spliced straight into a shell command.
    command = f"ping {'-n' if platform.system() == 'Windows' else '-c'} 1 {host}"
    write_target_event(
        "command",
        ip,
        f"Command injection via /ping: {command}",
        input_str=command,
        sid=current_sid(ip),
    )

    try:
        out = subprocess.run(command, shell=True, capture_output=True,
                             text=True, timeout=10).stdout
    except Exception as e:
        out = f"(simulated ping) {e}"
    return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="",
                  PING_OUT=out, READ_OUT="", SEARCH_OUT="", UPLOAD_OUT="")


@app.get("/read")
def read():
    ip = client_ip()
    fname = request.args.get("file", "README.txt")

    path, content = resolve_file(fname)
    # Log as an executed read of the resolved path so MITRE keyword rules
    # (e.g. "/etc/passwd") fire naturally. Use forward slashes so traversal
    # detection works identically on Linux (container) and Windows (lab).
    display_path = path.replace(os.sep, "/")
    write_target_event(
        "command",
        ip,
        f"File read via /read: {display_path}",
        input_str=f"cat {display_path}",
        sid=current_sid(ip),
    )

    if content is None:
        content = f"(no such file: {path})"
    return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="",
                  PING_OUT="", READ_OUT=content, SEARCH_OUT="", UPLOAD_OUT="")


@app.get("/search")
def search():
    ip = client_ip()
    q = request.args.get("q", "")
    # Reflected XSS sink (raw echo, no escaping) -> log suspicious hits as http.
    if re.search(r"(<script|javascript:|onerror=|alert\s*\()", q, re.I):
        write_target_event(
            "http",
            ip,
            f"Reflected XSS payload in /search: {q}",
            extra={"url": f"/search?q={q}"},
            sid=current_sid(ip),
        )
    else:
        write_target_event("http", ip, f"Search query on /search: {q}",
                           extra={"url": f"/search?q={q}"}, sid=current_sid(ip))
    return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="",
                  PING_OUT="", READ_OUT="", SEARCH_OUT=q, UPLOAD_OUT="")


@app.post("/upload")
def upload():
    ip = client_ip()
    f = request.files.get("file")
    if not f or not f.filename:
        write_target_event("http", ip, "Upload attempt with no file on /upload")
        return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="",
                      PING_OUT="", READ_OUT="", SEARCH_OUT="",
                      UPLOAD_OUT="<p style='color:#ffde7a'>No file selected.</p>")
    name = f.filename
    contents = f.read()
    write_target_event(
        "file_upload",
        ip,
        f"File uploaded to /upload: {name} ({len(contents)} bytes)",
        extra={"outfile": name,
               "note": "webshell-ish" if re.search(r"\.(php|jsp|sh|py|asp)$", name, re.I) else ""},
        sid=current_sid(ip),
    )
    return render(LOGO="Vertex Bank Employee Portal", LOGIN_MSG="",
                  PING_OUT="", READ_OUT="", SEARCH_OUT="",
                  UPLOAD_OUT=f"<p style='color:#9fe8a8'>Uploaded '<b>{name}</b>' ({len(contents)} bytes).</p>")


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    port = int(os.environ.get("TARGET_PORT", "9090"))
    print(f"[attack-target] lab listening on 0.0.0.0:{port} -> logs to {LOG_FILE}")
    app.run(host="0.0.0.0", port=port, threaded=True)
