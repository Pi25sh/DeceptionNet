import json
import time
import os
import logging
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

COWRIE_LOG_FILE = "/var/log/cowrie/cowrie.json"
CORE_API_URL = os.environ.get("CORE_API_URL", "http://core-api:8000/events")

# Which honeypot produced these logs. Member 2's Dionaea forwarder should set
# this to "dionaea" so the core-api can correlate / display by honeypot.
HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "cowrie")


def process_cowrie_line(event):
    """Process a single Cowrie log event."""
    event_id = event.get('eventid')
    session = event.get('session')

    payload = None

    if event_id == 'cowrie.login.success':
        payload = {
            "session_id": session,
            "event_type": "login",
            "timestamp": event.get('timestamp'),
            "src_ip": event.get('src_ip'),
            "username": event.get('username'),
            "password": event.get('password'),
            "message": f"Successful login by {event.get('username')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_id == 'cowrie.login.failed':
        payload = {
            "session_id": session,
            "event_type": "login_failed",
            "timestamp": event.get('timestamp'),
            "src_ip": event.get('src_ip'),
            "username": event.get('username'),
            "password": event.get('password'),
            "message": f"Failed login by {event.get('username')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_id == 'cowrie.command.input':
        payload = {
            "session_id": session,
            "event_type": "command",
            "timestamp": event.get('timestamp'),
            "src_ip": event.get('src_ip'),
            "input": event.get('input'),
            "message": f"Executed command: {event.get('input')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_id == 'cowrie.session.file_download':
        payload = {
            "session_id": session,
            "event_type": "download",
            "timestamp": event.get('timestamp'),
            "src_ip": event.get('src_ip'),
            "url": event.get('url'),
            "outfile": event.get('outfile'),
            "message": f"Downloaded file from {event.get('url')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_id == 'cowrie.session.file_upload':
        payload = {
            "session_id": session,
            "event_type": "file_upload",
            "timestamp": event.get('timestamp'),
            "src_ip": event.get('src_ip'),
            "url": event.get('url'),
            "outfile": event.get('outfile'),
            "message": f"Uploaded file to {event.get('url')}",
            "honeypot": HONEYPOT_NAME,
        }

    return payload


def process_dionaea_line(event):
    """Process a single Dionaea log event.

    Dionaea logs have a different structure:
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "connection": {
        "protocol": "tcp",
        "service": "smb",
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.50",
        "src_port": 12345,
        "dst_port": 445
      },
      "event": "shellcode" | "download" | "login" | "login_failed" | "scan" | ...
      ...
    }
    """
    conn = event.get('connection', {})
    event_type = event.get('event')
    session = event.get('session') or event.get('connection', {}).get('src_ip', 'unknown')
    timestamp = event.get('timestamp')
    src_ip = conn.get('src_ip')
    service = conn.get('service', 'unknown')
    protocol = conn.get('protocol', 'unknown')

    payload = None

    if event_type == 'shellcode':
        payload = {
            "session_id": session,
            "event_type": "shellcode",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"Shellcode detected on {service}/{protocol} from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'download':
        download = event.get('download', {})
        payload = {
            "session_id": session,
            "event_type": "download",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "url": download.get('url'),
            "outfile": download.get('file'),
            "message": f"Downloaded file from {download.get('url')} via {service}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'login':
        login = event.get('login', {})
        payload = {
            "session_id": session,
            "event_type": "login",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "username": login.get('user'),
            "password": login.get('pass'),
            "message": f"Login attempt on {service}: {login.get('user')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'login_failed':
        login = event.get('login', {})
        payload = {
            "session_id": session,
            "event_type": "login_failed",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "username": login.get('user'),
            "password": login.get('pass'),
            "message": f"Failed login on {service}: {login.get('user')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type in ('scan', 'pcap', 'dns'):
        payload = {
            "session_id": session,
            "event_type": event_type,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"{event_type.capitalize()} detected on {service}/{protocol} from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'sip':
        payload = {
            "session_id": session,
            "event_type": "sip",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"SIP connection from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'upnp':
        payload = {
            "session_id": session,
            "event_type": "upnp",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"UPnP connection from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'vnc':
        payload = {
            "session_id": session,
            "event_type": "vnc",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"VNC connection from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type == 'ftp':
        ftp = event.get('ftp', {})
        payload = {
            "session_id": session,
            "event_type": "ftp",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": f"FTP command: {ftp.get('cmd')}",
            "honeypot": HONEYPOT_NAME,
        }

    return payload


def process_decoy_line(event):
    """Process a single custom-decoy log event.

    The custom decoy writes JSON with the same structure as Dionaea
    (connection.service / connection.src_ip) but different event types:
    http, login_failed, redis, smtp.
    """
    conn = event.get("connection", {})
    event_type = event.get("event")
    session = event.get("session") or conn.get("src_ip", "unknown")
    timestamp = event.get("timestamp")
    src_ip = conn.get("src_ip")
    service = conn.get("service", "unknown")
    protocol = conn.get("protocol", "unknown")
    message = event.get("message", "")

    payload = None

    if event_type == "login_failed":
        login = event.get("login", {})
        payload = {
            "session_id": session,
            "event_type": "login_failed",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "username": login.get("user"),
            "password": login.get("pass"),
            "message": message or f"Failed login on {service}: {login.get('user')}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type in ("http", "redis", "smtp", "dns"):
        payload = {
            "session_id": session,
            "event_type": event_type,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": message or f"{event_type.upper()} interaction from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }
    elif event_type in ("scan", "shellcode", "download"):
        payload = {
            "session_id": session,
            "event_type": event_type,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "service": service,
            "protocol": protocol,
            "message": message or f"{event_type} detected on {service} from {src_ip}",
            "honeypot": HONEYPOT_NAME,
        }

    return payload


def process_log_line(line):
    try:
        event = json.loads(line)

        payload = None

        # Branch by honeypot type (set via HONEYPOT_NAME env var)
        if HONEYPOT_NAME == "dionaea":
            payload = process_dionaea_line(event)
        elif HONEYPOT_NAME == "custom-decoy":
            payload = process_decoy_line(event)
        else:
            # Default: Cowrie
            payload = process_cowrie_line(event)

        if payload:
            logger.info(f"Forwarding event: {payload['event_type']} from {payload['session_id']}")
            try:
                response = requests.post(CORE_API_URL, json=payload, timeout=5)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to forward event to core-api: {e}")

    except json.JSONDecodeError:
        pass
    except Exception as e:
        logger.error(f"Error processing log line: {e}")


def tail_file(file_path):
    """Robust tail: re-stat the file each second and read only newly appended
    bytes through a fresh file handle.

    Opening a fresh handle every pass is deliberate. A single long-lived
    buffered handle does not reliably observe appends made by another container
    on a Docker Desktop named volume (we hit exactly this in the baseline), so
    we re-open and re-stat instead of keeping state in the process.
    """
    while not os.path.exists(file_path):
        logger.info(f"Waiting for {file_path} to be created...")
        time.sleep(5)

    logger.info(f"Starting to tail {file_path}")
    position = 0
    current_inode = None
    while True:
        try:
            stat = os.stat(file_path)
            fsize = stat.st_size

            if current_inode is None:
                # First sight of the file: skip any historical backlog so we
                # only forward events that happen from now on.
                current_inode = stat.st_ino
                position = fsize
            elif stat.st_ino != current_inode:
                # Log rotated to a new file -> read it from the top
                current_inode = stat.st_ino
                position = 0

            if fsize < position:
                # File truncated in place -> start over from the top
                position = 0

            if fsize > position:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(position)
                    chunk = f.read(fsize - position)
                    for line in chunk.splitlines():
                        if line.strip():
                            process_log_line(line)
                    position = fsize
        except OSError as e:
            logger.error(f"Tailing error ({e}); retrying...")
            current_inode = None
            position = 0
        time.sleep(1)


if __name__ == "__main__":
    logger.info(f"Starting log forwarder for {HONEYPOT_NAME}...")
    tail_file(COWRIE_LOG_FILE)