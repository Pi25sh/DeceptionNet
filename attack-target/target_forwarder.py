import json
import time
import os
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("attack-target-forwarder")

TARGET_LOG_FILE = os.environ.get("TARGET_LOG_FILE", "/var/log/attack-target/target.jsonl")
CORE_API_URL = os.environ.get("CORE_API_URL", "http://core-api:8000/events")
HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "attack-target")


def to_core_payload(event):
    """Map an attack-target JSON line onto the core-api EventPayload shape."""
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
            "honeypot": HONEYPOT_NAME,
        }
    if et == "login":
        login = event.get("login", {})
        return {
            "session_id": event["session"],
            "event_type": "login",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "service": "http",
            "protocol": "http",
            "username": login.get("user"),
            "password": login.get("pass"),
            "message": msg,
            "honeypot": HONEYPOT_NAME,
        }
    if et == "command":
        return {
            "session_id": event["session"],
            "event_type": "command",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "input": event.get("input"),
            "message": msg,
            "honeypot": HONEYPOT_NAME,
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
            "honeypot": HONEYPOT_NAME,
        }
    if et == "file_upload":
        return {
            "session_id": event["session"],
            "event_type": "file_upload",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "message": msg,
            "honeypot": HONEYPOT_NAME,
        }
    if et == "http":
        return {
            "session_id": event["session"],
            "event_type": "http",
            "timestamp": event["timestamp"],
            "src_ip": src_ip,
            "url": event.get("url"),
            "message": msg,
            "honeypot": HONEYPOT_NAME,
        }
    return None


def process_line(line):
    try:
        event = json.loads(line)
        payload = to_core_payload(event)
        if payload:
            logger.info(
                f"Forwarding {payload['event_type']} session={payload['session_id'][:24]}"
            )
            try:
                resp = requests.post(CORE_API_URL, json=payload, timeout=5)
                resp.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"POST to core-api failed: {e}")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        logger.error(f"Error processing line: {e}")


def tail_file(file_path):
    """Robust tail re-reading appends (same approach as the honeypot forwarders)."""
    while not os.path.exists(file_path):
        logger.info(f"Waiting for {file_path} to be created...")
        waited_for_file = True
        time.sleep(5)

    logger.info(f"Tailing {file_path}")
    position = 0
    current_inode = None
    waited_for_file = False

    while True:
        try:
            stat = os.stat(file_path)
            fsize = stat.st_size

            if current_inode is None:
                current_inode = stat.st_ino
                if waited_for_file:
                    # The file only appeared while we were waiting for it, so its
                    # content is THIS run's traffic (a freshly created target log).
                    # Tail from the top so no attack events are skipped.
                    position = 0
                else:
                    # The file existed before we started — treat what's in it as
                    # historical backlog already shipped by an earlier run.
                    position = fsize
            elif stat.st_ino != current_inode:
                current_inode = stat.st_ino
                position = 0

            if fsize < position:
                position = 0

            if fsize > position:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(position)
                    chunk = f.read(fsize - position)
                    for line in chunk.splitlines():
                        if line.strip():
                            process_line(line)
                    position = fsize
        except OSError as e:
            logger.error(f"Tailing error ({e}); resetting...")
            current_inode = None
            position = 0
        time.sleep(1)


if __name__ == "__main__":
    logger.info(f"Starting attack-target forwarder ({HONEYPOT_NAME})...")
    tail_file(TARGET_LOG_FILE)
