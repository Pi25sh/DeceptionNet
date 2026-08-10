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


def process_log_line(line):
    try:
        event = json.loads(line)
        event_id = event.get('eventid')
        session = event.get('session')

        payload = None

        # We only forward the events that carry attacker intent for the MVP.
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

        if payload:
            logger.info(f"Forwarding event: {payload['event_type']} from {session}")
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
    logger.info("Starting log forwarder...")
    tail_file(COWRIE_LOG_FILE)
