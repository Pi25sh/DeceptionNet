# MITRE ATT&CK mapping for the MVP.
#
# Two sources of detections feed this table:
#   1. Cowrie (SSH/Telnet)  -> normalized event types ("login", "login_failed",
#      "command", "download", "file_upload") plus free-form command text.
#   2. Dionaea (SMB/FTP/HTTP/...) -> normalized event types such as "smb",
#      "shellcode", "ftp_login", "http_request", "scan" (Member 2's forwarder).
#
# EVENT_TYPE_RULES maps the event type; MITRE_RULES maps command keywords.
# Rules are evaluated first-match-wins, so more specific rules come first.
from typing import Tuple, List, Iterable
import re

# ---------------------------------------------------------------------------
# Command keyword rules (Cowrie command.input, plus SFTP/uploads)
# Ordered by specificity / severity so the most specific rule wins.
# ---------------------------------------------------------------------------
MITRE_RULES: List[dict] = [
    {
        "keywords": ["cat /etc/passwd", "cat /etc/shadow", "cat /etc/sudoers"],
        "technique": "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow",
        "weight": 5.0,
    },
    {
        "keywords": ["rm -rf", "history -c", "unset histfile"],
        "technique": "T1070 - Indicator Removal on Host",
        "weight": 4.0,
    },
    {
        "keywords": ["nc -e", "bash -i", "/dev/tcp", "python -c", "perl -e", "-e /bin/sh"],
        "technique": "T1071 - Application Layer Protocol (reverse shell / C2)",
        "weight": 4.0,
    },
    {
        "keywords": ["wget", "curl", "scp", "ftp ", "busybox wget"],
        "technique": "T1105 - Ingress Tool Transfer",
        "weight": 3.0,
    },
    {
        "keywords": ["crontab", "* * * * *", "*/1 * * * *"],
        "technique": "T1053.003 - Scheduled Task/Job: Cron",
        "weight": 3.0,
    },
    {
        "keywords": ["authorized_keys", "ssh-keygen", "ssh-copy-id"],
        "technique": "T1098.004 - Account Manipulation: SSH Authorized Keys",
        "weight": 3.0,
    },
    {
        "keywords": ["useradd", "adduser"],
        "technique": "T1136.001 - Create Account: Local Account",
        "weight": 3.0,
    },
    {
        # "passwd " (with trailing space) matches the *command* but not the
        # /etc/passwd *filename*, so archive/dump commands resolve correctly.
        "keywords": ["passwd ", "chpasswd"],
        "technique": "T1098 - Account Manipulation",
        "weight": 3.0,
    },
    {
        "keywords": ["iptables", "ufw ", "firewall-cmd"],
        "technique": "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
        "weight": 3.0,
    },
    {
        "keywords": ["tar -cvf", "tar -czf", "tar czf", "zip -r"],
        "technique": "T1560.001 - Archive Collected Data",
        "weight": 3.0,
    },
    {
        "keywords": ["chmod +x", "chmod 777", "chattr +i"],
        "technique": "T1222.002 - File and Directory Permissions Modification: Linux and Mac",
        "weight": 2.0,
    },
    {
        "keywords": ["nmap", "nc -z"],
        "technique": "T1046 - Network Service Discovery",
        "weight": 2.0,
    },
    {
        "keywords": ["sudo", "su "],
        "technique": "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "weight": 2.0,
    },
    {
        "keywords": ["netstat", "ss -", "ifconfig", "ip addr", "arp -a"],
        "technique": "T1016 - System Network Configuration Discovery",
        "weight": 1.0,
    },
    {
        "keywords": ["whoami", "id"],
        "technique": "T1033 - System Owner/User Discovery",
        "weight": 1.0,
    },
    {
        "keywords": ["uname"],
        "technique": "T1082 - System Information Discovery",
        "weight": 1.0,
    },
]

# ---------------------------------------------------------------------------
# Event-type rules (normalized by the forwarder). Matched as substrings of the
# lower-cased event type, in order, so "login_failed" wins over "login".
# Technique IDs intentionally reuse IDs from MITRE_RULES where they overlap.
# ---------------------------------------------------------------------------
EVENT_TYPE_RULES: List[Tuple[str, Tuple[str, float]]] = [
    ("login_failed", ("T1110 - Brute Force", 0.5)),
    ("login.success", ("T1078 - Valid Accounts", 1.0)),
    ("login", ("T1078 - Valid Accounts", 1.0)),
    ("sqli", ("T1190 - Exploit Public-Facing Application", 4.0)),
    ("file_upload", ("T1505.003 - Server Software Component: Web Shell", 3.0)),
    ("download", ("T1105 - Ingress Tool Transfer", 3.0)),
    ("shellcode", ("T1210 - Exploitation of Remote Services", 5.0)),
    ("smb", ("T1210 - Exploitation of Remote Services", 5.0)),
    ("pipe", ("T1210 - Exploitation of Remote Services", 5.0)),
    ("http", ("T1190 - Exploit Public-Facing Application", 4.0)),
    ("sip", ("T1190 - Exploit Public-Facing Application", 4.0)),
    ("vnc", ("T1190 - Exploit Public-Facing Application", 4.0)),
    ("upnp", ("T1190 - Exploit Public-Facing Application", 4.0)),
    ("redis", ("T1110 - Brute Force", 2.0)),
    ("smtp", ("T1071.003 - Application Layer Protocol: Mail Protocols", 2.0)),
    ("dns", ("T1046 - Network Service Discovery", 1.0)),
    ("scan", ("T1046 - Network Service Discovery", 1.0)),
    ("pcap", ("T1046 - Network Service Discovery", 1.0)),
]


def _has_keyword(input_lower: str, keyword: str) -> bool:
    """Substring match, with word boundaries for short single-token keywords so
    that e.g. 'id' matches 'id' but not 'rapid'."""
    keyword_lower = keyword.lower()
    if keyword_lower.isalpha():
        return re.search(r"\b" + re.escape(keyword_lower) + r"\b", input_lower) is not None
    return keyword_lower in input_lower


def map_event_to_mitre(event_type: str, input_str: str = None) -> Tuple[str, float]:
    """
    Evaluates an event against the rule tables and returns (technique, weight).
    Returns (None, 0.0) when nothing matches.
    """
    event_type = (event_type or "").lower()

    # 1) Event-type rules (logins, downloads, protocol attacks, scans...)
    for token, (technique, weight) in EVENT_TYPE_RULES:
        if token in event_type:
            return technique, weight

    # 2) Command keyword rules (only for command-style events)
    if event_type == "command" and input_str:
        input_lower = input_str.lower()
        for rule in MITRE_RULES:
            if any(_has_keyword(input_lower, kw) for kw in rule["keywords"]):
                return rule["technique"], rule["weight"]

    return None, 0.0


# ---------------------------------------------------------------------------
# Severity scoring formula
# ---------------------------------------------------------------------------
def combine_severity(current: float, weight: float) -> float:
    """
    Session severity is the additive sum of the weights of every positively
    detected event. Only weights > 0 contribute (non-detections and noise are 0).
    """
    if weight is None or weight <= 0:
        return current
    return round(float(current) + float(weight), 2)


def severity_from_events(event_specs: Iterable[Tuple[str, str]]) -> float:
    """
    Compute a session's severity from (event_type, input) pairs.
    This is the scoring formula as a pure function, used by the ingest path and
    covered by unit tests.
    """
    score = 0.0
    for event_type, input_str in event_specs:
        _, weight = map_event_to_mitre(event_type, input_str)
        score = combine_severity(score, weight)
    return score
