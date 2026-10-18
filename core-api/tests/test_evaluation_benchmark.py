"""Verification tests for session correlation edge cases and benchmark sample schema.
This module verifies real code behavior in get_or_create_session (cross-honeypot
correlation, independent session isolation, time window boundaries, and NAT collisions).
"""
import datetime
import json
import os
import pytest

from main import get_or_create_session
from database import AttackSession

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "benchmark"))


def test_illustrative_benchmark_sample_schema():
    """Verify that illustrative sample benchmark events are valid JSON with expected keys."""
    events_path = os.path.join(DATA_DIR, "events_redacted.json")
    if os.path.exists(events_path):
        with open(events_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        assert isinstance(events, list)
        for evt in events:
            assert "id" in evt
            assert "event_type" in evt


class TestCorrelationAccuracyAndBoundaryCases:
    """Verify session correlation rules implemented in get_or_create_session against
    concrete cross-honeypot, same-honeypot, timing window, and NAT scenarios.
    """

    def test_correlation_cases_ground_truth(self, db_session):
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        # Case 1: Standard cross-honeypot campaign (Cowrie -> Dionaea within 5m window)
        db_session.add(AttackSession(
            id="case1-cowrie", src_ip="198.51.100.10",
            start_time=now - datetime.timedelta(minutes=3),
            end_time=now - datetime.timedelta(minutes=2),
            honeypot="cowrie", severity_score=1.0
        ))
        db_session.commit()

        res1 = get_or_create_session(
            db_session, "case1-dionaea", "198.51.100.10", now, honeypot="dionaea"
        )
        assert res1.id == "case1-cowrie", "Standard cross-honeypot within window should correlate"

        # Case 2: Independent same-honeypot sessions (must NOT merge)
        db_session.add(AttackSession(
            id="case2-cowrie-1", src_ip="198.51.100.20",
            start_time=now - datetime.timedelta(minutes=2),
            end_time=now - datetime.timedelta(minutes=2),
            honeypot="cowrie", severity_score=1.0
        ))
        db_session.commit()

        res2 = get_or_create_session(
            db_session, "case2-cowrie-2", "198.51.100.20", now, honeypot="cowrie"
        )
        assert res2.id == "case2-cowrie-2", "Independent sessions on same honeypot must not merge"

        # Case 3: Timing Boundary Case - Inside 5m window (4m 50s)
        db_session.add(AttackSession(
            id="case3-win-inside", src_ip="198.51.100.30",
            start_time=now - datetime.timedelta(minutes=4, seconds=50),
            end_time=now - datetime.timedelta(minutes=4, seconds=50),
            honeypot="cowrie", severity_score=1.0
        ))
        db_session.commit()

        res3 = get_or_create_session(
            db_session, "case3-dionaea", "198.51.100.30", now, honeypot="dionaea"
        )
        assert res3.id == "case3-win-inside", "Event at 4m50s must correlate inside 5m window"

        # Case 4: Timing Boundary Case - Outside 5m window (5m 10s)
        db_session.add(AttackSession(
            id="case4-win-outside", src_ip="198.51.100.40",
            start_time=now - datetime.timedelta(minutes=5, seconds=10),
            end_time=now - datetime.timedelta(minutes=5, seconds=10),
            honeypot="cowrie", severity_score=1.0
        ))
        db_session.commit()

        res4 = get_or_create_session(
            db_session, "case4-dionaea", "198.51.100.40", now, honeypot="dionaea"
        )
        assert res4.id == "case4-dionaea", "Event at 5m10s must NOT correlate outside 5m window"

        # Case 5: NAT Boundary Case - Multiple hosts sharing same public IP
        db_session.add(AttackSession(
            id="nat-user-a", src_ip="203.0.113.50",
            start_time=now - datetime.timedelta(minutes=1),
            end_time=now - datetime.timedelta(minutes=1),
            honeypot="cowrie", severity_score=1.0
        ))
        db_session.commit()

        res_nat = get_or_create_session(
            db_session, "nat-user-b-decoy", "203.0.113.50", now, honeypot="custom-decoy"
        )
        # Without cookie pinning, IP heuristic merges (documented tradeoff):
        assert res_nat.id == "nat-user-a"
