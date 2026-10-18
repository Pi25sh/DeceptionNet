"""Unit tests for session correlation (get_or_create_session) and technique
upsert. These lock in the cross-honeypot-only fallback behavior: an unknown
session id is correlated by (src_ip, time-window) ONLY when the incoming event
comes from a *different* honeypot, so two Cowrie sessions from one IP are never
merged into one.
"""
import datetime

import pytest

from database import AttackSession, SessionTechnique
from main import get_or_create_session, upsert_technique


def _session(db, sid, ip, start, end=None, honeypot="cowrie", score=0.0):
    s = AttackSession(
        id=sid,
        src_ip=ip,
        start_time=start,
        end_time=end or start,
        severity_score=score,
        honeypot=honeypot,
    )
    db.add(s)
    db.flush()
    return s


def _t(days=0, minutes=0):
    return datetime.datetime.utcnow() - datetime.timedelta(days=days, minutes=minutes)


class TestGetOrCreateSession:
    def test_exact_session_id_match_wins(self, db_session):
        s = _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=10))
        result = get_or_create_session(db_session, "cowrie-a", "10.0.0.5", _t(), "cowrie")
        assert result.id == s.id

    def test_unknown_id_same_honeypot_is_new_session(self, db_session):
        """Two Cowrie sessions from one IP must never merge."""
        _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=5))
        result = get_or_create_session(db_session, "cowrie-b", "10.0.0.5", _t(), "cowrie")
        assert result.id == "cowrie-b"  # new session, not the correlated one

    def test_unknown_id_cross_honeypot_correlates(self, db_session):
        """A Dionaea event (foreign id) attaches to the recent Cowrie session."""
        s = _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=1))
        result = get_or_create_session(
            db_session, "dionaea-xyz", "10.0.0.5", _t(), honeypot="dionaea"
        )
        assert result.id == s.id

    def test_cross_honeypot_outside_window_is_new(self, db_session):
        _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=60))
        result = get_or_create_session(
            db_session, "dionaea-xyz", "10.0.0.5", _t(), honeypot="dionaea"
        )
        assert result.id == "dionaea-xyz"

    def test_unknown_id_no_honeypot_never_correlates(self, db_session):
        _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=1))
        result = get_or_create_session(db_session, "nohp-1", "10.0.0.5", _t(), honeypot=None)
        assert result.id == "nohp-1"

    def test_unknown_ip_never_correlates(self, db_session):
        _session(db_session, "cowrie-a", "10.0.0.5", _t(minutes=1))
        result = get_or_create_session(
            db_session, "dionaea-xyz", "unknown", _t(), honeypot="dionaea"
        )
        assert result.id == "dionaea-xyz"

    def test_new_session_initialized_with_zero_score(self, db_session):
        result = get_or_create_session(db_session, "fresh", "10.0.0.5", _t(), "cowrie")
        assert result.severity_score == 0.0
        assert result.src_ip == "10.0.0.5"


class TestUpsertTechnique:
    def test_dedup_same_technique_same_source(self, db_session):
        _session(db_session, "s1", "10.0.0.5", _t())
        upsert_technique(db_session, "s1", "T1078", 2.0, "rule")
        upsert_technique(db_session, "s1", "T1078", 2.0, "rule")
        db_session.commit()
        rows = db_session.query(SessionTechnique).filter(
            SessionTechnique.session_id == "s1"
        ).all()
        assert len(rows) == 1

    def test_rule_and_semantic_side_by_side(self, db_session):
        _session(db_session, "s1", "10.0.0.5", _t())
        upsert_technique(db_session, "s1", "T1078", 2.0, "rule")
        upsert_technique(db_session, "s1", "T1078", 3.0, "semantic")
        db_session.commit()
        rows = db_session.query(SessionTechnique).filter(
            SessionTechnique.session_id == "s1"
        ).all()
        assert {r.source for r in rows} == {"rule", "semantic"}

    def test_empty_technique_is_noop(self, db_session):
        _session(db_session, "s1", "10.0.0.5", _t())
        upsert_technique(db_session, "s1", "", 2.0, "rule")
        upsert_technique(db_session, "s1", None, 2.0, "rule")
        db_session.commit()
        assert db_session.query(SessionTechnique).count() == 0

    def test_unique_constraint_enforced_at_db_level(self, db_session):
        """The (session, technique, source) unique constraint must be real: a
        second, concurrent session inserting an identical row (both existence
        checks passed before either committed) is rejected by the DB."""
        from sqlalchemy.exc import IntegrityError

        _session(db_session, "s1", "10.0.0.5", _t())
        db_session.commit()

        # Thread A inserts + commits first.
        upsert_technique(db_session, "s1", "T1078", 2.0, "rule")
        db_session.commit()

        # Thread B had already passed its exists-check; insert the duplicate
        # behind a fresh transaction so the DB constraint is the only guard.
        db_session.add(
            SessionTechnique(session_id="s1", technique="T1078", weight=2.0, source="rule")
        )
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        rows = db_session.query(SessionTechnique).filter(
            SessionTechnique.session_id == "s1"
        ).all()
        assert len(rows) == 1  # losing insert absorbed, winner intact

    def test_concurrent_upsert_technique_threads(self, tmp_path):
        """Simulate concurrent threads calling upsert_technique with the same technique.
        Verifies begin_nested savepoints and unique constraints under multithreaded execution."""
        import threading
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from database import Base

        db_file = tmp_path / "test_concurrency.db"
        engine = create_engine(f"sqlite:///{db_file}", connect_args={"timeout": 30})
        Base.metadata.create_all(engine)
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL;")

        SessionFactory = sessionmaker(bind=engine)
        init_db = SessionFactory()
        init_db.add(AttackSession(
            id="conc-test", src_ip="198.51.100.99",
            start_time=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
            end_time=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
            severity_score=0.0, honeypot="cowrie"
        ))
        init_db.commit()
        init_db.close()

        def worker():
            db = SessionFactory()
            try:
                upsert_technique(db, "conc-test", "T1078", 1.0, "rule")
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        check_db = SessionFactory()
        rows = check_db.query(SessionTechnique).filter(
            SessionTechnique.session_id == "conc-test",
            SessionTechnique.technique == "T1078"
        ).all()
        check_db.close()
        engine.dispose()
        assert len(rows) == 1

