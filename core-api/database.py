from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.exc import OperationalError
import datetime
import os
import time

# Default to PostgreSQL (primary store). Tests / local dev can override with SQLite.
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://deceptionnet:deceptionnet@postgres:5432/deceptionnet",
)

# SQLite needs check_same_thread for FastAPI threadpool usage; Postgres does not.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AttackSession(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, index=True)
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    end_time = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String, index=True)
    severity_score = Column(Float, default=0.0)
    ai_summary = Column(Text, nullable=True)
    # Honeypot of the event that opened the session ("cowrie" | "dionaea" | ...).
    # Used to decide whether an unknown session id should be IP+time correlated.
    honeypot = Column(String, nullable=True)

    events = relationship("Event", back_populates="session", cascade="all, delete")
    techniques = relationship(
        "SessionTechnique", back_populates="session", cascade="all, delete"
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    event_type = Column(String)  # login, command, download, smb, ...
    message = Column(Text)
    raw_data = Column(Text)  # JSON string of the raw event
    mitre_technique = Column(String, nullable=True)
    honeypot = Column(String, nullable=True)  # which honeypot produced this event

    session = relationship("AttackSession", back_populates="events")


class SessionTechnique(Base):
    """MITRE technique attributed to a session and how it was detected.

    `source` is one of:
      - "rule"     -> matched by the keyword/event-type rule table in mitre.py
      - "semantic" -> returned by the AI semantic-mitre service
    """

    __tablename__ = "session_techniques"
    __table_args__ = (
        # One row per (session, technique, source). Ingestion runs in parallel
        # background threads, so the DB enforces dedup while upsert_technique
        # uses a savepoint to survive the concurrent-insert race.
        UniqueConstraint(
            "session_id", "technique", "source", name="uq_session_technique_source"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), index=True)
    technique = Column(String, index=True)
    weight = Column(Float, default=0.0)
    source = Column(String, default="rule")  # "rule" | "semantic"
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)

    session = relationship("AttackSession", back_populates="techniques")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(retries: int = 10, delay: int = 3):
    """Create tables, retrying so the app can start before Postgres is fully ready."""
    for attempt in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except OperationalError as e:
            if attempt == retries - 1:
                raise
            print(f"[database] DB not ready (attempt {attempt + 1}/{retries}): {e}")
            time.sleep(delay)


# RUN_INIT_DB=0 lets tests import this module (and main.py) without touching
# Postgres — they build their own in-memory engine. Production keeps the retry.
if os.environ.get("RUN_INIT_DB", "1") == "1":
    init_db()
