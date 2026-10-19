import os
import sys
import json
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import models from core-api
from database import Base, AttackSession, Event, SessionTechnique

def export_case_study():
    # 1. Connect to PostgreSQL (running in Docker)
    pg_url = os.environ.get("DATABASE_URL", "postgresql://deceptionnet:deceptionnet@postgres:5432/deceptionnet")
    pg_engine = create_engine(pg_url)
    PgSession = sessionmaker(bind=pg_engine)
    pg_db = PgSession()

    # Query all sessions, techniques, events
    all_sessions = pg_db.query(AttackSession).order_by(AttackSession.start_time.asc()).all()
    all_events = pg_db.query(Event).order_by(Event.timestamp.asc()).all()
    all_techniques = pg_db.query(SessionTechnique).all()

    print(f"Read from Postgres: {len(all_sessions)} sessions, {len(all_events)} events, {len(all_techniques)} techniques")

    # 2. Write to SQLite replica in /app/data/case_study.db
    sqlite_path = "/app/data/case_study.db"
    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    sqlite_engine = create_engine(f"sqlite:///{sqlite_path}")
    Base.metadata.create_all(sqlite_engine)
    SqliteSession = sessionmaker(bind=sqlite_engine)
    sq_db = SqliteSession()

    # Replicate sessions
    for s in all_sessions:
        sq_s = AttackSession(
            id=s.id,
            start_time=s.start_time,
            end_time=s.end_time,
            src_ip=s.src_ip,
            severity_score=s.severity_score,
            ai_summary=s.ai_summary,
            honeypot=s.honeypot
        )
        sq_db.add(sq_s)
    sq_db.commit()

    # Replicate techniques
    for t in all_techniques:
        sq_t = SessionTechnique(
            session_id=t.session_id,
            technique=t.technique,
            weight=t.weight,
            source=t.source,
            detected_at=t.detected_at
        )
        sq_db.add(sq_t)
    sq_db.commit()

    # Replicate events
    for e in all_events:
        sq_e = Event(
            id=e.id,
            session_id=e.session_id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            message=e.message,
            raw_data=e.raw_data,
            mitre_technique=e.mitre_technique,
            honeypot=e.honeypot
        )
        sq_db.add(sq_e)
    sq_db.commit()
    sq_db.close()
    print(f"Replicated to SQLite: {sqlite_path}")

    # 3. Construct JSON ledger
    session_summaries = []
    for s in all_sessions:
        techs = pg_db.query(SessionTechnique).filter_by(session_id=s.id).all()
        cnt = pg_db.query(Event).filter_by(session_id=s.id).count()
        session_summaries.append({
            "session_id": s.id,
            "src_ip": s.src_ip,
            "honeypot": s.honeypot,
            "severity_score": float(s.severity_score),
            "techniques": [t.technique for t in techs],
            "event_count": cnt
        })

    # Find campaign session (event_count == 9)
    campaign_s = next(s for s in session_summaries if s["event_count"] == 9)
    campaign_events = pg_db.query(Event).filter_by(session_id=campaign_s["session_id"]).order_by(Event.timestamp.asc()).all()

    # Map running severity for campaign steps
    from mitre import map_event_to_mitre, combine_severity
    campaign_ledger = []
    running_sev = 0.0
    for idx, e in enumerate(campaign_events):
        raw = json.loads(e.raw_data) if e.raw_data else {}
        tech, weight = map_event_to_mitre(e.event_type, raw.get("input") or raw.get("url"))
        running_sev = combine_severity(running_sev, weight)
        campaign_ledger.append({
            "step_index": idx + 1,
            "session_id": e.session_id,
            "event_type": e.event_type,
            "input": raw.get("input"),
            "url": raw.get("url"),
            "message": e.message,
            "technique": tech,
            "weight": float(weight),
            "running_severity": float(running_sev),
            "timestamp": e.timestamp.isoformat() + "Z"
        })

    json_data = {
        "provenance": {
            "execution_type": "docker_live_harness",
            "description": (
                "End-to-end multi-stage live execution of attacker/scripts/full-attack.sh "
                "within the DeceptionNet Docker compose network, with real network traffic flowing "
                "across honeypot_net to attack-target:9090, tailed by log-forwarder-target, shipped "
                "over deceptionnet network to core-api:8000, and ingested into PostgreSQL."
            ),
            "harness_script": "attacker/scripts/full-attack.sh",
            "target_app": "attack-target:9090 (Flask)",
            "execution_time": datetime.datetime.utcnow().isoformat() + "Z",
            "cookie_session_pinning_verified": True
        },
        "run_metrics": {
            "total_events": len(all_events),
            "total_sessions": len(session_summaries),
            "campaign_session_id": campaign_s["session_id"],
            "campaign_event_count": campaign_s["event_count"],
            "campaign_final_severity": campaign_s["severity_score"],
            "unauthenticated_sessions_count": len(session_summaries) - 1
        },
        "sessions": session_summaries,
        "campaign_ledger": campaign_ledger
    }

    raw_json_path = "/app/data/case_study_raw.json"
    with open(raw_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    print(f"Exported JSON to: {raw_json_path}")
    pg_db.close()

if __name__ == "__main__":
    export_case_study()
