"""Wipe all attack data (sessions / events / techniques) from the DB while
keeping user accounts and the postgres server intact. Use when you want the
dashboard to show only freshly-trapped attacks.

Run inside the core-api container:
    docker compose cp core-api/clean_db.py deciptionnet-core-api-1:/app/clean_db.py
    docker compose exec core-api python /app/clean_db.py
"""

from database import SessionLocal, Event, SessionTechnique, AttackSession


def wipe_attack_data():
    db = SessionLocal()
    try:
        # Delete children first (bulk delete bypasses ORM cascade), then sessions.
        remaining_events = db.query(Event).delete()
        remaining_techs = db.query(SessionTechnique).delete()
        remaining_sessions = db.query(AttackSession).delete()
        db.commit()
        print(
            f"Wiped {remaining_sessions} sessions, "
            f"{remaining_techs} techniques, {remaining_events} events."
        )
    finally:
        db.close()


if __name__ == "__main__":
    wipe_attack_data()