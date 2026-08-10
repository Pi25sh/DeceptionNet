from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, update, func
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool
from typing import List, Optional
from pydantic import BaseModel
import datetime
import os
import re
import requests

from database import (
    get_db,
    AttackSession,
    Event,
    SessionTechnique,
    SessionLocal,
)
from mitre import map_event_to_mitre
from report import generate_pdf_report

app = FastAPI(title="DeceptionNet Core API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AI_SERVICE_URL = os.environ.get("AI_SERVICE_URL", "http://ai-service:8001/summarize")
# Member 3's semantic MITRE endpoint. Gracefully skipped if unavailable.
SEMANTIC_MITRE_URL = os.environ.get(
    "SEMANTIC_MITRE_URL", "http://ai-service:8001/api/v1/ai/semantic-mitre"
)

# When an event arrives with a session id we've never seen, fall back to
# correlating it to a recent session from the same src_ip. This matters once
# Dionaea events (which carry their own session ids) start arriving.
SESSION_CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("SESSION_CORRELATION_WINDOW_MINUTES", "5")
)


class EventPayload(BaseModel):
    session_id: str
    event_type: str
    timestamp: str
    src_ip: Optional[str] = None
    input: Optional[str] = None
    url: Optional[str] = None
    outfile: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    message: str
    honeypot: Optional[str] = None  # "cowrie" | "dionaea" | ...
    protocol: Optional[str] = None


# ---------------------------------------------------------------------------
# WebSocket live-events
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws/live-events")
async def live_events(websocket: WebSocket):
    """Push channel: clients get a full session snapshot on connect, then a
    per-event update every time a honeypot event is ingested."""
    await manager.connect(websocket)
    try:
        # Snapshot so clients can render without an initial /sessions poll
        db = SessionLocal()
        try:
            sessions = [
                serialize_session(s, db)
                for s in db.query(AttackSession).order_by(desc(AttackSession.start_time)).all()
            ]
        finally:
            db.close()
        await websocket.send_json({"type": "sessions", "data": sessions})

        # Keep the socket open; client pings/disconnect are handled here.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def serialize_event(e: Event) -> dict:
    return {
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "event_type": e.event_type,
        "message": e.message,
        "mitre_technique": e.mitre_technique,
        "honeypot": e.honeypot,
    }


def session_techniques(db: Session, session_id: str) -> List[dict]:
    """Techniques attributed to a session, deduplicated, with their source."""
    rows = (
        db.query(SessionTechnique)
        .filter(SessionTechnique.session_id == session_id)
        .order_by(desc(SessionTechnique.weight))
        .all()
    )
    seen = {}
    for r in rows:
        if r.technique and r.technique not in seen:
            seen[r.technique] = {
                "technique": r.technique,
                "source": r.source,
                "weight": r.weight,
            }
    return list(seen.values())


def serialize_session(s: AttackSession, db: Session) -> dict:
    techs = session_techniques(db, s.id)
    return {
        "id": s.id,
        "src_ip": s.src_ip,
        "start_time": s.start_time.isoformat() if s.start_time else None,
        "end_time": s.end_time.isoformat() if s.end_time else None,
        "severity_score": s.severity_score,
        "ai_summary": s.ai_summary,
        # Plain technique strings for dashboard backwards-compat
        "techniques": [t["technique"] for t in techs],
        # Richer view (source = "rule" | "semantic") for live / detailed UIs
        "techniques_detail": techs,
    }


def _serialize_latest_session(session_id: str) -> Optional[dict]:
    """Re-read a session and serialize it for a WS broadcast. Returns None if
    the session vanished between the ingest and the summary refresh."""
    db = SessionLocal()
    try:
        s = db.query(AttackSession).filter(AttackSession.id == session_id).first()
        return serialize_session(s, db) if s else None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AI summary (plain-language narrative)
# ---------------------------------------------------------------------------
def trigger_ai_summary(session_id: str):
    db = SessionLocal()
    try:
        session = db.query(AttackSession).filter(AttackSession.id == session_id).first()
        if not session:
            return

        events = (
            db.query(Event)
            .filter(Event.session_id == session_id)
            .order_by(Event.timestamp)
            .all()
        )
        event_texts = [f"{e.event_type.upper()}: {e.message}" for e in events]

        try:
            response = requests.post(AI_SERVICE_URL, json={"events": event_texts}, timeout=10)
            if response.status_code == 200:
                summary = response.json().get("summary")
                if summary:
                    session.ai_summary = summary
                    db.commit()
        except Exception as e:
            print(f"[core-api] Failed to get AI summary: {e}")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Semantic MITRE enrichment (Member 3's service). Best-effort: a failure or
# 404 just means the report is generated from rule-based techniques alone.
# ---------------------------------------------------------------------------
def call_semantic_mitre(events: List[dict]) -> List[dict]:
    try:
        response = requests.post(SEMANTIC_MITRE_URL, json={"events": events}, timeout=15)
        if response.status_code == 200:
            data = response.json()
            techniques = data.get("techniques") or []
            if isinstance(techniques, list):
                return [t for t in techniques if isinstance(t, dict) and t.get("technique")]
    except Exception as e:
        print(f"[core-api] semantic-mitre unavailable ({e}); using rule-based only")
    return []


# ---------------------------------------------------------------------------
# Persistence (runs in a worker thread, off the event loop)
# ---------------------------------------------------------------------------
def parse_timestamp(ts: str) -> datetime.datetime:
    try:
        t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if t.tzinfo is not None:
            t = t.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return t
    except ValueError:
        return datetime.datetime.utcnow()


def get_or_create_session(
    db: Session,
    session_id: str,
    src_ip: Optional[str],
    event_time: datetime.datetime,
    honeypot: Optional[str] = None,
) -> AttackSession:
    """Exact session-id match first; if unknown, correlate by (src_ip, time
    window) so Dionaea events (which carry their own session ids) attach to the
    matching attack session.

    The fallback only fires for *cross-honeypot* events. A Cowrie event with an
    unseen session id is a genuinely new session (two distinct Cowrie sessions
    from one IP must not be merged); a Dionaea event carries a foreign id and is
    correlated to the recent session from the same attacker.
    """
    session = db.query(AttackSession).filter(AttackSession.id == session_id).first()
    if session:
        return session

    if src_ip and src_ip != "unknown" and honeypot:
        window_start = event_time - datetime.timedelta(minutes=SESSION_CORRELATION_WINDOW_MINUTES)
        candidate = (
            db.query(AttackSession)
            .filter(
                AttackSession.src_ip == src_ip,
                AttackSession.start_time >= window_start,
                # Only cross-honeypot: dionaea -> cowrie (or vice versa), never
                # cowrie -> cowrie, which would merge separate attack sessions.
                AttackSession.honeypot.isnot(None),
                AttackSession.honeypot != honeypot,
            )
            .order_by(desc(AttackSession.end_time))
            .first()
        )
        if candidate:
            return candidate

    session = AttackSession(
        id=session_id,
        start_time=event_time,
        end_time=event_time,
        src_ip=src_ip or "unknown",
        severity_score=0.0,
        honeypot=honeypot,
    )
    db.add(session)
    try:
        db.flush()
    except IntegrityError:
        # Concurrent ingest created the same session id first
        db.rollback()
        session = db.query(AttackSession).filter(AttackSession.id == session_id).first()
        if session is None:
            raise
    return session


def upsert_technique(db: Session, session_id: str, technique: str, weight: float, source: str):
    """Insert a technique row unless it already exists, tolerating the
    concurrent-insert race (background tasks run in parallel threads).

    The insert happens inside a nested savepoint; if a concurrent thread wins
    the race, the IntegrityError rolls back only the savepoint and leaves the
    outer transaction (the event insert + severity bump) untouched.
    """
    if not technique:
        return
    try:
        with db.begin_nested():
            exists = (
                db.query(SessionTechnique)
                .filter(
                    SessionTechnique.session_id == session_id,
                    SessionTechnique.technique == technique,
                    SessionTechnique.source == source,
                )
                .first()
            )
            if not exists:
                db.add(
                    SessionTechnique(
                        session_id=session_id,
                        technique=technique,
                        weight=weight,
                        source=source,
                    )
                )
    except IntegrityError:
        # A concurrent thread inserted the same (session, technique, source) row
        pass


def persist_event(payload: EventPayload) -> dict:
    db = SessionLocal()
    try:
        event_time = parse_timestamp(payload.timestamp)
        session = get_or_create_session(
            db, payload.session_id, payload.src_ip, event_time, honeypot=payload.honeypot
        )

        if session.start_time is None or event_time < session.start_time:
            session.start_time = event_time
        if session.end_time is None or event_time > session.end_time:
            session.end_time = event_time

        technique, weight = map_event_to_mitre(payload.event_type, payload.input)

        event = Event(
            session_id=session.id,
            timestamp=event_time,
            event_type=payload.event_type,
            message=payload.message,
            raw_data=payload.model_dump_json(),
            mitre_technique=technique,
            honeypot=payload.honeypot,
        )
        db.add(event)

        if weight > 0:
            # Atomic increment: background tasks may run in parallel threads, so
            # a read-modify-write here would lose concurrent updates. The DB does
            # the arithmetic instead.
            db.execute(
                update(AttackSession)
                .where(AttackSession.id == session.id)
                .values(
                    severity_score=func.coalesce(AttackSession.severity_score, 0.0) + weight
                )
            )
        upsert_technique(db, session.id, technique, weight, source="rule")

        db.commit()
        db.refresh(session)

        return {"session": serialize_session(session, db), "event": serialize_event(event)}
    finally:
        db.close()


async def process_event_background(payload: EventPayload):
    # A burst of honeypot traffic must not block the ingestion endpoint, so the
    # DB write runs in a worker thread; the response is already sent by now.
    try:
        view = await run_in_threadpool(persist_event, payload)
    except Exception as e:
        print(f"[core-api] Failed to persist event: {e}")
        return

    try:
        await manager.broadcast(
            {"type": "event", "session": view["session"], "event": view["event"]}
        )
    except Exception as e:
        print(f"[core-api] WS broadcast failed: {e}")

    if payload.event_type in ("command", "download"):
        try:
            await run_in_threadpool(trigger_ai_summary, view["session"]["id"])
            # The AI narrative lands after the event broadcast; push the refreshed
            # session so live dashboards show the summary without polling.
            refreshed = await run_in_threadpool(_serialize_latest_session, view["session"]["id"])
            if refreshed:
                await manager.broadcast({"type": "session", "session": refreshed})
        except Exception as e:
            print(f"[core-api] AI summary failed: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/events")
async def receive_event(payload: EventPayload, background_tasks: BackgroundTasks):
    """Accept an event immediately; persistence happens in the background."""
    background_tasks.add_task(process_event_background, payload)
    return {"status": "accepted"}


@app.get("/sessions")
def list_sessions(db: Session = Depends(get_db)):
    sessions = db.query(AttackSession).order_by(desc(AttackSession.start_time)).all()
    return [serialize_session(s, db) for s in sessions]


@app.get("/sessions/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db)):
    session = db.query(AttackSession).filter(AttackSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = (
        db.query(Event)
        .filter(Event.session_id == session_id)
        .order_by(Event.timestamp)
        .all()
    )
    result = serialize_session(session, db)
    result["events"] = [serialize_event(e) for e in events]
    return result


@app.get("/incidents/{session_id}/report")
def get_incident_report(session_id: str, db: Session = Depends(get_db)):
    session = db.query(AttackSession).filter(AttackSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = (
        db.query(Event)
        .filter(Event.session_id == session_id)
        .order_by(Event.timestamp)
        .all()
    )

    # Trigger the AI narrative synchronously if missing
    if not session.ai_summary:
        trigger_ai_summary(session.id)
        db.refresh(session)

    # Semantic MITRE enrichment (Member 3). Stored side-by-side with rule-based
    # techniques, both visible in session_techniques with their source.
    semantic = call_semantic_mitre(
        [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "message": e.message,
            }
            for e in events
        ]
    )
    if semantic:
        for item in semantic:
            upsert_technique(
                db,
                session.id,
                item["technique"],
                float(item.get("weight") or 0.0),
                source="semantic",
            )
        db.commit()

    techniques = session_techniques(db, session.id)

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:80] or "session"
    report_path = f"/app/data/report_{safe_id}.pdf"
    generate_pdf_report(session, events, report_path, techniques=techniques)

    return FileResponse(
        report_path,
        filename=f"DeceptionNet_Report_{safe_id}.pdf",
        media_type="application/pdf",
    )
