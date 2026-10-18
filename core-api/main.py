from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
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
import jwt
from passlib.context import CryptContext

from database import (
    get_db,
    AttackSession,
    Event,
    SessionTechnique,
    SessionLocal,
    User,
    Report,
)
from mitre import map_event_to_mitre
from report import generate_pdf_report

# JWT Configuration
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "deceptionnet-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

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
# When an event arrives with a session id we've never seen, fall back to
# correlating it to a recent session from the same src_ip. This matters once
# Dionaea events (which carry their own session ids) start arriving.
SESSION_CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("SESSION_CORRELATION_WINDOW_MINUTES", "5")
)

# Member 3's semantic MITRE endpoint
SEMANTIC_MITRE_URL = os.environ.get(
    "SEMANTIC_MITRE_URL", "http://ai-service:8001/api/v1/ai/semantic-mitre"
)
# Member 3's report narrative endpoint
REPORT_NARRATIVE_URL = os.environ.get(
    "REPORT_NARRATIVE_URL", "http://ai-service:8001/api/v1/ai/report-narrative"
)
# Grounding check endpoint
GROUNDING_CHECK_URL = os.environ.get(
    "GROUNDING_CHECK_URL", "http://ai-service:8001/api/v1/ai/grounding-check"
)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def get_current_user_ws(token: str, db: Session) -> Optional[User]:
    """Get user from WebSocket token (no exception, returns None if invalid)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        user = db.query(User).filter(User.username == username).first()
        return user
    except jwt.PyJWTError:
        return None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime.datetime
    last_login: Optional[datetime.datetime]


@app.post("/api/v1/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """OAuth2 compatible login endpoint - returns JWT token."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not user.verify_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Update last login
    user.last_login = datetime.datetime.utcnow()
    db.commit()
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/v1/auth/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Register a new user (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create users")

    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(username=user_data.username, role=user_data.role)
    user.set_password(user_data.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.get("/api/v1/auth/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return current_user


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
    honeypot: Optional[str] = None  # "cowrie" | "dionaea" | "custom-decoy" | ...
    service: Optional[str] = None
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
async def live_events(websocket: WebSocket, token: str = None):
    """Push channel: clients get a full session snapshot on connect, then a
    per-event update every time a honeypot event is ingested.

    Requires JWT token as query parameter: /ws/live-events?token=<jwt>
    """
    # Verify token
    db = SessionLocal()
    try:
        user = get_current_user_ws(token, db) if token else None
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    finally:
        db.close()

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
        "session_id": e.session_id,
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
        "honeypot": s.honeypot,
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


def call_grounding_check(events: List[dict], techniques: List[dict]) -> List[dict]:
    """Apply grounding check to filter out unsupported techniques."""
    try:
        response = requests.post(
            GROUNDING_CHECK_URL,
            json={"events": events},
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            grounded = data.get("techniques") or []
            if isinstance(grounded, list):
                return [t for t in grounded if isinstance(t, dict) and t.get("technique")]
    except Exception as e:
        print(f"[core-api] grounding-check unavailable ({e}); using techniques as-is")
    return techniques


def call_report_narrative(summary: str, techniques: List[dict]) -> str:
    """Generate narrative paragraph for PDF report."""
    try:
        response = requests.post(
            REPORT_NARRATIVE_URL,
            json={"summary": summary, "techniques": techniques},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            narrative = data.get("narrative")
            if narrative:
                return narrative
    except Exception as e:
        print(f"[core-api] report-narrative unavailable ({e}); using fallback")
    return ""


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
    """Accept an event immediately; persistence happens in the background.
    Note: This endpoint is public (no auth) for honeypot forwarders to ingest events.
    """
    background_tasks.add_task(process_event_background, payload)
    return {"status": "accepted"}


@app.get("/sessions")
def list_sessions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    sessions = db.query(AttackSession).order_by(desc(AttackSession.start_time)).all()
    return [serialize_session(s, db) for s in sessions]


@app.get("/events")
def list_events(
    limit: int = Query(300, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Recent honeypot events, oldest-first so the live feed can seed then append."""
    rows = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()
    rows.reverse()
    return [serialize_event(e) for e in rows]


@app.get("/sessions/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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
def get_incident_report(session_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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

    # Get current techniques (rule-based + any previously stored semantic)
    techniques = session_techniques(db, session.id)

    # Apply grounding check to semantic techniques only
    # (Rule-based techniques are already grounded by definition)
    semantic_techniques = [t for t in techniques if t.get("source") == "semantic"]
    rule_techniques = [t for t in techniques if t.get("source") == "rule"]

    if semantic_techniques:
        # Prepare events for grounding check
        event_data = [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "message": e.message,
            }
            for e in events
        ]
        grounded_semantic = call_grounding_check(event_data, semantic_techniques)
        # Keep only grounded semantic techniques
        grounded_ids = {t["technique"] for t in grounded_semantic if t.get("grounded", False)}
        techniques = rule_techniques + [t for t in semantic_techniques if t["technique"] in grounded_ids]

    # Generate narrative using AI service
    ai_summary = session.ai_summary or "No AI summary available."
    narrative = call_report_narrative(ai_summary, techniques)

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:80] or "session"
    filename = f"DeceptionNet_Report_{safe_id}.pdf"
    report_path = f"/app/data/{filename}"
    generate_pdf_report(session, events, report_path, techniques=techniques, narrative=narrative)

    # Record metadata so the dashboard can list this report in its history and
    # re-download it without regenerating. One report per session (regenerating
    # replaces the previous row, keeping the history tidy).
    size = os.path.getsize(report_path) if os.path.exists(report_path) else 0
    existing = (
        db.query(Report).filter(Report.session_id == session_id).first()
    )
    if existing:
        existing.filename = filename
        existing.file_path = report_path
        existing.generated_at = datetime.datetime.utcnow()
        existing.file_size = size
        existing.generated_by = current_user.username
    else:
        db.add(
            Report(
                session_id=session_id,
                filename=filename,
                file_path=report_path,
                file_size=size,
                generated_by=current_user.username,
            )
        )
    db.commit()

    return FileResponse(
        report_path,
        filename=filename,
        media_type="application/pdf",
    )


@app.get("/reports")
def list_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """History of generated incident reports, newest first."""
    rows = (
        db.query(Report, AttackSession.src_ip, AttackSession.severity_score)
        .join(AttackSession, AttackSession.id == Report.session_id)
        .order_by(Report.generated_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "session_id": r.session_id,
            "filename": r.filename,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "file_size": r.file_size,
            "generated_by": r.generated_by,
            "src_ip": src_ip,
            "severity_score": severity_score,
        }
        for r, src_ip, severity_score in rows
    ]


@app.get("/reports/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Re-download a previously generated report PDF."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(
        report.file_path,
        filename=report.filename,
        media_type="application/pdf",
    )
