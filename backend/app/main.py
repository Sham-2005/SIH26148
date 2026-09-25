"""
SIH26148 - JOCKY Forensic Platform FastAPI Application
Central Management Server for Authorized Defensive Forensic Operations
"""
import os
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings
from backend.app.database.session import engine, SessionLocal
from backend.app.database.base import Base
from backend.app.models.models import User, Case, Agent
from backend.app.security.auth import get_password_hash
from backend.app.api import auth, agents, tasks, results, evidence, reports, cases, audit, investigations, threat_intel, playbooks, security, ml, demo
from backend.app.services.event_broadcaster import broadcaster

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB tables and upgrade schemas
    Base.metadata.create_all(bind=engine)
    from backend.app.database.migrations import ensure_schema_upgrades
    ensure_schema_upgrades(engine, Base.metadata)

    # 2. Seed initial analyst user and demo case if database is fresh
    db = SessionLocal()
    try:
        analyst = db.query(User).filter(User.email == "analyst@jocky.defense").first()
        if not analyst:
            default_analyst = User(
                email="analyst@jocky.defense",
                hashed_password=get_password_hash("ForensicsPass2026!"),
                full_name="Chief Forensic Analyst",
                role="analyst"
            )
            db.add(default_analyst)
            db.commit()

        # Seed initial demo case
        demo_case = db.query(Case).filter(Case.id == "CASE-2026-001").first()
        if not demo_case:
            demo_case = Case(
                id="CASE-2026-001",
                title="Enterprise Triage & Persistence Analysis",
                description="Fleet-wide investigation of unauthorized persistence artifacts and anomalous processes.",
                severity="high",
                status="INVESTIGATING"
            )
            db.add(demo_case)
            db.commit()

        # Seed Phase 27 Provenance & Investigation Workspace demo case
        phase27_case = db.query(Case).filter(Case.id == "CASE-DEMO-01").first()
        if not phase27_case:
            from backend.app.services.provenance_service import ProvenanceService
            ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db)
    finally:
        db.close()

    # 3. Ensure storage directories exist
    os.makedirs(settings.EVIDENCE_STORAGE_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_STORAGE_DIR, exist_ok=True)

    yield

app = FastAPI(
    title="SIH26148 JOCKY Forensic Platform API",
    version="1.0.0",
    description="Defensive Digital-Forensics Platform & DSL Management Server",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import uuid
import re
from datetime import datetime, timezone
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

# HTTP Security Response Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; connect-src *"
    response.headers["X-Request-ID"] = request_id
    return response

def _sanitize_error_text(text: Any) -> str:
    """Removes sensitive paths, tokens, SQL fragments, and stack traces."""
    if not isinstance(text, str):
        text = str(text)
    # Mask Windows/Linux file paths
    text = re.sub(r'[A-Za-z]:\\[^"\'\s]+', "[REDACTED_PATH]", text)
    text = re.sub(r'/(?:Users|home|root|etc|tmp|var)/[^"\'\s]+', "[REDACTED_PATH]", text)
    # Mask potential bearer/JWT tokens or keys
    text = re.sub(r'eyJ[a-zA-Z0-9_\-\.]+', "[REDACTED_TOKEN]", text)
    text = re.sub(r'(?:secret|key|password|token)=[^&\s]+', "[REDACTED_SECRET]", text, flags=re.IGNORECASE)
    return text

def _extract_error_code(detail: Any, status_code: int) -> str:
    detail_str = str(detail) if detail else ""
    known_codes = [
        "UNSUPPORTED_CAPABILITY",
        "AGENT_ISOLATION_VIOLATION",
        "TASK_ALREADY_COMPLETED",
        "PLAYBOOK_INTEGRITY_VIOLATION",
        "UNSUPPORTED_RESPONSE_ACTION",
        "EVIDENCE_TAMPER_DETECTED",
        "REPLAY_ATTEMPT_DETECTED",
        "AGENT_IDENTITY_MISMATCH",
        "CONFIG_INTEGRITY_VIOLATION",
        "TIMESTAMP_ANOMALY",
        "REPORT_INTEGRITY_MISMATCH",
        "INVALID_APPROVAL_STATE",
    ]
    for code in known_codes:
        if code in detail_str:
            return code

    mapping = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        422: "VALIDATION_ERROR",
        500: "INTERNAL_SERVER_ERROR"
    }
    return mapping.get(status_code, "ERROR")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    now_ts = datetime.now(timezone.utc).isoformat()
    code = _extract_error_code(exc.detail, exc.status_code)
    safe_detail = _sanitize_error_text(exc.detail) if isinstance(exc.detail, str) else exc.detail
    safe_message = safe_detail if isinstance(safe_detail, str) else "Request failed"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": safe_detail,
            "error": {
                "code": code,
                "message": safe_message,
                "request_id": request_id,
                "timestamp": now_ts
            }
        },
        headers={"X-Request-ID": request_id}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    now_ts = datetime.now(timezone.utc).isoformat()
    safe_msg = "Invalid request payload or schema parameters."

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "error": {
                "code": "VALIDATION_ERROR",
                "message": safe_msg,
                "request_id": request_id,
                "timestamp": now_ts
            }
        },
        headers={"X-Request-ID": request_id}
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    now_ts = datetime.now(timezone.utc).isoformat()

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred.",
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal error occurred during forensic processing.",
                "request_id": request_id,
                "timestamp": now_ts
            }
        },
        headers={"X-Request-ID": request_id}
    )

# Register Routers
app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(agents.router)
app.include_router(tasks.router)
app.include_router(results.router)
app.include_router(evidence.router)
app.include_router(reports.router)
app.include_router(audit.router)
app.include_router(investigations.router)
app.include_router(threat_intel.router)
app.include_router(playbooks.router)
app.include_router(security.router)
app.include_router(ml.router)
app.include_router(demo.router)


@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time live activity feed in SOC dashboard."""
    await broadcaster.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "SYSTEM_CONNECTED",
            "message": "Connected to JOCKY SOC Real-Time Telemetry Stream",
            "timestamp": broadcaster.get_recent_events(1)[0]["timestamp"] if broadcaster.get_recent_events(1) else ""
        })
        while True:
            # Keep socket open and receive any ping messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception:
        broadcaster.disconnect(websocket)

@app.get("/api/events")
def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """REST fallback for live activity feed if WebSocket is unavailable."""
    return broadcaster.get_recent_events(limit=limit)

@app.get("/")
def root():
    return {
        "platform": "SIH26148 JOCKY Forensic Framework",
        "status": "operational",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

@app.get("/health")
@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "database": "connected"
    }
