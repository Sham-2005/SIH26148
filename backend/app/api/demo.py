"""
JOCKY One-Click Forensic Demo API Endpoint
Coordinates end-to-end execution of declarative JOCKY demo scripts,
recording execution history with deterministic verification and persistence.
"""
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.services.demo_service import JockyDemoService, JockyDemoParser
from backend.app.models.models import ExecutionHistory

router = APIRouter(prefix="/api/demo", tags=["Demo"])

DEMO_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "language",
    "examples",
    "demo_persistence.jocky"
)

DEFAULT_DEMO_SCRIPT = """CASE "CASE-2026-001"

TARGET "DEMO-WINDOWS-ENDPOINT"

COLLECT registry
WHERE path MATCHES "Run|RunOnce"

COLLECT process
WHERE parent == "explorer.exe"

COLLECT eventlog
WHERE event_id IN [4688, 7045]

COLLECT network

COLLECT filesystem

CORRELATE
    registry
    WITH process
    WITH eventlog
    WITH network
    WITH filesystem

ANALYZE forensic_vector

CALCULATE threat_score

VERIFY tamper

HASH evidence

CHAIN evidence

REPORT"""


class DemoRunRequest(BaseModel):
    script: Optional[str] = None


class HistoryRecordRequest(BaseModel):
    execution_id: Optional[str] = None
    case_id: Optional[str] = "CASE-2026-001"
    script_name: Optional[str] = "demo_persistence.jocky"
    script_content: str
    target: Optional[str] = "DEMO-WINDOWS-ENDPOINT"
    status: str = "SUCCESS"  # SUCCESS | FAILED
    duration_ms: Optional[float] = 0.0
    threat_score: Optional[int] = None
    risk_level: Optional[str] = None
    evidence_categories: Optional[List[str]] = None
    forensic_vector_dimensions: Optional[int] = 21
    tamper_checks_passed: Optional[int] = 12
    tamper_checks_total: Optional[int] = 12
    chain_status: Optional[str] = "VERIFIED"
    error_message: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None


def get_next_execution_id(db: Session) -> str:
    """Generates the next sequential EXE-XXXX execution identifier."""
    existing = db.query(ExecutionHistory.execution_id).all()
    max_num = 0
    for (eid,) in existing:
        if eid and eid.startswith("EXE-"):
            try:
                num = int(eid.split("-")[1])
                if num > max_num:
                    max_num = num
            except (ValueError, IndexError):
                pass
    return f"EXE-{max_num + 1:04d}"


@router.get("/script")
def get_demo_script() -> Dict[str, str]:
    """Returns the default built-in demo_persistence.jocky script."""
    content = DEFAULT_DEMO_SCRIPT
    if os.path.exists(DEMO_SCRIPT_PATH):
        try:
            with open(DEMO_SCRIPT_PATH, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            pass
    return {
        "filename": "demo_persistence.jocky",
        "script": content
    }


@router.post("/run")
def run_demo(payload: Optional[DemoRunRequest] = None, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Executes the JOCKY demo script through the full forensic pipeline:
    Parser -> Validation -> Evidence Collection -> Correlation ->
    21-dim Forensic Vector -> Threat Scoring -> 12 Tamper Detectors ->
    Evidence Hashing -> Chain of Custody -> Final Report.
    Automatically persists each execution to the Execution History database.
    """
    started_at = datetime.now(timezone.utc)
    t0 = time.time()
    script_text = (payload.script if payload and payload.script else None) or DEFAULT_DEMO_SCRIPT

    # Parse metadata from script for tracking
    parsed_info = {}
    try:
        parsed_info = JockyDemoParser.parse(script_text)
    except Exception:
        pass

    case_id = parsed_info.get("case_id", "CASE-2026-001")
    target = parsed_info.get("target", "DEMO-WINDOWS-ENDPOINT")

    try:
        result = JockyDemoService.execute_demo(script_text, db=db)
        completed_at = datetime.now(timezone.utc)
        elapsed_ms = result.get("execution_time_ms", round((time.time() - t0) * 1000, 2))

        # Persist to ExecutionHistory table
        next_id = get_next_execution_id(db)
        threat_score = result.get("threat_analysis", {}).get("threat_score")
        risk_level = result.get("threat_analysis", {}).get("risk_level")
        categories = result.get("evidence_collection", {}).get("categories_collected", [])
        dims = result.get("forensic_vector", {}).get("dimensions", 21)
        passed_tamper = result.get("tamper_detection", {}).get("passed_detectors", 12)
        total_tamper = result.get("tamper_detection", {}).get("total_detectors", 12)
        chain_stat = result.get("chain_of_custody", {}).get("chain_status", "VERIFIED")

        record = ExecutionHistory(
            execution_id=next_id,
            case_id=case_id,
            script_name="demo_persistence.jocky",
            script_content=script_text,
            target=target,
            status="SUCCESS",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=elapsed_ms,
            threat_score=threat_score,
            risk_level=risk_level,
            evidence_categories=categories,
            forensic_vector_dimensions=dims,
            tamper_checks_passed=passed_tamper,
            tamper_checks_total=total_tamper,
            chain_status=chain_stat,
            error_message=None,
            result_data=result
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        result["execution_id"] = next_id
        return result

    except Exception as e:
        completed_at = datetime.now(timezone.utc)
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        next_id = get_next_execution_id(db)

        # Record failed execution
        failed_record = ExecutionHistory(
            execution_id=next_id,
            case_id=case_id,
            script_name="demo_persistence.jocky",
            script_content=script_text,
            target=target,
            status="FAILED",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=elapsed_ms,
            threat_score=None,
            risk_level=None,
            evidence_categories=[],
            forensic_vector_dimensions=0,
            tamper_checks_passed=0,
            tamper_checks_total=12,
            chain_status="FAILED",
            error_message=str(e),
            result_data=None
        )
        try:
            db.add(failed_record)
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Execution failed: {str(e)}"
        )


@router.get("/history")
def get_history(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """
    Returns all historical JOCKY executions ordered with newest execution first.
    """
    records = db.query(ExecutionHistory).order_by(ExecutionHistory.id.desc()).all()
    history_list = []
    for r in records:
        time_str = r.completed_at.strftime("%H:%M") if r.completed_at else (
            r.started_at.strftime("%H:%M") if r.started_at else "--:--"
        )
        history_list.append({
            "id": r.id,
            "execution_id": r.execution_id,
            "case_id": r.case_id,
            "script_name": r.script_name,
            "script_content": r.script_content,
            "target": r.target,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "time_display": time_str,
            "duration_ms": r.duration_ms,
            "threat_score": r.threat_score,
            "risk_level": r.risk_level,
            "evidence_categories": r.evidence_categories or [],
            "forensic_vector_dimensions": r.forensic_vector_dimensions,
            "tamper_checks_passed": r.tamper_checks_passed,
            "tamper_checks_total": r.tamper_checks_total,
            "chain_status": r.chain_status,
            "error_message": r.error_message,
            "result_data": r.result_data
        })
    return history_list


@router.get("/history/{execution_id}")
def get_execution_details(execution_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns complete technical details for a specific execution record.
    """
    r = db.query(ExecutionHistory).filter(ExecutionHistory.execution_id == execution_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Execution {execution_id} not found")

    time_str = r.completed_at.strftime("%H:%M") if r.completed_at else (
        r.started_at.strftime("%H:%M") if r.started_at else "--:--"
    )
    return {
        "id": r.id,
        "execution_id": r.execution_id,
        "case_id": r.case_id,
        "script_name": r.script_name,
        "script_content": r.script_content,
        "target": r.target,
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "time_display": time_str,
        "duration_ms": r.duration_ms,
        "threat_score": r.threat_score,
        "risk_level": r.risk_level,
        "evidence_categories": r.evidence_categories or [],
        "forensic_vector_dimensions": r.forensic_vector_dimensions,
        "tamper_checks_passed": r.tamper_checks_passed,
        "tamper_checks_total": r.tamper_checks_total,
        "chain_status": r.chain_status,
        "error_message": r.error_message,
        "result_data": r.result_data
    }


@router.post("/history")
def save_history_record(payload: HistoryRecordRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Explicitly saves or syncs an execution record to the history database.
    """
    try:
        eid = payload.execution_id or get_next_execution_id(db)

        # Check if record already exists to prevent UNIQUE constraint violation
        existing = db.query(ExecutionHistory).filter(ExecutionHistory.execution_id == eid).first()
        if existing:
            if payload.status:
                existing.status = payload.status
            if payload.duration_ms is not None:
                existing.duration_ms = payload.duration_ms
            if payload.threat_score is not None:
                existing.threat_score = payload.threat_score
            if payload.risk_level:
                existing.risk_level = payload.risk_level
            if payload.evidence_categories:
                existing.evidence_categories = payload.evidence_categories
            if payload.result_data:
                existing.result_data = payload.result_data
            if payload.error_message:
                existing.error_message = payload.error_message
            db.commit()
            db.refresh(existing)
            return {"status": "UPDATED", "execution_id": eid, "id": existing.id}

        now = datetime.now(timezone.utc)
        record = ExecutionHistory(
            execution_id=eid,
            case_id=payload.case_id or "CASE-2026-001",
            script_name=payload.script_name or "demo_persistence.jocky",
            script_content=payload.script_content,
            target=payload.target or "DEMO-WINDOWS-ENDPOINT",
            status=payload.status,
            started_at=now,
            completed_at=now,
            duration_ms=payload.duration_ms or 0.0,
            threat_score=payload.threat_score,
            risk_level=payload.risk_level,
            evidence_categories=payload.evidence_categories or [],
            forensic_vector_dimensions=payload.forensic_vector_dimensions or 21,
            tamper_checks_passed=payload.tamper_checks_passed or 12,
            tamper_checks_total=payload.tamper_checks_total or 12,
            chain_status=payload.chain_status or "VERIFIED",
            error_message=payload.error_message,
            result_data=payload.result_data
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return {"status": "SAVED", "execution_id": eid, "id": record.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not persist history record: {str(e)}"
        )


@router.delete("/history")
def clear_history(db: Session = Depends(get_db)) -> Dict[str, str]:
    """Clears all execution history records."""
    db.query(ExecutionHistory).delete()
    db.commit()
    return {"status": "SUCCESS", "message": "Execution history cleared"}


@router.post("/benchmark")
def benchmark_demo(payload: Optional[DemoRunRequest] = None, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Runs multi-pass execution benchmark to measure actual latency and verify repeatability.
    """
    script_text = (payload.script if payload and payload.script else None) or DEFAULT_DEMO_SCRIPT
    times = []
    for _ in range(5):
        res = JockyDemoService.execute_demo(script_text, db=None)
        times.append(res["execution_time_ms"])

    avg_time = round(sum(times) / len(times), 2)
    min_time = round(min(times), 2)
    max_time = round(max(times), 2)

    return {
        "status": "SUCCESS",
        "iterations": len(times),
        "latencies_ms": times,
        "average_latency_ms": avg_time,
        "min_latency_ms": min_time,
        "max_latency_ms": max_time,
        "observed_latency_label": f"<38 ms ({avg_time} ms)" if avg_time < 38 else f"{avg_time} ms",
        "environment": "Local demonstration environment",
        "workload": "1 synthetic investigation",
        "artifacts_count": 5
    }

