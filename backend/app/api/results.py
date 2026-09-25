"""
Task Results & Evidence Submission API Endpoints
"""
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import Task, TaskResult, Evidence, AuditLog
from backend.app.schemas.schemas import ResultSubmit
from backend.app.services.evidence_service import EvidenceService

router = APIRouter(prefix="/api/results", tags=["Results"])

@router.post("", status_code=status.HTTP_201_CREATED)
def submit_results(payload: ResultSubmit, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == payload.task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")

    task_res = TaskResult(
        task_id=task.id,
        status="completed",
        output_summary=f"Collected {len(payload.evidence_envelopes)} evidence envelopes."
    )
    db.add(task_res)
    db.flush()

    from backend.app.services.security_integrity_service import IntegrityService
    latest_ev = db.query(Evidence).filter(Evidence.case_id == task.case_id).order_by(Evidence.collected_at.desc(), Evidence.id.desc()).first()
    running_prev_hash = (latest_ev.content_hash or latest_ev.sha256_hash) if latest_ev else "0" * 64
    now = datetime.now(timezone.utc)

    # Process and store each evidence envelope
    saved_evidence_ids = []
    for env in payload.evidence_envelopes:
        is_valid, claimed_hash, _, _ = EvidenceService.verify_envelope(env)
        ev_id = env.get("evidence_id")
        collector = env.get("collector", "unknown")
        platform = env.get("platform", "unknown")

        ev_hashes = IntegrityService.calculate_evidence_hashes(env, previous_hash=running_prev_hash)

        evidence_entry = Evidence(
            id=ev_id,
            case_id=task.case_id,
            agent_id=payload.agent_id,
            task_result_id=task_res.id,
            collector=collector,
            platform=platform,
            sha256_hash=claimed_hash,
            envelope_data=env,
            is_verified=is_valid,
            content_hash=ev_hashes["content_hash"],
            metadata_hash=ev_hashes["metadata_hash"],
            previous_hash=running_prev_hash,
            integrity_status="VERIFIED" if is_valid else "TAMPERED",
            sealed_at=now
        )
        db.add(evidence_entry)
        running_prev_hash = ev_hashes["content_hash"]
        saved_evidence_ids.append(ev_id)

    task.status = "completed"
    task.completed_at = now

    IntegrityService.record_chained_audit(
        db=db,
        actor=payload.agent_id,
        actor_type="AGENT",
        action="EVIDENCE_SUBMITTED",
        resource=f"Task:{task.id}",
        resource_type="Task",
        resource_id=task.id,
        case_id=task.case_id,
        result="SUCCESS",
        details={"agent_id": payload.agent_id, "evidence_count": len(saved_evidence_ids)}
    )
    db.commit()


    return {
        "status": "success",
        "task_id": task.id,
        "evidence_saved": len(saved_evidence_ids),
        "evidence_ids": saved_evidence_ids
    }

@router.get("")
def list_results(task_id: str = None, db: Session = Depends(get_db)):
    query = db.query(TaskResult)
    if task_id:
        query = query.filter(TaskResult.task_id == task_id)
    return query.all()
