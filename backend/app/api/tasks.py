"""
Forensic Task Management API Endpoints
Implements capability pre-verification, atomic task lifecycle, and plan integrity enforcement.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import Task, Agent, Case, AuditLog
from backend.app.schemas.schemas import (
    TaskCreate,
    TaskResponse,
    TaskFailPayload,
    CapabilityCheckRequest,
    CapabilityCheckResponse
)
from backend.app.services.task_service import TaskService
from backend.app.services.event_broadcaster import broadcaster
from agent.security.capabilities import get_platform_capabilities, resolve_polymorphic_operation
from compiler.diagnostics.errors import JockyError

router = APIRouter(prefix="/api/tasks", tags=["Tasks"])

def _extract_plan_operations(plan_payload: dict) -> List[str]:
    ops = []
    scripts = plan_payload.get("scripts", [plan_payload])
    for s in scripts:
        for step in s.get("steps", []):
            fn = step.get("function")
            if fn:
                ops.append(fn)
    return ops

@router.post("/check-compatibility", response_model=CapabilityCheckResponse)
def check_task_compatibility(payload: CapabilityCheckRequest, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == payload.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{payload.agent_id}' not found.")

    agent_caps = agent.capabilities or get_platform_capabilities(agent.platform)
    operations = payload.operations or []

    if payload.jocky_script and not operations:
        try:
            plan = TaskService.compile_jocky_script(payload.jocky_script)
            operations = _extract_plan_operations(plan)
        except Exception:
            pass

    supported = []
    unsupported = []
    for op in operations:
        is_sup, _ = resolve_polymorphic_operation(op, agent.platform, agent_caps)
        if is_sup:
            supported.append(op)
        else:
            unsupported.append(op)

    is_compatible = (len(unsupported) == 0)
    reason = None if is_compatible else f"Agent platform '{agent.platform}' does not support: {', '.join(unsupported)}"

    return CapabilityCheckResponse(
        agent_id=agent.id,
        platform=agent.platform,
        is_compatible=is_compatible,
        supported_operations=supported,
        unsupported_operations=unsupported,
        reason=reason
    )

@router.post("", response_model=TaskResponse)
def create_task(task_in: TaskCreate, db: Session = Depends(get_db)):
    # 1. Verify agent exists
    agent = db.query(Agent).filter(Agent.id == task_in.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{task_in.agent_id}' not found.")

    # 2. Ensure case exists or create on the fly
    case = db.query(Case).filter(Case.id == task_in.case_id).first()
    if not case:
        case = Case(id=task_in.case_id, title=f"Investigation Case {task_in.case_id}")
        db.add(case)
        db.commit()

    # 3. Compile script if provided
    plan_payload = task_in.plan_payload
    if task_in.jocky_script:
        try:
            plan_payload = TaskService.compile_jocky_script(task_in.jocky_script)
        except JockyError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"JOCKY Compilation Error: {e}"
            )

    if not plan_payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'jocky_script' or 'plan_payload' must be provided."
        )

    # 4. Controlled Polymorphism & Agent Capability Verification
    operations = _extract_plan_operations(plan_payload)
    agent_caps = agent.capabilities or get_platform_capabilities(agent.platform)
    for op in operations:
        is_sup, err = resolve_polymorphic_operation(op, agent.platform, agent_caps)
        if not is_sup:
            # Audit log rejected dispatch attempt
            audit = AuditLog(
                actor="ANALYST",
                actor_type="USER",
                action="TASK_DISPATCH_REJECTED",
                resource=f"Agent:{agent.id}",
                resource_id=agent.id,
                result="DENIED",
                details={"reason": "UNSUPPORTED_CAPABILITY", "operation": op, "platform": agent.platform}
            )
            db.add(audit)
            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"UNSUPPORTED_CAPABILITY: Operation '{op}' is not supported by {agent.platform} agent '{agent.id}'."
            )

    task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
    from backend.app.services.security_integrity_service import IntegrityService
    plan_hash = IntegrityService.canonical_hash(plan_payload)
    task_hash = IntegrityService.canonical_hash({
        "task_id": task_id,
        "case_id": task_in.case_id,
        "agent_id": task_in.agent_id,
        "plan_hash": plan_hash
    })

    new_task = Task(
        id=task_id,
        case_id=task_in.case_id,
        agent_id=task_in.agent_id,
        name=task_in.name,
        script_source=task_in.jocky_script,
        plan_payload=plan_payload,
        task_hash=task_hash,
        plan_hash=plan_hash,
        status="pending",
        retry_count=0,
        timeout_seconds=300
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    broadcaster.broadcast(
        event_type="TASK_CREATED",
        message=f"New Forensic Task '{new_task.name}' queued for Agent '{new_task.agent_id}'",
        data={"task_id": new_task.id, "agent_id": new_task.agent_id, "case_id": new_task.case_id}
    )

    IntegrityService.record_chained_audit(
        db=db,
        actor="ANALYST",
        actor_type="USER",
        action="TASK_CREATE",
        resource=f"Task:{task_id}",
        resource_type="Task",
        resource_id=task_id,
        case_id=task_in.case_id,
        result="SUCCESS",
        details={"case_id": task_in.case_id, "agent_id": task_in.agent_id, "task_hash": task_hash, "plan_hash": plan_hash}
    )


    return new_task

@router.get("", response_model=List[TaskResponse])
def list_tasks(agent_id: Optional[str] = None, case_id: Optional[str] = None, status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Task)
    if agent_id:
        query = query.filter(Task.agent_id == agent_id)
    if case_id:
        query = query.filter(Task.case_id == case_id)
    if status:
        query = query.filter(Task.status == status)
    return query.order_by(Task.created_at.desc()).all()

@router.get("/{task_id}", response_model=TaskResponse)
def get_task(task_id: str, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")
    return task

@router.post("/{task_id}/fail")
def fail_task(task_id: str, payload: TaskFailPayload, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")

    task.status = "failed"
    task.error_message = payload.error
    task.completed_at = datetime.now(timezone.utc)
    db.commit()

    broadcaster.broadcast(
        event_type="TASK_FAILED",
        message=f"Task '{task.name}' ({task.id}) failed on Agent '{task.agent_id}': {payload.error}",
        data={"task_id": task.id, "error": payload.error}
    )

    audit = AuditLog(
        actor=payload.agent_id or task.agent_id,
        actor_type="AGENT",
        action="TASK_FAILED",
        resource=f"Task:{task.id}",
        resource_id=task.id,
        result="FAILURE",
        details={"error": payload.error}
    )
    db.add(audit)
    db.commit()

    return {"status": "failed", "task_id": task_id, "error": payload.error}

@router.post("/{task_id}/cancel")
def cancel_task(task_id: str, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")
    task.status = "cancelled"
    db.commit()

    broadcaster.broadcast(
        event_type="TASK_CANCELLED",
        message=f"Task '{task.name}' ({task.id}) cancelled by analyst.",
        data={"task_id": task.id}
    )
    return {"status": "cancelled", "task_id": task_id}
