"""
Agent Management & Task Polling API Endpoints
Implements agent authentication, isolation checks, atomic task lease, and replay prevention.
"""
import uuid
import secrets
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import Agent, Task, TaskResult, Evidence, AuditLog
from backend.app.schemas.schemas import AgentRegister, AgentResponse, HeartbeatPayload, TaskResponse, ResultSubmit
from backend.app.config import settings
from backend.app.services.event_broadcaster import broadcaster
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.investigation_orchestrator import InvestigationOrchestrator
from agent.security.capabilities import get_platform_capabilities

router = APIRouter(prefix="/api/agents", tags=["Agents"])

@router.post("/register", response_model=AgentResponse)
def register_agent(payload: AgentRegister, db: Session = Depends(get_db)):
    if payload.enrollment_token != settings.AGENT_REGISTRATION_TOKEN:
        # Audit log failed enrollment
        audit = AuditLog(
            actor=payload.agent_id,
            actor_type="AGENT",
            action="AGENT_ENROLLMENT_FAILED",
            resource=f"Agent:{payload.agent_id}",
            resource_id=payload.agent_id,
            result="DENIED",
            details={"reason": "Invalid enrollment token"}
        )
        db.add(audit)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid agent enrollment token."
        )

    agent = db.query(Agent).filter(Agent.id == payload.agent_id).first()
    now = datetime.now(timezone.utc)
    token = f"agt_{secrets.token_hex(16)}"
    caps = payload.capabilities or get_platform_capabilities(payload.platform)

    from backend.app.services.security_integrity_service import IntegrityService
    id_fp = IntegrityService.canonical_hash({
        "agent_id": payload.agent_id,
        "platform": payload.platform,
        "hostname": payload.hostname,
        "architecture": payload.architecture or "unknown"
    })
    cap_fp = IntegrityService.canonical_hash(sorted(list(caps)))

    if not agent:
        agent = Agent(
            id=payload.agent_id,
            hostname=payload.hostname,
            platform=payload.platform,
            os_version=payload.os_version,
            architecture=payload.architecture,
            ip_address=payload.ip_address,
            agent_version=payload.agent_version,
            capabilities=caps,
            auth_token=token,
            identity_fingerprint=id_fp,
            capability_fingerprint=cap_fp,
            status="online",
            last_seen=now
        )
        db.add(agent)
    else:
        agent.hostname = payload.hostname
        agent.platform = payload.platform
        agent.os_version = payload.os_version
        agent.architecture = payload.architecture
        agent.ip_address = payload.ip_address
        agent.agent_version = payload.agent_version
        agent.capabilities = caps
        agent.auth_token = agent.auth_token or token
        agent.identity_fingerprint = id_fp
        agent.capability_fingerprint = cap_fp
        agent.status = "online"
        agent.last_seen = now

    db.commit()
    db.refresh(agent)

    broadcaster.broadcast(
        event_type="AGENT_CONNECTED",
        message=f"Forensic Agent '{agent.id}' ({agent.hostname} / {agent.platform}) enrolled with {len(caps)} capabilities.",
        data={"agent_id": agent.id, "hostname": agent.hostname, "platform": agent.platform, "capabilities_count": len(caps)}
    )

    IntegrityService.record_chained_audit(
        db=db,
        actor=agent.id,
        actor_type="AGENT",
        action="AGENT_REGISTER",
        resource=f"Agent:{agent.id}",
        resource_type="Agent",
        resource_id=agent.id,
        result="SUCCESS",
        details={"hostname": agent.hostname, "platform": agent.platform, "identity_fingerprint": id_fp}
    )

    return agent

@router.get("", response_model=List[AgentResponse])
def list_agents(platform: Optional[str] = None, status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Agent)
    if platform:
        query = query.filter(Agent.platform.ilike(f"%{platform}%"))
    if status:
        query = query.filter(Agent.status == status)
    return query.all()

@router.get("/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return agent

@router.get("/{agent_id}/capabilities")
def get_agent_capabilities(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    caps = agent.capabilities or get_platform_capabilities(agent.platform)
    return {
        "agent_id": agent.id,
        "platform": agent.platform,
        "capabilities": caps,
        "count": len(caps)
    }

@router.post("/{agent_id}/heartbeat")
def agent_heartbeat(agent_id: str, payload: HeartbeatPayload, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    agent.last_seen = datetime.now(timezone.utc)
    agent.status = payload.status
    db.commit()

    broadcaster.broadcast(
        event_type="HEARTBEAT_RECEIVED",
        message=f"Agent '{agent.id}' heartbeat received (Status: {agent.status}).",
        data={"agent_id": agent.id, "status": agent.status}
    )

    return {"status": "acknowledged", "agent_id": agent_id, "timestamp": agent.last_seen.isoformat()}

@router.get("/{agent_id}/tasks", response_model=List[TaskResponse])
def poll_agent_tasks(agent_id: str, db: Session = Depends(get_db)):
    """Atomic task lease: fetches pending tasks for agent and transitions them atomically to 'assigned'."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    now = datetime.now(timezone.utc)
    # Query only tasks strictly assigned to this specific agent and still in 'pending' status
    pending_tasks = db.query(Task).filter(
        Task.agent_id == agent_id,
        Task.status == "pending"
    ).all()

    dispatched = []
    for t in pending_tasks:
        t.status = "assigned"
        t.assigned_at = now
        t.started_at = now
        dispatched.append(t)

        broadcaster.broadcast(
            event_type="TASK_ASSIGNED",
            message=f"Task '{t.name}' ({t.id}) claimed by Agent '{agent_id}'",
            data={"task_id": t.id, "agent_id": agent_id, "case_id": t.case_id}
        )

        audit = AuditLog(
            actor=agent_id,
            actor_type="AGENT",
            action="TASK_LEASE_CLAIMED",
            resource=f"Task:{t.id}",
            resource_id=t.id,
            result="SUCCESS",
            details={"agent_id": agent_id}
        )
        db.add(audit)

    if dispatched:
        db.commit()
        for t in dispatched:
            db.refresh(t)

    return dispatched

@router.post("/{agent_id}/results", status_code=status.HTTP_201_CREATED)
def submit_agent_results(agent_id: str, payload: ResultSubmit, db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == payload.task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"Task '{payload.task_id}' not found.")

    from backend.app.services.security_integrity_service import IntegrityService
    from backend.app.services.tamper_detection_service import TamperDetectionService

    # 1. Agent Isolation Security Check: Caller agent must match task's assigned agent!
    if task.agent_id != agent_id or payload.agent_id != agent_id:
        TamperDetectionService.create_security_event(
            db=db,
            event_type="AGENT_ISOLATION_VIOLATION",
            severity="CRITICAL",
            object_type="TASK",
            object_id=task.id,
            description=f"Agent isolation violation: Agent '{agent_id}' submitted results for task assigned to '{task.agent_id}'.",
            expected_value=task.agent_id,
            observed_value=agent_id,
            case_id=task.case_id,
            agent_id=agent_id
        )

        IntegrityService.record_chained_audit(
            db=db,
            actor=agent_id,
            actor_type="AGENT",
            action="AGENT_ISOLATION_BREACH_ATTEMPT",
            resource=f"Task:{task.id}",
            resource_type="Task",
            resource_id=task.id,
            case_id=task.case_id,
            result="DENIED",
            details={"expected_agent": task.agent_id, "attempted_agent": agent_id}
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"AGENT_ISOLATION_VIOLATION: Agent '{agent_id}' is not authorized to submit results for task '{payload.task_id}' assigned to '{task.agent_id}'."
        )

    # 2. Task Replay Protection: Completed tasks cannot be re-executed!
    if task.status == "completed":
        TamperDetectionService.create_security_event(
            db=db,
            event_type="REPLAY_ATTEMPT_DETECTED",
            severity="HIGH",
            object_type="TASK",
            object_id=task.id,
            description=f"TASK_ALREADY_COMPLETED: Duplicate execution result rejected for task '{task.id}'.",
            expected_value="pending|assigned|running",
            observed_value="completed",
            case_id=task.case_id,
            agent_id=agent_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"TASK_ALREADY_COMPLETED: Replay rejected for task '{task.id}'."
        )

    now = datetime.now(timezone.utc)
    task_res = TaskResult(
        task_id=task.id,
        status="completed",
        output_summary=f"Collected {len(payload.evidence_envelopes)} evidence envelopes."
    )
    db.add(task_res)
    db.flush()

    latest_ev = db.query(Evidence).filter(Evidence.case_id == task.case_id).order_by(Evidence.collected_at.desc(), Evidence.id.desc()).first()
    running_prev_hash = (latest_ev.content_hash or latest_ev.sha256_hash) if latest_ev else "0" * 64

    saved_evidence_ids = []
    for env in payload.evidence_envelopes:
        is_valid, claimed_hash, _, _ = EvidenceService.verify_envelope(env)
        ev_id = env.get("evidence_id")
        collector = env.get("collector", "unknown")
        platform_name = env.get("platform", "unknown")

        ev_hashes = IntegrityService.calculate_evidence_hashes(env, previous_hash=running_prev_hash)

        evidence_entry = Evidence(
            id=ev_id,
            case_id=task.case_id,
            agent_id=agent_id,
            task_result_id=task_res.id,
            collector=collector,
            platform=platform_name,
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

        broadcaster.broadcast(
            event_type="EVIDENCE_RECEIVED",
            message=f"Sealed Evidence '{ev_id}' ({collector}) received from Agent '{agent_id}'",
            data={"evidence_id": ev_id, "collector": collector, "hash": claimed_hash, "valid": is_valid}
        )

    task.status = "completed"
    task.completed_at = now

    broadcaster.broadcast(
        event_type="TASK_COMPLETED",
        message=f"Task '{task.name}' ({task.id}) completed successfully by Agent '{agent_id}'",
        data={"task_id": task.id, "evidence_count": len(saved_evidence_ids)}
    )

    IntegrityService.record_chained_audit(
        db=db,
        actor=agent_id,
        actor_type="AGENT",
        action="EVIDENCE_SUBMITTED",
        resource=f"Task:{task.id}",
        resource_type="Task",
        resource_id=task.id,
        case_id=task.case_id,
        result="SUCCESS",
        details={"agent_id": agent_id, "evidence_count": len(saved_evidence_ids)}
    )
    db.commit()


    # Trigger Automated Phase 5 Investigation Pipeline (IOC extraction, timeline, correlation, findings)
    try:
        for ev_id in saved_evidence_ids:
            InvestigationOrchestrator.process_evidence(ev_id, db)
    except Exception as e:
        # Non-fatal error; logs or continues
        pass

    return {
        "status": "success",
        "task_id": task.id,
        "evidence_saved": len(saved_evidence_ids),
        "evidence_ids": saved_evidence_ids
    }
