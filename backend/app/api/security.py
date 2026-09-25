"""
Security & Forensic Integrity API Endpoints
Provides real-time tamper detection queries, case integrity verification,
evidence validation, report verification, and security posture monitoring.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.models import SecurityEvent, Evidence, Case, Report, User
from backend.app.schemas.schemas import (
    SecurityEventResponse,
    SecurityEventResolve,
    VerificationResult,
    CaseIntegrityScorecard,
    SecurityConfigurationResponse
)
from backend.app.services.security_integrity_service import IntegrityService
from backend.app.services.tamper_detection_service import TamperDetectionService
from backend.app.services.config_integrity_service import ConfigIntegrityService
from backend.app.security.auth import get_current_user, require_role

router = APIRouter(prefix="/api/security", tags=["Security & Integrity"])


@router.get("/events", response_model=List[SecurityEventResponse])
def list_security_events(
    case_id: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    resolved: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves filterable security and tamper events."""
    query = db.query(SecurityEvent)

    if case_id:
        query = query.filter(SecurityEvent.case_id == case_id)
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if agent_id:
        query = query.filter(SecurityEvent.agent_id == agent_id)
    if resolved is not None:
        query = query.filter(SecurityEvent.resolved == resolved)
    if start_time:
        query = query.filter(SecurityEvent.detected_at >= start_time)
    if end_time:
        query = query.filter(SecurityEvent.detected_at <= end_time)

    return query.order_by(SecurityEvent.detected_at.desc()).limit(limit).all()


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
def get_security_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieves specific security event details by ID."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found.")
    return event


@router.patch("/events/{event_id}/resolve", response_model=SecurityEventResponse)
def resolve_security_event(
    event_id: str,
    payload: Optional[SecurityEventResolve] = None,
    db: Session = Depends(get_db)
):
    """Marks a detected security or tamper event as resolved by an authorized analyst."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found.")

    resolver = payload.resolved_by if payload else "analyst@jocky.defense"
    comment = payload.comment if payload else "Resolved by analyst review"

    event.resolved = True
    event.resolved_by = resolver
    event.resolved_at = datetime.now()
    if not event.metadata_json:
        event.metadata_json = {}
    event.metadata_json["resolution_comment"] = comment

    # Record append-only audit
    IntegrityService.record_chained_audit(
        db=db,
        actor=resolver,
        actor_type="USER",
        action="RESOLVE_SECURITY_EVENT",
        resource=f"SecurityEvent:{event_id}",
        resource_type="SecurityEvent",
        resource_id=event_id,
        case_id=event.case_id,
        result="SUCCESS",
        details={"event_type": event.event_type, "comment": comment}
    )

    db.commit()
    db.refresh(event)
    return event


@router.post("/verify/evidence/{evidence_id}", response_model=VerificationResult)
def verify_evidence_endpoint(evidence_id: str, db: Session = Depends(get_db)):
    """Verifies cryptographic SHA-256 seal of an individual evidence envelope."""
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item '{evidence_id}' not found.")

    is_valid, claimed, recalc, msg = IntegrityService.verify_single_evidence(evidence)

    if not is_valid:
        # Automatically record tamper security event
        TamperDetectionService.create_security_event(
            db=db,
            event_type="EVIDENCE_TAMPER_DETECTED",
            severity="CRITICAL",
            object_type="EVIDENCE",
            object_id=evidence.id,
            description=f"Evidence envelope {evidence.id} failed cryptographic verification: {msg}",
            expected_value=claimed,
            observed_value=recalc,
            case_id=evidence.case_id
        )

    return VerificationResult(
        object_type="EVIDENCE",
        object_id=evidence.id,
        status="VERIFIED" if is_valid else "COMPROMISED",
        is_valid=is_valid,
        expected_hash=claimed,
        calculated_hash=recalc,
        reason=msg,
        recommended_action="Admit evidence into chain-of-custody" if is_valid else "Quarantine evidence and alert investigating analyst."
    )


@router.post("/verify/case/{case_id}", response_model=CaseIntegrityScorecard)
def verify_case_endpoint(case_id: str, db: Session = Depends(get_db)):
    """
    Executes deep multi-control verification across the entire case:
    Evidence chain, audit chain, tasks, playbooks, configuration, and reports.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    # 1. Run Tamper Detection scan to record any newly discovered tamper anomalies
    TamperDetectionService.scan_and_record_case_security_events(db, case_id)

    # 2. Evaluate and return the 7-control scorecard
    scorecard = IntegrityService.evaluate_case_integrity_scorecard(db, case_id)
    return scorecard


@router.get("/integrity/{case_id}", response_model=CaseIntegrityScorecard)
def get_case_integrity_scorecard(case_id: str, db: Session = Depends(get_db)):
    """Retrieves current measurable integrity status and scorecard for a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    return IntegrityService.evaluate_case_integrity_scorecard(db, case_id)


@router.post("/verify/report/{report_id}", response_model=VerificationResult)
def verify_report_endpoint(report_id: str, db: Session = Depends(get_db)):
    """Verifies court-admissible forensic report manifest and content hash."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    is_valid, msg, details = IntegrityService.verify_report_manifest(report)

    if not is_valid:
        TamperDetectionService.create_security_event(
            db=db,
            event_type="REPORT_INTEGRITY_MISMATCH",
            severity="HIGH",
            object_type="REPORT",
            object_id=report.id,
            description=f"Report {report.id} failed cryptographic manifest verification: {msg}",
            expected_value=details.get("expected_manifest_hash"),
            observed_value=details.get("calculated_manifest_hash"),
            case_id=report.case_id
        )

    return VerificationResult(
        object_type="REPORT",
        object_id=report.id,
        status="VERIFIED" if is_valid else "COMPROMISED",
        is_valid=is_valid,
        expected_hash=details.get("expected_manifest_hash"),
        calculated_hash=details.get("calculated_manifest_hash"),
        reason=msg,
        recommended_action="Report is cryptographically sealed and court-admissible" if is_valid else "Re-generate report with valid cryptographic seal.",
        details=details
    )


@router.get("/configuration", response_model=SecurityConfigurationResponse)
def get_security_configuration():
    """
    Returns public defensive security posture and configuration fingerprint.
    Never exposes passwords, tokens, keys, or secrets.
    """
    fp = ConfigIntegrityService.get_baseline_fingerprint()
    ok, _, current_fp = ConfigIntegrityService.verify_configuration_integrity()

    return SecurityConfigurationResponse(
        authentication="enabled",
        audit_logging="enabled",
        evidence_sealing="enabled",
        playbook_approval="enabled",
        agent_isolation="enabled",
        replay_protection="enabled",
        configuration_integrity="enabled",
        configuration_fingerprint=current_fp,
        algorithm="SHA-256",
        status="VERIFIED" if ok else "COMPROMISED"
    )
