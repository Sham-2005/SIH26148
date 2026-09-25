"""
Forensic Case Management API Endpoints
"""
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import Case, AuditLog
from backend.app.schemas.schemas import CaseCreate, CaseUpdate, CaseResponse
from backend.app.services.event_broadcaster import broadcaster

router = APIRouter(prefix="/api/cases", tags=["Cases"])

@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    case_id = payload.id or f"CASE-{uuid.uuid4().hex[:8].upper()}"

    existing = db.query(Case).filter(Case.id == case_id).first()
    if existing:
        existing.title = payload.title
        existing.description = payload.description
        existing.severity = payload.severity.lower()
        existing.status = payload.status.upper()
        db.commit()
        db.refresh(existing)
        return existing

    case = Case(
        id=case_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity.lower(),
        status=payload.status.upper()
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    # Broadcast event
    broadcaster.broadcast(
        event_type="CASE_CREATED",
        message=f"Forensic Case '{case.title}' ({case.id}) opened with severity {case.severity.upper()}",
        data={"case_id": case.id, "severity": case.severity, "status": case.status}
    )

    audit = AuditLog(
        action="CASE_CREATE",
        resource=f"Case:{case.id}",
        details={"title": case.title, "severity": case.severity}
    )
    db.add(audit)
    db.commit()

    return case

@router.get("", response_model=List[CaseResponse])
def list_cases(status: Optional[str] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status.upper())
    if severity:
        query = query.filter(Case.severity == severity.lower())
    return query.order_by(Case.created_at.desc()).all()

@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case

@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    if payload.title is not None:
        case.title = payload.title
    if payload.description is not None:
        case.description = payload.description
    if payload.severity is not None:
        case.severity = payload.severity.lower()
    if payload.status is not None:
        case.status = payload.status.upper()

    db.commit()
    db.refresh(case)

    broadcaster.broadcast(
        event_type="CASE_UPDATED",
        message=f"Case '{case.id}' status updated to {case.status} (Severity: {case.severity})",
        data={"case_id": case.id, "status": case.status, "severity": case.severity}
    )

    return case
