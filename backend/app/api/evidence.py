"""
Evidence Vault & Cryptographic Verification API Endpoints
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import Evidence, AuditLog
from backend.app.schemas.schemas import EvidenceResponse, EvidenceVerificationResponse
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.event_broadcaster import broadcaster

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])

@router.get("", response_model=List[EvidenceResponse])
def list_evidence(case_id: Optional[str] = None, agent_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Evidence)
    if case_id:
        query = query.filter(Evidence.case_id == case_id)
    if agent_id:
        query = query.filter(Evidence.agent_id == agent_id)
    return query.order_by(Evidence.collected_at.desc()).all()

@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return ev

def _perform_verification(evidence_id: str, db: Session) -> EvidenceVerificationResponse:
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    is_valid, claimed_hash, recalculated_hash, msg = EvidenceService.verify_envelope(ev.envelope_data)

    ev.is_verified = is_valid
    db.commit()

    broadcaster.broadcast(
        event_type="EVIDENCE_VERIFIED",
        message=f"Evidence '{evidence_id}' integrity checked: {'VALID (Untampered)' if is_valid else 'TAMPERED (Mismatch)'}",
        data={"evidence_id": evidence_id, "is_valid": is_valid, "hash": recalculated_hash}
    )

    audit = AuditLog(
        action="VERIFY_EVIDENCE",
        resource=f"Evidence:{evidence_id}",
        details={"is_valid": is_valid, "hash": recalculated_hash}
    )
    db.add(audit)
    db.commit()

    return EvidenceVerificationResponse(
        evidence_id=evidence_id,
        is_valid=is_valid,
        algorithm="SHA-256",
        claimed_hash=claimed_hash,
        recalculated_hash=recalculated_hash,
        message=msg
    )

@router.get("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def verify_evidence_get(evidence_id: str, db: Session = Depends(get_db)):
    return _perform_verification(evidence_id, db)

@router.post("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def verify_evidence_post(evidence_id: str, db: Session = Depends(get_db)):
    return _perform_verification(evidence_id, db)
