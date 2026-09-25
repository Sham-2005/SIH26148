"""
Audit Logging API Endpoints
Provides tamper-evident activity logging query interface.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import AuditLog
from backend.app.schemas.schemas import AuditLogResponse

router = APIRouter(prefix="/api/audit", tags=["Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
def list_audit_logs(
    action: Optional[str] = None,
    actor: Optional[str] = None,
    actor_type: Optional[str] = None,
    result: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor == actor)
    if actor_type:
        query = query.filter(AuditLog.actor_type == actor_type)
    if result:
        query = query.filter(AuditLog.result == result)

    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
