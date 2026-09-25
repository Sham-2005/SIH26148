"""
Defensive Incident Response Playbook API Endpoints
Provides endpoints for creating, listing, approving, rejecting, and executing playbooks.
Enforces strict allowlist validation and analyst approval workflow.
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.models import Playbook, PlaybookExecution, Case
from backend.app.schemas.schemas import (
    PlaybookCreate,
    PlaybookResponse,
    PlaybookApprovalCreate,
    PlaybookApprovalResponse,
    PlaybookExecutionResponse,
)
from backend.app.services.playbook_service import PlaybookService

router = APIRouter(prefix="/api/playbooks", tags=["Incident Response Playbooks"])


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    """Creates a new defensive playbook, validating actions against the safety allowlist."""
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{payload.case_id}' not found."
        )

    # Convert Pydantic actions to dicts
    actions_data = [act.model_dump() for act in payload.actions]

    try:
        playbook = PlaybookService.create_playbook(
            db=db,
            case_id=payload.case_id,
            name=payload.name,
            actions_data=actions_data,
            description=payload.description,
            version=payload.version or "1.0.0",
            trigger_type=payload.trigger_type or "MANUAL",
            created_by="analyst@jocky.defense"
        )
        return playbook
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("", response_model=List[PlaybookResponse])
def list_playbooks(
    case_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists defensive playbooks with optional filtering by case or status."""
    query = db.query(Playbook)
    if case_id:
        query = query.filter(Playbook.case_id == case_id)
    if status:
        query = query.filter(Playbook.status == status.upper())
    return query.order_by(Playbook.created_at.desc()).all()


@router.get("/{playbook_id}", response_model=PlaybookResponse)
def get_playbook(playbook_id: str, db: Session = Depends(get_db)):
    """Gets full playbook details, including steps, approvals, and execution history."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{playbook_id}' not found."
        )
    return pb


@router.post("/{playbook_id}/approve", response_model=PlaybookApprovalResponse)
def approve_playbook(
    playbook_id: str,
    payload: PlaybookApprovalCreate,
    db: Session = Depends(get_db)
):
    """Submits analyst approval for a playbook, transitioning it to APPROVED status."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{playbook_id}' not found."
        )

    approval = PlaybookService.approve_playbook(
        db=db,
        playbook=pb,
        approver_email="analyst@jocky.defense",
        comment=payload.comment
    )
    return approval


@router.post("/{playbook_id}/reject", response_model=PlaybookApprovalResponse)
def reject_playbook(
    playbook_id: str,
    payload: PlaybookApprovalCreate,
    db: Session = Depends(get_db)
):
    """Rejects a playbook, preventing execution."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{playbook_id}' not found."
        )

    approval = PlaybookService.reject_playbook(
        db=db,
        playbook=pb,
        approver_email="analyst@jocky.defense",
        comment=payload.comment
    )
    return approval


@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionResponse)
def execute_playbook(
    playbook_id: str,
    db: Session = Depends(get_db)
):
    """
    Executes an APPROVED playbook step-by-step.
    Fails if the playbook has not been approved by an analyst.
    """
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{playbook_id}' not found."
        )

    try:
        execution = PlaybookService.execute_playbook(
            db=db,
            playbook=pb,
            executor_email="analyst@jocky.defense"
        )
        return execution
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{playbook_id}/executions", response_model=List[PlaybookExecutionResponse])
def get_playbook_executions(playbook_id: str, db: Session = Depends(get_db)):
    """Lists past executions for a playbook."""
    executions = db.query(PlaybookExecution).filter(PlaybookExecution.playbook_id == playbook_id).order_by(PlaybookExecution.started_at.desc()).all()
    return executions
