"""
REST API Endpoints for JOCKY ML Threat Detection Engine
Provides case threat analysis, prediction history, cryptographic integrity verification,
and model status & performance metrics queries.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.models import Case
from backend.app.ml.schemas import (
    ThreatPredictionResponse,
    PredictionVerifyResponse,
    ModelStatusResponse,
    ModelMetricsResponse,
    PredictRequest,
)
from backend.app.ml.threat_detector import ThreatDetectionService
from backend.app.ml.model_registry import model_registry

router = APIRouter(prefix="/api/ml", tags=["ML Threat Detection"])


@router.post("/predict", response_model=ThreatPredictionResponse, status_code=status.HTTP_200_OK)
def predict_threat(
    request: Optional[PredictRequest] = None,
    db: Session = Depends(get_db)
):
    """
    Executes on-demand threat classification on a provided forensic feature vector
    or default baseline. Returns threat score, classification, explainability factors,
    and canonical RFC-8785 prediction hash.
    """
    req = request or PredictRequest()
    return ThreatDetectionService.predict_features(
        feature_dict=req.feature_vector,
        case_id=req.case_id or "CASE-LIVE-PREDICT",
        evidence_id=req.evidence_id,
        agent_id=req.agent_id,
        persist=bool(req.persist),
        db=db
    )


@router.post("/predict-case/{case_id}", response_model=ThreatPredictionResponse, status_code=status.HTTP_200_OK)
def predict_case_threat(
    case_id: str,
    evidence_id: Optional[str] = Query(None, description="Optional specific evidence ID associated with run"),
    agent_id: Optional[str] = Query(None, description="Optional specific agent ID associated with run"),
    db: Session = Depends(get_db)
):
    """
    Executes ML forensic feature extraction and threat prediction for an entire case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    try:
        return ThreatDetectionService.analyze_case(
            case_id=case_id,
            db=db,
            evidence_id=evidence_id,
            agent_id=agent_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ML threat analysis failed: {str(e)}"
        )


@router.post("/verify-prediction/{prediction_id}", response_model=PredictionVerifyResponse)
def verify_prediction_by_id(
    prediction_id: str,
    db: Session = Depends(get_db)
):
    """
    Cryptographically verifies the RFC-8785 canonical SHA-256 seal of a prediction.
    """
    result = ThreatDetectionService.verify_prediction(prediction_id, db)
    if result.status == "NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction '{prediction_id}' not found."
        )
    return result


@router.post("/analyze/{case_id}", response_model=ThreatPredictionResponse, status_code=status.HTTP_201_CREATED)
def analyze_case_threat(
    case_id: str,
    evidence_id: Optional[str] = Query(None, description="Optional specific evidence ID associated with run"),
    agent_id: Optional[str] = Query(None, description="Optional specific agent ID associated with run"),
    db: Session = Depends(get_db)
):
    """
    Executes ML forensic feature extraction, Random Forest classification,
    transparent factor explanation, RFC-8785 canonical hash sealing, and persistence.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    try:
        prediction = ThreatDetectionService.analyze_case(
            case_id=case_id,
            db=db,
            evidence_id=evidence_id,
            agent_id=agent_id
        )
        return prediction
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ML threat analysis failed: {str(e)}"
        )


@router.get("/predictions/{case_id}", response_model=List[ThreatPredictionResponse])
def get_case_predictions(
    case_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves all historical threat predictions generated for a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    return ThreatDetectionService.get_predictions_for_case(case_id, db)


@router.get("/predictions/{case_id}/{prediction_id}", response_model=ThreatPredictionResponse)
def get_single_prediction(
    case_id: str,
    prediction_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves a specific prediction by case ID and prediction ID."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    prediction = ThreatDetectionService.get_prediction_by_id(case_id, prediction_id, db)
    if not prediction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction '{prediction_id}' not found in case '{case_id}'."
        )
    return prediction


@router.post("/predictions/{prediction_id}/verify", response_model=PredictionVerifyResponse)
def verify_prediction_integrity(
    prediction_id: str,
    db: Session = Depends(get_db)
):
    """
    Cryptographically verifies the RFC-8785 canonical SHA-256 seal of a prediction.
    Detects any post-inference tampering with threat score, classification, or features.
    """
    result = ThreatDetectionService.verify_prediction(prediction_id, db)
    if result.status == "NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction '{prediction_id}' not found."
        )
    return result


@router.get("/model/status", response_model=ModelStatusResponse)
def get_model_status():
    """Returns current model operational status, algorithm, and SHA-256 integrity."""
    return model_registry.get_status()


@router.get("/model/metrics", response_model=ModelMetricsResponse)
def get_model_metrics():
    """Returns evaluation metrics, sample counts, and feature importances for trained model."""
    metrics = model_registry.get_metrics()
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metrics are not available. Model has not been trained or metadata is missing."
        )
    return metrics
