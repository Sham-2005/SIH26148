"""
Threat Detection Service for JOCKY Platform
Coordinates feature extraction, Random Forest threat classification, explainability,
RFC-8785 canonical prediction hashing, DB persistence, finding creation, and verification.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.models import (
    MLThreatPrediction,
    Finding,
    SecurityEvent,
    Case
)
from backend.app.services.security_integrity_service import hash_object
from backend.app.ml.schemas import (
    ForensicFeatureVector,
    ThreatPredictionResponse,
    PredictionVerifyResponse,
    ContributingFactor,
    FEATURE_SCHEMA_VERSION
)
from backend.app.ml.feature_extractor import ForensicFeatureExtractor
from backend.app.ml.model_registry import model_registry
from backend.app.ml.explainability import ThreatExplainer

logger = logging.getLogger("jocky.ml.threat_detector")


def compute_prediction_canonical_hash(
    case_id: str,
    classification: str,
    threat_score: float,
    confidence: float,
    feature_vector: Dict[str, Any],
    model_hash: str,
    created_at_iso: Optional[str] = None
) -> str:
    """Computes RFC-8785 canonical JSON SHA-256 hash for a threat prediction record."""
    canonical_payload = {
        "case_id": case_id,
        "classification": classification,
        "confidence": round(float(confidence), 4),
        "feature_vector": feature_vector,
        "model_hash": model_hash,
        "threat_score": round(float(threat_score), 4)
    }
    if created_at_iso:
        canonical_payload["created_at"] = created_at_iso
    return hash_object(canonical_payload)


class ThreatDetectionService:
    """Service providing end-to-end ML forensic threat analysis and prediction verification."""

    @classmethod
    def analyze_case(
        cls,
        case_id: str,
        db: Session,
        evidence_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ) -> ThreatPredictionResponse:
        """
        Executes ML forensic threat analysis for a case.
        Extracts features, runs model inference, generates explanation factors,
        seals with canonical SHA-256 hash, and saves to database.
        """
        # 1. Extract feature vector
        features: ForensicFeatureVector = ForensicFeatureExtractor.extract_from_case(case_id, db)

        # 2. Retrieve model & status
        classifier = model_registry.get_model()
        model_status = model_registry.get_status()

        # 3. Model Inference
        classification, threat_score, confidence, probabilities = classifier.predict(features)

        # 4. Explainability
        factors: List[ContributingFactor] = ThreatExplainer.explain(
            features,
            classification,
            classifier.get_feature_importances()
        )

        now = datetime.now(timezone.utc)
        created_at_iso = now.isoformat()
        feat_dict = features.to_dict_features()

        # 5. Cryptographic prediction sealing (RFC-8785 canonical hash)
        prediction_hash = compute_prediction_canonical_hash(
            case_id=case_id,
            classification=classification,
            threat_score=threat_score,
            confidence=confidence,
            feature_vector=feat_dict,
            model_hash=model_status.model_hash
        )

        prediction_id = f"MLPRED-{uuid.uuid4().hex[:12].upper()}"

        # 6. Database record persistence
        record = MLThreatPrediction(
            id=prediction_id,
            case_id=case_id,
            evidence_id=evidence_id,
            agent_id=agent_id,
            model_name=model_status.model_name,
            model_version=model_status.model_version,
            feature_schema_version=features.feature_schema_version,
            classification=classification,
            threat_score=threat_score,
            confidence=confidence,
            feature_vector=feat_dict,
            top_factors=[f.model_dump() for f in factors],
            probabilities=probabilities,
            model_hash=model_status.model_hash,
            prediction_hash=prediction_hash,
            integrity_status="VERIFIED",
            created_at=now
        )
        db.add(record)

        # 7. Create defensive finding if suspicious or malicious (decision support)
        if classification in ("SUSPICIOUS", "MALICIOUS") or threat_score >= 0.5:
            finding_id = f"FND-ML-{prediction_id.replace('MLPRED-', '')}"
            existing_fnd = db.query(Finding).filter(Finding.id == finding_id).first()
            if not existing_fnd:
                priority = "CRITICAL" if (classification == "MALICIOUS" or threat_score >= 0.75) else "HIGH"
                priority_score = int(threat_score * 100)
                reasons = [f.description for f in factors[:4]]

                finding = Finding(
                    id=finding_id,
                    case_id=case_id,
                    title=f"ML Threat Detection: {classification} (Score: {threat_score:.2f})",
                    description=(
                        f"Machine learning forensic threat classifier flagged host activity as {classification} "
                        f"with {confidence * 100:.1f}% model confidence. Threat score: {threat_score:.2f}/1.00. "
                        f"Top factors: {'; '.join(reasons[:2])}."
                    ),
                    reason=f"Forensic classifier identified anomalous telemetry: {', '.join(reasons[:2])}",
                    status="OPEN",
                    priority=priority,
                    priority_score=priority_score,
                    priority_reasons=reasons,
                    related_agents=[agent_id] if agent_id else [],
                    evidence_ids=[evidence_id] if evidence_id else [],
                    created_at=now,
                    updated_at=now
                )
                db.add(finding)

        db.commit()
        db.refresh(record)

        return ThreatPredictionResponse(
            prediction_id=record.id,
            case_id=record.case_id,
            evidence_id=record.evidence_id,
            agent_id=record.agent_id,
            model_name=record.model_name,
            model_version=record.model_version,
            feature_schema_version=record.feature_schema_version,
            classification=record.classification,
            threat_score=record.threat_score,
            confidence=record.confidence,
            feature_vector=record.feature_vector,
            top_factors=factors,
            model_hash=record.model_hash,
            prediction_hash=record.prediction_hash,
            integrity_status=record.integrity_status,
            created_at=record.created_at
        )

    @classmethod
    def predict_features(
        cls,
        feature_dict: Optional[Dict[str, Any]] = None,
        case_id: str = "CASE-LIVE-PREDICT",
        evidence_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        persist: bool = False,
        db: Optional[Session] = None
    ) -> ThreatPredictionResponse:
        """
        Runs ML prediction directly on a provided feature dictionary or empty baseline.
        """
        if feature_dict:
            feat_kwargs = {}
            for k in ForensicFeatureVector.model_fields.keys():
                if k in feature_dict:
                    feat_kwargs[k] = feature_dict[k]
            features = ForensicFeatureVector(**feat_kwargs)
        else:
            features = ForensicFeatureVector()

        classifier = model_registry.get_model()
        model_status = model_registry.get_status()

        classification, threat_score, confidence, probabilities = classifier.predict(features)
        factors = ThreatExplainer.explain(
            features,
            classification,
            classifier.get_feature_importances()
        )

        now = datetime.now(timezone.utc)
        feat_dict = features.to_dict_features()
        prediction_hash = compute_prediction_canonical_hash(
            case_id=case_id,
            classification=classification,
            threat_score=threat_score,
            confidence=confidence,
            feature_vector=feat_dict,
            model_hash=model_status.model_hash
        )
        prediction_id = f"MLPRED-{uuid.uuid4().hex[:12].upper()}"

        if persist and db is not None:
            case = db.query(Case).filter(Case.id == case_id).first()
            if not case:
                case = Case(
                    id=case_id,
                    title="Live ML Prediction Case",
                    description="Auto-created case for live ML threat prediction",
                    severity="medium",
                    status="INVESTIGATING"
                )
                db.add(case)
                db.commit()

            record = MLThreatPrediction(
                id=prediction_id,
                case_id=case_id,
                evidence_id=evidence_id,
                agent_id=agent_id,
                model_name=model_status.model_name,
                model_version=model_status.model_version,
                feature_schema_version=features.feature_schema_version,
                classification=classification,
                threat_score=threat_score,
                confidence=confidence,
                feature_vector=feat_dict,
                top_factors=[f.model_dump() for f in factors],
                probabilities=probabilities,
                model_hash=model_status.model_hash,
                prediction_hash=prediction_hash,
                integrity_status="VERIFIED",
                created_at=now
            )
            db.add(record)
            db.commit()
            db.refresh(record)

        return ThreatPredictionResponse(
            prediction_id=prediction_id,
            case_id=case_id,
            evidence_id=evidence_id,
            agent_id=agent_id,
            model_name=model_status.model_name,
            model_version=model_status.model_version,
            feature_schema_version=features.feature_schema_version,
            classification=classification,
            threat_score=threat_score,
            confidence=confidence,
            feature_vector=feat_dict,
            top_factors=factors,
            model_hash=model_status.model_hash,
            prediction_hash=prediction_hash,
            integrity_status="VERIFIED",
            created_at=now
        )

    @classmethod
    def verify_prediction(cls, prediction_id: str, db: Session) -> PredictionVerifyResponse:
        """
        Cryptographically verifies the SHA-256 seal of a stored threat prediction.
        Detects tampering with threat scores, classifications, or feature payloads.
        """
        record = db.query(MLThreatPrediction).filter(MLThreatPrediction.id == prediction_id).first()

        if not record:
            return PredictionVerifyResponse(
                prediction_id=prediction_id,
                case_id="UNKNOWN",
                is_valid=False,
                status="NOT_FOUND",
                claimed_hash="",
                recalculated_hash="",
                message=f"Prediction record {prediction_id} not found."
            )

        recalculated_hash = compute_prediction_canonical_hash(
            case_id=record.case_id,
            classification=record.classification,
            threat_score=record.threat_score,
            confidence=record.confidence,
            feature_vector=record.feature_vector,
            model_hash=record.model_hash
        )

        is_valid = (recalculated_hash == record.prediction_hash)
        if not is_valid:
            # Check with created_at_iso for backward compatibility
            created_at_iso = record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else str(record.created_at)
            alt_hash = compute_prediction_canonical_hash(
                case_id=record.case_id,
                classification=record.classification,
                threat_score=record.threat_score,
                confidence=record.confidence,
                feature_vector=record.feature_vector,
                model_hash=record.model_hash,
                created_at_iso=created_at_iso
            )
            if alt_hash == record.prediction_hash:
                is_valid = True
                recalculated_hash = alt_hash

        if not is_valid:
            record.integrity_status = "TAMPERED"
            # Log security event for audit and SOC alerts
            sec_event = SecurityEvent(
                id=f"SECEV-ML-{uuid.uuid4().hex[:8].upper()}",
                case_id=record.case_id,
                event_type="ML_PREDICTION_INTEGRITY_FAILURE",
                severity="HIGH",
                object_type="ML_PREDICTION",
                object_id=record.id,
                description=f"ML threat prediction {record.id} hash verification failed! Evidence or score tampering detected.",
                expected_value=record.prediction_hash,
                observed_value=recalculated_hash,
                detected_at=datetime.now(timezone.utc),
                integrity_hash=recalculated_hash
            )
            db.add(sec_event)
            db.commit()

            return PredictionVerifyResponse(
                prediction_id=record.id,
                case_id=record.case_id,
                is_valid=False,
                status="TAMPERED",
                claimed_hash=record.prediction_hash,
                recalculated_hash=recalculated_hash,
                message="Integrity violation! Prediction record has been modified after cryptographic sealing."
            )

        return PredictionVerifyResponse(
            prediction_id=record.id,
            case_id=record.case_id,
            is_valid=True,
            status="VERIFIED",
            claimed_hash=record.prediction_hash,
            recalculated_hash=recalculated_hash,
            message="Prediction integrity verified. Hash matches canonical RFC-8785 seal."
        )

    @classmethod
    def get_predictions_for_case(cls, case_id: str, db: Session) -> List[ThreatPredictionResponse]:
        """Returns all threat predictions generated for a case ordered by timestamp descending."""
        records = db.query(MLThreatPrediction).filter(
            MLThreatPrediction.case_id == case_id
        ).order_by(MLThreatPrediction.created_at.desc()).all()

        results: List[ThreatPredictionResponse] = []
        for r in records:
            factors = [
                ContributingFactor(**f) if isinstance(f, dict) else f
                for f in (r.top_factors or [])
            ]
            results.append(ThreatPredictionResponse(
                prediction_id=r.id,
                case_id=r.case_id,
                evidence_id=r.evidence_id,
                agent_id=r.agent_id,
                model_name=r.model_name,
                model_version=r.model_version,
                feature_schema_version=r.feature_schema_version,
                classification=r.classification,
                threat_score=r.threat_score,
                confidence=r.confidence,
                feature_vector=r.feature_vector,
                top_factors=factors,
                model_hash=r.model_hash,
                prediction_hash=r.prediction_hash,
                integrity_status=r.integrity_status,
                created_at=r.created_at
            ))
        return results

    @classmethod
    def get_prediction_by_id(
        cls,
        case_id: str,
        prediction_id: str,
        db: Session
    ) -> Optional[ThreatPredictionResponse]:
        """Retrieves a specific threat prediction by case ID and prediction ID."""
        r = db.query(MLThreatPrediction).filter(
            MLThreatPrediction.case_id == case_id,
            MLThreatPrediction.id == prediction_id
        ).first()
        if not r:
            return None

        factors = [
            ContributingFactor(**f) if isinstance(f, dict) else f
            for f in (r.top_factors or [])
        ]
        return ThreatPredictionResponse(
            prediction_id=r.id,
            case_id=r.case_id,
            evidence_id=r.evidence_id,
            agent_id=r.agent_id,
            model_name=r.model_name,
            model_version=r.model_version,
            feature_schema_version=r.feature_schema_version,
            classification=r.classification,
            threat_score=r.threat_score,
            confidence=r.confidence,
            feature_vector=r.feature_vector,
            top_factors=factors,
            model_hash=r.model_hash,
            prediction_hash=r.prediction_hash,
            integrity_status=r.integrity_status,
            created_at=r.created_at
        )
