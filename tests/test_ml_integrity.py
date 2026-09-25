"""
Test Suite: Cryptographic Integrity Verification & Tamper Detection
Validates ModelRegistry SHA-256 binary validation, adversarial model tampering detection,
RFC-8785 prediction canonical hashing, and database-level prediction tamper detection.
"""
import pytest
import copy
from datetime import datetime, timezone
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import Case, Evidence, MLThreatPrediction, SecurityEvent
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.threat_detector import ThreatDetectionService, compute_prediction_canonical_hash


@pytest.fixture(scope="module", autouse=True)
def setup_integrity_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    case = db.query(Case).filter(Case.id == "CASE-INTEG-TEST").first()
    if not case:
        case = Case(
            id="CASE-INTEG-TEST",
            title="Integrity Verification Test Case",
            description="Case for validating cryptographic model and prediction tamper detection",
            severity="high",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()
    db.close()


def test_model_registry_integrity_verification():
    """Validates that ModelRegistry verifies valid model SHA-256 hash."""
    registry = ModelRegistry()
    assert registry.verify_integrity() is True
    status = registry.get_status()
    assert status.status == "READY"
    assert status.integrity == "VALID"
    assert status.model_hash == status.calculated_hash


def test_prediction_integrity_verification_pass():
    """Validates that untampered prediction returns VERIFIED status."""
    db = SessionLocal()
    try:
        # Generate prediction
        pred_res = ThreatDetectionService.analyze_case("CASE-INTEG-TEST", db)
        verify_res = ThreatDetectionService.verify_prediction(pred_res.prediction_id, db)

        assert verify_res.is_valid is True
        assert verify_res.status == "VERIFIED"
        assert verify_res.claimed_hash == verify_res.recalculated_hash
    finally:
        db.close()


def test_prediction_tamper_detection_alert():
    """Validates that tampering with threat score or classification triggers TAMPERED status and SecurityEvent."""
    db = SessionLocal()
    try:
        pred_res = ThreatDetectionService.analyze_case("CASE-INTEG-TEST", db)

        # Adversarially modify threat score in DB directly
        record = db.query(MLThreatPrediction).filter(
            MLThreatPrediction.id == pred_res.prediction_id
        ).first()
        original_score = record.threat_score
        record.threat_score = 0.01  # Altered!
        db.commit()

        # Run verification
        verify_res = ThreatDetectionService.verify_prediction(pred_res.prediction_id, db)
        assert verify_res.is_valid is False
        assert verify_res.status == "TAMPERED"

        # Check that a SecurityEvent was logged
        sec_event = db.query(SecurityEvent).filter(
            SecurityEvent.object_id == pred_res.prediction_id,
            SecurityEvent.event_type == "ML_PREDICTION_INTEGRITY_FAILURE"
        ).first()
        assert sec_event is not None
        assert sec_event.severity == "HIGH"
        assert sec_event.expected_value == record.prediction_hash

        # Restore score for clean state
        record.threat_score = original_score
        db.commit()
    finally:
        db.close()
