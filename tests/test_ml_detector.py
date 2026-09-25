"""
Test Suite: Threat Detection Service & DB Persistence
Validates ThreatDetectionService case analysis, RFC-8785 canonical hash sealing,
database record creation, and defensive finding synthesis.
"""
import pytest
from datetime import datetime, timezone
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import Case, Evidence, MLThreatPrediction, Finding
from backend.app.ml.threat_detector import ThreatDetectionService, compute_prediction_canonical_hash


@pytest.fixture(scope="module", autouse=True)
def setup_detector_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    case = db.query(Case).filter(Case.id == "CASE-DETECTOR-TEST").first()
    if not case:
        case = Case(
            id="CASE-DETECTOR-TEST",
            title="Threat Detector Test Case",
            description="Case for validating ML threat detector service",
            severity="high",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()

    # Add evidence with suspicious/malicious indicators to trigger finding
    ev = Evidence(
        id="EV-DETECTOR-01",
        case_id="CASE-DETECTOR-TEST",
        agent_id="AGENT-WIN-01",
        collector="process.list",
        platform="windows",
        envelope_data={
            "processes": [
                {"pid": 201, "name": "powershell.exe", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\ps.exe"},
                {"pid": 202, "name": "cobaltstrike.exe", "path": "C:\\Temp\\cs.exe"}
            ]
        },
        sha256_hash="f" * 64,
        is_verified=True
    )
    if not db.query(Evidence).filter(Evidence.id == ev.id).first():
        db.add(ev)
    db.commit()
    db.close()


def test_analyze_case_and_persistence():
    """Validates analyze_case creates MLThreatPrediction record in DB."""
    db = SessionLocal()
    try:
        response = ThreatDetectionService.analyze_case(
            case_id="CASE-DETECTOR-TEST",
            db=db,
            evidence_id="EV-DETECTOR-01",
            agent_id="AGENT-WIN-01"
        )
        assert response.prediction_id.startswith("MLPRED-")
        assert response.case_id == "CASE-DETECTOR-TEST"
        assert response.classification in ("NORMAL", "SUSPICIOUS", "MALICIOUS")
        assert 0.0 <= response.threat_score <= 1.0
        assert 0.0 <= response.confidence <= 1.0
        assert response.integrity_status == "VERIFIED"
        assert len(response.prediction_hash) == 64
        assert len(response.model_hash) == 64

        # Verify DB record
        record = db.query(MLThreatPrediction).filter(
            MLThreatPrediction.id == response.prediction_id
        ).first()
        assert record is not None
        assert record.case_id == "CASE-DETECTOR-TEST"
        assert record.prediction_hash == response.prediction_hash

        # If score >= 0.5 or suspicious/malicious, a finding was created
        if response.classification in ("SUSPICIOUS", "MALICIOUS") or response.threat_score >= 0.5:
            finding = db.query(Finding).filter(Finding.case_id == "CASE-DETECTOR-TEST").first()
            assert finding is not None
            assert "ML Threat Detection" in finding.title
    finally:
        db.close()


def test_get_predictions_for_case():
    """Validates retrieving historical predictions for a case."""
    db = SessionLocal()
    try:
        predictions = ThreatDetectionService.get_predictions_for_case("CASE-DETECTOR-TEST", db)
        assert len(predictions) >= 1
        assert predictions[0].case_id == "CASE-DETECTOR-TEST"

        single = ThreatDetectionService.get_prediction_by_id(
            "CASE-DETECTOR-TEST",
            predictions[0].prediction_id,
            db
        )
        assert single is not None
        assert single.prediction_id == predictions[0].prediction_id
    finally:
        db.close()
