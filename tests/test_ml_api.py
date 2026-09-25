"""
Test Suite: ML Threat Detection REST API Endpoints
Validates /api/ml/ routes: analyze, list predictions, get single prediction,
cryptographic verification, model status, and model metrics.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import Case

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_api_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    case = db.query(Case).filter(Case.id == "CASE-API-TEST").first()
    if not case:
        case = Case(
            id="CASE-API-TEST",
            title="ML API Test Case",
            description="Case for validating ML REST endpoints",
            severity="medium",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()
    db.close()


def test_api_model_status():
    """Validates GET /api/ml/model/status."""
    response = client.get("/api/ml/model/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("READY", "UNAVAILABLE")
    assert data["algorithm"] == "RandomForestClassifier"
    assert "model_hash" in data


def test_api_model_metrics():
    """Validates GET /api/ml/model/metrics."""
    response = client.get("/api/ml/model/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["algorithm"] == "RandomForestClassifier"
    assert "metrics" in data
    assert "feature_importance" in data
    assert data["metrics"].get("evaluation_type") == "Synthetic Demonstration Evaluation"


def test_api_analyze_and_get_predictions():
    """Validates POST /api/ml/analyze/{case_id} and GET /api/ml/predictions/{case_id}."""
    post_res = client.post("/api/ml/analyze/CASE-API-TEST")
    assert post_res.status_code == 201
    pred_data = post_res.json()
    assert pred_data["case_id"] == "CASE-API-TEST"
    assert "prediction_id" in pred_data
    assert "classification" in pred_data
    assert "threat_score" in pred_data
    assert "confidence" in pred_data
    assert "prediction_hash" in pred_data

    prediction_id = pred_data["prediction_id"]

    # List predictions
    list_res = client.get("/api/ml/predictions/CASE-API-TEST")
    assert list_res.status_code == 200
    preds = list_res.json()
    assert len(preds) >= 1
    assert any(p["prediction_id"] == prediction_id for p in preds)

    # Get single prediction
    single_res = client.get(f"/api/ml/predictions/CASE-API-TEST/{prediction_id}")
    assert single_res.status_code == 200
    assert single_res.json()["prediction_id"] == prediction_id

    # Verify prediction
    verify_res = client.post(f"/api/ml/predictions/{prediction_id}/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True
    assert verify_res.json()["status"] == "VERIFIED"


def test_api_error_handling():
    """Validates proper 404 responses for missing entities."""
    # Unknown case analyze
    res1 = client.post("/api/ml/analyze/CASE-DOES-NOT-EXIST")
    assert res1.status_code == 404

    # Unknown case predictions list
    res2 = client.get("/api/ml/predictions/CASE-DOES-NOT-EXIST")
    assert res2.status_code == 404

    # Unknown prediction verify
    res3 = client.post("/api/ml/predictions/MLPRED-FAKE123/verify")
    assert res3.status_code == 404
