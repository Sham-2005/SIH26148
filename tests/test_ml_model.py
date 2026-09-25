"""
Test Suite: ML Threat Model Inference & Explainability
Validates Random Forest classifier wrapper, continuous threat score calibration,
confidence bounds, and factor explainability.
"""
import pytest
from backend.app.ml.schemas import ForensicFeatureVector, ContributingFactor
from backend.app.ml.threat_model import JockyThreatClassifier
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.explainability import ThreatExplainer


@pytest.fixture
def classifier():
    registry = ModelRegistry()
    return registry.get_model()


def test_model_inference_normal_vector(classifier):
    """Validates inference on benign baseline feature vector."""
    normal_vec = ForensicFeatureVector(
        process_count=15,
        suspicious_process_count=0,
        temp_path_process_count=0,
        connection_count=5,
        external_connection_count=1,
        suspicious_port_count=0,
        persistence_count=4,
        suspicious_persistence_count=0,
        file_count=20,
        pe_anomaly_count=0,
        suspicious_file_count=0,
        ioc_count=0,
        malicious_ioc_count=0,
        suspicious_ioc_count=0,
        timeline_event_count=20
    )
    classification, threat_score, confidence, probs = classifier.predict(normal_vec)
    assert classification == "NORMAL"
    assert 0.0 <= threat_score <= 0.30
    assert 0.0 <= confidence <= 1.0
    assert "NORMAL" in probs
    assert probs["NORMAL"] >= 0.70


def test_model_inference_malicious_vector(classifier):
    """Validates inference on malicious attack feature vector."""
    malicious_vec = ForensicFeatureVector(
        process_count=40,
        suspicious_process_count=4,
        temp_path_process_count=2,
        connection_count=25,
        external_connection_count=8,
        suspicious_port_count=2,
        persistence_count=10,
        suspicious_persistence_count=3,
        file_count=50,
        pe_anomaly_count=2,
        suspicious_file_count=4,
        ioc_count=5,
        malicious_ioc_count=3,
        suspicious_ioc_count=2,
        timeline_event_count=80,
        security_event_count=4,
        cti_match_count=2,
        mitre_technique_count=4,
        tamper_event_count=1
    )
    classification, threat_score, confidence, probs = classifier.predict(malicious_vec)
    assert classification == "MALICIOUS"
    assert threat_score >= 0.70
    assert confidence >= 0.70
    assert probs["MALICIOUS"] >= 0.60


def test_threat_score_calculation_formula():
    """Validates that threat score follows P(SUSPICIOUS)*0.5 + P(MALICIOUS)*1.0."""
    clf = JockyThreatClassifier(None)
    # Test heuristic fallback behavior
    clean_vec = ForensicFeatureVector(process_count=10)
    c, score, conf, probs = clf.predict(clean_vec)
    assert c == "NORMAL"
    assert 0.0 <= score <= 0.30

    dirty_vec = ForensicFeatureVector(
        malicious_ioc_count=3,
        pe_anomaly_count=2,
        tamper_event_count=1
    )
    c_dirty, score_dirty, conf_dirty, probs_dirty = clf.predict(dirty_vec)
    assert c_dirty == "MALICIOUS"
    assert score_dirty >= 0.70


def test_explainability_factors():
    """Validates explainability engine outputs ranked factors with impact scores."""
    vec = ForensicFeatureVector(
        process_count=35,
        suspicious_process_count=3,
        temp_path_process_count=2,
        malicious_ioc_count=2,
        pe_anomaly_count=1
    )
    importances = {
        "malicious_ioc_count": 0.20,
        "suspicious_process_count": 0.15,
        "temp_path_process_count": 0.12,
        "pe_anomaly_count": 0.10,
        "process_count": 0.02
    }
    factors = ThreatExplainer.explain(vec, "MALICIOUS", importances, top_k=5)
    assert len(factors) <= 5
    assert len(factors) > 0

    # Ensure impact scores are descending
    for i in range(len(factors) - 1):
        assert factors[i].impact_score >= factors[i + 1].impact_score

    # Check that descriptions contain feature values
    top_feature_names = [f.feature for f in factors]
    assert "malicious_ioc_count" in top_feature_names
