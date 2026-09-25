"""
JOCKY Level 3 — Machine Learning Threat Detection Demonstration Script
Demonstrates end-to-end ML forensic capabilities across three distinct scenarios:
  Scenario A: Normal Host Baseline (Clean telemetry, benign processes, zero IOCs)
  Scenario B: Suspicious Activity (Temp execution, anomalous outbound port, persistence)
  Scenario C: Malicious Attack (Confirmed IOCs, PE structural anomaly, CTI correlation, tamper alert)

Also demonstrates cryptographic RFC-8785 prediction verification and model binary SHA-256 tamper detection.
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.ml.schemas import ForensicFeatureVector
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.explainability import ThreatExplainer
from backend.app.ml.threat_detector import compute_prediction_canonical_hash


def banner(text: str) -> None:
    print("\n" + "=" * 76)
    print(f"  {text}")
    print("=" * 76)


def section(text: str) -> None:
    print(f"\n--- {text} ---")


def run_scenario(name: str, features: ForensicFeatureVector, registry: ModelRegistry) -> dict:
    classifier = registry.get_model()
    model_status = registry.get_status()

    # 1. Inference
    classification, threat_score, confidence, probabilities = classifier.predict(features)

    # 2. Explainability
    factors = ThreatExplainer.explain(
        features,
        classification,
        classifier.get_feature_importances()
    )

    # 3. Canonical SHA-256 Sealing
    now_iso = datetime.now(timezone.utc).isoformat()
    pred_hash = compute_prediction_canonical_hash(
        case_id="DEMO-CASE",
        classification=classification,
        threat_score=threat_score,
        confidence=confidence,
        feature_vector=features.to_dict_features(),
        model_hash=model_status.model_hash,
        created_at_iso=now_iso
    )

    print(f"\n[SCENARIO] {name}")
    print(f"  Classification:     {classification}")
    print(f"  Threat Score:       {threat_score:.4f} / 1.0000")
    print(f"  Model Confidence:   {confidence * 100:.1f}%")
    print(f"  Probabilities:      NORMAL={probabilities.get('NORMAL', 0):.3f} | SUSPICIOUS={probabilities.get('SUSPICIOUS', 0):.3f} | MALICIOUS={probabilities.get('MALICIOUS', 0):.3f}")
    print(f"  Prediction SHA-256: {pred_hash}")
    print("  Top Contributing Factors:")
    for i, factor in enumerate(factors[:3], 1):
        print(f"    {i}. [{factor.feature}] (Impact: {factor.impact_score:.4f}) — {factor.description}")

    return {
        "classification": classification,
        "threat_score": threat_score,
        "confidence": confidence,
        "prediction_hash": pred_hash,
        "created_at_iso": now_iso,
        "features": features.to_dict_features(),
        "model_hash": model_status.model_hash
    }


def main():
    banner("SIH26148 JOCKY — LEVEL 3 MACHINE LEARNING THREAT DETECTION DEMO")
    print("Defensive Digital-Forensics Intelligence & Cryptographic Prediction Sealing")

    # 1. Model Registry & Integrity
    section("1. Model Registry Cryptographic Verification")
    registry = ModelRegistry()
    status = registry.get_status()
    print(f"  Model Name:       {status.model_name}")
    print(f"  Model Version:    {status.model_version}")
    print(f"  Algorithm:        {status.algorithm}")
    print(f"  Status:           {status.status}")
    print(f"  Integrity:        {status.integrity}")
    print(f"  Model SHA-256:    {status.model_hash}")
    print(f"  Calculated Hash:  {status.calculated_hash}")
    assert status.integrity == "VALID", "Model integrity verification failed!"
    print("  => Cryptographic Model File Seal: VERIFIED [OK]")

    # 2. Scenario A: Normal Host Baseline
    scenario_a_features = ForensicFeatureVector(
        process_count=18,
        suspicious_process_count=0,
        temp_path_process_count=0,
        connection_count=8,
        external_connection_count=2,
        suspicious_port_count=0,
        persistence_count=4,
        suspicious_persistence_count=0,
        file_count=25,
        pe_anomaly_count=0,
        suspicious_file_count=0,
        ioc_count=0,
        malicious_ioc_count=0,
        suspicious_ioc_count=0,
        ip_ioc_count=0,
        hash_ioc_count=0,
        timeline_event_count=30,
        security_event_count=0,
        cti_match_count=0,
        mitre_technique_count=0,
        tamper_event_count=0
    )
    res_a = run_scenario("Scenario A — Normal Benign Host Baseline", scenario_a_features, registry)
    assert res_a["classification"] == "NORMAL", f"Expected NORMAL, got {res_a['classification']}"
    assert res_a["threat_score"] <= 0.25, f"Threat score too high: {res_a['threat_score']}"

    # 3. Scenario B: Suspicious Activity
    scenario_b_features = ForensicFeatureVector(
        process_count=28,
        suspicious_process_count=2,
        temp_path_process_count=1,
        connection_count=16,
        external_connection_count=5,
        suspicious_port_count=1,
        persistence_count=8,
        suspicious_persistence_count=1,
        file_count=35,
        pe_anomaly_count=0,
        suspicious_file_count=2,
        ioc_count=2,
        malicious_ioc_count=0,
        suspicious_ioc_count=2,
        ip_ioc_count=1,
        hash_ioc_count=1,
        timeline_event_count=45,
        security_event_count=2,
        cti_match_count=1,
        mitre_technique_count=2,
        tamper_event_count=0
    )
    res_b = run_scenario("Scenario B — Suspicious Activity (Temp Path & Non-Standard Port)", scenario_b_features, registry)
    assert res_b["classification"] == "SUSPICIOUS", f"Expected SUSPICIOUS, got {res_b['classification']}"
    assert 0.40 <= res_b["threat_score"] <= 0.75, f"Threat score out of bounds: {res_b['threat_score']}"

    # 4. Scenario C: Malicious Attack Incident
    scenario_c_features = ForensicFeatureVector(
        process_count=42,
        suspicious_process_count=4,
        temp_path_process_count=3,
        connection_count=35,
        external_connection_count=10,
        suspicious_port_count=3,
        persistence_count=12,
        suspicious_persistence_count=3,
        file_count=65,
        pe_anomaly_count=2,
        suspicious_file_count=5,
        ioc_count=6,
        malicious_ioc_count=3,
        suspicious_ioc_count=3,
        ip_ioc_count=3,
        hash_ioc_count=3,
        timeline_event_count=90,
        security_event_count=6,
        cti_match_count=3,
        mitre_technique_count=5,
        tamper_event_count=1
    )
    res_c = run_scenario("Scenario C — Malicious Attack (PE Anomaly, Threat Intel Match, Tamper)", scenario_c_features, registry)
    assert res_c["classification"] == "MALICIOUS", f"Expected MALICIOUS, got {res_c['classification']}"
    assert res_c["threat_score"] >= 0.75, f"Threat score too low: {res_c['threat_score']}"

    # 5. Cryptographic Prediction Integrity & Tamper Detection
    section("5. Cryptographic Prediction Integrity & Tamper Detection")
    # Verify untampered prediction
    valid_hash = compute_prediction_canonical_hash(
        case_id="DEMO-CASE",
        classification=res_c["classification"],
        threat_score=res_c["threat_score"],
        confidence=res_c["confidence"],
        feature_vector=res_c["features"],
        model_hash=res_c["model_hash"],
        created_at_iso=res_c["created_at_iso"]
    )
    is_valid = (valid_hash == res_c["prediction_hash"])
    print(f"  Original Prediction Hash: {res_c['prediction_hash']}")
    print(f"  Recalculated Hash:        {valid_hash}")
    print(f"  Integrity Status:         {'VERIFIED' if is_valid else 'TAMPERED'} [OK]")
    assert is_valid, "Valid prediction failed integrity verification"

    # Simulate adversarial tampering (attacker lowers threat score from 0.95 to 0.10)
    print("\n  [Simulating Adversarial Tamper]: Attacker alters threat_score to 0.10...")
    tampered_hash = compute_prediction_canonical_hash(
        case_id="DEMO-CASE",
        classification="NORMAL",  # Altered!
        threat_score=0.10,        # Altered!
        confidence=res_c["confidence"],
        feature_vector=res_c["features"],
        model_hash=res_c["model_hash"],
        created_at_iso=res_c["created_at_iso"]
    )
    is_tampered_valid = (tampered_hash == res_c["prediction_hash"])
    print(f"  Claimed Original Hash:    {res_c['prediction_hash']}")
    print(f"  Tampered Data Hash:       {tampered_hash}")
    print(f"  Tamper Detection Status:  {'TAMPERED (ALERT GENERATED)' if not is_tampered_valid else 'FAILED'}")
    assert not is_tampered_valid, "Tamper detection failed to flag manipulated prediction!"
    print("  => Cryptographic Prediction Tamper Detection: PASSED [OK]")

    banner("DEMO COMPLETED SUCCESSFULLY — ALL LEVEL 3 ML CRITERIA VERIFIED")


if __name__ == "__main__":
    main()
