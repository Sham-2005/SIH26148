"""
JOCKY Threat Model Wrapper
Encapsulates scikit-learn Random Forest classifier inference, probability extraction,
threat score computation, and confidence calibration.
"""
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import logging
from backend.app.ml.schemas import (
    ForensicFeatureVector,
    FEATURE_NAMES,
    CLASS_LABELS,
    LABEL_TO_INT
)

logger = logging.getLogger("jocky.ml.threat_model")


class JockyThreatClassifier:
    """Wrapper around trained scikit-learn model for forensic threat classification."""

    def __init__(self, estimator: Optional[Any] = None, feature_names: Optional[List[str]] = None):
        self.estimator = estimator
        self.feature_names = feature_names or list(FEATURE_NAMES)

    def predict(self, feature_vector: ForensicFeatureVector) -> Tuple[str, float, float, Dict[str, float]]:
        """
        Executes model inference on a forensic feature vector.

        Returns:
            Tuple of:
            - classification (str): NORMAL, SUSPICIOUS, or MALICIOUS
            - threat_score (float): Continuous score in [0.0, 1.0]
            - confidence (float): Model classification confidence in [0.0, 1.0]
            - probabilities (Dict[str, float]): Class-specific probability distribution
        """
        if self.estimator is not None:
            return self._predict_ml(feature_vector)
        return self._heuristic_fallback(feature_vector)

    def _predict_ml(self, feature_vector: ForensicFeatureVector) -> Tuple[str, float, float, Dict[str, float]]:
        """Inference using trained scikit-learn model."""
        features_array = np.array([feature_vector.to_array()], dtype=np.float64)

        # Get probabilities
        if hasattr(self.estimator, "predict_proba"):
            probs = self.estimator.predict_proba(features_array)[0]
            classes = self.estimator.classes_

            prob_dict = {"NORMAL": 0.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0}
            for cls_idx, prob in zip(classes, probs):
                label_name = CLASS_LABELS.get(cls_idx, str(cls_idx))
                prob_dict[label_name] = round(float(prob), 4)

            pred_idx = int(self.estimator.predict(features_array)[0])
            classification = CLASS_LABELS.get(pred_idx, "NORMAL")

            # Continuous threat score: P(SUSPICIOUS) * 0.5 + P(MALICIOUS) * 1.0
            p_susp = prob_dict.get("SUSPICIOUS", 0.0)
            p_mal = prob_dict.get("MALICIOUS", 0.0)
            threat_score = round(min(1.0, max(0.0, (p_susp * 0.5) + (p_mal * 1.0))), 4)

            confidence = round(float(max(probs)), 4)
            return classification, threat_score, confidence, prob_dict
        else:
            # Estimator has only predict
            pred_idx = int(self.estimator.predict(features_array)[0])
            classification = CLASS_LABELS.get(pred_idx, "NORMAL")
            score_map = {"NORMAL": 0.1, "SUSPICIOUS": 0.6, "MALICIOUS": 0.95}
            threat_score = score_map.get(classification, 0.5)
            prob_dict = {k: (1.0 if k == classification else 0.0) for k in ["NORMAL", "SUSPICIOUS", "MALICIOUS"]}
            return classification, threat_score, 0.85, prob_dict

    def _heuristic_fallback(self, feature_vector: ForensicFeatureVector) -> Tuple[str, float, float, Dict[str, float]]:
        """
        Deterministic heuristic fallback when no trained model is loaded.
        Ensures system resilience without sacrificing safety.
        """
        feats = feature_vector.to_dict_features()
        high_severity_indicators = (
            feats.get("malicious_ioc_count", 0) * 3.0 +
            feats.get("pe_anomaly_count", 0) * 2.5 +
            feats.get("tamper_event_count", 0) * 3.0 +
            feats.get("suspicious_persistence_count", 0) * 2.0
        )
        med_severity_indicators = (
            feats.get("suspicious_process_count", 0) * 1.5 +
            feats.get("temp_path_process_count", 0) * 1.2 +
            feats.get("suspicious_port_count", 0) * 1.5 +
            feats.get("suspicious_file_count", 0) * 1.0 +
            feats.get("suspicious_ioc_count", 0) * 1.2 +
            feats.get("cti_match_count", 0) * 1.5
        )

        total_penalty = high_severity_indicators + med_severity_indicators

        if total_penalty >= 5.0 or feats.get("malicious_ioc_count", 0) > 0 or feats.get("tamper_event_count", 0) > 0:
            classification = "MALICIOUS"
            threat_score = min(0.98, 0.70 + (total_penalty * 0.03))
            prob_dict = {"NORMAL": 0.05, "SUSPICIOUS": 0.20, "MALICIOUS": 0.75}
            confidence = 0.88
        elif total_penalty >= 2.0 or feats.get("suspicious_process_count", 0) > 0 or feats.get("suspicious_port_count", 0) > 0:
            classification = "SUSPICIOUS"
            threat_score = min(0.69, 0.40 + (total_penalty * 0.04))
            prob_dict = {"NORMAL": 0.15, "SUSPICIOUS": 0.70, "MALICIOUS": 0.15}
            confidence = 0.82
        else:
            classification = "NORMAL"
            threat_score = max(0.02, total_penalty * 0.05)
            prob_dict = {"NORMAL": 0.90, "SUSPICIOUS": 0.08, "MALICIOUS": 0.02}
            confidence = 0.92

        return classification, round(threat_score, 4), round(confidence, 4), prob_dict

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns feature importances from underlying model if available."""
        if self.estimator is not None and hasattr(self.estimator, "feature_importances_"):
            importances = self.estimator.feature_importances_
            return {
                name: round(float(imp), 4)
                for name, imp in zip(self.feature_names, importances)
            }
        # Fallback default weights
        return {
            "malicious_ioc_count": 0.16,
            "pe_anomaly_count": 0.14,
            "tamper_event_count": 0.12,
            "suspicious_process_count": 0.10,
            "temp_path_process_count": 0.08,
            "suspicious_persistence_count": 0.08,
            "suspicious_port_count": 0.07,
            "cti_match_count": 0.06,
            "suspicious_ioc_count": 0.05,
            "suspicious_file_count": 0.04,
            "mitre_technique_count": 0.03,
            "security_event_count": 0.02,
            "external_connection_count": 0.015,
            "process_count": 0.005,
            "connection_count": 0.005,
            "file_count": 0.005,
            "ioc_count": 0.005,
            "persistence_count": 0.003,
            "ip_ioc_count": 0.003,
            "hash_ioc_count": 0.003,
            "timeline_event_count": 0.002,
        }
