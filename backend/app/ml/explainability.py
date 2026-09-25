"""
Explainability Engine for JOCKY ML Threat Detection
Extracts top contributing features, calculates impact scores, and produces
analyst-actionable natural language forensic descriptions.
"""
from typing import List, Dict, Any
from backend.app.ml.schemas import ForensicFeatureVector, ContributingFactor, FEATURE_NAMES

# Normal baseline expectations for a benign baseline host
NORMAL_BASELINES: Dict[str, float] = {
    "process_count": 15.0,
    "suspicious_process_count": 0.0,
    "temp_path_process_count": 0.0,
    "connection_count": 8.0,
    "external_connection_count": 2.0,
    "suspicious_port_count": 0.0,
    "persistence_count": 5.0,
    "suspicious_persistence_count": 0.0,
    "file_count": 25.0,
    "pe_anomaly_count": 0.0,
    "suspicious_file_count": 0.0,
    "ioc_count": 0.0,
    "malicious_ioc_count": 0.0,
    "suspicious_ioc_count": 0.0,
    "ip_ioc_count": 0.0,
    "hash_ioc_count": 0.0,
    "timeline_event_count": 20.0,
    "security_event_count": 0.0,
    "cti_match_count": 0.0,
    "mitre_technique_count": 0.0,
    "tamper_event_count": 0.0,
}

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "suspicious_process_count": "{val} suspicious processes identified (e.g. masqueraded or unverified system names)",
    "temp_path_process_count": "{val} binaries executing from volatile or temporary file paths (%TEMP% / /tmp)",
    "pe_anomaly_count": "{val} portable executable structural anomalies (high entropy, abnormal section flags, or corrupted timestamps)",
    "malicious_ioc_count": "{val} indicators confirmed malicious by cyber threat intelligence feeds",
    "suspicious_ioc_count": "{val} indicators flagged as suspicious or untrusted",
    "tamper_event_count": "{val} system integrity violations, hash chain breaks, or unauthorized modifications detected",
    "suspicious_port_count": "{val} network connections targeting known high-risk or C2 ports",
    "suspicious_persistence_count": "{val} suspicious auto-run or scheduled task persistence mechanisms installed",
    "cti_match_count": "{val} telemetry items correlated with threat actor campaigns",
    "mitre_technique_count": "{val} distinct MITRE ATT&CK adversarial techniques observed",
    "suspicious_file_count": "{val} suspicious files located in sensitive system directories",
    "security_event_count": "{val} security alert events recorded in timeline",
    "external_connection_count": "{val} outbound external IP connections established",
    "connection_count": "{val} active network sockets observed",
    "process_count": "{val} total running processes active",
    "persistence_count": "{val} total system persistence items recorded",
    "file_count": "{val} total artifacts analyzed",
    "ioc_count": "{val} total extracted indicators of compromise",
    "ip_ioc_count": "{val} IP address indicators recorded",
    "hash_ioc_count": "{val} file hash indicators evaluated",
    "timeline_event_count": "{val} forensic timeline events analyzed",
}


class ThreatExplainer:
    """Computes transparent, evidence-grounded contributing factors for an ML threat prediction."""

    @classmethod
    def explain(
        cls,
        feature_vector: ForensicFeatureVector,
        classification: str,
        feature_importances: Dict[str, float],
        top_k: int = 5
    ) -> List[ContributingFactor]:
        """
        Calculates impact scores for each feature and returns the top K contributing factors.

        Impact Score = max(0, (value - baseline)) * importance_weight
        For NORMAL classification with low values, also highlights absence of anomalies.
        """
        features_dict = feature_vector.to_dict_features()
        factors: List[ContributingFactor] = []

        for feat_name in FEATURE_NAMES:
            val = float(features_dict.get(feat_name, 0.0))
            baseline = NORMAL_BASELINES.get(feat_name, 0.0)
            weight = float(feature_importances.get(feat_name, 0.05))

            # Non-zero suspicious features have high positive contribution
            deviation = max(0.0, val - baseline)
            impact = round(deviation * weight, 4)

            desc_template = FEATURE_DESCRIPTIONS.get(
                feat_name, f"Feature {feat_name} value: {{val}}"
            )
            description = desc_template.format(val=int(val) if val.is_integer() else val)

            factors.append(ContributingFactor(
                feature=feat_name,
                value=round(val, 2),
                importance_weight=round(weight, 4),
                impact_score=impact,
                description=description
            ))

        # Sort by impact_score descending
        factors.sort(key=lambda f: f.impact_score, reverse=True)

        # If all impacts are 0 (e.g. clean system), present lowest-risk confirming features
        if all(f.impact_score == 0.0 for f in factors):
            clean_factors = [
                ContributingFactor(
                    feature="suspicious_process_count",
                    value=0.0,
                    importance_weight=feature_importances.get("suspicious_process_count", 0.1),
                    impact_score=0.0,
                    description="0 suspicious processes detected across running system tasks"
                ),
                ContributingFactor(
                    feature="malicious_ioc_count",
                    value=0.0,
                    importance_weight=feature_importances.get("malicious_ioc_count", 0.16),
                    impact_score=0.0,
                    description="0 malicious threat indicators matched in forensic evidence"
                ),
                ContributingFactor(
                    feature="tamper_event_count",
                    value=0.0,
                    importance_weight=feature_importances.get("tamper_event_count", 0.12),
                    impact_score=0.0,
                    description="0 evidence hash chain breaks or tamper events observed"
                ),
                ContributingFactor(
                    feature="pe_anomaly_count",
                    value=0.0,
                    importance_weight=feature_importances.get("pe_anomaly_count", 0.14),
                    impact_score=0.0,
                    description="0 binary header or executable section anomalies found"
                ),
                ContributingFactor(
                    feature="suspicious_port_count",
                    value=0.0,
                    importance_weight=feature_importances.get("suspicious_port_count", 0.07),
                    impact_score=0.0,
                    description="0 connections to high-risk C2 network ports"
                )
            ]
            return clean_factors[:top_k]

        return factors[:top_k]
