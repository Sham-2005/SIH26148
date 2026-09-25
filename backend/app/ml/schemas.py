"""
Pydantic Schemas for JOCKY ML Threat Detection Engine
Defines feature vector schemas, prediction payloads, model metadata, and verification results.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field

FEATURE_SCHEMA_VERSION = "1.0"

FEATURE_NAMES = (
    "process_count",
    "suspicious_process_count",
    "temp_path_process_count",
    "connection_count",
    "external_connection_count",
    "suspicious_port_count",
    "persistence_count",
    "suspicious_persistence_count",
    "file_count",
    "pe_anomaly_count",
    "suspicious_file_count",
    "ioc_count",
    "malicious_ioc_count",
    "suspicious_ioc_count",
    "ip_ioc_count",
    "hash_ioc_count",
    "timeline_event_count",
    "security_event_count",
    "cti_match_count",
    "mitre_technique_count",
    "tamper_event_count"
)

CLASS_LABELS = {
    0: "NORMAL",
    1: "SUSPICIOUS",
    2: "MALICIOUS"
}

LABEL_TO_INT = {v: k for k, v in CLASS_LABELS.items()}


class ForensicFeatureVector(BaseModel):
    """Deterministic numeric feature vector extracted from case forensic artifacts."""
    process_count: int = 0
    suspicious_process_count: int = 0
    temp_path_process_count: int = 0
    connection_count: int = 0
    external_connection_count: int = 0
    suspicious_port_count: int = 0
    persistence_count: int = 0
    suspicious_persistence_count: int = 0
    file_count: int = 0
    pe_anomaly_count: int = 0
    suspicious_file_count: int = 0
    ioc_count: int = 0
    malicious_ioc_count: int = 0
    suspicious_ioc_count: int = 0
    ip_ioc_count: int = 0
    hash_ioc_count: int = 0
    timeline_event_count: int = 0
    security_event_count: int = 0
    cti_match_count: int = 0
    mitre_technique_count: int = 0
    tamper_event_count: int = 0
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def to_array(self) -> List[float]:
        """Returns ordered float values for model inference."""
        return [float(getattr(self, name, 0)) for name in FEATURE_NAMES]

    def to_dict_features(self) -> Dict[str, Any]:
        """Returns pure feature dict without schema version."""
        return {name: getattr(self, name, 0) for name in FEATURE_NAMES}


class ContributingFactor(BaseModel):
    feature: str
    value: float
    importance_weight: float
    impact_score: float
    description: str


class ThreatPredictionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    prediction_id: str
    case_id: str
    evidence_id: Optional[str] = None
    agent_id: Optional[str] = None

    model_name: str
    model_version: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    classification: str  # NORMAL, SUSPICIOUS, MALICIOUS
    threat_score: float  # 0.0 - 1.0
    confidence: float    # 0.0 - 1.0

    feature_vector: Dict[str, Any]
    top_factors: List[ContributingFactor]

    model_hash: str
    prediction_hash: str
    integrity_status: str  # VERIFIED, TAMPERED

    created_at: datetime


class ModelStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    model_name: str
    model_version: str
    algorithm: str
    status: str          # READY, UNAVAILABLE, INTEGRITY_FAILURE
    integrity: str       # VALID, TAMPERED, UNKNOWN
    model_hash: str
    calculated_hash: Optional[str] = None
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    training_timestamp: Optional[str] = None
    evaluation_summary: Optional[Dict[str, Any]] = None


class ModelMetricsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    model_name: str
    model_version: str
    algorithm: str
    training_dataset: str
    sample_count: int
    train_count: int
    test_count: int
    random_seed: int
    metrics: Dict[str, Any]
    feature_importance: Dict[str, float]
    feature_schema_version: str = FEATURE_SCHEMA_VERSION


class PredictionVerifyResponse(BaseModel):
    prediction_id: str
    case_id: str
    is_valid: bool
    status: str
    claimed_hash: str
    recalculated_hash: str
    message: str


class PredictRequest(BaseModel):
    case_id: Optional[str] = "CASE-LIVE-PREDICT"
    evidence_id: Optional[str] = None
    agent_id: Optional[str] = None
    feature_vector: Optional[Dict[str, Any]] = None
    persist: Optional[bool] = False

