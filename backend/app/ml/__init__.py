"""
JOCKY Machine-Learning Threat Detection Package
Level 3 Defensive Digital-Forensics Intelligence
"""
from backend.app.ml.schemas import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    CLASS_LABELS,
    LABEL_TO_INT,
    ForensicFeatureVector,
    ContributingFactor,
    ThreatPredictionResponse,
    ModelStatusResponse,
    ModelMetricsResponse,
    PredictionVerifyResponse,
)
from backend.app.ml.feature_extractor import ForensicFeatureExtractor
from backend.app.ml.threat_model import JockyThreatClassifier
from backend.app.ml.explainability import ThreatExplainer
from backend.app.ml.model_registry import ModelRegistry, model_registry
from backend.app.ml.model_trainer import ModelTrainer
from backend.app.ml.threat_detector import ThreatDetectionService

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "CLASS_LABELS",
    "LABEL_TO_INT",
    "ForensicFeatureVector",
    "ContributingFactor",
    "ThreatPredictionResponse",
    "ModelStatusResponse",
    "ModelMetricsResponse",
    "PredictionVerifyResponse",
    "ForensicFeatureExtractor",
    "JockyThreatClassifier",
    "ThreatExplainer",
    "ModelRegistry",
    "model_registry",
    "ModelTrainer",
    "ThreatDetectionService",
]
