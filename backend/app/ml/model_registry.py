"""
Model Registry and Integrity Verifier for JOCKY ML Threat Engine
Manages model loading, SHA-256 cryptographic verification, tamper detection,
and model status reporting.
"""
import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import joblib

from backend.app.ml.schemas import (
    ModelStatusResponse,
    ModelMetricsResponse,
    FEATURE_SCHEMA_VERSION,
    FEATURE_NAMES,
)
from backend.app.ml.threat_model import JockyThreatClassifier

logger = logging.getLogger("jocky.ml.registry")


def get_repo_root() -> Path:
    """Resolves repository root path."""
    return Path(__file__).resolve().parent.parent.parent.parent


class ModelRegistry:
    """Thread-safe singleton managing the JOCKY forensic threat detection model."""

    _instance: Optional["ModelRegistry"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        model_path: Optional[str] = None,
        metadata_path: Optional[str] = None
    ):
        if getattr(self, "_initialized", False):
            return

        repo_root = get_repo_root()
        self.model_path = Path(
            model_path or os.environ.get(
                "JOCKY_MODEL_PATH",
                str(repo_root / "models" / "jocky_threat_model.joblib")
            )
        )
        self.metadata_path = Path(
            metadata_path or os.environ.get(
                "JOCKY_MODEL_METADATA_PATH",
                str(repo_root / "models" / "jocky_threat_model_metadata.json")
            )
        )

        self._classifier: Optional[JockyThreatClassifier] = None
        self._metadata: Optional[Dict[str, Any]] = None
        self._status: str = "UNAVAILABLE"
        self._integrity: str = "UNKNOWN"
        self._calculated_hash: Optional[str] = None
        self._error_message: Optional[str] = None

        self._load_and_verify()
        self._initialized = True

    @staticmethod
    def compute_sha256(filepath: Path) -> str:
        """Computes SHA-256 hex digest of file contents."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _load_and_verify(self) -> None:
        """Loads metadata, verifies model file SHA-256 integrity, and deserializes model."""
        if not self.model_path.exists() or not self.metadata_path.exists():
            self._status = "UNAVAILABLE"
            self._integrity = "UNKNOWN"
            self._calculated_hash = None
            self._metadata = None
            self._classifier = JockyThreatClassifier(None)
            logger.warning(
                f"ML model files not found (Model: {self.model_path}, Meta: {self.metadata_path}). "
                "Running in fallback heuristic mode."
            )
            return

        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self._metadata = json.load(f)

            expected_hash = self._metadata.get("sha256_hash", "")
            self._calculated_hash = self.compute_sha256(self.model_path)

            if self._calculated_hash.lower() != expected_hash.lower():
                self._status = "INTEGRITY_FAILURE"
                self._integrity = "TAMPERED"
                self._classifier = None
                self._error_message = (
                    f"Integrity check failed: expected {expected_hash}, calculated {self._calculated_hash}"
                )
                logger.error(
                    f"CRITICAL: ML model integrity compromised! Expected {expected_hash}, "
                    f"got {self._calculated_hash}. Model execution suspended."
                )
                return

            # Integrity verified - load model
            estimator = joblib.load(self.model_path)
            feature_names = self._metadata.get("feature_names", list(FEATURE_NAMES))
            self._classifier = JockyThreatClassifier(estimator, feature_names=feature_names)
            self._status = "READY"
            self._integrity = "VALID"
            self._error_message = None
            logger.info(
                f"ML model loaded and verified successfully: {self.model_path} (SHA-256: {self._calculated_hash[:16]}...)"
            )

        except Exception as e:
            self._status = "ERROR"
            self._integrity = "UNKNOWN"
            self._classifier = None
            self._error_message = str(e)
            logger.error(f"Failed to load ML model: {e}")

    def reload(self) -> None:
        """Forces re-verification and reloading of the model from disk."""
        self._load_and_verify()

    def get_model(self) -> JockyThreatClassifier:
        """
        Returns verified classifier or raises RuntimeError if integrity check failed.
        If unavailable, returns fallback heuristic classifier.
        """
        if self._integrity == "TAMPERED":
            raise RuntimeError(
                f"ML model integrity verification failed: {self._error_message}. Model compromised."
            )
        if self._classifier is not None:
            return self._classifier
        # Return fallback heuristic classifier if unavailable
        return JockyThreatClassifier(None)

    def get_status(self) -> ModelStatusResponse:
        """Returns comprehensive model operational status and integrity state."""
        meta = self._metadata or {}
        return ModelStatusResponse(
            model_name=meta.get("model_name", "JOCKY-Forensic-Threat-Classifier"),
            model_version=meta.get("model_version", "1.0.0"),
            algorithm=meta.get("algorithm", "RandomForestClassifier"),
            status=self._status,
            integrity=self._integrity,
            model_hash=meta.get("sha256_hash", "0" * 64),
            calculated_hash=self._calculated_hash,
            feature_schema_version=meta.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
            training_timestamp=meta.get("training_timestamp"),
            evaluation_summary=meta.get("metrics")
        )

    def get_metrics(self) -> Optional[ModelMetricsResponse]:
        """Returns model evaluation metrics and feature importances."""
        if not self._metadata:
            return None
        return ModelMetricsResponse(
            model_name=self._metadata.get("model_name", "JOCKY-Forensic-Threat-Classifier"),
            model_version=self._metadata.get("model_version", "1.0.0"),
            algorithm=self._metadata.get("algorithm", "RandomForestClassifier"),
            training_dataset=self._metadata.get("training_dataset", "data/ml/jocky_threat_training.csv"),
            sample_count=self._metadata.get("sample_count", 0),
            train_count=self._metadata.get("train_count", 0),
            test_count=self._metadata.get("test_count", 0),
            random_seed=self._metadata.get("random_seed", 42),
            metrics=self._metadata.get("metrics", {}),
            feature_importance=self._metadata.get("feature_importance", {}),
            feature_schema_version=self._metadata.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
        )

    def verify_integrity(self) -> bool:
        """Returns True if model file hash matches metadata hash."""
        if not self.model_path.exists() or not self.metadata_path.exists():
            return False
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        calc_hash = self.compute_sha256(self.model_path)
        return calc_hash.lower() == meta.get("sha256_hash", "").lower()


# Default singleton instance
model_registry = ModelRegistry()
