"""
Model Trainer for JOCKY ML Threat Detection
Trains a Random Forest forensic threat classifier on synthetic forensic feature vectors,
evaluates performance metrics, and produces cryptographically sealed model artifacts.
"""
import os
import json
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from backend.app.ml.schemas import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    CLASS_LABELS,
    LABEL_TO_INT
)


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hex digest of file contents."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class ModelTrainer:
    """Encapsulates training, validation, and serialization for the JOCKY threat classifier."""

    @classmethod
    def load_dataset_from_csv(cls, csv_path: Path) -> Tuple[np.ndarray, np.ndarray]:
        """Loads feature matrix and label vector from training CSV."""
        rows_x: List[List[float]] = []
        rows_y: List[int] = []

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                feat_values = [float(row[feat]) for feat in FEATURE_NAMES]
                label_str = row["label"].strip().upper()
                label_int = LABEL_TO_INT.get(label_str, 0)
                rows_x.append(feat_values)
                rows_y.append(label_int)

        return np.array(rows_x, dtype=np.float64), np.array(rows_y, dtype=np.int64)

    @classmethod
    def train_and_export(
        cls,
        csv_path: Path,
        model_output_path: Path,
        metadata_output_path: Path,
        random_seed: int = 42,
        n_estimators: int = 100,
        max_depth: int = 10
    ) -> Dict[str, Any]:
        """
        Trains RandomForestClassifier, computes metrics on test holdout,
        persists model with joblib, calculates SHA-256 hash, and generates metadata.
        """
        model_output_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_output_path.parent.mkdir(parents=True, exist_ok=True)

        X, y = cls.load_dataset_from_csv(csv_path)
        total_samples = len(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=random_seed,
            stratify=y
        )

        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_seed,
            class_weight="balanced",
            n_jobs=-1
        )
        clf.fit(X_train, y_train)

        # Evaluation
        y_pred = clf.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

        cm = confusion_matrix(y_test, y_pred).tolist()

        # Feature importances
        importances = {
            name: round(float(imp), 4)
            for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
        }

        # Save model artifact
        joblib.dump(clf, model_output_path, compress=3)

        # Compute SHA-256
        model_sha256 = compute_file_sha256(model_output_path)

        metadata: Dict[str, Any] = {
            "model_name": "JOCKY-Forensic-Threat-Classifier",
            "model_version": "1.0.0",
            "algorithm": "RandomForestClassifier",
            "sha256_hash": model_sha256,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "class_labels": {str(k): v for k, v in CLASS_LABELS.items()},
            "training_dataset": str(csv_path),
            "sample_count": total_samples,
            "train_count": len(X_train),
            "test_count": len(X_test),
            "random_seed": random_seed,
            "hyperparameters": {
                "n_estimators": n_estimators,
                "max_depth": max_depth,
                "class_weight": "balanced"
            },
            "metrics": {
                "evaluation_type": "Synthetic Demonstration Evaluation",
                "disclaimer": (
                    "Metrics evaluated on synthetic forensic datasets for demonstration and verification "
                    "purposes only. Model is strictly designed as human-in-the-loop decision support "
                    "and must never trigger autonomous containment or response actions."
                ),
                "accuracy": round(acc, 4),
                "precision_macro": round(prec_macro, 4),
                "recall_macro": round(rec_macro, 4),
                "f1_macro": round(f1_macro, 4),
                "precision_weighted": round(prec_weighted, 4),
                "recall_weighted": round(rec_weighted, 4),
                "f1_weighted": round(f1_weighted, 4),
                "confusion_matrix": cm,
                "classes": ["NORMAL", "SUSPICIOUS", "MALICIOUS"]
            },
            "feature_importance": importances,
            "training_timestamp": datetime.now(timezone.utc).isoformat()
        }

        with open(metadata_output_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return metadata
