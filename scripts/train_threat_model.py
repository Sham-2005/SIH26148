"""
Training Script for JOCKY ML Threat Engine
Trains Random Forest forensic threat classifier on synthetic forensic training data,
evaluates precision/recall/F1/confusion matrix, computes SHA-256 seal,
and generates signed model metadata.
"""
import sys
import json
from pathlib import Path

# Add project root to sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.ml.model_trainer import ModelTrainer
from backend.app.ml.model_registry import ModelRegistry


def main():
    csv_path = repo_root / "data" / "ml" / "jocky_threat_training.csv"
    model_output_path = repo_root / "models" / "jocky_threat_model.joblib"
    metadata_output_path = repo_root / "models" / "jocky_threat_model_metadata.json"

    if not csv_path.exists():
        print(f"Error: Dataset not found at {csv_path}. Run generate_ml_dataset.py first.")
        sys.exit(1)

    print("=" * 70)
    print("JOCKY Level 3 — Machine Learning Threat Detection Model Training")
    print("=" * 70)
    print(f"Dataset:  {csv_path}")
    print(f"Output:   {model_output_path}")
    print(f"Metadata: {metadata_output_path}")
    print("-" * 70)

    metadata = ModelTrainer.train_and_export(
        csv_path=csv_path,
        model_output_path=model_output_path,
        metadata_output_path=metadata_output_path,
        random_seed=42,
        n_estimators=100,
        max_depth=10
    )

    metrics = metadata.get("metrics", {})
    print("Training Complete. Evaluation Summary (Synthetic Demonstration Evaluation):")
    print(f"  Accuracy:           {metrics.get('accuracy'):.4f}")
    print(f"  Precision (Macro):  {metrics.get('precision_macro'):.4f}")
    print(f"  Recall (Macro):     {metrics.get('recall_macro'):.4f}")
    print(f"  F1-Score (Macro):   {metrics.get('f1_macro'):.4f}")
    print(f"  Confusion Matrix:   {metrics.get('confusion_matrix')}")
    print(f"  Model SHA-256:      {metadata.get('sha256_hash')}")
    print("-" * 70)

    # Verify loading via ModelRegistry
    registry = ModelRegistry(
        model_path=str(model_output_path),
        metadata_path=str(metadata_output_path)
    )
    registry.reload()
    status = registry.get_status()
    print(f"ModelRegistry Verification: Status={status.status}, Integrity={status.integrity}")
    print("=" * 70)


if __name__ == "__main__":
    main()
