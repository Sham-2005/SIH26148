"""
Synthetic Dataset Generator for JOCKY ML Threat Engine
Generates 2,000 deterministic forensic feature vectors with ground-truth labels
(NORMAL, SUSPICIOUS, MALICIOUS) using fixed random seed (42).

NOTE: Explicitly designated as a Synthetic Demonstration Dataset for defensive
digital-forensics architecture validation, model training, and integration testing.
"""
import os
import sys
import csv
import random
from pathlib import Path
from typing import List, Dict, Any

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.ml.schemas import FEATURE_NAMES

RANDOM_SEED = 42
TOTAL_SAMPLES = 2000
SAMPLE_DISTRIBUTION = {
    "NORMAL": 1000,       # 50%
    "SUSPICIOUS": 600,    # 30%
    "MALICIOUS": 400      # 20%
}


def generate_sample(label: str, rng: random.Random) -> Dict[str, Any]:
    """Generates a single synthetic feature row with realistic forensic distributions."""
    row: Dict[str, Any] = {}

    if label == "NORMAL":
        row["process_count"] = rng.randint(8, 25)
        row["suspicious_process_count"] = 0
        row["temp_path_process_count"] = 0
        row["connection_count"] = rng.randint(2, 15)
        row["external_connection_count"] = rng.randint(0, 4)
        row["suspicious_port_count"] = 0
        row["persistence_count"] = rng.randint(2, 8)
        row["suspicious_persistence_count"] = 0
        row["file_count"] = rng.randint(10, 40)
        row["pe_anomaly_count"] = 0
        row["suspicious_file_count"] = 0
        row["ioc_count"] = 0
        row["malicious_ioc_count"] = 0
        row["suspicious_ioc_count"] = 0
        row["ip_ioc_count"] = 0
        row["hash_ioc_count"] = 0
        row["timeline_event_count"] = rng.randint(10, 50)
        row["security_event_count"] = 0
        row["cti_match_count"] = 0
        row["mitre_technique_count"] = 0
        row["tamper_event_count"] = 0

        # 2% benign noise (e.g. 1 untracked temp file or 1 external IP)
        if rng.random() < 0.02:
            row["external_connection_count"] += 1
        if rng.random() < 0.01:
            row["file_count"] += 5

    elif label == "SUSPICIOUS":
        row["process_count"] = rng.randint(15, 40)
        row["suspicious_process_count"] = rng.randint(1, 3)
        row["temp_path_process_count"] = rng.randint(0, 2)
        row["connection_count"] = rng.randint(10, 30)
        row["external_connection_count"] = rng.randint(2, 8)
        row["suspicious_port_count"] = rng.randint(0, 2)
        row["persistence_count"] = rng.randint(4, 12)
        row["suspicious_persistence_count"] = rng.randint(1, 2)
        row["file_count"] = rng.randint(20, 60)
        row["pe_anomaly_count"] = rng.choice([0, 1])
        row["suspicious_file_count"] = rng.randint(1, 3)
        row["ioc_count"] = rng.randint(1, 4)
        row["malicious_ioc_count"] = 0
        row["suspicious_ioc_count"] = rng.randint(1, 4)
        row["ip_ioc_count"] = rng.randint(0, 2)
        row["hash_ioc_count"] = rng.randint(0, 2)
        row["timeline_event_count"] = rng.randint(25, 80)
        row["security_event_count"] = rng.randint(1, 3)
        row["cti_match_count"] = rng.choice([0, 1, 2])
        row["mitre_technique_count"] = rng.randint(1, 3)
        row["tamper_event_count"] = 0

    elif label == "MALICIOUS":
        row["process_count"] = rng.randint(20, 60)
        row["suspicious_process_count"] = rng.randint(2, 6)
        row["temp_path_process_count"] = rng.randint(1, 4)
        row["connection_count"] = rng.randint(15, 50)
        row["external_connection_count"] = rng.randint(4, 15)
        row["suspicious_port_count"] = rng.randint(1, 4)
        row["persistence_count"] = rng.randint(6, 18)
        row["suspicious_persistence_count"] = rng.randint(2, 5)
        row["file_count"] = rng.randint(30, 90)
        row["pe_anomaly_count"] = rng.randint(1, 4)
        row["suspicious_file_count"] = rng.randint(2, 7)
        row["ioc_count"] = rng.randint(3, 10)
        row["malicious_ioc_count"] = rng.randint(1, 6)
        row["suspicious_ioc_count"] = rng.randint(1, 5)
        row["ip_ioc_count"] = rng.randint(1, 5)
        row["hash_ioc_count"] = rng.randint(1, 5)
        row["timeline_event_count"] = rng.randint(40, 150)
        row["security_event_count"] = rng.randint(2, 8)
        row["cti_match_count"] = rng.randint(1, 5)
        row["mitre_technique_count"] = rng.randint(2, 7)
        row["tamper_event_count"] = rng.choice([0, 0, 1, 2])

    row["label"] = label
    return row


def generate_dataset(output_path: Path, seed: int = RANDOM_SEED) -> None:
    """Generates the full dataset and writes to CSV."""
    rng = random.Random(seed)
    samples: List[Dict[str, Any]] = []

    for label, count in SAMPLE_DISTRIBUTION.items():
        for _ in range(count):
            samples.append(generate_sample(label, rng))

    # Shuffle deterministically
    rng.shuffle(samples)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(FEATURE_NAMES) + ["label"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)

    print(f"Generated {len(samples)} synthetic forensic samples -> {output_path}")
    print(f"Distribution: {SAMPLE_DISTRIBUTION}")


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent.parent
    target_csv = repo_root / "data" / "ml" / "jocky_threat_training.csv"
    generate_dataset(target_csv)
