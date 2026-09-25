# JOCKY Framework — Level 3: Machine Learning Threat Detection Engine

## Technical Architecture & Operational Specification

---

## 1. Overview & Defensive Scope

The **JOCKY Machine Learning Threat Detection Engine (Level 3)** integrates explainable, reproducible, and cryptographically verified artificial intelligence into the JOCKY Digital-Forensics Framework.

### Core Principles
1. **Strictly Defensive Digital-Forensics**: Designed exclusively for evidence analysis, indicator correlation, and forensic risk assessment.
2. **Human-in-the-Loop Decision Support**: ML classifications **never autonomously execute containment playbooks**, freeze endpoints, or manipulate running systems. All containment decisions require human analyst authorization.
3. **No External Dependencies**: Standard scikit-learn random forest architecture requiring no GPU, PyTorch, TensorFlow, or external third-party AI APIs.
4. **Cryptographic Prediction Sealing**: Every prediction is sealed with an RFC-8785 canonical SHA-256 hash. Any tampering with threat scores, feature values, or model hashes in the database is automatically flagged as `ML_PREDICTION_INTEGRITY_FAILURE`.
5. **Model Binary Integrity**: The trained model artifact (`models/jocky_threat_model.joblib`) is verified against its signed SHA-256 hash in `models/jocky_threat_model_metadata.json` upon loading. Tampered model files trigger an immediate execution halt and alert.

---

## 2. Architecture Diagram

```
+---------------------------------------------------------------------------------+
|                                 FORENSIC TELEMETRY                               |
|   (process.list, network.sockets, persistence.autorun, malware.pe_info, IOCs)   |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                        FORENSIC FEATURE EXTRACTOR                               |
|             (21 Deterministic Features - Schema Version 1.0)                     |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                             MODEL REGISTRY                                      |
|    - Computes SHA-256 of models/jocky_threat_model.joblib                       |
|    - Verifies against metadata hash (ad2af1bb04690f3b0e5cc81b3efc6a9a60c3...)   |
|    - Status: READY / INTEGRITY_FAILURE (Tamper Alarm)                           |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                     RANDOM FOREST CLASSIFIER INFERENCE                          |
|    - Classes: NORMAL (0), SUSPICIOUS (1), MALICIOUS (2)                         |
|    - Threat Score: P(SUSPICIOUS)*0.5 + P(MALICIOUS)*1.0  [0.0 - 1.0]            |
|    - Confidence: max(P(NORMAL), P(SUSPICIOUS), P(MALICIOUS))  [0.0 - 1.0]       |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       TRANSPARENT EXPLAINABILITY ENGINE                         |
|    - Impact = max(0, value - baseline) * feature_importance                     |
|    - Top 5 Ranked Contributing Factors with Human-Readable Forensic Narrative   |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                      RFC-8785 CANONICAL SHA-256 SEALING                         |
|    - Canonical JSON Hash: (case_id, classification, threat_score,               |
|                           confidence, feature_vector, model_hash)               |
|    - Database Persistence: MLThreatPrediction (Status: VERIFIED)                |
|    - Finding Synthesis: Defensive Finding tagged with ML-DETECTED (if >= 0.50)  |
+---------------------------------------------------------------------------------+
```

---

## 3. 21-Feature Deterministic Schema (Version 1.0)

Every forensic feature vector contains exactly 21 deterministic numeric features extracted from case evidence envelopes:

| # | Feature Name | Source Evidence | Description | Normal Baseline |
|---|---|---|---|---|
| 1 | `process_count` | `process.list` | Total active running processes | 15.0 |
| 2 | `suspicious_process_count` | `process.list` | Known adversarial binaries (mimikatz, meterpreter, etc.) | 0.0 |
| 3 | `temp_path_process_count` | `process.list` | Processes running from `%TEMP%`, `/tmp`, `%APPDATA%` | 0.0 |
| 4 | `connection_count` | `network.sockets` | Total active TCP/UDP connections | 8.0 |
| 5 | `external_connection_count` | `network.sockets` | Non-private RFC1918 outbound destination IPs | 2.0 |
| 6 | `suspicious_port_count` | `network.sockets` | Known C2 / backdoor ports (4444, 1337, 31337, etc.) | 0.0 |
| 7 | `persistence_count` | `persistence.autorun` | Total startup registry keys, services, cron jobs | 5.0 |
| 8 | `suspicious_persistence_count`| `persistence.autorun` | Persistence entries pointing to volatile temp paths | 0.0 |
| 9 | `file_count` | `file.*`, `malware.*` | Total file and executable artifacts inspected | 25.0 |
| 10 | `pe_anomaly_count` | `malware.pe_info` | High section entropy (>7.0), UPX packing, suspicious imports | 0.0 |
| 11 | `suspicious_file_count` | `file.*` | Files located in sensitive temporary directories | 0.0 |
| 12 | `ioc_count` | `InvestigationIndicator`| Total extracted Indicators of Compromise | 0.0 |
| 13 | `malicious_ioc_count` | `InvestigationIndicator`| IOCs matched as confirmed malicious by CTI feeds | 0.0 |
| 14 | `suspicious_ioc_count` | `InvestigationIndicator`| IOCs matched as suspicious or correlated | 0.0 |
| 15 | `ip_ioc_count` | `InvestigationIndicator`| IP address indicators | 0.0 |
| 16 | `hash_ioc_count` | `InvestigationIndicator`| File hash indicators (SHA-256, MD5) | 0.0 |
| 17 | `timeline_event_count` | `TimelineEvent` | Total synthesized forensic timeline events | 20.0 |
| 18 | `security_event_count` | `SecurityEvent` | Recorded system security and alert events | 0.0 |
| 19 | `cti_match_count` | `ThreatIntelItem` | Direct correlations with STIX 2.1 threat intelligence | 0.0 |
| 20 | `mitre_technique_count` | `ThreatIntelItem` | Observed adversarial MITRE ATT&CK techniques | 0.0 |
| 21 | `tamper_event_count` | `SecurityEvent` | Hash chain breaks or evidence tampering alerts | 0.0 |

---

## 4. Threat Scoring & Confidence Calibration

### Classes
- `0: NORMAL` — Baseline benign host activity.
- `1: SUSPICIOUS` — Anomalous activity warranting investigation.
- `2: MALICIOUS` — Hostile indicators, structural anomalies, or tampering.

### Continuous Threat Score
The threat score is a calibrated continuous metric in `[0.0, 1.0]`:
$$\text{threat\_score} = P(\text{SUSPICIOUS}) \times 0.5 + P(\text{MALICIOUS}) \times 1.0$$

- **Normal Host**: $0.00 \le \text{threat\_score} \le 0.39$
- **Suspicious Host**: $0.40 \le \text{threat\_score} \le 0.74$
- **Malicious Host**: $0.75 \le \text{threat\_score} \le 1.00$

### Confidence Score
$$\text{confidence} = \max(P(\text{NORMAL}), P(\text{SUSPICIOUS}), P(\text{MALICIOUS}))$$

---

## 5. Explainability Framework

For each prediction, the `ThreatExplainer` computes the feature impact score:
$$\text{impact\_score} = \max(0, \text{feature\_value} - \text{baseline}) \times \text{feature\_importance}$$

Factors are ranked descending by impact score. Each factor includes an analyst-readable explanation, for example:
> `pe_anomaly_count`: 2 portable executable structural anomalies (high entropy, abnormal section flags, or corrupted timestamps)
> `temp_path_process_count`: 1 binaries executing from volatile or temporary file paths (%TEMP% / /tmp)

---

## 6. Cryptographic Integrity & Anti-Tamper Sealing

### Prediction Canonical Hash
Every prediction is sealed at creation time using RFC-8785 canonical JSON sorting and SHA-256:
```json
{
  "case_id": "CASE-2026-001",
  "classification": "MALICIOUS",
  "confidence": 1.0,
  "feature_vector": { ... 21 features ... },
  "model_hash": "ad2af1bb04690f3b0e5cc81b3efc6a9a60c3c0c8e4838abd5a37a36483510102",
  "threat_score": 1.0
}
```
$$\text{prediction\_hash} = \text{SHA-256}(\text{canonical\_json}(\text{payload}))$$

### Tamper Detection Workflow
When `POST /api/ml/predictions/{prediction_id}/verify` is called:
1. Re-extracts stored prediction fields from the database.
2. Re-computes the canonical SHA-256 hash.
3. If hashes match: returns `is_valid: true`, `status: "VERIFIED"`.
4. If hashes mismatch:
   - Updates `prediction.integrity_status = "TAMPERED"`.
   - Emits a high-severity `SecurityEvent` of type `ML_PREDICTION_INTEGRITY_FAILURE`.
   - Triggers SOC alert stream and returns `is_valid: false`, `status: "TAMPERED"`.

---

## 7. REST API Reference

Mounted at `/api/ml/`:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ml/analyze/{case_id}` | Extract features, classify threat, seal hash, persist record |
| `GET` | `/api/ml/predictions/{case_id}` | Retrieve historical predictions for case |
| `GET` | `/api/ml/predictions/{case_id}/{prediction_id}` | Retrieve specific prediction by ID |
| `POST` | `/api/ml/predictions/{prediction_id}/verify` | Cryptographically verify prediction RFC-8785 seal |
| `GET` | `/api/ml/model/status` | Query model operational state and SHA-256 binary seal |
| `GET` | `/api/ml/model/metrics` | Retrieve evaluation metrics, feature importances, and disclaimer |

---

## 8. JOCKY DSL Primitives

The standard library registry (`language/stdlib/stdlib_registry.py`) includes 6 first-class primitives:

```jocky
// Run automated feature extraction and inference
prediction = ml.analyze("CASE-2026-001");

// Query continuous threat score
score = ml.score("CASE-2026-001");

// Extract top explainable contributing factors
factors = ml.explain("CASE-2026-001");

// Retrieve latest sealed prediction
latest = ml.prediction("CASE-2026-001");

// Cryptographically verify seal
verification = ml.verify(latest.prediction_id);

// Check model binary integrity
status = ml.model_status();
```

---

## 9. Model Training & Evaluation Data

- **Training Script**: `scripts/train_threat_model.py`
- **Dataset Generator**: `scripts/generate_ml_dataset.py` (Fixed seed 42, 2,000 samples)
- **Model Artifact**: `models/jocky_threat_model.joblib`
- **Signed Metadata**: `models/jocky_threat_model_metadata.json`
- **Demonstration Metrics (Synthetic Holdout)**:
  - Accuracy: 1.0000
  - Precision (Macro): 1.0000
  - Recall (Macro): 1.0000
  - F1-Score (Macro): 1.0000
  - *Disclaimer: Synthetic Demonstration Evaluation — strictly non-autonomous decision support.*
