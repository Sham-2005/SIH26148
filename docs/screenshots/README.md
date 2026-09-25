# JOCKY Visual Interface & Screenshots Directory

This directory documents the key graphical interfaces and forensic workflows provided by the JOCKY Digital Forensics Platform.

---

## Workspace & Interface Overview

| View Name | Primary Forensic Function | Key Elements |
|---|---|---|
| **1. JOCKY Studio** | DSL Scripting & Execution | Code editor with syntax highlighting, compilation diagnostics, collector configuration, and one-click execution. |
| **2. Execution History** | Audit Trail & Re-run | Complete ledger of all past forensic script runs, case IDs, execution statuses, and direct links to workspace cases. |
| **3. Workspace — Overview** | Investigation Summary | Executive case banner, threat score gauge, collector summary, and overall cryptographic verification status. |
| **4. Workspace — Script** | Investigation Provenance | Audited JOCKY script code, execution lease, SHA-256 script digest, and compiler compilation options. |
| **5. Workspace — Execution** | Runtime Diagnostics | Step-by-step collector task execution logs, timestamps, process states, and runtime resource metrics. |
| **6. Workspace — Evidence** | Sealed Evidence Envelopes | Grid of 28+ sealed digital evidence items with sequential SHA-256 hash chains, collector tags, and envelope inspection. |
| **7. Workspace — Findings** | Threat Intelligence & ML | AI-driven threat findings (Random Forest classifier + rules), MITRE ATT&CK technique IDs, confidence scores, and reasoning. |
| **8. Workspace — Timeline** | Unified Event Sequence | Chronological forensic activity trail mapped directly to corresponding evidence record IDs. |
| **9. Workspace — Integrity Verification** | Cryptographic Ledger Audit | 4-point verification scorecard: Raw hash, Normalized hash, Binary Merkle tree, and Local Evidence Blockchain anchor. Features live **Anti-Tamper Simulation**. |
| **10. Workspace — Forensic Report** | Court-Admissible Reporting | Formatted executive & technical forensic report with instant export to JSON, HTML, and CSV formats. |
| **11. Evidence Envelope Inspector** | Deep Forensics Modal | Raw payload viewer, RFC-8785 canonical normalized representation, hash chain linkage (`previous_hash` -> `current_hash`), and provenance chain. |
| **12. Vertical Traceability Chain** | Finding-to-Anchor Proof | Modal visualization showing the complete provenance path: `Finding -> Evidence -> Raw Telemetry -> Collector -> Script -> Merkle Root -> Blockchain Anchor`. |

---

## Screenshot Placement Guide

To add screenshots to your documentation or repository presentation:

1. **JOCKY Studio**: Save screenshot as `01_jocky_studio.png`
2. **Investigation Workspace Overview**: Save screenshot as `02_workspace_overview.png`
3. **Sealed Evidence Envelopes**: Save screenshot as `03_evidence_envelopes.png`
4. **Evidence Envelope Inspector (Deep View)**: Save screenshot as `04_envelope_inspector.png`
5. **Findings & ML Threat Analysis**: Save screenshot as `05_findings_ml.png`
6. **Unified Timeline**: Save screenshot as `06_forensic_timeline.png`
7. **Integrity Verification & Anti-Tamper**: Save screenshot as `07_integrity_verification.png`
8. **Court-Admissible Forensic Report**: Save screenshot as `08_forensic_report.png`
9. **Execution History**: Save screenshot as `09_execution_history.png`
