# JOCKY — SIH26148 Demonstration & Evaluation Guide

This guide provides an end-to-end walkthrough for judges, evaluators, and engineers to demonstrate the full forensic lifecycle of the **JOCKY Intelligent Digital Forensics Platform**.

---

## 1. Quick Startup & Seeding

Ensure the platform is installed and running:

```bash
# Terminal 1 - Backend
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 - Frontend
cd frontend
npm run dev
```

Seed the deterministic SIH demo case (if not automatically seeded on startup):
```bash
python scripts/seed_demo_data.py
```

Open your browser to: **`http://localhost:5173`**

---

## 2. Step-by-Step Evaluator Walkthrough

### Step 1: JOCKY Studio — DSL Authoring & Execution
1. In the left navigation, ensure **JOCKY Studio** is selected.
2. Select a preloaded template or examine the active investigation script:
   - Notice the domain-specific syntax: `investigate "APT_Persistence_Triage"`, target hosts, collector lease definitions, and extraction rules.
3. Click **▶ Run Investigation**.
4. The execution engine compiles the script to intermediate representation (IR), registers execution tasks, and triggers forensic collectors.

### Step 2: Investigation Workspace — Case Overview
1. Navigate to the **Investigation Workspace** for case **`CASE-DEMO-01`**.
2. **Tab 1: Overview**
   - View the overall **Threat Score (82/100 - High Risk)**.
   - Note the summary counters: 28 Evidence Envelopes, 4 Actionable Findings, 100% Chain Integrity.
   - Note the active case metadata and investigator identifier.

### Step 3: Script & Execution Provenance
1. **Tab 2: Script**
   - Review the complete captured script text.
   - Note the immutable **Script SHA-256 Digest**:
     `e2a1b9c7...` proving the exact code executed during triage.
2. **Tab 3: Execution**
   - Examine the collector runtimes, output status codes, and execution timestamps.

### Step 4: Sealed Evidence Envelopes & Canonical Hashing
1. **Tab 4: Evidence**
   - Observe the table of 28 cryptographically sealed evidence records.
   - Click on any evidence row (e.g., `EVD-DEMO-01-00009` — RunKey Persistence).
   - In the **Evidence Envelope Inspector**:
     - View **Raw Telemetry**: Original Windows registry value data.
     - View **Normalized Data**: RFC-8785 canonical JSON serialization.
     - Verify **Hash Chain**: Notice how `previous_hash` of this record matches the `current_hash` of `EVD-DEMO-01-00008`.

### Step 5: Explainable AI Findings & Vertical Traceability
1. **Tab 5: Findings**
   - Review the 4 security findings identified by rule matching and the trained **Random Forest Threat Classifier** (e.g., Registry RunKey Persistence, Suspicious PowerShell Encoded Execution).
   - Click **Trace Provenance** on any finding.
   - Inspect the **Vertical Traceability Chain**:
     ```text
     Finding (FND-DEMO-01-001)
        ↓
     Supporting Evidence (EVD-DEMO-01-00009)
        ↓
     Raw Telemetry (HKLM\...\Run\SystemUpdate)
        ↓
     Forensic Collector (registry_collector)
        ↓
     Execution Run (EXEC-DEMO-01)
        ↓
     JOCKY Script (APT_Persistence_Triage.jocky)
        ↓
     Binary Merkle Tree Root
        ↓
     Local Evidence Blockchain Anchor (Block #1)
     ```

### Step 6: Unified Forensic Timeline
1. **Tab 6: Timeline**
   - Follow the chronological forensic event sequence from initial access to persistence installation.
   - Click on any timeline node's linked evidence badge to immediately open that specific envelope.

### Step 7: Integrity Verification & Live Anti-Tamper Simulation
1. **Tab 7: Integrity Verification**
   - Observe the 4-point verification scorecard:
     - Sequential Hash Chain: `VERIFIED (28/28 linked)`
     - Merkle Tree Root: `VERIFIED (Matches computed root)`
     - Local Evidence Blockchain: `ANCHORED (Block #1 confirmed)`
     - Overall Status: **`ALL CHECKS PASS`**
2. **Simulate Evidence Tampering**:
   - Click **⚡ Simulate Tampering**.
   - The platform injects an out-of-band alteration into evidence item `EVD-DEMO-01-00009`.
   - The verification engine immediately flags:
     - Status: **`TAMPERED / INTEGRITY FAILURE`**
     - Detailed diagnosis identifying exact evidence ID, expected vs calculated SHA-256 hash, and broken sequential chain linkage.
3. **Restore Integrity**:
   - Click **↺ Restore Clean State**.
   - The original pristine record is restored and re-verified: **`ALL CHECKS PASS`**.

### Step 8: Court-Admissible Forensic Report Export
1. **Tab 8: Forensic Report**
   - Review the formal forensic report preview, including Scope, Chain of Custody, Collector Logs, ML Analysis, Limitations, and Cryptographic Anchors.
   - Click **Download JSON**: Obtains machine-readable RFC-8785 evidence envelope package.
   - Click **Download HTML**: Obtains court-admissible styled HTML document with embedded CSS.
   - Click **Download CSV**: Obtains spreadsheet-compatible evidence and findings export.

---

## 3. Blockchain Clarification

> **Important Note for Evaluators**:
> JOCKY currently implements a **Local Evidence Blockchain**: an append-only, tamper-evident cryptographic ledger used internally to anchor evidence integrity and Merkle roots. It is designed for forensic immutability without requiring a public decentralized Proof-of-Work or Proof-of-Stake network.
