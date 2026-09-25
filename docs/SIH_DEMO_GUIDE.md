# Smart India Hackathon (SIH) Live Demonstration Guide

## JOCKY: Defensive Digital-Forensics & Automated Incident Response Platform
**Project ID**: SIH26148  
**Demonstration Scope**: 8-Part Comprehensive Enterprise Incident Triage & Defense Lifecycle

---

### Demonstration Overview

This guide provides the exact spoken script, actions, and terminal commands for a flawless live demonstration of JOCKY before evaluators. It illustrates an enterprise intrusion detection, forensic artifact collection, threat correlation, containment approval, anti-tampering verification, and forensic reporting.

---

### Part 1: Incident Scenario & Case Initialization

**Objective**: Demonstrate case creation with severity prioritization and analyst attribution.

1. **Presenter Narration**:
   > *"Welcome. We demonstrate JOCKY, an automated defensive digital-forensics and incident response platform. We begin with an enterprise triage alert: anomalous outbound connections detected from an engineering workstation."*

2. **Actions & Commands**:
   - In the Web UI (or API), open case `CASE-2026-001`.
   - Title: `Enterprise Lateral Movement & Beaconing Investigation`
   - Severity: `CRITICAL`
   - View initial case overview and status `INVESTIGATING`.

---

### Part 2: Heterogeneous Agent Fleet Triage & Task Dispatch

**Objective**: Demonstrate cross-platform agent registration (Windows, Linux, Domain Controllers) and non-destructive forensic artifact collection.

1. **Presenter Narration**:
   > *"JOCKY coordinates a heterogeneous fleet of non-destructive endpoint agents across Windows and Linux. The analyst drafts a domain-specific JOCKY script to collect volatile memory artifacts, active process trees, network sockets, and file hashes."*

2. **Actions & Commands**:
   - Run fleet simulator:
     ```bash
     python scripts/simulate_agents.py --agents 6 --once
     ```
   - Demonstrate compiler safety check:
     ```bash
     python -m compiler.cli compile examples/incident_triage.jocky
     ```
   - The compiled plan is signed with a deterministic SHA-256 hash and dispatched to endpoints.

---

### Part 3: Evidence Ingestion, RFC-8785 Sealing & IOC Normalization

**Objective**: Showcase cryptographic evidence sealing and automatic indicator extraction.

1. **Presenter Narration**:
   > *"Every evidence artifact collected by an agent is sealed in an RFC-8785 canonical JSON envelope, hashed using SHA-256, and cryptographically chained to prevent evidence tampering or chain-of-custody breaks."*

2. **Actions & Commands**:
   - View Evidence Ledger in UI or API: `GET /api/investigations/CASE-2026-001/summary`
   - Show extracted Indicators of Compromise (IOCs): `GET /api/investigations/CASE-2026-001/iocs`
   - Highlight normalized IPv4 addresses, domain names, file paths, and SHA-256 process hashes.

---

### Part 4: Automated Cross-Agent Evidence Correlation

**Objective**: Highlight automated correlation engine finding cross-host attack patterns.

1. **Presenter Narration**:
   > *"Rather than forcing analysts to manually grep through disparate logs, JOCKY's correlation engine automatically links findings across endpoints. It identifies matching hashes on separate hosts, process-to-network socket links, and registry persistence mechanisms."*

2. **Actions & Commands**:
   - View Correlations: `GET /api/investigations/CASE-2026-001/correlations`
   - Point out:
     - `SAME_HASH_CROSS_AGENT`: Suspicious payload `svchost_update.exe` discovered across both `AGENT-WIN-01` and `AGENT-WIN-02`.
     - `PROCESS_NETWORK_OUTBOUND`: Process communicating with known suspicious IP `10.200.1.50`.

---

### Part 5: Threat Intelligence (CTI) & MITRE ATT&CK Mapping

**Objective**: Demonstrate STIX 2.1 threat intelligence ingestion and automated rule matching.

1. **Presenter Narration**:
   > *"JOCKY integrates Cyber Threat Intelligence (CTI) using standard STIX 2.1 bundles. It matches extracted endpoint indicators against threat actor profiles and maps every observed behavior directly to the MITRE ATT&CK Enterprise Matrix."*

2. **Actions & Commands**:
   - Query Threat Intel Matches: `GET /api/threat-intel/matches?case_id=CASE-2026-001`
   - Show MITRE ATT&CK technique tags:
     - `T1059.001` (Command and Scripting Interpreter: PowerShell)
     - `T1053` (Scheduled Task/Job)
     - `T1071.001` (Application Layer Protocol: Web Protocols)

---

### Part 6: Response Playbooks & Two-Person Approval Workflow

**Objective**: Demonstrate automated response orchestration with human-in-the-loop safety.

1. **Presenter Narration**:
   > *"For enterprise defense, automated response actions must never be triggered unilaterally without strict access controls. JOCKY enforces a dual-custody approval workflow: an analyst generates a containment playbook, but execution is blocked until an authorized manager cryptographically approves it."*

2. **Actions & Commands**:
   - View Playbook: `PB-CONTAIN-001` (`Isolate Endpoint & Terminate Rogue PID`)
   - Show Playbook Status: `PENDING_APPROVAL`
   - Approve Playbook via authorized account:
     ```bash
     curl -X POST http://localhost:8000/api/playbooks/PB-CONTAIN-001/approve -H "Content-Type: application/json" -d "{\"approver_email\": \"security_lead@jocky.defense\", \"comment\": \"Authorized for simulated containment\"}"
     ```
   - Execute Playbook and view step-by-step execution log.

---

### Part 7: Anti-Tampering Engine & 7-Control Security Scorecard

**Objective**: Prove the tamper-resistance of the chain of custody.

1. **Presenter Narration**:
   > *"In legal and defensive proceedings, digital evidence must be provably tamper-proof. We now intentionally inject a simulated tampering attack—modifying an evidence record and altering an audit entry."*

2. **Actions & Commands**:
   - Trigger simulated security event:
     ```bash
     python scripts/simulate_security_events.py --case CASE-2026-001
     ```
   - Check Security Scorecard: `GET /api/investigations/CASE-2026-001/integrity-scorecard`
   - Evaluators observe:
     - Immediate detection of `EVIDENCE_TAMPER_DETECTED` and `AUDIT_CHAIN_BREAK`.
     - Scorecard status reflects anomaly while protecting pristine chain history.
     - Tamper incident is recorded in append-only cryptographic audit trail.

---

### Part 8: Multi-Format Forensic Reporting & Release Certification

**Objective**: Generate court-admissible forensic reports in multiple formats and verify manifests.

1. **Presenter Narration**:
   > *"Finally, JOCKY compiles a comprehensive, forensically sealed investigation report with an embedded cryptographic manifest. Reports can be exported instantly as PDF, structured HTML, CSV evidence ledger, or RFC-8785 canonical JSON."*

2. **Actions & Commands**:
   - Export Reports:
     - PDF: `GET /api/reports/CASE-2026-001/export?format=pdf`
     - HTML: `GET /api/reports/CASE-2026-001/export?format=html`
     - CSV: `GET /api/reports/CASE-2026-001/export?format=csv`
     - JSON: `GET /api/reports/CASE-2026-001/export?format=json`
   - Verify report manifest integrity:
     ```bash
     python scripts/validate_reports.py --case CASE-2026-001
     ```
   - Present final release certification artifact: `phase8_validation_report.json`.

---

### Conclusion & Key Takeaways

1. **Full Chain-of-Custody**: Zero-loss, cryptographically chained evidence ledger.
2. **Defensive Safety**: Strict non-destructive collector boundary with two-person approval.
3. **High Performance**: < 10ms micro-latencies across compiler, API, and agent communications.
4. **Release Certified**: 114/114 automated tests passing across 8 complete validation stages.
