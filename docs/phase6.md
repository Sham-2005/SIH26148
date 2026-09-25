# SIH26148 — JOCKY Framework: Phase 6 Documentation
# Threat Intelligence, Incident Response & Advanced SOC Visualization

## 1. Overview & Objectives

Phase 6 extends the **SIH26148 JOCKY Framework** into a comprehensive, enterprise-ready digital forensics, threat intelligence, and incident-response orchestration platform:

1. **Threat Intelligence Ingestion**: STIX 2.1 JSON bundle parsing and TAXII 2.1 provider abstraction (`LocalSTIXProvider`, `TAXIIProvider`, `DemoThreatIntelProvider`).
2. **Threat Intelligence Correlation**: Cross-referencing endpoint forensic indicators (hashes, IPs, domains, file paths) against threat intelligence records with confidence metrics and provenance tracking.
3. **Defensive Incident-Response Playbook Engine**: Safe, declarative response workflows with strict action allowlisting (`collect.system`, `collect.processes`, `collect.network`, `collect.persistence`, `collect.file_metadata`, `generate.report`, `isolate.endpoint.simulated`, `suspend.process.simulated`) and zero arbitrary command/shell execution.
4. **Mandatory Analyst Approval Workflow**: Multi-state authorization lifecycle (`DRAFT` → `PENDING_APPROVAL` → `APPROVED` → `EXECUTING` → `COMPLETED` / `REJECTED`) with immutable audit logging.
5. **Advanced SOC Visualizations**:
   - **Timeline Heatmap**: Hourly event density histogram with severity and event type filtering.
   - **Attack-Pattern Mapping**: Threat technique correlation (`OBSERVED`, `POTENTIAL`, `ANALYST-CONFIRMED`).
   - **Response Center**: Interactive incident response queue with one-click playbook approvals and execution monitoring.
   - **Threat Intelligence View**: Intel matches ledger with confidence distribution and source traceability.
6. **Enhanced Court-Admissible Reporting**: Multi-format exports (PDF via ReportLab, HTML, CSV, canonical JSON) incorporating Threat Intel Matches, Playbook Actions, and Analyst Approvals alongside cryptographic non-tamper seals.

---

## 2. Threat Intelligence Architecture & STIX 2.1 Ingestion

```
  [ External Feed / STIX 2.1 Bundle ]
                   │
                   ▼
       [ ThreatIntelProvider ]
       ├── LocalSTIXProvider
       ├── TAXIIProvider (Extensible)
       └── DemoThreatIntelProvider
                   │
                   ▼
         [ STIX 2.1 Parser ]
       ├── Indicators (Pattern Parsing)
       ├── Malware / Threat-Actor Objects
       ├── Attack Patterns (MITRE ATT&CK)
       └── Relationships (indicates, uses)
                   │
                   ▼
     [ Threat Intelligence Ledger ]
                   │
                   ▼
     [ Correlation Matcher Engine ]
     (Matches Case Evidence IOCs <-> Threat Intel)
                   │
                   ▼
     [ Status: MATCHED / REVIEW_REQUIRED ]
```

### Supported STIX 2.1 Objects:
- **`indicator`**: Extracts observable patterns for SHA-256, MD5, IPv4, IPv6, Domain, URL, File Path, and Process Name.
- **`attack-pattern`**: MITRE ATT&CK techniques with external IDs (e.g. `T1059`, `T1547`) and descriptions.
- **`malware` & `threat-actor`**: Threat attribution metadata and aliases.
- **`relationship`**: Associates threat actors and malware with specific indicators and techniques.

### Neutral Terminology:
Indicators are catalogued with objective statuses:
- `OBSERVED`: Detected on endpoints via forensic collectors.
- `MATCHED`: Corroborated by external threat intelligence feeds.
- `SUSPICIOUS`: Flagged by defensive heuristic rules (e.g. Temp execution, unknown outbound socket).
- `REVIEW_REQUIRED`: High-priority indicator requiring manual analyst disposition.

---

## 3. Incident Response Playbook Engine & Safety Model

### 3.1 Strict Action Allowlist
The playbook engine (`backend/app/services/playbook_service.py`) strictly enforces a whitelist of defensive, non-destructive response actions:

```python
ALLOWED_ACTIONS = {
    "collect.system",
    "collect.processes",
    "collect.network",
    "collect.persistence",
    "collect.file_metadata",
    "generate.report",
    "isolate.endpoint.simulated",
    "suspend.process.simulated"
}
```

Any unknown, unlisted, or arbitrary command is rejected with:
```text
UNSUPPORTED_RESPONSE_ACTION
```
* **No Arbitrary Execution**: Never invokes remote shell, PowerShell, Python `eval`, or downloaded binary payloads.
* **Controlled Lab Containment**: In the SIH demonstration environment, host isolation and process suspension are performed as safe simulated actions (`[DEMO / SIMULATED]`) that update endpoint states and log audit records without severing physical network adapters.

### 3.2 Analyst Approval Lifecycle
Every response playbook must pass an explicit human authorization gate:

```text
       [ Trigger: Investigative Finding ]
                       │
                       ▼
                    [ DRAFT ]
                       │
                       ▼
              [ PENDING_APPROVAL ]
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
    [ APPROVED ]                [ REJECTED ]
         │                           │
         ▼                           ▼
    [ EXECUTING ]              [ Audit Logged ]
         │
         ▼
    [ COMPLETED ]
```

- Unapproved playbooks cannot be executed; any execution attempt triggers HTTP `400 Bad Request`.
- Every transition (creation, approval, rejection, completion) is immutably logged in `AuditLog`.

---

## 4. Advanced SOC Visualizations

### 4.1 Timeline Heatmap (`GET /api/investigations/{case_id}/heatmap`)
Calculates dynamic event density across 24 hourly time buckets, reporting event counts, severity breakdowns (`HIGH`, `MEDIUM`, `INFO`), and collector distributions.

### 4.2 Attack-Pattern Mapping (`GET /api/investigations/{case_id}/attack-patterns`)
Maps observed evidence and threat intelligence indicators to MITRE ATT&CK techniques with verified confidence levels and supporting evidence references.

### 4.3 Incident Response Center (React UI)
Provides analysts with a dedicated operational workspace:
- Metrics: Open Findings, Pending Approvals, Active Playbooks, Completed Responses.
- Playbook authorization cards with one-click **Approve** and **Reject** controls.
- Interactive Approval Modal requiring explicit confirmation of target, actions, risk rating, and justification reason.

---

## 5. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threat-intel/sources` | Lists active threat intelligence providers and source feeds |
| `POST` | `/api/threat-intel/import` | Ingests a STIX 2.1 JSON bundle into the threat intelligence ledger |
| `GET` | `/api/investigations/{case_id}/intel` | Retrieves threat intelligence matches and correlations for a case |
| `GET` | `/api/playbooks` | Lists defensive response playbooks (filterable by case or status) |
| `POST` | `/api/playbooks` | Creates a new defensive response playbook |
| `GET` | `/api/playbooks/{id}` | Retrieves playbook details, itemized actions, and approval history |
| `POST` | `/api/playbooks/{id}/approve` | Analyst authorization gate approving playbook execution |
| `POST` | `/api/playbooks/{id}/reject` | Analyst rejection gate with mandatory justification reason |
| `POST` | `/api/playbooks/{id}/execute` | Executes approved allowlisted actions |
| `GET` | `/api/investigations/{case_id}/heatmap` | Computes hourly timeline event density buckets |
| `GET` | `/api/investigations/{case_id}/attack-patterns` | Maps observed telemetry to MITRE ATT&CK techniques |

---

## 6. End-to-End SIH Demonstration Workflow

1. **Start Backend Server**: `python -m uvicorn backend.app.main:app --port 8000 --reload`
2. **Start Simulated Fleet**: `python scripts/simulate_agents.py --agents 6 --server http://localhost:8000`
3. **Launch SOC Dashboard**: `npm --prefix frontend run dev` -> Navigate to `http://localhost:5173`
4. **Select Case**: Open `CASE-2026-001`.
5. **Import Threat Intelligence**: Ingest the demo STIX 2.1 bundle (`POST /api/threat-intel/import`).
6. **Review Threat Matches**: Inspect matched indicators and high-confidence correlations in the Threat Intelligence tab.
7. **Inspect Timeline Heatmap**: In the Investigation Hub, observe event density peaks across hourly buckets.
8. **Navigate to Response Center**:
   - Review pending playbook triggered by investigative findings.
   - Click **Approve Playbook** in the approval modal.
   - Observe real-time execution of allowlisted collection and simulated isolation.
   - Confirm completed status and immutable audit entry.
9. **Export Forensic Report**: Generate court-admissible PDF report verifying SHA-256 evidence integrity, threat intel matches, and authorized playbook responses.
