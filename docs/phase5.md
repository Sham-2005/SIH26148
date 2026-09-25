# SIH26148 — JOCKY Framework: Phase 5 Documentation
# Intelligent Forensic Investigation & Threat Correlation Platform

## 1. Overview & Objectives

Phase 5 transitions the **SIH26148 JOCKY Framework** from an endpoint evidence collection platform into an **Intelligent Forensic Investigation & Threat Correlation Platform**. 

While Phases 1–4 established safe DSL compilation, multi-agent fleet simulation (6 heterogeneous Windows & Linux endpoints), tamper-evident RFC-8785 evidence envelopes, agent isolation, and report generation, Phase 5 provides defensive analysts with automated contextual understanding:

* **What happened?** Synthesized findings detailing suspicious patterns.
* **When did it happen?** Unified, chronologically ordered cross-collector investigation timeline.
* **Which system was affected?** Cross-agent attribution tracking affected endpoints.
* **Which process/file/network event is related?** Multi-dimensional correlation across telemetry types.
* **Which indicators are suspicious?** Normalized IOC extraction with neutral, objective terminology (`observed`, `suspicious`, `matched`, `correlated`).
* **What evidence supports the finding?** Strict cryptographic traceability linking every finding to underlying Evidence IDs.
* **What should the analyst investigate next?** Explainable risk scores with human-readable priority factors.

---

## 2. Investigation Architecture

```
                               ┌────────────────────────────────┐
                               │ 6 Endpoint Agents (Win/Linux)  │
                               └───────────────┬────────────────┘
                                               │
                                               ▼ (Sealed Evidence Envelopes: RFC-8785 + SHA-256)
                               ┌────────────────────────────────┐
                               │ FastAPI Central Server Ingestion│
                               └───────────────┬────────────────┘
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        │                                             │
                        ▼                                             ▼
          ┌───────────────────────────┐                 ┌───────────────────────────┐
          │   IOC Extraction Engine   │                 │   Timeline Synthesis      │
          │     (ioc_service.py)      │                 │   (timeline_service.py)   │
          └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                        │                                             │
                        └──────────────────────┬──────────────────────┘
                                               │
                                               ▼
                               ┌────────────────────────────────┐
                               │ Evidence Correlation Engine    │
                               │  (correlation_service.py)      │
                               │  • Cross-Agent Hashes          │
                               │  • Process-to-Network Sockets  │
                               │  • Persistence-to-Executable   │
                               └───────────────┬────────────────┘
                                               │
                                               ▼
                               ┌────────────────────────────────┐
                               │ Explainable Risk & Finding     │
                               │ Engine (finding/risk_service)  │
                               │  • Priority (LOW/MED/HIGH/CRIT)│
                               │  • Itemized Justification List │
                               └───────────────┬────────────────┘
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        │                                             │
                        ▼                                             ▼
          ┌───────────────────────────┐                 ┌───────────────────────────┐
          │ Investigation Workspace   │                 │ Court-Admissible Reports  │
          │ (React SOC UI + WebSocket)│                 │ (PDF, HTML, CSV, JSON)    │
          └───────────────────────────┘                 └───────────────────────────┘
```

---

## 3. Core Forensic Engines

### 3.1 IOC Extraction & Normalization Engine (`backend/app/services/ioc_service.py`)
Extracts indicators from structured evidence payloads (`process.list`, `network.connections`, `malware.pe_info`, `persistence.startup`, `file.hash`):
- **Indicator Types**: `ipv4`, `ipv6`, `domain`, `url`, `filepath`, `sha256`, `md5`, `process_name`, `service_name`, `registry_path`.
- **Normalization Rules**:
  - Cryptographic hashes are lowercased and stripped of prefixes.
  - File paths are normalized to forward slashes with drive letters standardized.
  - IP addresses are trimmed, validated, and normalized.
- **Neutral Terminology**: Indicators are tagged with objective states: `observed`, `suspicious`, `matched`, `correlated`.

### 3.2 Unified Timeline Engine (`backend/app/services/timeline_service.py`)
Assembles a chronological audit sequence across all collectors and agents:
- **Event Types**: `PROCESS`, `FILE`, `NETWORK`, `PERSISTENCE`, `SERVICE`, `REGISTRY`, `SYSTEM`, `ANALYSIS`.
- **Sorting & Filtering**: Guarantees deterministic chronological sorting with query filters by `agent_id`, `event_type`, `severity`, and timestamp bounds.

### 3.3 Evidence Correlation Engine (`backend/app/services/correlation_service.py`)
Identifies non-obvious relationships across forensic telemetry:
- **Cross-Agent Concurrency**: Detects when an identical file hash or binary appears across multiple workstations or servers.
- **Process-to-Network Binding**: Associates open socket ports and outbound network connections with active process IDs and names.
- **Persistence-to-Binary Association**: Links Registry RunKeys, startup folders, or scheduled tasks directly to executable inspection and PE headers.

### 3.4 Explainable Risk & Priority Engine (`backend/app/services/risk_service.py`)
Calculates deterministic, auditable threat priorities without opaque AI or generative hallucination:
- **Scoring Breakdown**:
  - Persistence mechanism identified: `+30`
  - Cross-endpoint observation (lateral movement indicator): `+25`
  - Suspicious execution location (`/Temp`, `AppData`): `+25`
  - Active outbound network socket: `+20`
- **Output**: Generates a priority classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), numerical score (0–100), and an itemized list of human-readable justification reasons.

### 3.5 Finding Lifecycle Engine (`backend/app/services/finding_service.py`)
Packages correlated events and risk calculations into reviewable investigative findings:
- **States**: `OPEN` → `UNDER_REVIEW` → `CONFIRMED` or `DISMISSED`.
- **Evidence Traceability**: Every finding contains explicit foreign keys (`evidence_ids`) pointing to sealed evidence envelopes.

---

## 4. Database Schema Extensions

Five new models are added to `backend/app/models/models.py`:

1. **`InvestigationIndicator`**:
   - `id`, `case_id`, `indicator_type`, `value`, `normalized_value`, `source_evidence_id`, `agent_id`, `first_seen`, `last_seen`, `status`, `context_data`.
2. **`TimelineEvent`**:
   - `id`, `case_id`, `agent_id`, `timestamp`, `event_type`, `description`, `evidence_id`, `severity`, `details`.
3. **`EvidenceCorrelation`**:
   - `id`, `case_id`, `correlation_type`, `title`, `description`, `primary_agent_id`, `related_agent_ids`, `evidence_ids`, `indicators`, `score`, `detected_at`.
4. **`Finding`**:
   - `id`, `case_id`, `title`, `description`, `reason`, `status`, `priority`, `priority_score`, `priority_reasons`, `related_agents`, `evidence_ids`, `created_at`, `updated_at`.
5. **`AnalystNote`**:
   - `id`, `case_id`, `analyst_name`, `note_type` (`observation`, `hypothesis`, `conclusion`, `investigation_note`), `content`, `created_at`.

---

## 5. REST API Specifications

All endpoints are mounted under `/api/investigations`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{case_id}/summary` | Comprehensive investigation overview (counts, status, severity) |
| `GET` | `/api/investigations/{case_id}/timeline` | Chronological event list with agent/type/severity filtering |
| `GET` | `/api/investigations/{case_id}/indicators` | Normalized IOC ledger with first/last seen and counts |
| `GET` | `/api/investigations/{case_id}/correlations`| Discovered cross-agent and cross-collector correlation clusters |
| `GET` | `/api/investigations/{case_id}/findings` | Actionable findings with risk scores and evidence links |
| `PATCH`| `/api/investigations/{case_id}/findings/{id}` | Updates finding status (`OPEN`, `CONFIRMED`, `DISMISSED`) |
| `GET` | `/api/investigations/{case_id}/graph` | Node-edge relationship graph (Agents, Processes, Files, Hashes, IPs) |
| `GET` | `/api/investigations/{case_id}/search` | Structured keyword search (`process:`, `hash:`, `ip:`, `agent:`) |
| `POST`| `/api/investigations/{case_id}/notes` | Appends timestamped analyst note with audit logging |
| `GET` | `/api/investigations/{case_id}/notes` | Lists all analyst notes for the investigation |
| `POST`| `/api/investigations/{case_id}/analyze` | Triggers or re-executes automated investigation pipeline on case |

---

## 6. Investigation Workspace UI

The React SOC dashboard (`frontend/src/App.jsx`) integrates the **Investigation Workspace**:
- **Case Summary Cards**: Live counts for Investigated Endpoints, Sealed Evidence Items, Extracted Indicators, Timeline Events, and Open Findings.
- **Interactive Timeline**: Visual stream with event type badges (`PROCESS`, `NETWORK`, `PERSISTENCE`, `FILE`), timestamps, and severity colors.
- **Findings Ledger**: Expandable finding cards with priority badges, explainable reason tags, and status transition controls.
- **Visual Correlation Graph**: Interactive node-edge relationship map highlighting connections between agents, files, processes, and remote IPs.
- **Investigation Search Bar**: Instant search across processes, hashes, IPs, and agent IDs.
- **Analyst Notes Feed**: Form for analysts to log observations, hypotheses, and conclusions with immutable audit timestamps.

---

## 7. Court-Admissible Reporting Updates

`ReportExportService` incorporates full investigation context into all 4 export formats:
- **PDF**: ReportLab generated document with Executive Summary, Investigation Scope, Agent Inventory, Chronological Timeline, Normalized Indicators Table, Correlated Findings, Risk Breakdown, Analyst Notes, and Legal Non-Tamper Declaration.
- **HTML**: Styled responsive investigation dossier with collapsible JSON trees.
- **CSV**: Multi-sheet / structured rows of evidence, indicators, and findings for SIEM ingest.
- **JSON**: Full RFC-8785 canonical representation with cryptographic proofs.

---

## 8. SIH Demonstration Workflow

1. **Launch Backend**: `python -m uvicorn backend.app.main:app --port 8000 --reload`
2. **Launch Fleet Simulator**: `python scripts/simulate_agents.py --agents 6 --server http://localhost:8000`
3. **Open Frontend**: `http://localhost:5173`
4. **Select or Create Case**: Choose `CASE-2026-001`.
5. **Dispatch Tasks via JOCKY Studio**: Run Endpoint Triage and PE Inspection tasks.
6. **Navigate to Investigation Workspace**:
   - Inspect automatically extracted IOCs (IPs, hashes, persistence entries).
   - Review the chronological timeline.
   - Inspect cross-agent correlations and findings.
   - Change finding status to `CONFIRMED`.
   - Add an analyst hypothesis note.
7. **Export Forensic Report**: Download court-admissible PDF report verifying SHA-256 evidence integrity.
8. **Verify Audit Trail**: Review audit logs recording all analyst and agent activities.
