# SIH26148 — JOCKY Framework: Phase 4 Architecture & Hardening Guide

## 1. Phase 4 Overview

Phase 4 elevates the **JOCKY Defensive Digital-Forensics Framework** from a single-agent prototype into an enterprise-ready, cross-platform forensic orchestration and incident response platform.

Key achievements of Phase 4 include:
1. **Multi-Agent Fleet Architecture (5+ Endpoints)**: Concurrent simulation and orchestration of heterogeneous Windows and Linux endpoints.
2. **Capability Registry & Controlled Polymorphism**: Safe, cross-platform mapping of high-level JOCKY forensic operations to platform-native collectors with zero arbitrary code execution.
3. **Enterprise Security Hardening**:
   - **Agent Isolation Enforcement**: Rejection of cross-agent task spoofing (`403 AGENT_ISOLATION_VIOLATION`).
   - **Replay Protection**: Cryptographic and state validation preventing duplicate task submissions (`409 TASK_ALREADY_COMPLETED`).
   - **Atomic Task Leases**: Concurrency control preventing duplicate agent claims.
   - **Pre-Dispatch Compatibility Checking**: Endpoint capability validation prior to task dispatch.
   - **Immutable Audit Trail**: Queryable audit records tracking all analyst actions, agent heartbeats, task dispatches, and evidence submissions.
4. **Court-Admissible Multi-Format Reporting**: Exporting forensic cases into sealed PDF (via ReportLab), HTML, CSV, and canonical JSON.

---

## 2. Multi-Agent Fleet Architecture

The framework coordinates heterogeneous enterprise environments with distinct OS builds, kernel versions, and architecture profiles:

| Agent ID | Hostname | Platform | OS Version | Architecture | Status | Capabilities |
|---|---|---|---|---|---|---|
| `AGENT-WIN-01` | `DESKTOP-IR-PRIMARY` | Windows | Windows 11 Enterprise | x86_64 | Online | Full Windows suite (Processes, Network, Registry, Services, Persistence, PE Parser) |
| `AGENT-WIN-02` | `WIN-FORENSIC-02` | Windows | Windows 10 Pro | x86_64 | Online | Full Windows suite |
| `AGENT-WIN-03` | `WIN-OFFICE-09` | Windows | Windows 11 Pro | x86_64 | Online | Standard Windows endpoint suite |
| `AGENT-LINUX-01` | `SRV-LINUX-PROD` | Linux | Ubuntu 22.04 LTS (Kernel 5.15) | x86_64 | Online | Linux suite (Procfs, Netstat/ss, Systemd, Cron persistence, Hash collectors) |
| `AGENT-LINUX-02` | `SRV-LINUX-EDGE` | Linux | Debian 12 (Kernel 6.1) | aarch64 | Online | Linux ARM64 suite (Procfs, Network, Cron persistence) |
| `AGENT-WIN-SERVER-01` | `DC-CORP-01` | Windows | Windows Server 2022 | x86_64 | Online | Windows Server suite (Full forensics + Event logs) |

### Fleet Simulator (`scripts/simulate_agents.py`)
The fleet simulator launches background threads for 5+ concurrent agents, each generating realistic, platform-specific forensic telemetry.
- All simulated telemetry is stamped with `[DEMO / SIMULATED]`.
- Agents automatically query `POST /api/agents/poll` using their authentication token (`X-Agent-Token: JOCKY-AGENT-TOKEN-<id>`), claim pending tasks, generate cryptographically sealed evidence envelopes (RFC-8785 + SHA-256), and submit results via `POST /api/agents/{agent_id}/results`.

```bash
# Run 6 simulated enterprise agents
python scripts/simulate_agents.py --agents 6 --server http://127.0.0.1:8000
```

---

## 3. Capability Registry & Controlled Polymorphism

JOCKY scripts define declarative forensic intent (e.g., `process.list()`, `persistence.scan()`). The Agent Capability Registry (`agent/security/capabilities.py`) dynamically and safely resolves these high-level calls to platform-specific collectors.

```
                  ┌───────────────────────────────┐
                  │ JOCKY Script Operation        │
                  │ (e.g., persistence.scan())    │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │ Platform Capability Resolver        │
               │ (agent/security/capabilities.py)    │
               └──────────────┬───────────────┬──────┘
                              │               │
       [Platform: Windows]    │               │    [Platform: Linux]
                              ▼               ▼
        ┌───────────────────────────┐   ┌───────────────────────────┐
        │ Windows Registry RunKeys, │   │ Linux Systemd Units,      │
        │ Startup Folders, & Tasks  │   │ Cron Dirs (/etc/cron.*),  │
        │ (collector: persistence)  │   │ & Shell Profiles          │
        └───────────────────────────┘   └───────────────────────────┘
```

### Safety Guarantees
- **No Arbitrary Commands**: If an operation is requested that does not exist in the platform's registered capability profile (e.g., executing `registry.read` on a Linux agent), the agent halts execution with `UNSUPPORTED_CAPABILITY` before touching the system.
- **Pre-Dispatch Verification**: The analyst dashboard calls `POST /api/tasks/check-compatibility` to verify that the targeted agent supports all instructions in the compiled execution plan before creating the task.

---

## 4. Security Hardening & Concurrency Controls

### 4.1 Agent Isolation Enforcement
Endpoints cannot impersonate or tamper with tasks assigned to other endpoints:
- Tasks are bound to a specific `agent_id` at creation.
- When an agent calls `POST /api/agents/{agent_id}/results`, the server enforces:
  1. URL path `agent_id` must match `task.agent_id`.
  2. The evidence envelope `agent_id` must match `task.agent_id`.
  3. Mismatches immediately trigger an HTTP `403 Forbidden` with error code `AGENT_ISOLATION_VIOLATION` and log an audit alert.

### 4.2 Replay Protection
- Once a task transitions to `completed` or `failed`, the backend marks it immutable.
- Subsequent submissions for the same `task_id` are rejected with HTTP `409 Conflict` and error code `TASK_ALREADY_COMPLETED`.

### 4.3 Atomic Task Leases
- Polling via `POST /api/agents/poll` atomically transitions a `pending` task to `in_progress`, stamping `assigned_at = datetime.utcnow()` to prevent race conditions when multiple agent workers poll concurrently.

### 4.4 Comprehensive Audit Trail
Every critical operational event is persisted in the `audit_logs` table (`GET /api/audit`):
- User authentication and token creation
- JOCKY script compilation
- Pre-dispatch compatibility checks
- Task creation and assignment
- Agent polling and lease acquisition
- Evidence submission, sealing, and tamper verification
- Multi-format report export requests

---

## 5. Multi-Format Forensic Report Generation

The reporting service (`backend/app/services/report_export_service.py`) provides 4 court-ready export formats via `GET /api/reports/{case_id}/export?format={pdf|html|csv|json}`:

1. **PDF (`format=pdf`)**: Built using ReportLab. Includes formal case metadata, analyst chain of custody, evidence inventory table, SHA-256 integrity seal, and an official legal non-tamper declaration.
2. **HTML (`format=html`)**: Interactive, styled responsive report with expandable evidence JSON viewers and status badges.
3. **CSV (`format=csv`)**: Tabular export of all evidence items, collectors, execution times, and SHA-256 envelope hashes for spreadsheet ingestion.
4. **JSON (`format=json`)**: Canonical RFC-8785 representation containing full raw evidence envelopes and cryptographic proofs.

---

## 6. End-to-End SIH Demonstration Workflow

Follow these steps to demonstrate the complete Phase 4 capabilities:

### Step 1: Start the Backend Server
```bash
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Open OpenAPI documentation: `http://localhost:8000/docs`

### Step 2: Start the 5+ Agent Fleet Simulator
In a separate terminal:
```bash
python scripts/simulate_agents.py --agents 6 --server http://localhost:8000
```
Verify terminal output showing 6 agents registering and polling.

### Step 3: Launch the React SOC Analyst Dashboard
In a separate terminal:
```bash
cd frontend
npm run dev
```
Open the dashboard in your browser: `http://localhost:5173`

### Step 4: Verify Fleet Health
1. Navigate to **Fleet Health**.
2. Confirm 6 agents (`AGENT-WIN-01` through `AGENT-WIN-03`, `AGENT-LINUX-01` through `AGENT-LINUX-02`, and `AGENT-WIN-SERVER-01`) are displaying `online` with their respective platform capability badges.

### Step 5: Author and Check JOCKY Script
1. Navigate to **JOCKY Script Studio**.
2. Select target agent: `AGENT-WIN-01`.
3. Click **Check Compatibility** — observe compatibility confirmation.
4. Click **Compile & Dispatch Task** — the task is compiled, dispatched, claimed by `AGENT-WIN-01`, executed, cryptographically sealed, and stored in the database.

### Step 6: Review Tamper-Evident Evidence
1. Navigate to **Evidence Vault**.
2. Click **Verify Integrity** on the new evidence record.
3. Confirm green checkmark verifying SHA-256 seal integrity.

### Step 7: Export Court-Admissible Reports
1. Navigate to **Reports & Cases**.
2. Under Case Actions, click **Export PDF**, **Export HTML**, **Export CSV**, and **Export JSON**.
3. Inspect the downloaded files to review chain-of-custody seals.

### Step 8: Inspect Audit Trail
1. Navigate to **Audit Trail**.
2. Filter or search logs to verify immutable tracking of dispatches, submissions, and export events.

---

## 7. Verification & Automated Test Suite

Run the full cross-platform test suite:
```bash
pytest compiler/tests agent/tests backend/tests tests -v
```
Expected result: **33 passed in ~2.5s**.
