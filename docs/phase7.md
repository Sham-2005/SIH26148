# SIH26148 — JOCKY Framework: Phase 7 Documentation
# Security Hardening, Evidence Integrity, Tamper Detection & Operational Security

## 1. Executive Summary & Security Philosophy

Phase 7 hardens the **SIH26148 JOCKY Defensive Digital-Forensics Framework** against tampering, credential leakage, unauthorized action dispatch, and evidence corruption. Digital forensic integrity demands that artifacts collected from remote endpoints can withstand adversarial scrutiny, administrative tampering, and court cross-examination.

JOCKY implements a zero-trust, defense-in-depth architecture where every state mutation is bound by cryptographic proofs:
- **Canonical Serialization**: RFC-8785 JSON normalization eliminates formatting variance across operating systems.
- **Append-Only Hash Chains**: Audit logs and evidence records are linked sequentially with cryptographic SHA-256 seals.
- **Controlled Authorization**: Role boundaries (Admin, Analyst, Operator, Agent) enforce least privilege and dual-custody gates.
- **Deterministic Tamper Detection**: 12 discrete, explainable heuristic detectors continuously scan cases for integrity anomalies.
- **Court-Admissible Manifests**: Generated reports bind evidence hashes, audit states, and threat intelligence into tamper-evident packages.

---

## 2. Defensive Forensic Boundary & Anti-Offensive Stance

The JOCKY framework strictly operates within defensive forensic boundaries:
- **Zero Offensive Capabilities**: No rootkit loaders, credential dumpers, exploitation payloads, or arbitrary shell execution.
- **Safe Response Allowlist**: Incident response playbooks can only execute pre-approved defensive actions (`collect.system`, `collect.processes`, `collect.network`, `collect.persistence`, `collect.file_metadata`, `generate.report`, `isolate.endpoint.simulated`, `suspend.process.simulated`).
- **Deterministic Simulation**: All security event testing and containment actions are executed via deterministic, non-destructive simulations clearly tagged `[SIMULATED SECURITY EVENT]`.
- **Neutral Terminology**: Findings and detections use objective, evidentiary language (`EVIDENCE_HASH_MISMATCH`, `TIMESTAMP_ANOMALY`, `UNAUTHORIZED_CONFIGURATION_CHANGE`) without premature attribution or hyperbolic claims.

---

## 3. Comprehensive Threat Model (12 Threat Vectors & Mitigations)

| # | Threat Vector | Description | Forensic Mitigation | Enforcement Layer |
|---|---------------|-------------|---------------------|-------------------|
| 1 | **Evidence Tampering** | Adversary or rogue operator modifies stored forensic JSON envelope | RFC-8785 canonical hash recalculation detects signature mismatch | `IntegrityService.verify_single_evidence` |
| 2 | **Evidence Dropping / Deletion** | Adversary deletes evidence records to conceal persistence | Sequential cryptographic hash-chain detects broken link between predecessor and successor | `IntegrityService.verify_evidence_chain` |
| 3 | **Audit Ledger Corruption** | Privileged user alters past audit log entries | Append-only chained audit log binds previous event hash into current event hash | `IntegrityService.verify_audit_chain` |
| 4 | **Agent Identity Spoofing** | Rogue host registers claiming to be enrolled endpoint | Hardware and OS identity fingerprint binding verified on check-in | `TamperDetectionService.check_agent_fingerprint_integrity` |
| 5 | **Agent Capability Forgery** | Endpoint declares unauthorized collector capabilities | Enrolled capability fingerprint verified against signed registry | `IntegrityService.compute_capability_fingerprint` |
| 6 | **Task Instruction Modification** | Man-in-the-middle alters dispatched JOCKY script | `task_hash` binds script source and parameters at dispatch | `TamperDetectionService.check_task_integrity` |
| 7 | **Execution Plan Tampering** | Injected AST bytecode into compiler plan payload | `plan_hash` verified by agent before step execution | Agent dispatch verification |
| 8 | **Task Replay Attack** | Captured task or result replayed to poison investigation | Atomic task lease, one-time execution tokens, and replay cache | `TamperDetectionService.check_replay_attack` |
| 9 | **Playbook Action Modification** | Approved playbook modified before execution | `content_hash` and `approval_hash` verified before execution; raises `PLAYBOOK_INTEGRITY_VIOLATION` | `PlaybookService.execute_playbook` |
| 10 | **Configuration Drift** | System allowlist, token expiration, or collector registry altered | Runtime configuration fingerprint compared against sealed startup baseline | `ConfigIntegrityService.verify_configuration_integrity` |
| 11 | **Timestomping & Causality Drift** | Endpoint or analyst falsifies creation or completion timestamps | Temporal ordering verified (`created_at <= started_at <= completed_at`) | `TimeIntegrityService.verify_task_temporal_causality` |
| 12 | **Report Modification** | Court exhibit report text modified after generation | Canonical Report Manifest binds content hash, evidence manifest, and audit chain hash | `IntegrityService.verify_report_manifest` |

---

## 4. Security Architecture & Defense-in-Depth Layering

```
  ┌─────────────────────────────────────────────────────────────┐
  │                 FastAPI Defense-in-Depth API                │
  │  (Security Headers: CSP, X-Frame-Options, X-Content-Type)   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │               Security Policy & RBAC Engine                 │
  │    (Role Matrix, Immutable Resource Protection, Redaction)   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │            Cryptographic Integrity Service (RFC-8785)       │
  │   - Evidence Envelopes        - Append-Only Audit Chain     │
  │   - Agent Identity Fingerprint - Response Playbook Signatures│
  │   - Dispatched Task Hashes     - Canonical Report Manifests  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │              12-Detector Tamper Detection Engine            │
  │      (Deterministic Anomaly Identification & Event Logging) │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │               Measurable Case Scorecard (7/7)               │
  │     (Continuous Real-Time Verification Across All Objects)  │
  └─────────────────────────────────────────────────────────────┘
```

---

## 5. Cryptographic Specifications & RFC-8785 JSON Canonicalization

To achieve deterministic hashing across varied platforms (Windows, Linux, macOS) and programming environments:
1. **RFC-8785 Canonical JSON**:
   - Keys sorted lexicographically by UTF-8 code point.
   - Whitespace strictly compacted (`separators=(',', ':')`).
   - Unicode preserved without escape sequence variation (`ensure_ascii=False`).
   - Timestamps formatted canonically (`YYYY-MM-DDTHH:MM:SSZ`).
2. **Digest Algorithm**: SHA-256 (`256-bit hexadecimal string`, 64 characters).
3. **Genesis Hash**: 64 consecutive zeros (`"0" * 64`) serves as the immutable predecessor for the first entry in any chain.

---

## 6. Append-Only Audit Ledger & Cryptographic Chaining

Every administrative and investigative operation writes an append-only `AuditLog` row:
- **`event_id`**: Globally unique event identifier (`AUD-UUID`).
- **`previous_event_hash`**: SHA-256 digest of the immediately preceding audit event.
- **`event_hash`**: `SHA256(canonical_json(event_data + previous_event_hash))`.
- **Validation**:
  ```python
  is_chain_intact, findings = IntegrityService.verify_audit_chain(db, case_id)
  ```
  If any past log is deleted, altered, or inserted out of order, `recalculated_hash != event_hash` or predecessor links mismatch, immediately flagging `AUDIT_RECORD_TAMPERED`.

---

## 7. Evidence Envelope Hashing & Tamper Detection

Evidence submitted by endpoints is encapsulated in signed envelopes:
```json
{
  "evidence_id": "EV-2026-001",
  "case_id": "CASE-2026-001",
  "agent_id": "AGENT-WIN-01",
  "timestamp": "2026-09-19T07:30:00Z",
  "collector": "process_collector",
  "platform": "Windows",
  "parameters": {},
  "results": { ... }
}
```
- **Sealing**: The `content_hash` seals the raw `results`, while `sha256_hash` seals the complete envelope metadata.
- **Tamper Verification**: Modifying any field inside `results` or metadata causes `verify_single_evidence` to return `status: "TAMPERED"` and automatically records a `SecurityEvent`.

---

## 8. Sequential Evidence Hash-Chain Lifecycle

Evidence items within an investigation form a continuous hash chain:
- Item 0: `previous_hash = "0" * 64`
- Item 1: `previous_hash = sha256_hash(Item 0)`
- Item *N*: `previous_hash = sha256_hash(Item N-1)`
- **Chain Verification**: If an evidence record is pruned or injected, `verify_evidence_chain` identifies the missing link (`BROKEN_EVIDENCE_HASH_CHAIN`) and alerts the lead investigator.

---

## 9. Agent Enrollment, Fingerprinting & Capability Enclosure

During enrollment with `AGENT_REGISTRATION_TOKEN`, each agent computes:
1. **Identity Fingerprint**: `SHA256(agent_id, hostname, platform, os_version, architecture)`.
2. **Capability Fingerprint**: `SHA256(sorted(capabilities))`.

On every subsequent check-in, task poll, and evidence submission:
- The agent's declared profile is matched against the enrolled fingerprints.
- If an agent modifies its OS declaration or reports unauthorized collectors, `check_agent_fingerprint_integrity` rejects the transaction and generates an `AGENT_IDENTITY_MISMATCH` alert.

---

## 10. Task Execution Parameter Binding & Replay Prevention

1. **Cryptographic Task Binding**:
   - `task_hash = SHA256(case_id, script_source, plan_payload)`.
   - Before execution, both server and agent verify that instructions and arguments match `task_hash`.
2. **Replay Prevention**:
   - Each task lease receives a unique execution token.
   - Tasks in terminal states (`completed`, `failed`) reject duplicate result submissions with `REPLAY_ATTEMPT_DETECTED`.

---

## 11. Response Playbook Cryptographic Authorization Lifecycle

1. **Creation**: Analyst authors response steps (`APPROVED_DEFENSIVE_ACTIONS`). The system computes `content_hash`.
2. **Review & Approval**: Authorized analyst/lead reviews definition and signs approval (`approval_hash = SHA256(playbook_id, content_hash, approver_email)`).
3. **Pre-Execution Gate**:
   - When execution is initiated, `PlaybookService.execute_playbook` recalculates the content hash from active database actions.
   - If any step, parameter, or target was modified post-approval, execution halts immediately with `PLAYBOOK_INTEGRITY_VIOLATION`.

---

## 12. System Configuration Baseline & Drift Detection

- At server startup, `ConfigIntegrityService` snapshots all security-critical settings:
  - Token expiration windows
  - Approved defensive response actions allowlist
  - Platform collector capability registries
  - Cryptographic parameters and storage paths
- Computes canonical `baseline_fingerprint`.
- Periodic or on-demand checks compare runtime configuration against the baseline, flagging `UNAUTHORIZED_CONFIGURATION_CHANGE` if unauthorized modifications occur.

---

## 13. Temporal Causality & Anti-Timestomping Integrity

`TimeIntegrityService` enforces chronological causality across all investigative records:
- **Tasks**: `created_at <= assigned_at <= started_at <= completed_at`.
- **Playbooks**: `created_at <= approval.created_at <= execution.started_at <= execution.completed_at`.
- **Reports**: `max(evidence.collected_at) <= report.created_at`.
- **Clock Skew**: Flags any event timestamp in the future relative to server time (`FUTURE_TIMESTAMP`) or backward time jumps (`BACKWARD_TIME_DRIFT`).

---

## 14. Court-Admissible Canonical Report Manifests

Generated forensic reports include an embedded `ReportManifest`:
```json
{
  "report_id": "REP-2026-001",
  "case_id": "CASE-2026-001",
  "content_sha256": "8a4f...3e",
  "evidence_manifest_hash": "c2b1...90",
  "evidence_count": 14,
  "audit_chain_hash": "e5d4...11",
  "investigation_hash": "0a1b...22",
  "cti_hash": "9f8e...77",
  "generated_at": "2026-09-19T07:30:00Z",
  "status": "VERIFIED",
  "manifest_hash": "3d2c...44"
}
```
Verifying `manifest_hash` validates that not only the report text is untampered, but that every single supporting evidence item, audit trail, and threat intelligence match remains identically intact.

---

## 15. Role-Based Access Control (RBAC) & Immutable Barriers

| Role | Evidence | Tasks | Playbooks | Threat Intel | Security Events | Config |
|------|----------|-------|-----------|--------------|-----------------|--------|
| **ADMIN** | Read, Seal | Create, Dispatch | Create, Approve, Exec | Read, Ingest | Read, Resolve | Read, Verify |
| **ANALYST** | Read, Verify | Create, Dispatch | Create, Approve | Read, Ingest, Correlate | Read, Resolve | Read |
| **OPERATOR** | Read | Poll, Status | Execute (Approved Only) | Read | Read | Read |
| **AGENT** | Submit (Sealed) | Poll, Return Results | None | None | None | None |

**Immutable Barriers**:
- `modify_evidence`: STRICTLY DENIED for ALL roles.
- `modify_audit_log`: STRICTLY DENIED for ALL roles.

---

## 16. Recursive Secret Scrubbing & Data Protection

`SecurityPolicyService.redact_sensitive_data` recursively scrubs passwords, API keys, private keys, bearer tokens, and JWT credentials from:
- Audit log details
- Security event metadata
- Exported reports (PDF, HTML, CSV, JSON)
- WebSocket telemetry broadcasts

---

## 17. Safe JOCKY Integrity Primitives (`verify.*`)

The JOCKY language compiler includes safe forensic verification primitives:
- `verify.evidence(evidence_id)`: Verifies cryptographic envelope seal.
- `verify.audit(case_id)`: Verifies append-only chained audit integrity.
- `verify.agent(agent_id)`: Verifies endpoint identity and capability fingerprint.
- `verify.playbook(playbook_id)`: Verifies approved action hash binding.
- `verify.report(report_id)`: Verifies canonical report manifest.
- `security.events(case_id)`: Retrieves active case tamper alerts.

Any unauthorized, unrecognized, or simulated bypass attempt (e.g. `verify.bypass_kernel_audit()`) is rejected at compile-time with `SemanticError`.

---

## 18. Measurable 7/7 Security Scorecard Specification

The `/api/security/integrity/{case_id}` endpoint and CLI evaluate 7 quantifiable controls:
1. **Evidence Cryptographic Integrity**: Hash-chain and individual envelope seals.
2. **Append-Only Audit Hash-Chain**: Sequential linkage across administrative events.
3. **Endpoint Identity & Capabilities**: Enrolled hardware and OS profile matches.
4. **Dispatched Task Parameter Binding**: Execution plan and instruction hashes.
5. **Response Playbook Cryptographic Binding**: Post-approval action modifications.
6. **System Configuration Drift**: Runtime posture vs baseline fingerprint.
7. **Temporal Event Causality**: Chronological consistency across all timestamps.

Score: `7/7 Verified` (Green), `5-6/7 Warning` (Amber), `<5/7 Compromised` (Red).

---

## 19. Synthetic Security Event Simulation Framework

The CLI simulator `scripts/simulate_security_events.py` allows SOC analysts and test engineers to generate deterministic synthetic security events:
1. Evidence envelope modification simulation (`EVIDENCE_TAMPER_DETECTED`)
2. Audit-chain break simulation (`AUDIT_CHAIN_CORRUPTION`)
3. Agent identity spoofing simulation (`AGENT_IDENTITY_MISMATCH`)
4. Task replay attempt simulation (`REPLAY_ATTEMPT_DETECTED`)
5. Playbook post-approval drift simulation (`PLAYBOOK_INTEGRITY_VIOLATION`)
6. Configuration parameter drift simulation (`UNAUTHORIZED_CONFIGURATION_CHANGE`)
7. Temporal causality anomaly simulation (`TIMESTAMP_ANOMALY`)

All simulated events carry `[SIMULATED SECURITY EVENT]` in their description and provide recommended remediation actions.

---

## 20. Operator Verification & Incident Handling Playbook

### CLI Verification:
```bash
# Verify entire case integrity (7/7 controls)
python -m compiler.cli verify-integrity --case CASE-2026-001

# Verify system configuration baseline
python -m compiler.cli verify-integrity --configuration

# Run synthetic security event simulation
python scripts/simulate_security_events.py --case CASE-2026-001
```

### Web UI Workflow:
1. Navigate to the **Security & Integrity** tab in the sidebar.
2. Inspect the **Case Integrity Scorecard (7/7)** for verified controls.
3. Review the **7 Security Controls** grid with status indicators and details.
4. Filter and review entries in the **Security & Tamper Events Ledger**.
5. Click **Resolve Event** to record analyst review with an append-only audit trace.
6. Click **Simulate Tamper Event** to demonstrate real-time defensive tamper alerting.
