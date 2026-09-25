# CHANGELOG — SIH26148 JOCKY Framework

## [Level 3: Core + Evidence Hash Chain + Basic ML Threat Detection] - 2026-09-24

### Added
- **Machine Learning Threat Detection Engine (`backend/app/ml/`)**:
  - Supervised offline Random Forest classifier trained on 2,000 synthetic forensic telemetry samples.
  - Normalized 21-dimensional forensic feature vector extracting process anomalies, persistence mechanisms, network activity, IOC densities, CTI matches, and tamper events.
  - Continuous threat score ($[0.0, 1.0]$) alongside confidence metrics and 4-tier discrete classification (`NORMAL`, `SUSPICIOUS`, `MALICIOUS`, `CRITICAL`).
  - Explainability engine (`backend/app/ml/explainability.py`) generating itemized contributing factors with relative impact scores and human-readable forensic narratives.
  - Model registry (`backend/app/ml/model_registry.py`) providing cryptographic SHA-256 integrity verification of the `.joblib` model binary against signed metadata before loading.
  - Deterministic training script (`scripts/train_threat_model.py`) and synthetic dataset generator (`scripts/generate_ml_dataset.py`, seed 42).
- **Cryptographic Prediction Sealing & Tamper Verification**:
  - RFC-8785 canonical JSON serialization with SHA-256 prediction hashing (`prediction_hash`).
  - Prediction tamper detector comparing canonical hashes against database records.
  - Prediction verification REST endpoint (`POST /api/ml/verify-prediction/{prediction_id}`).
  - Integration with evidence hash chains and audit ledgers.
- **REST APIs (`backend/app/api/ml.py`)**:
  - `POST /api/ml/predict`: On-demand forensic feature inference.
  - `POST /api/ml/predict-case/{case_id}`: Full case-level evidence aggregation and prediction.
  - `GET /api/ml/model/status`: Model deployment status, algorithm details, and binary SHA-256 hash.
  - `GET /api/ml/model/metrics`: Model evaluation metrics (ROC-AUC, Precision, Recall, F1).
  - `POST /api/ml/verify-prediction/{prediction_id}`: Cryptographic seal verification.
- **JOCKY Domain-Specific Language (DSL) Primitives (`language/stdlib/stdlib_registry.py`)**:
  - Registered 6 safe forensic ML primitives: `ml.analyze`, `ml.prediction`, `ml.score`, `ml.explain`, `ml.verify`, `ml.model_status`.
- **Investigation Orchestrator & Multi-Format Reporting Integration**:
  - Integrated automated ML threat inference into `InvestigationOrchestrator` (`process_evidence` and `run_full_case_analysis`).
  - Enriched PDF, HTML, CSV, and canonical JSON report exports with ML Threat Detection findings, threat scores, confidence metrics, and prediction hashes.
- **React SOC Operations Dashboard (`frontend/src/App.jsx`)**:
  - Added dedicated **ML Threat Engine** navigation tab.
  - Threat score circular/arc gauge meter with color-coded classification chips.
  - Top contributing factors breakdown with impact bars and direction tags.
  - Model provenance and SHA-256 integrity badge.
  - Sealed prediction audit ledger with interactive cryptographic verification modal.
- **Automated Validation Suite (`tests/`)**:
  - Added 18 new automated unit and integration tests across 6 dedicated test modules:
    - `tests/test_ml_features.py` (2 tests): Feature vector shape, bounds, and deterministic normalization.
    - `tests/test_ml_model.py` (4 tests): Prediction outputs, heuristic fallback, confidence calibration, binary integrity.
    - `tests/test_ml_detector.py` (2 tests): Detection service lifecycle, DB persistence, finding synthesis.
    - `tests/test_ml_integrity.py` (3 tests): RFC-8785 canonical hashing, tamper detection, feature mutation alerts.
    - `tests/test_ml_api.py` (4 tests): REST endpoints `/predict`, `/status`, `/metrics`, `/verify-prediction`.
    - `tests/test_ml_integration.py` (3 tests): Orchestrator integration, JOCKY DSL primitives, multi-format report exports.
  - Total test suite expanded to **132/132 tests PASS** (100% pass rate, 0 regressions).
- **Deterministic Demonstration & Certification (`scripts/demo_ml_detection.py`)**:
  - Validates 3 standard forensic scenarios:
    - Scenario A: Baseline clean host (`NORMAL`, Score < 0.20).
    - Scenario B: Suspicious persistence & beaconing (`SUSPICIOUS`, Score 0.40 - 0.70).
    - Scenario C: Cobalt Strike / Ransomware attack (`CRITICAL`, Score > 0.85).
  - Demonstrates synthetic prediction tampering detection and cryptographic proof validation.
- **Documentation Suite (`docs/`)**:
  - `docs/ML_THREAT_DETECTION.md`: Architectural reference, feature vector schema, API reference, and JOCKY DSL syntax.
  - `docs/LEVEL3_VALIDATION_REPORT.md`: Level 3 validation and certification report.

---

## [Phase 8: Final Validation, Testing, Benchmarking, Documentation & Release Certification] - 2026-09-23

### Added
- **Master Validation Test Suite (`tests/test_phase8_validation.py`)**:
  - 17 comprehensive automated tests covering plan hash determinism, IOC normalization determinism, RFC-8785 evidence envelope sealing determinism, compiler certification, syntax/semantic negative testing, 7-control integrity scorecard, audit chain tamper detection, evidence tamper detection, standardized API error contract, HTTP security headers, agent isolation and single-lease replay protection, malformed STIX bundle rejection, sensitive secret redaction, temporal causality anomaly detection, multi-agent heterogeneous fleet simulation, database foreign key constraints, and configuration integrity drift.
- **End-to-End Investigation Lifecycle Suite (`tests/test_phase8_end_to_end.py`)**:
  - Full 26-step consecutive lifecycle test executing authentication, case creation, 6-agent fleet enrollment, script compilation, task dispatch, evidence ingestion, replay protection, IOC extraction, cross-agent correlation, finding scoring, STIX CTI ingestion, threat matching, response playbook creation, dual-custody approval, playbook execution, analyst annotation, audit verification, evidence chain verification, synthetic tampering detection, security scorecard generation, and multi-format report export (PDF, HTML, CSV, JSON).
- **Master Certification Orchestrator (`scripts/run_phase8_validation.py`)**:
  - 8-stage automated release verification pipeline evaluating pytest regression (114 tests), compiler determinism, API standards, cryptographic primitives, database audit, report manifests, empirical benchmarks, and frontend production build.
  - Generates machine-readable `phase8_validation_report.json` with overall status `PASS` and release decision `CERTIFIED`.
- **Empirical Benchmarking Suite (`scripts/benchmark_phase8.py`)**:
  - Micro-benchmarking for compiler (0.19ms vs 1000ms SLA), backend REST APIs (2-38ms vs 100-3000ms SLA), cryptographic audit chaining (4.8ms append, 72ms verify 100), and multi-agent concurrency loads (6, 10, 25 agents at 47-52 req/s).
- **Database Schema & Cryptographic Auditor (`scripts/audit_database.py`)**:
  - SQLite PRAGMA foreign key constraint validator, orphaned record detector, and global audit hash-chain verifier.
- **Forensic Report Validator (`scripts/validate_reports.py`)**:
  - Verifies PDF, HTML, CSV, and RFC-8785 canonical JSON report structures and SHA-256 embedded manifests.
- **Standardized API Error Contract & Security Headers (`backend/app/main.py`)**:
  - Implemented standardized error schema `{"detail": ..., "error": {"code", "message", "request_id", "timestamp"}}` with sensitive secret redaction and defense-in-depth HTTP security headers (`nosniff`, `DENY`, CSP, `X-Request-ID`).
- **Agent Capabilities Endpoint (`backend/app/api/agents.py`)**:
  - Added `GET /api/agents/{agent_id}/capabilities` resolving registered platform capabilities and capability profiles.
- **Comprehensive Release Documentation Suite (`docs/`)**:
  - `phase8.md`: Master validation and release manual.
  - `QUICKSTART.md`: Developer and forensic analyst onboarding guide.
  - `SIH_DEMO_GUIDE.md`: 8-part SIH live demonstration script.
  - `TEST_MATRIX.md`: 114-test verification matrix across all subsystems.
  - `SECURITY_VALIDATION.md`: Security architecture, threat model, and boundary validation report.
  - `PERFORMANCE_REPORT.md`: Empirical latency, throughput, and concurrency measurements.
  - `RELEASE_CHECKLIST.md`: 14-point pre-release readiness checklist.
  - `RELEASE_CERTIFICATION.md`: Official release certificate (CERTIFIED).

### Verified
- **Unified Test Regression**: 114/114 passing tests (100% pass rate, 0 failures, 0 regressions).
- **Frontend Production Build**: Clean Vite/React distribution bundle build (0 errors).

---

## [Phase 7: Security Hardening, Evidence Integrity, Tamper Detection & Operational Security] - 2026-09-19

### Added
- **Cryptographic Integrity Engine (`backend/app/services/security_integrity_service.py`)**:
  - RFC-8785 canonical JSON serialization with deterministic lexicographic key sorting and compact UTF-8 encoding.
  - Append-only cryptographic audit hash-chains binding each event to the SHA-256 seal of its predecessor block.
  - Continuous sequential evidence hash chaining with both direct predecessor and rolling hash verification.
  - Court-admissible Canonical Report Manifests binding report content hash, evidence hashes, and audit chain state.
  - Playbook content hashing and analyst approval cryptographic signature binding.
  - Measurable 7/7 Security Controls Scorecard generator with quantitative scoring.
- **Tamper Detection Engine (`backend/app/services/tamper_detection_service.py`)**:
  - 12 deterministic, explainable anomaly detectors:
    1. Evidence hash mismatch
    2. Audit entry modification / broken link
    3. Missing evidence sequence
    4. Unexpected agent identity declarations
    5. Duplicate task submissions
    6. Replay attempts on terminal task leases
    7. Invalid compiler execution plan hashes
    8. Unauthorized playbook modification after approval
    9. Unauthorized configuration changes against baseline
    10. Report integrity manifest mismatches
    11. Invalid approval state transitions
    12. Timestamp anomalies & causality violations
  - Full-case audit and tamper scan engine creating persistent, auditable `SecurityEvent` entries.
- **Configuration & Time Integrity Services**:
  - `ConfigIntegrityService`: Canonical system configuration snapshotting, baseline SHA-256 fingerprinting, drift detection, and simulation hooks.
  - `TimeIntegrityService`: Temporal causality verification across tasks, playbooks, and reports; flags `FUTURE_TIMESTAMP` and `BACKWARD_TIME_DRIFT`.
- **Security Policy & Sensitive Data Protection (`backend/app/services/security_policy_service.py`)**:
  - Role-based authorization matrix for `ADMIN`, `ANALYST`, `OPERATOR`, and `AGENT`.
  - Immutable resource barriers (`modify_evidence` and `modify_audit_log` strictly denied for all roles).
  - Dual-custody containment action gating (`REQUIRES_APPROVAL`).
  - Recursive scrubbing (`redact_sensitive_data`) of passwords, API keys, private keys, bearer tokens, and JWT credentials.
- **Compiler CLI & Language Stdlib Extensions**:
  - Registered safe forensic verification primitives in JOCKY stdlib: `verify.evidence`, `verify.audit`, `verify.agent`, `verify.playbook`, `verify.report`, `security.events`.
  - Implemented `verify-integrity` CLI subparser supporting `--case`, `--evidence`, `--audit`, `--report`, and `--configuration`.
- **Synthetic Security Event Simulator (`scripts/simulate_security_events.py`)**:
  - Generates 7 deterministic synthetic security events strictly tagged with `[SIMULATED SECURITY EVENT]`.
- **React Frontend Security & Integrity Center (`frontend/src/App.jsx`)**:
  - Real-time Case Integrity Scorecard displaying 7/7 measurable controls.
  - 7 Security Controls status grid with interactive Deep Verification trigger.
  - Filterable Security & Tamper Events Ledger with modal resolution workflow and append-only audit tracking.
  - Defensive Security Posture panel displaying canonical configuration fingerprint and defense-in-depth statuses.
- **Automated Test Suite Expansion (`tests/test_phase7_security_hardening.py`)**:
  - Added 28 new automated unit and integration tests covering all 7 controls, tamper detection, RBAC boundaries, redaction, and CLI workflows.
  - Full regression test suite passing at **96/96 tests** (0 failures, 0 regressions).

---

## [Phase 6: Threat Intelligence, Incident Response & Advanced SOC Visualization] - 2026-09-18

### Added
- **STIX 2.1 Parsing & Extraction Engine (`backend/app/services/stix_service.py`)**:
  - Full STIX 2.1 SDO and SRO parser validating and extracting `indicator`, `malware`, `threat-actor`, `attack-pattern`, `relationship`, and `bundle` objects.
  - STIX pattern compiler and IOC extractor supporting file hashes (MD5, SHA-1, SHA-256), IPv4/IPv6 addresses, domain names, URLs, Windows Registry keys, and process names.
  - MITRE ATT&CK technique extraction from `external_references` (e.g. `T1059.001`, `T1055`).
  - Strict validation of required STIX 2.1 properties with graceful skipping of malformed bundle entries.
- **TAXII 2.1 Provider Abstraction (`backend/app/services/threat_intelligence_service.py`)**:
  - Extensible `ThreatIntelProvider` interface supporting asynchronous fetching and ingestion.
  - `LocalSTIXProvider` for local filesystem STIX 2.1 JSON file ingestion.
  - `TAXIIProvider` for TAXII 2.1 API collections with authentication and discovery.
  - `DemoThreatIntelProvider` generating realistic synthetic threat intelligence feeds explicitly tagged with `[DEMO THREAT INTELLIGENCE]`.
  - Ingestion deduplication by `stix_id` avoiding duplicate indicators in database.
- **Evidence-to-CTI Cross-Correlation Engine (`backend/app/services/threat_intelligence_service.py`)**:
  - Automatically matches collected case evidence against ingested STIX intelligence.
  - Generates bidirectional correlation results matching file hashes, IP addresses, domains, URLs, and registry keys with confidence scoring and MITRE ATT&CK technique mapping.
- **Defensive Incident Response Playbook Engine (`backend/app/services/playbook_service.py`)**:
  - Defensive security playbook definitions targeting specific case and agent scopes.
  - Strict action allowlist enforcement (`collect.*`, `generate.report`, `isolate.endpoint.simulated`, `suspend.process.simulated`). Unapproved actions fail immediately with `UNSUPPORTED_RESPONSE_ACTION`.
  - Non-destructive execution guarantee: simulation tags and defensive constraints ensure zero production damage.
- **Dual-Control Analyst Approval Workflow (`backend/app/services/playbook_service.py`, `backend/app/models/models.py`)**:
  - Lifecycle state machine: `DRAFT` / `PENDING_APPROVAL` → `APPROVED` / `REJECTED` → `EXECUTING` → `COMPLETED`.
  - Required analyst approval step before execution; unapproved execution triggers HTTP 400 rejection.
  - Detailed audit logging of approvals, rejections, and action execution sequences with timestamps and step-level outputs.
- **Advanced SOC Visualizations (`backend/app/api/investigations.py`, `frontend/src/App.jsx`)**:
  - **Temporal Activity Heatmap**: `GET /api/investigations/{case_id}/heatmap` aggregating chronological forensic events into 24-hour / 7-day time buckets with activity intensity scoring.
  - **MITRE ATT&CK Matrix Mapping**: `GET /api/investigations/{case_id}/attack-patterns` mapping forensic findings, timeline events, and CTI indicators to standard MITRE Enterprise ATT&CK tactics and techniques.
  - Interactive Heatmap visualization with hour/weekday heat grid and ATT&CK Matrix board with mapped technique counts.
- **Multi-Format Reporting Enhancements (`backend/app/services/report_export_service.py`, `backend/app/api/reports.py`)**:
  - Multi-format exports (PDF via ReportLab, HTML, CSV, canonical JSON) augmented with Threat Intelligence matches, MITRE ATT&CK technique breakdown, and Incident Response Playbook execution audit ledgers.
- **Automated Test Suite Expansion (`tests/test_phase6_threat_intel_response.py`)**:
  - 19 new automated tests covering STIX parsing, pattern extraction, TAXII providers, deduplication, CTI correlation, playbook allowlist enforcement, approval workflow, and visualizations.
  - Full suite passing at **68/68 tests** (0 regressions).

---

## [Phase 5: Intelligent Forensic Investigation & Threat Correlation] - 2026-09-18

### Added
- **Extended Investigation Data Architecture (`backend/app/models/models.py`)**:
  - Added `InvestigationIndicator`, `TimelineEvent`, `EvidenceCorrelation`, `Finding`, and `AnalystNote` SQLAlchemy models.
  - Linked to `Case` model with cascading relationships.
- **IOC Extraction & Normalization Engine (`backend/app/services/ioc_service.py`)**:
  - Automatically extracts IPv4, IPv6, Domain, URL, File Path, SHA-256, MD5, Process Name, Service Name, and Registry paths from evidence payloads.
  - Normalizes and deduplicates indicators with neutral terminology (`observed`, `suspicious`, `matched`, `correlated`).
- **Unified Timeline Engine (`backend/app/services/timeline_service.py`)**:
  - Assembles unified chronological timelines across all agents and collectors.
  - Supports filtering by agent, event type (`PROCESS`, `FILE`, `NETWORK`, `PERSISTENCE`, `SERVICE`, `REGISTRY`, `SYSTEM`, `ANALYSIS`), severity, and time range.
- **Evidence Correlation Engine (`backend/app/services/correlation_service.py`)**:
  - Cross-agent hash correlation detecting binary presence on multiple endpoints.
  - Process-to-network socket correlation and persistence-to-executable linking.
- **Explainable Risk & Priority Engine (`backend/app/services/risk_service.py`)**:
  - Deterministic priority scoring (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with itemized justification reasons.
- **Finding Synthesis & Lifecycle Engine (`backend/app/services/finding_service.py`)**:
  - Formats correlations into reviewable findings with lifecycle states (`OPEN`, `UNDER_REVIEW`, `CONFIRMED`, `DISMISSED`).
  - Strict evidence traceability linking every finding to underlying Evidence IDs.
- **Investigation REST APIs (`backend/app/api/investigations.py`)**:
  - Endpoints for summary, timeline, indicators, correlations, findings, graph topology, search, analyst notes, and on-demand analysis.
- **Enhanced Multi-Format Reporting**:
  - Extended PDF (ReportLab), HTML, CSV, and JSON exports to include Findings, Indicators, Timeline, and Risk Explanations.
- **React SOC Investigation Workspace (`frontend/src/App.jsx`)**:
  - Added Investigation Workspace tab with Case Summary cards, interactive timeline, findings ledger with status toggles, node-edge correlation graph, and analyst notes.

---

## [Phase 4: Enterprise Multi-Agent Orchestration, Security Hardening & Court-Admissible Reporting] - 2026-09-18

### Added
- **Agent Capability Registry & Controlled Polymorphism (`agent/security/capabilities.py`)**:
  - Profiled endpoint capabilities across Windows (`windows_full`, `windows_standard`) and Linux (`linux_standard`, `linux_arm64`).
  - Implemented safe cross-platform resolver mapping operations (`persistence.scan`, `process.list`, etc.) to platform-native collectors.
  - Safe failure mode returning `UNSUPPORTED_CAPABILITY` on mismatched operations without arbitrary execution.
- **Enterprise Fleet Simulator Expansion (`scripts/simulate_agents.py`)**:
  - Expanded fleet from 3 to 6 heterogeneous agents (`AGENT-WIN-01`, `AGENT-WIN-02`, `AGENT-WIN-03`, `AGENT-LINUX-01`, `AGENT-LINUX-02`, `AGENT-WIN-SERVER-01`).
  - Added `--agents N` CLI argument.
  - Explicitly tagged all synthetic telemetry with `[DEMO / SIMULATED]`.
- **Security & Concurrency Hardening**:
  - **Agent Isolation Enforcement**: Verified that submitting agent matches task-assigned agent; spoofing attempts trigger HTTP `403 AGENT_ISOLATION_VIOLATION`.
  - **Replay Protection**: Enforced terminal task state immutability; duplicate submissions trigger HTTP `409 TASK_ALREADY_COMPLETED`.
  - **Atomic Task Leases**: Implemented atomic transition from `pending` to `in_progress` during task polling with `assigned_at` timestamps.
  - **Pre-Dispatch Compatibility Check**: Added `POST /api/tasks/check-compatibility` verifying agent capability support before task dispatch.
  - **Immutable Audit Logging (`backend/app/api/audit.py`, `backend/app/models/models.py`)**: Added queryable `GET /api/audit` endpoint recording all analyst actions, agent heartbeats, task lifecycles, and cryptographic evidence seals.
- **Court-Admissible Multi-Format Forensic Exporter (`backend/app/services/report_export_service.py`, `backend/app/api/reports.py`)**:
  - PDF export via ReportLab with case summary, analyst sign-off, evidence inventory table, SHA-256 seal verification, and legal non-tamper declaration.
  - HTML export with modern styling and responsive collapsible JSON inspection.
  - CSV export for spreadsheet analysis and SIEM ingestion.
  - JSON export for RFC-8785 canonical data interchange.
- **SOC Operations Dashboard Enhancements (`frontend/src/App.jsx`)**:
  - Live fleet monitoring for 5+ heterogeneous agents with capability chips and OS indicators.
  - Pre-dispatch capability verification in JOCKY Script Studio.
  - Audit Trail exploration interface with search and category filtering.
  - Multi-format report export buttons (PDF, HTML, CSV, JSON) in Case Management.
- **Automated Test Suite Expansion (`tests/test_phase4_security_and_hardening.py`)**:
  - Added 9 Phase 4 tests covering capability registry, agent isolation, replay protection, multi-format report generation (PDF, HTML, CSV, JSON), and audit logging.
  - Test suite passing at **33/33 tests** in 2.59s.
  - Frontend production build verified with Vite (0 errors, 1.35s build time).

---

## [Phase 2 & Phase 3: Deep Forensic Collectors and Multi-Agent Execution Pipeline] - 2026-09-18

### Added
- **Deep Forensic Collectors (`agent/collectors/`)**:
  - `pe_collector.py`: Pure-Python read-only Windows PE (PE32/PE32+) binary parser. Unpacks DOS `MZ` header, PE signature, COFF header, Optional header, sections, and directories. Gracefully returns structured errors for non-PE or corrupted binaries without crashing or executing the binary.
  - `persistence_collector.py`: Cross-platform defensive persistence inspector. Collects Windows Registry `Run`/`RunOnce` keys, Startup folders, Windows Services, Scheduled Tasks, and Linux `/etc/cron*`, systemd daemon units. Standardized finding format with risk metadata.
  - Updated `agent/executor/dispatcher.py` to register `malware.pe_info`, `persistence.startup`, `persistence.services`, `persistence.scheduled_tasks`.
- **Multi-Agent Runtime Engine (`agent/core/agent.py`)**:
  - Added continuous periodic polling loop (`poll_tasks()`, `run_polling_loop()`).
  - Added plan integrity verification: validates `plan_hash` against plan payload before executing allowlisted collectors.
  - Added task failure reporting and dedicated results submission.
- **Backend Architecture & APIs (`backend/`)**:
  - `event_broadcaster.py`: WebSocket manager broadcasting live events (`AGENT_CONNECTED`, `HEARTBEAT_RECEIVED`, `TASK_ASSIGNED`, `TASK_COMPLETED`, `EVIDENCE_RECEIVED`, `EVIDENCE_VERIFIED`) with thread-safe ring buffer for REST polling fallback.
  - Case Management API (`/api/cases`): Full CRUD supporting severity levels (`low`, `medium`, `high`, `critical`) and investigation statuses (`OPEN`, `INVESTIGATING`, `CONTAINED`, `CLOSED`).
  - Multi-Agent Orchestration (`/api/agents/{agent_id}/tasks`): Atomic task retrieval ensuring tasks are not double-polled or duplicated across agents.
  - Reports Generation (`/api/reports/{case_id}`): Structured forensic report compiling involved agents, executed tasks, evidence ledger, timeline, findings, and legal disclaimers.
  - Mounted `/api/ws` WebSocket and `/api/events` REST fallback in `main.py`.
- **React SOC Operations Dashboard (`frontend/src/App.jsx`)**:
  - Live activity feed connected via WebSocket with automatic REST polling fallback.
  - Fleet Monitor with live status badges (`online`, `offline`), platform distribution, and heartbeats.
  - Task Monitor displaying real-time lifecycle states (`pending` → `assigned` → `running` → `completed` / `failed`).
  - JOCKY Script Studio: integrated editor, script templates (triage, PE malware inspection, network forensics), target agent selector, compile preview, and 1-click Dispatch.
  - Evidence Vault: detailed evidence viewer with instant "VERIFY INTEGRITY" check displaying cryptographic proof.
  - Case Management View with New Case creation modal and case selector.
- **Fleet Simulator (`scripts/simulate_agents.py`)**:
  - Multi-agent simulator enrolling 3 endpoints (`AGENT-WIN-01`, `AGENT-WIN-02`, `AGENT-LINUX-01`), dispatching tasks, and sending heartbeats.
- **Automated Test Suite Expansion**:
  - 24/24 automated tests passing (Compiler, Agent, PE Parser, Persistence, Backend, Multi-Agent Pipeline, Fleet Simulator).

---

## [Phase 1: Initial Architecture, Compiler Foundation & Skeletons] - 2026-09-18

### Added
- Core repository initialization, EBNF and Lark grammar, lexer, recursive-descent parser, AST nodes, semantic analyzer, IR, safe codegen, agent skeleton, FastAPI backend, and React dashboard.
