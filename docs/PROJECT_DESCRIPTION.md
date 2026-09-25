# SIH26148 — JOCKY Framework: Project Description

> **A Defensive Digital-Forensics Platform, Domain-Specific Language (DSL) & Automated Incident Response System**

---

## 1. Executive Summary

The **JOCKY Framework** (Project ID: **SIH26148**) is a full-stack, enterprise-grade defensive digital-forensics and automated incident response platform. It was engineered to solve a critical dilemma in cyber incident response: **traditional forensic collection tools and ad-hoc scripts often trigger endpoint security defenses (Antivirus / EDR / SIEM false alarms), risk evidence corruption, and produce fragmented, legally unsealed data.**

JOCKY addresses this by introducing:
1. **JOCKY DSL & Compiler**: A purpose-built, strictly validated, declarative domain-specific language designed specifically for forensic triage.
2. **Safety-by-Design Execution**: An allowlisted execution pipeline that strictly forbids arbitrary shell execution or unsafe system calls.
3. **Cryptographically Sealed Evidence**: Full RFC-8785 canonical JSON serialization paired with sequential SHA-256 hash chains for tamper-evident, court-admissible custody.
4. **Automated Threat Intelligence & Correlation**: STIX 2.1 / TAXII 2.1 feed ingestion, MITRE ATT&CK enterprise matrix mapping, and multi-agent artifact correlation.
5. **Human-in-the-Loop Response Playbooks**: Dual-custody approval workflows preventing unauthorized or destructive automated actions.
6. **Level 3 Explainable ML Threat Engine**: Scikit-Learn Random Forest classification over a 21-dimensional normalized forensic vector with cryptographic prediction sealing and model integrity checks.
7. **Unified SOC Analyst Dashboard**: Modern React + Vite web console providing fleet telemetry, interactive investigations, tamper detection, and multi-format court-admissible reporting (PDF, HTML, CSV, JSON).

---

## 2. Problem Statement & Context

- **Problem ID**: SIH26148
- **Core Challenge**: Authoring and executing forensic scripts and functions in a specialized language that allows authorized forensic investigators to extract volatile memory, process trees, network sockets, persistence mechanisms, and filesystem artifacts without triggering antivirus/security solution false positives or compromising host stability.
- **Defensive Imperative**: The platform must guarantee absolute non-destructiveness, strict privilege containment, robust chain of custody, and auditable integrity across heterogeneous environments (Windows and Linux).

---

## 3. High-Level Architecture & End-to-End Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                   1. JOCKY SCRIPT AUTHORING (.jocky)                  │
│       e.g., collect volatile processes, persistence, network sockets   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   2. COMPILER & VALIDATION PIPELINE                    │
│   Lexer ──▶ Parser (Lark) ──▶ Typed AST ──▶ Semantic Validation        │
│   (Strict Allowlist Verification) ──▶ IR ──▶ Safe Execution Plan JSON │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Signed Task Dispatch
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               3. HETEROGENEOUS ENDPOINT AGENT FLEET                    │
│   - Windows & Linux Endpoint Daemons                                   │
│   - Capability Registry (OS Abstraction: Registry vs. Systemd/Cron)    │
│   - Read-Only Non-Destructive Forensic Collectors                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             4. RFC-8785 CRYPTOGRAPHIC EVIDENCE ENVELOPE                │
│   - Canonical JSON Serialization                                       │
│   - SHA-256 Digest Sealing & Sequential Evidence Hash Chaining         │
│   - Append-Only Cryptographic Audit Ledger                             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Secure Ingestion
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               5. FASTAPI CENTRAL MANAGEMENT BACKEND                    │
│   ├── Automated Cross-Agent Correlation Engine                         │
│   ├── STIX 2.1 / TAXII 2.1 CTI Ingestion & MITRE ATT&CK Mapping        │
│   ├── 7-Control Security & 12 Tamper Detector Engine                   │
│   ├── Level 3 ML Threat Detection Engine (21 Features, Random Forest)  │
│   └── Defensive Playbooks with Two-Person Approval Gates               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ REST APIs & WebSocket Telemetry
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               6. ANALYST WORKSPACE & REPORTING ENGINE                  │
│   - Modern React 18/19 + Vite SOC Dashboard                            │
│   - Multi-Format Reports: PDF, Structured HTML, CSV, Canonical JSON    │
│   - Certified Integrity Manifests for Judicial Admissibility           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Subsystems & Core Capabilities

### 4.1 JOCKY Domain-Specific Language (DSL) & Compiler
- **Declarative Forensic Grammar**: Designed using Lark (EBNF notation) to express investigative tasks naturally (`inspect process.list`, `scan persistence.autorun`, `verify hash`).
- **Strict Semantic Analyzer**: Verifies function existence, parameter arity, data types, and scope.
- **Safety by Design**: All arbitrary system commands, shell spawns (`cmd.exe`, `/bin/sh`), and unsafe binary executions are rejected at compile time.
- **Intermediate Representation (IR)**: Decouples high-level scripts from endpoint-specific implementation details.

### 4.2 Endpoint Agent Fleet Management
- **Heterogeneous OS Support**: Runs natively on both Windows and Linux endpoints.
- **Dynamic Capability Registry**: Automatically discovers and registers supported OS collectors (e.g., Windows Registry RunKeys vs. Linux systemd units).
- **Concurrency & Security Hardening**: Atomic task leases, agent isolation enforcement, replay protection, and enrolled agent verification.

### 4.3 Evidence Sealing & Chain of Custody (Anti-Tampering)
- **RFC-8785 Canonical JSON**: Eliminates byte-level ambiguities (whitespace, key ordering) to ensure deterministic hash generation.
- **Sequential Hash Chains**: Every piece of collected evidence references the SHA-256 digest of the previous record, creating a cryptographic chain of custody.
- **12 Deterministic Tamper Detectors**: Instantly identifies payload alterations, broken audit chains, modified timestamps, and out-of-order records.
- **7-Control Security Scorecard**: Provides a measurable, objective integrity rating for every investigation case.

### 4.4 Automated Threat Correlation & MITRE ATT&CK Mapping
- **IOC Extraction Engine**: Automatically normalizes IPv4/IPv6 addresses, domain names, file paths, and cryptographic hashes from raw forensic artifacts.
- **Cross-Agent Correlation**: Uncovers coordinated enterprise intrusions by correlating identical binary hashes across multiple endpoints and linking rogue PIDs to outbound network sockets.
- **Cyber Threat Intelligence (CTI)**: Ingests STIX 2.1 bundles and TAXII 2.1 feeds to match indicators against known threat actor profiles and tag behaviors with MITRE ATT&CK technique IDs (e.g., `T1059`, `T1053`, `T1071`).

### 4.5 Level 3 Explainable Machine Learning Threat Engine
- **Supervised Random Forest Classifier**: Evaluates evidence across a 21-dimensional normalized forensic feature vector (process anomalies, network beacons, persistence density, hash entropy, etc.).
- **Dual Output**: Delivers both continuous risk scoring ($[0.0, 1.0]$) and 4-tier discrete classifications (`NORMAL`, `SUSPICIOUS`, `MALICIOUS`, `CRITICAL`).
- **Transparent Explainability**: Produces factor-level forensic narratives highlighting the top contributing indicators without "black-box" opacity.
- **Model & Prediction Integrity**: Predictions are canonically sealed with SHA-256 hashes, and the offline-trained model binary (`.joblib`) is verified against signed SHA-256 metadata before any inference.

### 4.6 Controlled Incident Response Playbooks
- **Allowlisted Defensive Actions**: Restricts remediation to safe actions (`isolate_network`, `kill_process`, `quarantine_file`).
- **Dual-Custody Approval Gates**: Prevents unilateral or automated disruption. Playbooks require cryptographic sign-off by an authorized security lead before dispatch.

### 4.7 Multi-Format Court-Admissible Reporting
- **Multi-Format Export**: Generates comprehensive forensic case dossiers in **PDF**, **HTML**, **CSV Evidence Ledger**, and **RFC-8785 Canonical JSON**.
- **Cryptographic Manifest Verification**: Every export bundles a cryptographically verifiable manifest ensuring legal admissibility in corporate and judicial inquiries.

---

## 5. Technology Stack Summary

| Layer | Technologies Used |
|---|---|
| **Core Languages** | Python 3.11+, JavaScript (ES2022+), JOCKY DSL |
| **Compiler & Grammar** | Lark Parsing Framework (EBNF/LALR), Custom Python AST / IR Engine |
| **Backend & APIs** | FastAPI, Pydantic v2, SQLAlchemy ORM, Uvicorn, SQLite / PostgreSQL |
| **Authentication & RBAC** | JWT (PyJWT), Passlib (bcrypt hashing), Role-Based Access Control |
| **Machine Learning** | Scikit-learn (Random Forest), NumPy, Pandas, Joblib |
| **Frontend UI / SOC** | React 18/19, Vite, Lucide Icons, Modern Dark/Glassmorphic SOC Theme |
| **Threat Intelligence** | STIX 2.1 Object Model, TAXII 2.1 Client, MITRE ATT&CK Matrix |
| **Security & Standards** | RFC-8785 (Canonical JSON), SHA-256 Hash Chaining, Cryptographic Audit Ledger |
| **Testing & Benchmarking** | PyTest (132 test suite), Custom Concurrency & Micro-Benchmark Suites |

---

## 6. Empirical Validation & Certification Metrics

The JOCKY Framework has completed rigorous end-to-end verification across 8 distinct development phases, earning official **Phase 8 Release Certification** and **Level 3 ML Certification**:

- **Automated Test Coverage**: **132 / 132 tests passing (100% pass rate)**.
- **Compiler Performance**: **< 1.0 ms** average compilation latency per `.jocky` script.
- **Backend API Latency**: **< 38 ms** average response time across critical investigation endpoints.
- **Concurrency Resilience**: Stress-tested under **25+ simulated concurrent endpoint agents** with zero deadlocks or dropped evidence envelopes.
- **Integrity Scorecard**: **7 / 7 measurable security controls verified**, with instant tamper detection upon adversarial bit-flip injection.

---

## 7. Target Audience & Operational Use Cases

1. **Enterprise SOC Analysts**: Rapidly triage endpoint alerts, map threats to MITRE ATT&CK, and correlate indicators across enterprise hosts without tripping EDR alarms.
2. **Digital Forensic & Incident Response (DFIR) Teams**: Collect volatile artifacts, maintain verifiable chains of custody, and generate court-admissible forensic packages.
3. **Security Leadership & Incident Managers**: Authorize controlled response playbooks under strict dual-custody governance and review transparent, explainable ML risk reports.
