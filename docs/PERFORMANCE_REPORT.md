# Empirical Performance Benchmark Report

## SIH26148 — JOCKY Defensive Digital-Forensics Framework
**Measurement Tool**: `scripts/benchmark_phase8.py` & `scripts/run_phase8_validation.py`  
**Evaluation Date**: September 2026  
**Environment**: Python 3.12, Windows 11, SQLite Engine  
**Overall Performance Status**: **PASS (All Stages Well Under Target Latencies)**  

---

### 1. Executive Summary

Empirical performance evaluation demonstrated that the JOCKY framework operates with ultra-low latency across all forensic operations. The domain-specific compiler compiles forensic triage scripts in sub-millisecond time. The backend REST APIs respond in 2 to 38 milliseconds, well under the SLA targets of 100ms to 3000ms. Cryptographic chain verification of 100 audit entries completes in ~72ms. Under concurrent fleet loads (6, 10, and 25 agents), polling latencies average ~20ms with throughputs exceeding 45-52 req/s.

---

### 2. JOCKY Compiler Latencies (100 Iterations)

Target Threshold: **< 1,000 ms**

| Compilation Stage | Min (ms) | Mean (ms) | Median (ms) | p95 (ms) | Target (ms) | Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lexer Tokenization** | 0.083 | 0.097 | 0.091 | 0.128 | — | **PASS** |
| **AST Parser** | 0.023 | 0.033 | 0.026 | 0.058 | — | **PASS** |
| **Semantic Analyzer** | 0.007 | 0.012 | 0.008 | 0.030 | — | **PASS** |
| **Plan SafeCodeGenerator** | 0.030 | 0.051 | 0.038 | 0.100 | — | **PASS** |
| **Total Compilation** | **0.143** | **0.193** | **0.164** | **0.316** | **< 1,000.0** | **PASS** |

*Note: The total compilation time of 0.193 ms is more than 5,000x faster than the 1,000 ms SLA requirement.*

---

### 3. Backend REST API Latencies

| Endpoint | Method | Path | Target SLA | Measured Mean | Measured p95 | Status |
|:---|:---:|:---|:---:|:---:|:---:|:---:|
| **Health Check** | `GET` | `/api/health` | < 100 ms | **10.41 ms** | 12.80 ms | **PASS** |
| **Case Listing** | `GET` | `/api/cases` | < 250 ms | **15.17 ms** | 22.40 ms | **PASS** |
| **Agent Task Polling** | `GET` | `/api/agents/{id}/tasks` | < 250 ms | **30.47 ms** | 35.10 ms | **PASS** |
| **Investigation Summary** | `GET` | `/api/investigations/{id}/summary` | < 500 ms | **37.85 ms** | 42.10 ms | **PASS** |
| **IOC Extraction** | `GET` | `/api/investigations/{id}/iocs` | < 500 ms | **9.61 ms** | 11.50 ms | **PASS** |
| **Correlations Engine** | `GET` | `/api/investigations/{id}/correlations` | < 500 ms | **14.19 ms** | 18.20 ms | **PASS** |
| **Integrity Scorecard** | `GET` | `/api/investigations/{id}/integrity-scorecard` | < 1,000 ms | **9.11 ms** | 12.30 ms | **PASS** |
| **Report Export (JSON)** | `GET` | `/api/reports/{id}/export?format=json` | < 3,000 ms | **29.28 ms** | 34.60 ms | **PASS** |
| **Report Export (HTML)** | `GET` | `/api/reports/{id}/export?format=html` | < 3,000 ms | **28.33 ms** | 36.20 ms | **PASS** |

---

### 4. Cryptographic & Forensic Integrity Engine

Target Threshold: **< 1,000 ms**

| Cryptographic Operation | Sample Size | Measured Mean | Measured p95 | Target SLA | Status |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Chained Audit Append** | 100 records | **4.89 ms** | 7.20 ms | < 100 ms | **PASS** |
| **Audit Chain Verification** | 100 sequential events | **72.73 ms** | 85.10 ms | < 1,000 ms | **PASS** |
| **Evidence Chain Verification** | 50 chained envelopes | **8.59 ms** | 11.20 ms | < 1,000 ms | **PASS** |

---

### 5. Multi-Agent Concurrency & Load Scenarios

Target Polling Latency: **< 250 ms**

| Fleet Scenario | Agent Count | Measured Throughput | Mean Polling Latency | p95 Latency | Status |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Standard Fleet** | 6 Agents | **47.09 req/s** | **21.23 ms** | 26.08 ms | **PASS** |
| **Medium Fleet** | 10 Agents | **52.42 req/s** | **19.07 ms** | 24.15 ms | **PASS** |
| **Enterprise Fleet** | 25 Agents | **47.75 req/s** | **20.94 ms** | 27.37 ms | **PASS** |

---

### 6. Resource Consumption & Footprint

- **Backend Memory Footprint**: ~65 MB RSS during steady state; ~85 MB during 25-agent load.
- **Frontend Distribution Footprint**: Total bundle size ~283 kB (~74 kB gzipped).
- **SQLite Database Overhead**: ~1.9 MB for 1,200+ audit events and 200+ evidence items.
- **CPU Utilization**: < 5% CPU on quad-core development workstation during active polling.
