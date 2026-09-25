# Quickstart Guide: SIH26148 JOCKY Defensive Digital-Forensics Framework

This guide provides step-by-step instructions to set up, test, benchmark, and operate the **JOCKY Defensive Digital-Forensics Framework**.

---

## 1. Prerequisites & System Requirements

- **Operating System**: Windows 10/11, Ubuntu 22.04+, or macOS 13+
- **Python**: Version 3.11 or 3.12
- **Node.js**: Version 18+ (Node 20 recommended) with `npm`
- **Memory**: Minimum 4 GB RAM (8 GB recommended)
- **Disk Space**: ~500 MB free space

---

## 2. Environment Setup

### 2.1 Backend Setup
Open a terminal in the project root:
```bash
# Verify Python installation
python --version

# Install Python backend dependencies
pip install -r backend/requirements.txt
```

### 2.2 Frontend Setup
```bash
# Navigate to frontend and install npm packages
cd frontend
npm install
cd ..
```

---

## 3. Running Development Servers

### 3.1 Launch Backend (FastAPI + Uvicorn)
From project root:
```bash
python scripts/run_dev.py backend
```
- **API URL**: [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

### 3.2 Launch Frontend (Vite + React)
In a separate terminal:
```bash
cd frontend
npm run dev
```
- **Web UI URL**: [http://localhost:5173](http://localhost:5173)

---

## 4. Multi-Agent Fleet Simulation

To simulate a heterogeneous enterprise fleet (Windows, Linux, Domain Controllers) collecting forensic artifacts:
```bash
# Run a single cycle of 6 simulated agents
python scripts/simulate_agents.py --agents 6 --once

# Or run continuous background agent polling (heartbeat every 4s)
python scripts/simulate_agents.py --agents 6 --interval 4
```

---

## 5. Security & Tamper Detection Simulation

To generate synthetic defensive security events (evidence tampering, audit chain violations, config drift):
```bash
python scripts/simulate_security_events.py --case CASE-2026-001
```

---

## 6. Verification, Auditing & Benchmarking

### 6.1 Run Unified Test Suite (114 Tests)
```bash
python -m pytest compiler/tests agent/tests backend/tests tests -v
```

### 6.2 Audit Database Integrity & Hash Chains
```bash
python scripts/audit_database.py
```

### 6.3 Validate Forensic Report Exports (JSON, HTML, CSV, PDF)
```bash
python scripts/validate_reports.py --case CASE-2026-001
```

### 6.4 Execute Empirical Benchmarking Suite
```bash
python scripts/benchmark_phase8.py --runs 30
```

### 6.5 Run Master Release Certification Orchestrator
To execute all 8 certification stages in an automated pipeline:
```bash
python scripts/run_phase8_validation.py
```
This produces `phase8_validation_report.json` with overall status `PASS` and release decision `CERTIFIED`.
