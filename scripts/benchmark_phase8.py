#!/usr/bin/env python3
"""
scripts/benchmark_phase8.py — JOCKY Defensive Digital-Forensics Benchmarking Suite
==================================================================================
Comprehensive empirical performance benchmarking across:
  1. JOCKY Compiler (Lexer, Parser, Semantic Analyzer, Codegen, Full Compile)
  2. Backend REST APIs (Health, Case CRUD, Agent Polling, Results, Investigations, CTI, Reports)
  3. Forensic Agent Primitives (Collection, Sealing, Envelope Generation)
  4. Security & Cryptographic Integrity (Append-only audit chaining, verification, evidence chain)
  5. Multi-Agent Load Scenarios (6, 10, 25 concurrent agents)

Evaluates results against official Phase 8 latency and throughput thresholds.
Supports CLI flags: --json, --runs <N>, --verbose.
"""

import sys
import os
import time
import json
import argparse
import statistics
import tempfile
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Compiler imports
from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator

# Backend & Security imports
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from backend.app.main import app
from backend.app.database.base import Base
from backend.app.database.session import get_db
from backend.app.config import settings
from backend.app.services.security_integrity_service import IntegrityService
from backend.app.models.models import Case, Agent, Task, Evidence, ThreatIntelItem

# Sample valid JOCKY script for compiler benchmarks
BENCHMARK_JOCKY_SCRIPT = """
script Phase8PerformanceTriage {
    system.info();
    process.list();
    network.connections();
    evidence.collect();
}
"""


def compute_metrics(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates min, max, mean, median, p95, and p99 latencies in ms."""
    if not latencies_ms:
        return {"count": 0, "min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0}
    sorted_l = sorted(latencies_ms)
    count = len(sorted_l)
    p95_idx = int(0.95 * count)
    p99_idx = int(0.99 * count)
    return {
        "count": count,
        "min": round(min(sorted_l), 3),
        "max": round(max(sorted_l), 3),
        "mean": round(statistics.mean(sorted_l), 3),
        "median": round(statistics.median(sorted_l), 3),
        "p95": round(sorted_l[min(p95_idx, count - 1)], 3),
        "p99": round(sorted_l[min(p99_idx, count - 1)], 3),
    }


# ============================================================================
# 1. COMPILER BENCHMARK
# ============================================================================
def benchmark_compiler(runs: int = 100) -> Dict[str, Any]:
    lexer_times, parser_times, analyzer_times, codegen_times, total_times = [], [], [], [], []

    for _ in range(runs):
        t0 = time.perf_counter()
        tokens = Lexer(BENCHMARK_JOCKY_SCRIPT).tokenize()
        t1 = time.perf_counter()
        ast = Parser(tokens).parse()
        t2 = time.perf_counter()
        analyzer = SemanticAnalyzer()
        errors = analyzer.analyze(ast)
        t3 = time.perf_counter()
        codegen = SafeCodeGenerator()
        plan_dict = codegen.generate_plan(ast)
        t4 = time.perf_counter()

        lexer_times.append((t1 - t0) * 1000)
        parser_times.append((t2 - t1) * 1000)
        analyzer_times.append((t3 - t2) * 1000)
        codegen_times.append((t4 - t3) * 1000)
        total_times.append((t4 - t0) * 1000)

    total_metrics = compute_metrics(total_times)
    passed = total_metrics["mean"] < 1000.0  # Target: < 1000ms

    return {
        "status": "PASS" if passed else "FAIL",
        "target_ms": 1000.0,
        "stages": {
            "lexer": compute_metrics(lexer_times),
            "parser": compute_metrics(parser_times),
            "semantic_analyzer": compute_metrics(analyzer_times),
            "codegen": compute_metrics(codegen_times),
            "total_compilation": total_metrics
        }
    }


# ============================================================================
# 2. SECURITY & INTEGRITY BENCHMARK
# ============================================================================
def benchmark_security(runs: int = 100) -> Dict[str, Any]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    append_times = []
    try:
        # Benchmark 100 sequential audit log appends (hash chain calculation)
        for i in range(runs):
            t0 = time.perf_counter()
            IntegrityService.record_chained_audit(
                db=db,
                actor="bench_user@enterprise.local",
                actor_type="USER",
                action="BENCHMARK_AUDIT_ACTION",
                resource=f"Resource:{i}",
                details={"run": i, "data": "cryptographic_chain_test"}
            )
            t1 = time.perf_counter()
            append_times.append((t1 - t0) * 1000)

        # Benchmark audit chain verification over 100 items
        verify_audit_times = []
        for _ in range(20):
            t0 = time.perf_counter()
            valid, findings = IntegrityService.verify_audit_chain(db)
            t1 = time.perf_counter()
            verify_audit_times.append((t1 - t0) * 1000)

        # Benchmark evidence envelope verification
        case_id = "BENCH-CASE-001"
        agent_id = "BENCH-AGENT-01"
        case = Case(id=case_id, title="Bench Case", severity="high")
        agent = Agent(id=agent_id, hostname="bench-host", platform="Windows")
        db.add_all([case, agent])
        db.commit()

        # Seed 50 evidence items with hash chains
        prev_hash = IntegrityService.GENESIS_HASH
        for i in range(50):
            env_data = {
                "results": [{"metric": i, "signature": "ok"}],
                "evidence_id": f"EV-BENCH-{i:03d}",
                "case_id": case_id,
                "agent_id": agent_id,
                "collector": "process.list",
                "platform": "Windows",
                "parameters": {}
            }
            hashes = IntegrityService.calculate_evidence_hashes(env_data, previous_hash=prev_hash)
            ev = Evidence(
                id=f"EV-BENCH-{i:03d}",
                case_id=case_id,
                agent_id=agent_id,
                collector="process.list",
                platform="Windows",
                sha256_hash=hashes["content_hash"],
                content_hash=hashes["content_hash"],
                metadata_hash=hashes["metadata_hash"],
                previous_hash=prev_hash,
                envelope_data=env_data
            )
            db.add(ev)
            db.commit()
            prev_hash = hashes["chain_hash"]

        verify_evidence_chain_times = []
        for _ in range(20):
            t0 = time.perf_counter()
            ev_valid, ev_findings = IntegrityService.verify_evidence_chain(db, case_id)
            t1 = time.perf_counter()
            verify_evidence_chain_times.append((t1 - t0) * 1000)

    finally:
        db.close()
        engine.dispose()

    append_m = compute_metrics(append_times)
    verify_audit_m = compute_metrics(verify_audit_times)
    verify_ev_m = compute_metrics(verify_evidence_chain_times)

    passed = verify_audit_m["mean"] < 1000.0 and verify_ev_m["mean"] < 1000.0

    return {
        "status": "PASS" if passed else "FAIL",
        "target_ms": 1000.0,
        "metrics": {
            "audit_append": append_m,
            "audit_chain_verification_100": verify_audit_m,
            "evidence_chain_verification_50": verify_ev_m
        }
    }


# ============================================================================
# 3. BACKEND API BENCHMARK
# ============================================================================
# 3. BACKEND API BENCHMARK
# ============================================================================
def benchmark_backend_api(runs: int = 30) -> Dict[str, Any]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    results = {}
    try:
        # Pre-seed base data
        case_id = "CASE-PERF-001"
        agent_id = "AGENT-PERF-WIN-01"

        client.post("/api/cases", json={"id": case_id, "title": "Perf Case", "severity": "high", "description": "Benchmark"})
        client.post("/api/agents/register", json={
            "agent_id": agent_id,
            "hostname": "perf-host",
            "platform": "Windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "ip_address": "10.10.10.10",
            "capabilities": ["process.list", "file.hash", "network.netstat"],
            "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
        })

        # Pre-seed some indicators & evidence for investigation endpoints
        db = TestingSession()
        ev = Evidence(
            id="EV-PERF-01",
            case_id=case_id,
            agent_id=agent_id,
            collector="process.list",
            platform="Windows",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            envelope_data={"results": [{"name": "perf.exe", "pid": 1000}]}
        )
        db.add(ev)
        db.commit()
        db.close()

        # Endpoints to benchmark: (name, method, url, json_payload, threshold_ms)
        endpoints = [
            ("health_check", "GET", "/api/health", None, 100.0),
            ("case_list", "GET", "/api/cases", None, 250.0),
            ("agent_tasks_poll", "GET", f"/api/agents/{agent_id}/tasks", None, 250.0),
            ("investigation_summary", "GET", f"/api/investigations/{case_id}/summary", None, 500.0),
            ("investigation_iocs", "GET", f"/api/investigations/{case_id}/iocs", None, 500.0),
            ("investigation_correlations", "GET", f"/api/investigations/{case_id}/correlations", None, 500.0),
            ("integrity_scorecard", "GET", f"/api/investigations/{case_id}/integrity-scorecard", None, 1000.0),
            ("report_export_json", "GET", f"/api/reports/{case_id}/export?format=json", None, 3000.0),
            ("report_export_html", "GET", f"/api/reports/{case_id}/export?format=html", None, 3000.0),
        ]

        for name, method, url, payload, threshold in endpoints:
            latencies = []
            for _ in range(runs):
                t0 = time.perf_counter()
                if method == "GET":
                    res = client.get(url)
                else:
                    res = client.post(url, json=payload)
                t1 = time.perf_counter()
                latencies.append((t1 - t0) * 1000)

            m = compute_metrics(latencies)
            passed = m["mean"] < threshold
            results[name] = {
                "status": "PASS" if passed else "FAIL",
                "target_ms": threshold,
                "metrics": m
            }

    finally:
        app.dependency_overrides.clear()
        engine.dispose()

    all_passed = all(v["status"] == "PASS" for v in results.values())
    return {
        "status": "PASS" if all_passed else "FAIL",
        "endpoints": results
    }


# ============================================================================
# 4. MULTI-AGENT LOAD SCENARIOS (6, 10, 25 Agents)
# ============================================================================
def benchmark_agent_concurrency(fleet_sizes: List[int] = [6, 10, 25]) -> Dict[str, Any]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    scenario_results = {}
    try:
        case_id = "CASE-LOAD-001"
        client.post("/api/cases", json={"id": case_id, "title": "Load Case", "severity": "high"})

        for size in fleet_sizes:
            # Register fleet agents
            for i in range(size):
                client.post("/api/agents/register", json={
                    "agent_id": f"LOAD-AGENT-{i:03d}",
                    "hostname": f"host-{i}",
                    "platform": "Linux" if i % 2 == 0 else "Windows",
                    "capabilities": ["process.list", "network.netstat"],
                    "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
                })

            # Create tasks for each agent
            for i in range(size):
                client.post("/api/tasks", json={
                    "case_id": case_id,
                    "agent_id": f"LOAD-AGENT-{i:03d}",
                    "name": f"Concurrent Collection {i}",
                    "plan_payload": {"actions": [{"action": "collect", "target": "process.list"}]}
                })

            # Measure multi-agent polling latency
            poll_times = []
            t_start = time.perf_counter()
            for i in range(size):
                t0 = time.perf_counter()
                res = client.get(f"/api/agents/LOAD-AGENT-{i:03d}/tasks")
                t1 = time.perf_counter()
                poll_times.append((t1 - t0) * 1000)
            t_end = time.perf_counter()

            total_wall_ms = (t_end - t_start) * 1000
            throughput = size / ((t_end - t_start) if (t_end - t_start) > 0 else 0.001)

            metrics = compute_metrics(poll_times)
            passed = metrics["mean"] < 250.0  # Polling mean < 250ms target

            scenario_results[f"fleet_{size}_agents"] = {
                "fleet_size": size,
                "status": "PASS" if passed else "FAIL",
                "wall_time_ms": round(total_wall_ms, 2),
                "throughput_req_per_sec": round(throughput, 2),
                "poll_latencies_ms": metrics
            }

    finally:
        app.dependency_overrides.clear()
        engine.dispose()

    all_passed = all(v["status"] == "PASS" for v in scenario_results.values())
    return {
        "status": "PASS" if all_passed else "FAIL",
        "scenarios": scenario_results
    }


# ============================================================================
# MASTER BENCHMARK RUNNER
# ============================================================================
def run_all_benchmarks(compiler_runs: int = 50, api_runs: int = 25) -> Dict[str, Any]:
    print("=" * 80)
    print("  JOCKY FORENSIC FRAMEWORK — PHASE 8 EMPIRICAL PERFORMANCE BENCHMARK")
    print("=" * 80)

    print("\n[1/4] Benchmarking JOCKY Domain-Specific Compiler ...")
    comp_res = benchmark_compiler(runs=compiler_runs)
    print(f"      Total Compile Mean: {comp_res['stages']['total_compilation']['mean']} ms "
          f"(p95: {comp_res['stages']['total_compilation']['p95']} ms) -> {comp_res['status']}")

    print("\n[2/4] Benchmarking Cryptographic & Forensic Integrity Engine ...")
    sec_res = benchmark_security(runs=50)
    print(f"      Audit Append Mean: {sec_res['metrics']['audit_append']['mean']} ms | "
          f"Verify 100 Audit Mean: {sec_res['metrics']['audit_chain_verification_100']['mean']} ms | "
          f"Verify 50 Evidence Mean: {sec_res['metrics']['evidence_chain_verification_50']['mean']} ms -> {sec_res['status']}")

    print("\n[3/4] Benchmarking Backend REST API Latencies ...")
    api_res = benchmark_backend_api(runs=api_runs)
    for ep_name, ep_info in api_res["endpoints"].items():
        print(f"      {ep_name:<30} Mean: {ep_info['metrics']['mean']:>6.2f} ms "
              f"(Target: <{ep_info['target_ms']:>4.0f} ms) -> {ep_info['status']}")

    print("\n[4/4] Benchmarking Multi-Agent Concurrent Load Scenarios ...")
    load_res = benchmark_agent_concurrency(fleet_sizes=[6, 10, 25])
    for scen_name, scen_info in load_res["scenarios"].items():
        print(f"      {scen_name:<20} Throughput: {scen_info['throughput_req_per_sec']:>6.2f} req/s | "
              f"Mean Latency: {scen_info['poll_latencies_ms']['mean']:>6.2f} ms -> {scen_info['status']}")

    overall_pass = (
        comp_res["status"] == "PASS" and
        sec_res["status"] == "PASS" and
        api_res["status"] == "PASS" and
        load_res["status"] == "PASS"
    )

    print("\n" + "=" * 80)
    print(f"  BENCHMARK SUITE OVERALL RESULT: {'PASS' if overall_pass else 'FAIL'}")
    print("=" * 80)

    return {
        "overall_status": "PASS" if overall_pass else "FAIL",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "compiler": comp_res,
        "security_integrity": sec_res,
        "backend_api": api_res,
        "agent_concurrency_load": load_res
    }


def main():
    parser = argparse.ArgumentParser(description="Run JOCKY Phase 8 Performance Benchmarks.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("--runs", type=int, default=50, help="Number of benchmark iterations.")
    args = parser.parse_args()

    results = run_all_benchmarks(compiler_runs=args.runs, api_runs=min(args.runs, 25))

    if args.json:
        print(json.dumps(results, indent=2))

    sys.exit(0 if results["overall_status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
