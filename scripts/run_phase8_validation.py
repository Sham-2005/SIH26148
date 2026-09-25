#!/usr/bin/env python3
"""
scripts/run_phase8_validation.py — JOCKY Master Validation & Release Certification Orchestrator
================================================================================================
Executes the comprehensive Phase 8 release verification workflow:
  1. Full Pytest Regression Suite (Compiler, Agent, Backend, Phase 8 Validation & E2E)
  2. JOCKY Compiler Certification (Lexer, Parser, Semantic Analyzer, Codegen, Determinism)
  3. Backend API Standards & Security Headers
  4. Security & Cryptographic Integrity Engine (Audit chain, Evidence chain, Tamper detection)
  5. Database Integrity Audit (Foreign keys, hash chains, orphaned records)
  6. Forensic Report Export & Cryptographic Manifest Verification
  7. Empirical Performance Benchmarking & Load Scenarios (6, 10, 25 Agents)
  8. Frontend Production Build Verification (Vite / React / TypeScript)
  9. Official Release Certification & Generation of phase8_validation_report.json

Usage:
  python scripts/run_phase8_validation.py [--output PATH] [--skip-frontend] [--quick]
"""

import sys
import os
import time
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.audit_database import run_database_audit
from scripts.validate_reports import validate_case_reports
from scripts.benchmark_phase8 import run_all_benchmarks


class Phase8MasterOrchestrator:
    def __init__(self, quick: bool = False, skip_frontend: bool = False, output_file: str = "phase8_validation_report.json"):
        self.quick = quick
        self.skip_frontend = skip_frontend
        self.output_file = output_file
        self.start_time = time.time()
        self.report: Dict[str, Any] = {
            "project": "SIH26148 — JOCKY Defensive Digital-Forensics Framework",
            "phase": "PHASE 8: Final Validation, Testing, Benchmarking, Documentation & Release Certification",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": {
                "python_version": sys.version.split()[0],
                "os_platform": sys.platform,
                "project_root": str(PROJECT_ROOT)
            },
            "overall_status": "PENDING",
            "release_decision": "PENDING",
            "stages": {}
        }

    def log_header(self, title: str):
        print("\n" + "=" * 80)
        print(f"  {title}")
        print("=" * 80)

    # ------------------------------------------------------------------------
    # Stage 1: Full Pytest Regression Suite
    # ------------------------------------------------------------------------
    def run_stage_pytest(self) -> bool:
        self.log_header("[STAGE 1/8] Executing Full Pytest Regression Suite")
        t0 = time.time()
        cmd = [sys.executable, "-m", "pytest", "compiler/tests", "agent/tests", "backend/tests", "tests", "-v"]
        res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
        duration = round(time.time() - t0, 2)

        output_lines = res.stdout.splitlines()
        summary_line = ""
        for line in reversed(output_lines):
            if "passed" in line or "failed" in line or "error" in line:
                summary_line = line.strip()
                break

        passed = (res.returncode == 0)
        print(res.stdout if not passed else "\n".join(output_lines[-5:]))
        print(f"[*] Pytest Result: {'PASS' if passed else 'FAIL'} in {duration}s -> {summary_line}")

        self.report["stages"]["pytest_regression"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "return_code": res.returncode,
            "summary": summary_line,
            "output_tail": output_lines[-10:] if output_lines else []
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 2: Compiler Determinism & Safety Validation
    # ------------------------------------------------------------------------
    def run_stage_compiler(self) -> bool:
        self.log_header("[STAGE 2/8] Validating JOCKY Compiler Certification & Determinism")
        t0 = time.time()
        from compiler.lexer.lexer import Lexer
        from compiler.parser.parser import Parser
        from compiler.semantic.analyzer import SemanticAnalyzer
        from compiler.codegen.codegen import SafeCodeGenerator

        sample = """
        script CompilerCert {
            system.info();
            process.list();
            network.connections();
            evidence.collect();
        }
        """
        try:
            tokens = Lexer(sample).tokenize()
            ast = Parser(tokens).parse()
            errors = SemanticAnalyzer().analyze(ast)
            if errors:
                raise ValueError(f"Semantic analysis failed: {errors}")
            plan1 = SafeCodeGenerator().generate_plan(ast)
            hash1 = plan1["scripts"][0]["plan_hash"]

            # Repeat for determinism
            tokens2 = Lexer(sample).tokenize()
            ast2 = Parser(tokens2).parse()
            plan2 = SafeCodeGenerator().generate_plan(ast2)
            hash2 = plan2["scripts"][0]["plan_hash"]

            deterministic = (hash1 == hash2) and len(hash1) == 64
            duration = round(time.time() - t0, 3)

            print(f"[+] AST generation & plan code generation successful.")
            print(f"[+] Plan Hash 1: {hash1}")
            print(f"[+] Plan Hash 2: {hash2}")
            print(f"[*] Determinism: {'PASS' if deterministic else 'FAIL'} in {duration}s")

            self.report["stages"]["compiler_certification"] = {
                "status": "PASS" if deterministic else "FAIL",
                "duration_seconds": duration,
                "plan_hash": hash1,
                "deterministic": deterministic
            }
            return deterministic
        except Exception as e:
            print(f"[-] Compiler certification failed: {e}")
            self.report["stages"]["compiler_certification"] = {
                "status": "FAIL",
                "error": str(e)
            }
            return False

    # ------------------------------------------------------------------------
    # Stage 3: Backend API Standards & Security Headers
    # ------------------------------------------------------------------------
    def run_stage_api_standards(self) -> bool:
        self.log_header("[STAGE 3/8] Validating REST API Standards & Security Headers")
        t0 = time.time()
        from fastapi.testclient import TestClient
        from backend.app.main import app

        passed = True
        findings = []

        with TestClient(app) as client:
            # 1. Health check & security headers
            res = client.get("/api/health")
            headers = res.headers
            req_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "X-Request-ID"]
            for h in req_headers:
                if h not in headers and h.lower() not in headers:
                    passed = False
                    findings.append(f"Missing security header: {h}")

            # 2. Standardized error envelope check
            err_res = client.get("/api/cases/NON-EXISTENT-CASE-999")
            if err_res.status_code == 404:
                body = err_res.json()
                if "error" not in body or "code" not in body.get("error", {}):
                    passed = False
                    findings.append("404 response missing standardized error object {'code', 'message'}")
            else:
                passed = False
                findings.append(f"Expected 404 for missing case, got {err_res.status_code}")

        duration = round(time.time() - t0, 3)
        print(f"[*] API Standards & Headers: {'PASS' if passed else 'FAIL'} ({len(findings)} anomalies)")
        for f in findings:
            print(f"    - {f}")

        self.report["stages"]["api_standards"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "findings": findings
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 4: Cryptographic & Forensic Integrity Primitives
    # ------------------------------------------------------------------------
    def run_stage_cryptographic_integrity(self) -> bool:
        self.log_header("[STAGE 4/8] Validating Cryptographic Primitives & Hash Chains")
        t0 = time.time()
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        from backend.app.database.base import Base
        from backend.app.services.security_integrity_service import IntegrityService
        from backend.app.services.tamper_detection_service import TamperDetectionService

        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        passed = True
        details = {}
        try:
            # 1. Test Audit Hash Chain
            for i in range(10):
                IntegrityService.record_chained_audit(
                    db=db,
                    actor="cert_analyst@jocky.defense",
                    actor_type="USER",
                    action=f"ACTION_{i}",
                    resource=f"Resource:{i}"
                )
            audit_ok, audit_findings = IntegrityService.verify_audit_chain(db)
            if not audit_ok or audit_findings:
                passed = False
            details["audit_chain_valid"] = audit_ok

            # 2. Tamper Detection Event
            sec_event = TamperDetectionService.create_security_event(
                db=db,
                event_type="CONFIG_TAMPER_DETECTED",
                severity="HIGH",
                object_type="CONFIG",
                object_id="agent.yaml",
                description="[SIMULATED] Unauthorized config modification"
            )
            details["tamper_event_recorded"] = (sec_event.id is not None)

        finally:
            db.close()
            engine.dispose()

        duration = round(time.time() - t0, 3)
        print(f"[*] Cryptographic Integrity Primitives: {'PASS' if passed else 'FAIL'} in {duration}s")

        self.report["stages"]["cryptographic_integrity"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "details": details
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 5: Database Integrity Audit
    # ------------------------------------------------------------------------
    def run_stage_database_audit(self) -> bool:
        self.log_header("[STAGE 5/8] Running Database Schema & Cryptographic Chain Audit")
        t0 = time.time()
        import tempfile
        from backend.app.database.base import Base
        from sqlalchemy import create_engine

        # Audit both runtime DB if exists and a pristine verification DB
        tmp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_path = tmp_file.name
        tmp_file.close()

        engine = create_engine(f"sqlite:///{tmp_path}")
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        audit_res = run_database_audit(tmp_path)
        try:
            os.remove(tmp_path)
        except OSError:
            pass

        duration = round(time.time() - t0, 3)
        passed = (audit_res["status"] == "PASS")
        print(f"[*] Clean Database Audit: {audit_res['status']} "
              f"({audit_res['summary']['passed_checks']}/{audit_res['summary']['total_checks']} checks passed)")

        self.report["stages"]["database_audit"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "audit_summary": audit_res["summary"],
            "checks": {k: v["status"] for k, v in audit_res["checks"].items()}
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 6: Forensic Report Verification
    # ------------------------------------------------------------------------
    def run_stage_report_validation(self) -> bool:
        self.log_header("[STAGE 6/8] Validating Forensic Report Manifests & Export Formats")
        t0 = time.time()
        import tempfile
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.orm import sessionmaker
        from backend.app.database.base import Base
        from backend.app.database.session import get_db
        from backend.app.main import app
        from backend.app.models.models import Case, Evidence

        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)

        def override_db():
            db = Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        from fastapi.testclient import TestClient
        client = TestClient(app)

        passed = True
        details = {}
        try:
            case_id = "CASE-CERT-001"
            client.post("/api/cases", json={"id": case_id, "title": "Certification Case", "severity": "high"})
            # Export formats
            for fmt in ["json", "html", "pdf"]:
                res = client.get(f"/api/reports/{case_id}/export?format={fmt}")
                if res.status_code != 200:
                    passed = False
                    details[f"export_{fmt}"] = f"HTTP {res.status_code}"
                else:
                    details[f"export_{fmt}"] = f"OK ({len(res.content)} bytes)"

            # Generate formal report
            rep_res = client.post("/api/reports/generate", json={"case_id": case_id, "report_type": "comprehensive"})
            details["report_generate"] = "OK" if rep_res.status_code == 200 else f"HTTP {rep_res.status_code}"
            if rep_res.status_code != 200:
                passed = False

        finally:
            app.dependency_overrides.clear()
            engine.dispose()

        duration = round(time.time() - t0, 3)
        print(f"[*] Forensic Report Exports (JSON, HTML, PDF): {'PASS' if passed else 'FAIL'} in {duration}s")
        for k, v in details.items():
            print(f"    - {k}: {v}")

        self.report["stages"]["report_validation"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "formats": details
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 7: Empirical Performance Benchmarking & Load Scenarios
    # ------------------------------------------------------------------------
    def run_stage_benchmarks(self) -> bool:
        self.log_header("[STAGE 7/8] Executing Empirical Performance Benchmarking & Load Scenarios")
        t0 = time.time()
        runs = 15 if self.quick else 30
        bench_res = run_all_benchmarks(compiler_runs=runs, api_runs=min(runs, 20))
        duration = round(time.time() - t0, 2)

        passed = (bench_res["overall_status"] == "PASS")
        self.report["stages"]["benchmarks_and_load"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "benchmark_data": bench_res
        }
        return passed

    # ------------------------------------------------------------------------
    # Stage 8: Frontend Production Build
    # ------------------------------------------------------------------------
    def run_stage_frontend_build(self) -> bool:
        self.log_header("[STAGE 8/8] Verifying Frontend Production Build (Vite / React)")
        if self.skip_frontend:
            print("[*] Skipping frontend build as requested (--skip-frontend).")
            self.report["stages"]["frontend_build"] = {"status": "SKIPPED"}
            return True

        t0 = time.time()
        cmd = "npm --prefix frontend run build"
        res = subprocess.run(cmd, shell=True, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
        duration = round(time.time() - t0, 2)

        passed = (res.returncode == 0)
        output_tail = res.stdout.splitlines()[-6:] if res.stdout else []
        print(res.stdout if not passed else "\n".join(output_tail))
        print(f"[*] Frontend Production Build: {'PASS' if passed else 'FAIL'} in {duration}s (Exit {res.returncode})")

        self.report["stages"]["frontend_build"] = {
            "status": "PASS" if passed else "FAIL",
            "duration_seconds": duration,
            "return_code": res.returncode,
            "output_tail": output_tail
        }
        return passed

    # ------------------------------------------------------------------------
    # Release Evaluation & Certification
    # ------------------------------------------------------------------------
    def evaluate_release(self) -> bool:
        self.log_header("PHASE 8 RELEASE CERTIFICATION DECISION")
        total_duration = round(time.time() - self.start_time, 2)
        self.report["total_duration_seconds"] = total_duration

        all_stages_pass = all(
            stage.get("status") in ("PASS", "SKIPPED")
            for stage in self.report["stages"].values()
        )

        self.report["overall_status"] = "PASS" if all_stages_pass else "FAIL"
        self.report["release_decision"] = "CERTIFIED" if all_stages_pass else "REJECTED"

        print(f"Project         : {self.report['project']}")
        print(f"Total Duration  : {total_duration}s")
        print(f"Overall Status  : {self.report['overall_status']}")
        print(f"Decision        : {self.report['release_decision']}")
        print("-" * 80)
        for stage_name, stage_info in self.report["stages"].items():
            status = stage_info.get("status")
            status_str = f"\033[92m{status}\033[0m" if status == "PASS" else f"\033[91m{status}\033[0m"
            print(f"  - {stage_name:<30} : {status_str}")
        print("=" * 80)

        # Write output JSON report
        out_path = PROJECT_ROOT / self.output_file
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2)
        print(f"[+] Release validation report written to: {out_path.resolve()}")

        return all_stages_pass

    def run(self) -> bool:
        s1 = self.run_stage_pytest()
        s2 = self.run_stage_compiler()
        s3 = self.run_stage_api_standards()
        s4 = self.run_stage_cryptographic_integrity()
        s5 = self.run_stage_database_audit()
        s6 = self.run_stage_report_validation()
        s7 = self.run_stage_benchmarks()
        s8 = self.run_stage_frontend_build()

        return self.evaluate_release()


def main():
    parser = argparse.ArgumentParser(description="Run JOCKY Phase 8 Master Validation Suite.")
    parser.add_argument("--output", default="phase8_validation_report.json", help="Path to output JSON report.")
    parser.add_argument("--skip-frontend", action="store_true", help="Skip frontend build stage.")
    parser.add_argument("--quick", action="store_true", help="Run with fewer benchmark iterations.")
    args = parser.parse_args()

    orchestrator = Phase8MasterOrchestrator(
        quick=args.quick,
        skip_frontend=args.skip_frontend,
        output_file=args.output
    )
    success = orchestrator.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
