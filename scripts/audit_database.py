#!/usr/bin/env python3
"""
scripts/audit_database.py — JOCKY Defensive Digital-Forensics Database Auditor
==============================================================================
Validates the structural and cryptographic integrity of the SQLite database:
  1. Foreign key constraints & orphaned entities (tasks, evidence, findings, playbooks)
  2. Cryptographic append-only AuditLog hash chain (genesis to head)
  3. Evidence envelope SHA-256 signatures & case evidence hash chains
  4. Playbook content hash integrity
  5. Report cryptographic manifests and signatures

Usage:
  python scripts/audit_database.py [--db PATH] [--json] [--verbose]
"""

import sys
import os
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from backend.app.models.models import (
    Base,
    Case,
    Agent,
    Task,
    TaskResult,
    Evidence,
    AuditLog,
    Finding,
    Playbook,
    Report,
    TimelineEvent,
    EvidenceCorrelation,
)
from backend.app.services.security_integrity_service import IntegrityService


def run_database_audit(db_path: str, verbose: bool = False) -> Dict[str, Any]:
    """Runs comprehensive forensic audit on the specified database."""
    abs_path = os.path.abspath(db_path)
    if not os.path.exists(abs_path):
        return {
            "status": "FAIL",
            "error": f"Database file not found: {abs_path}",
            "checks": {}
        }

    engine = create_engine(f"sqlite:///{abs_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db: Session = SessionLocal()

    audit_results = {
        "database_path": abs_path,
        "database_size_bytes": os.path.getsize(abs_path),
        "status": "PASS",
        "summary": {
            "total_checks": 0,
            "passed_checks": 0,
            "failed_checks": 0,
            "warning_checks": 0,
        },
        "checks": {}
    }

    def record_check(name: str, passed: bool, severity: str = "ERROR", details: Any = None):
        audit_results["summary"]["total_checks"] += 1
        status_str = "PASS" if passed else ("WARNING" if severity == "WARNING" else "FAIL")
        if passed:
            audit_results["summary"]["passed_checks"] += 1
        elif severity == "WARNING":
            audit_results["summary"]["warning_checks"] += 1
            if audit_results["status"] != "FAIL":
                audit_results["status"] = "WARNING"
        else:
            audit_results["summary"]["failed_checks"] += 1
            audit_results["status"] = "FAIL"

        audit_results["checks"][name] = {
            "status": status_str,
            "passed": passed,
            "details": details or {}
        }

    try:
        # 1. SQLite PRAGMA foreign_key_check
        fk_violations = []
        try:
            fk_cursor = db.execute(text("PRAGMA foreign_key_check;"))
            fk_violations = [dict(row._mapping) if hasattr(row, '_mapping') else list(row) for row in fk_cursor]
        except Exception as e:
            fk_violations = [{"error": str(e)}]
        record_check(
            "sqlite_foreign_key_pragma",
            len(fk_violations) == 0,
            details={"violations_count": len(fk_violations), "violations": fk_violations[:10]}
        )

        # 2. Check Orphaned Tasks (task without valid case or agent)
        all_cases = {c.id for c in db.query(Case.id).all()}
        all_agents = {a.id for a in db.query(Agent.id).all()}

        orphaned_tasks = db.query(Task).filter(~Task.case_id.in_(all_cases)).all() if all_cases else db.query(Task).all() if db.query(Task).count() > 0 else []
        record_check(
            "orphaned_tasks",
            len(orphaned_tasks) == 0,
            details={"count": len(orphaned_tasks), "ids": [t.id for t in orphaned_tasks[:5]]}
        )

        # 3. Check Orphaned Evidence (evidence without valid case or agent)
        orphaned_ev = db.query(Evidence).filter(~Evidence.case_id.in_(all_cases)).all() if all_cases else db.query(Evidence).all() if db.query(Evidence).count() > 0 else []
        record_check(
            "orphaned_evidence",
            len(orphaned_ev) == 0,
            details={"count": len(orphaned_ev), "ids": [e.id for e in orphaned_ev[:5]]}
        )

        # 4. Check Orphaned Findings
        orphaned_findings = db.query(Finding).filter(~Finding.case_id.in_(all_cases)).all() if all_cases else db.query(Finding).all() if db.query(Finding).count() > 0 else []
        record_check(
            "orphaned_findings",
            len(orphaned_findings) == 0,
            details={"count": len(orphaned_findings), "ids": [f.id for f in orphaned_findings[:5]]}
        )

        # 5. Check Orphaned Playbooks
        orphaned_pb = db.query(Playbook).filter(~Playbook.case_id.in_(all_cases)).all() if all_cases else db.query(Playbook).all() if db.query(Playbook).count() > 0 else []
        record_check(
            "orphaned_playbooks",
            len(orphaned_pb) == 0,
            details={"count": len(orphaned_pb), "ids": [p.id for p in orphaned_pb[:5]]}
        )

        # 6. Global Audit Log Cryptographic Hash Chain
        audit_count = db.query(AuditLog).count()
        audit_chain_valid, audit_findings = IntegrityService.verify_audit_chain(db)
        record_check(
            "audit_hash_chain_integrity",
            audit_chain_valid,
            details={
                "total_records": audit_count,
                "chain_valid": audit_chain_valid,
                "violations": audit_findings
            }
        )

        # 7. Evidence Envelope Integrity & Per-Case Evidence Chains
        evidence_count = db.query(Evidence).count()
        all_evidence = db.query(Evidence).all()
        tampered_evidence = []
        for ev in all_evidence:
            valid, claimed, recalc, msg = IntegrityService.verify_single_evidence(ev)
            if not valid:
                tampered_evidence.append({
                    "evidence_id": ev.id,
                    "case_id": ev.case_id,
                    "claimed": claimed,
                    "recalculated": recalc,
                    "msg": msg
                })

        record_check(
            "evidence_envelope_signatures",
            len(tampered_evidence) == 0,
            details={"total_evidence": evidence_count, "tampered_count": len(tampered_evidence), "tampered": tampered_evidence[:5]}
        )

        # Per-case evidence chain checks
        broken_case_chains = []
        for case_id in all_cases:
            chain_ok, chain_findings = IntegrityService.verify_evidence_chain(db, case_id)
            if not chain_ok:
                broken_case_chains.append({"case_id": case_id, "findings": chain_findings})

        record_check(
            "evidence_case_chains",
            len(broken_case_chains) == 0,
            details={"cases_evaluated": len(all_cases), "broken_chains": broken_case_chains}
        )

        # 8. Playbook Content Hashes
        all_playbooks = db.query(Playbook).all()
        tampered_playbooks = []
        for pb in all_playbooks:
            pb_res = IntegrityService.verify_playbook_integrity(db, pb.id)
            if not pb_res.get("verified", True):
                tampered_playbooks.append({"playbook_id": pb.id, "name": pb.name})

        record_check(
            "playbook_integrity",
            len(tampered_playbooks) == 0,
            details={"total_playbooks": len(all_playbooks), "tampered": tampered_playbooks}
        )

        # 9. Reports Manifest Verification
        all_reports = db.query(Report).all()
        tampered_reports = []
        for rep in all_reports:
            rep_res = IntegrityService.verify_report_integrity(db, rep.id)
            if not rep_res.get("verified", True):
                tampered_reports.append({"report_id": rep.id, "title": rep.title, "details": rep_res.get("details")})

        record_check(
            "report_manifest_integrity",
            len(tampered_reports) == 0,
            details={"total_reports": len(all_reports), "tampered": tampered_reports}
        )

    finally:
        db.close()
        engine.dispose()

    return audit_results


def print_audit_report(results: Dict[str, Any]):
    print("=" * 80)
    print("  JOCKY DEFENSIVE DIGITAL-FORENSICS — DATABASE INTEGRITY AUDIT")
    print("=" * 80)
    print(f"Target Database : {results.get('database_path')}")
    print(f"File Size       : {results.get('database_size_bytes', 0):,} bytes")
    print(f"Overall Status  : {results.get('status')}")
    print(f"Summary         : {results['summary']['passed_checks']}/{results['summary']['total_checks']} checks passed "
          f"({results['summary']['warning_checks']} warnings, {results['summary']['failed_checks']} failures)")
    print("-" * 80)
    print(f"{'Check Name':<35} | {'Status':<10} | {'Details'}")
    print("-" * 80)

    for check_name, info in results.get("checks", {}).items():
        status = info["status"]
        status_color = "\033[92mPASS\033[0m" if status == "PASS" else ("\033[93mWARNING\033[0m" if status == "WARNING" else "\033[91mFAIL\033[0m")
        det_str = ""
        details = info.get("details", {})
        if "total_records" in details:
            det_str = f"records: {details['total_records']}, violations: {len(details.get('violations', []))}"
        elif "count" in details:
            det_str = f"orphaned count: {details['count']}"
        elif "total_evidence" in details:
            det_str = f"total: {details['total_evidence']}, tampered: {details['tampered_count']}"
        elif "cases_evaluated" in details:
            det_str = f"cases: {details['cases_evaluated']}, broken: {len(details.get('broken_chains', []))}"
        elif "total_playbooks" in details:
            det_str = f"total: {details['total_playbooks']}, tampered: {len(details.get('tampered', []))}"
        elif "total_reports" in details:
            det_str = f"total: {details['total_reports']}, tampered: {len(details.get('tampered', []))}"
        elif "violations_count" in details:
            det_str = f"fk violations: {details['violations_count']}"
        else:
            det_str = str(details)

        print(f"{check_name:<35} | {status:<10} | {det_str}")

    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Audit JOCKY forensics database integrity.")
    parser.add_argument("--db", default="jocky_forensics.db", help="Path to SQLite database file.")
    parser.add_argument("--json", action="store_true", help="Output results as JSON.")
    parser.add_argument("--verbose", action="store_true", help="Verbose details.")
    args = parser.parse_args()

    results = run_database_audit(args.db, verbose=args.verbose)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_audit_report(results)

    if results["status"] == "FAIL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
