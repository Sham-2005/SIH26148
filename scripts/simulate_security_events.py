"""
SIH26148 - JOCKY Security Test Simulator
Generates deterministic synthetic defensive test security events for demonstration and testing.
All events are strictly tagged with '[SIMULATED SECURITY EVENT]' and perform NO destructive operations.
"""
import os
import sys
import argparse
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.database.session import SessionLocal
from backend.app.models.models import (
    SecurityEvent,
    Case,
    Agent,
    Evidence,
    Task,
    Playbook,
    AuditLog
)
from backend.app.services.tamper_detection_service import TamperDetectionService
from backend.app.services.security_integrity_service import IntegrityService, hash_object
from backend.app.services.config_integrity_service import ConfigIntegrityService


def ensure_test_case(db, case_id: str):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        case = Case(
            id=case_id,
            title="Simulated Enterprise Triage",
            severity="high",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()
    return case


def simulate_evidence_tamper(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """1. Simulated Evidence Modification"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="EVIDENCE_TAMPER_DETECTED",
            severity="CRITICAL",
            object_type="EVIDENCE",
            object_id="EV-SIMULATED-01",
            description="[SIMULATED SECURITY EVENT] Simulated unauthorized alteration of evidence JSON envelope payload.",
            expected_value="4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712",
            observed_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_HASH_MISMATCH",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of cryptographic seal violation",
                "defensive_response": "Quarantine evidence envelope and alert SOC analyst"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_audit_break(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """2. Simulated Audit-Chain Break"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="AUDIT_CHAIN_CORRUPTION",
            severity="CRITICAL",
            object_type="AUDIT_LOG",
            object_id="AUD-SIMULATED-02",
            description="[SIMULATED SECURITY EVENT] Simulated audit hash-chain disruption: Predecessor hash link does not match previous block.",
            expected_value="7c9f521b89ef9012cd456ab78912ef0123456789abcdef0123456789abcdef01",
            observed_value="0000000000000000000000000000000000000000000000000000000000000000",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_PREV_HASH_BREAK",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of audit ledger tamper detection",
                "defensive_response": "Preserve snapshot and inspect administrative access logs"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_agent_spoof(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """3. Simulated Agent Identity Mismatch"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="AGENT_IDENTITY_MISMATCH",
            severity="HIGH",
            object_type="AGENT",
            object_id="AGENT-SIMULATED-SPOOF",
            description="[SIMULATED SECURITY EVENT] Simulated agent identity anomaly: Host OS declaration differs from registered capability profile.",
            expected_value="Windows (Win11 Ent, x86_64)",
            observed_value="Linux (Ubuntu 24.04, arm64)",
            case_id=case_id,
            agent_id="AGENT-WIN-01",
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_AGENT_SPOOF",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of agent identity spoofing defense",
                "defensive_response": "Revoke enrollment token and inspect agent host"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_replay_attack(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """4. Simulated Task Replay"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="REPLAY_ATTEMPT_DETECTED",
            severity="HIGH",
            object_type="TASK",
            object_id="TASK-SIMULATED-REPLAY",
            description="[SIMULATED SECURITY EVENT] Simulated duplicate submission attempt blocked: Task is already in terminal 'completed' status.",
            expected_value="status == pending/assigned",
            observed_value="status == completed",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_REPLAY_ATTEMPT",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of replay protection and token idempotency",
                "defensive_response": "Disallow task re-execution and inspect dispatch origin"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_playbook_tamper(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """5. Simulated Playbook Modification"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="PLAYBOOK_INTEGRITY_VIOLATION",
            severity="CRITICAL",
            object_type="PLAYBOOK",
            object_id="PB-SIMULATED-TAMPER",
            description="[SIMULATED SECURITY EVENT] Simulated unauthorized playbook tampering: Action steps altered following analyst approval signature.",
            expected_value="8b3a0f12c98d71e2fa012345bc6789de1234567890abcdef1234567890abcdef",
            observed_value="f1029384756abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_PLAYBOOK_DRIFT",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of response playbook signature verification",
                "defensive_response": "Halt execution and alert incident commander"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_config_drift(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """6. Simulated Configuration Modification"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="UNAUTHORIZED_CONFIGURATION_CHANGE",
            severity="HIGH",
            object_type="CONFIGURATION",
            object_id="SYSTEM_CONFIG",
            description="[SIMULATED SECURITY EVENT] Simulated configuration drift: Response action allowlist was modified outside authorization policy.",
            expected_value=ConfigIntegrityService.get_baseline_fingerprint(),
            observed_value="9999999999999999999999999999999999999999999999999999999999999999",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_CONFIG_DRIFT",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of configuration baseline drift detection",
                "defensive_response": "Lockdown configuration and revert to cryptographically sealed baseline"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def simulate_timestamp_anomaly(case_id: str = "CASE-2026-001") -> Dict[str, Any]:
    """7. Simulated Timestamp Anomaly"""
    db = SessionLocal()
    try:
        ensure_test_case(db, case_id)
        ev = TamperDetectionService.create_security_event(
            db=db,
            event_type="TIMESTAMP_ANOMALY",
            severity="MEDIUM",
            object_type="TASK",
            object_id="TASK-SIMULATED-TIME",
            description="[SIMULATED SECURITY EVENT] Simulated temporal causality anomaly: Task completed_at timestamp precedes created_at.",
            expected_value="completed_at >= 2026-09-18T14:30:00Z",
            observed_value="completed_at == 2026-09-18T14:28:15Z",
            case_id=case_id,
            metadata_json={
                "simulation": True,
                "technique": "SIMULATED_CAUSALITY_VIOLATION",
                "simulation_note": "[SIMULATED SECURITY EVENT] Demonstration of temporal ordering and anti-timestomping defense",
                "defensive_response": "Audit NTP time-sync sources across endpoints"
            }
        )
        return {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "case_id": ev.case_id,
            "details": ev.metadata_json
        }
    finally:
        db.close()


def run_all_simulations(case_id: str = "CASE-2026-001") -> List[Dict[str, Any]]:
    """Runs all 7 simulations and returns list of event dicts."""
    results = [
        simulate_evidence_tamper(case_id),
        simulate_audit_break(case_id),
        simulate_agent_spoof(case_id),
        simulate_replay_attack(case_id),
        simulate_playbook_tamper(case_id),
        simulate_config_drift(case_id),
        simulate_timestamp_anomaly(case_id),
    ]
    return results


def simulate_all_events(case_id: str = "CASE-2026-001") -> List[SecurityEvent]:
    """Backward compatibility wrapper returning SecurityEvent model objects."""
    run_all_simulations(case_id)
    db = SessionLocal()
    try:
        return db.query(SecurityEvent).filter(SecurityEvent.case_id == case_id).all()
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="JOCKY Defensive Security Test Event Simulator")
    parser.add_argument("--case", default="CASE-2026-001", help="Target Case ID for simulated events")
    args = parser.parse_args()

    results = run_all_simulations(case_id=args.case)
    print(f"[*] Successfully generated {len(results)} synthetic defensive security events for case '{args.case}'.")


if __name__ == "__main__":
    main()
