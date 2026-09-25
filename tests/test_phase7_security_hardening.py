"""
Phase 7 Test Suite: Security Hardening, Evidence Integrity, Tamper Detection & Operational Security
Validates:
1. Evidence hash verification (matching sha256_hash returns VALID)
2. Evidence tamper detection (mismatched hash detected as TAMPERED)
3. Evidence hash chain verification (sequential chaining over case evidence verified)
4. Audit chain creation & linking (AuditLog previous_event_hash correctly chained)
5. Audit chain tamper detection (broken audit link detected)
6. Security event creation & indexing (SecurityEvent persisted with all fields)
7. Security event filtering API (filter by case_id, severity, event_type, resolved)
8. Agent identity fingerprint verification (deterministic hash of agent attributes)
9. Agent identity mismatch rejection (tampered capability/identity detected)
10. Task integrity verification (task_hash matching instructions/params)
11. Task tampering rejection (tampered task instruction/hash fails verification)
12. Replay detection (duplicate task dispatch or duplicate agent result rejected)
13. Playbook hash verification (content_hash and approval_hash computed and matched)
14. Modified playbook execution rejection (PLAYBOOK_INTEGRITY_VIOLATION raised when executed after tampering)
15. Configuration fingerprint verification (baseline hash computed deterministically)
16. Configuration tamper detection (drift detected when configuration altered)
17. Timestamp anomaly detection (out-of-order/future timestamps flagged)
18. Report integrity manifest verification (canonical report manifest verified with evidence/audit hashes)
19. Role-based authorization boundaries (role permissions enforce READ/WRITE/EXECUTE restrictions)
20. Sensitive data redaction (recursive redaction of API keys, tokens, passwords)
21. Security policy allow (authorized actions proceed)
22. Security policy deny (unauthorized actions denied)
23. Security policy requires approval (sensitive actions gated)
24. JOCKY integrity primitive compilation (AST compilation of verify.* primitives)
25. Unsupported security primitive rejection (unsupported primitive rejected gracefully)
26. Security API authorization & headers (security response headers present on responses)
27. Simulated tamper event generation (scripts/simulate_security_events.py generates valid tagged simulation events)
28. Complete case integrity verification workflow (all 7 controls evaluated and scored via IntegrityService)
"""
import pytest
import json
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.database.migrations import ensure_schema_upgrades
from backend.app.models.models import (
    Case, Agent, Evidence, Task, AuditLog, Playbook, PlaybookAction,
    PlaybookApproval, PlaybookExecution, SecurityEvent, Report
)
from backend.app.services.security_integrity_service import IntegrityService
from backend.app.services.config_integrity_service import ConfigIntegrityService
from backend.app.services.time_integrity_service import TimeIntegrityService
from backend.app.services.security_policy_service import SecurityPolicyService
from backend.app.services.tamper_detection_service import TamperDetectionService
from backend.app.services.playbook_service import PlaybookService

from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator
from compiler.diagnostics.errors import SemanticError

from scripts.simulate_security_events import (
    simulate_evidence_tamper,
    simulate_audit_break,
    simulate_playbook_tamper,
    simulate_config_drift,
    simulate_replay_attack,
    simulate_agent_spoof,
    simulate_timestamp_anomaly,
    run_all_simulations,
)

client = TestClient(app)

TEST_CASE_P7 = "CASE-P7-TEST"
TEST_AGENT_P7 = "AGENT-P7-TEST-01"


@pytest.fixture(scope="module", autouse=True)
def setup_phase7_test_env():
    Base.metadata.create_all(bind=engine)
    ensure_schema_upgrades(engine, Base.metadata)
    db = SessionLocal()
    try:
        # Create test case if not present
        test_case = db.query(Case).filter(Case.id == TEST_CASE_P7).first()
        if not test_case:
            test_case = Case(
                id=TEST_CASE_P7,
                title="Phase 7 Defensive Hardening & Integrity Verification Test Case",
                description="Fleet test case for cryptographic integrity, chained audits, and tamper defense.",
                severity="critical",
                status="INVESTIGATING"
            )
            db.add(test_case)

        # Create test agent if not present
        test_agent = db.query(Agent).filter(Agent.id == TEST_AGENT_P7).first()
        if not test_agent:
            agent_data = {
                "id": TEST_AGENT_P7,
                "hostname": "ENDPOINT-P7-SEC",
                "platform": "Windows",
                "os_version": "Windows 11 Pro 23H2",
                "architecture": "x86_64",
                "ip_address": "10.0.70.25",
                "status": "online",
                "capabilities": ["process_collector", "network_collector", "evidence_collector"]
            }
            id_fp = IntegrityService.compute_agent_fingerprint(
                agent_data["id"], agent_data["hostname"], agent_data["platform"],
                agent_data["os_version"], agent_data["architecture"]
            )
            cap_fp = IntegrityService.compute_capability_fingerprint(agent_data["capabilities"])

            test_agent = Agent(
                **agent_data,
                identity_fingerprint=id_fp,
                capability_fingerprint=cap_fp
            )
            db.add(test_agent)

        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 1: Evidence Hash Verification
# ---------------------------------------------------------------------------
def test_evidence_hash_verification():
    """Verify that an untampered evidence envelope produces a matching hash and reports VALID."""
    envelope = {
        "collector": "process_collector",
        "processes": [{"pid": 1001, "name": "lsass.exe", "user": "SYSTEM"}]
    }
    content_hash = IntegrityService.canonical_hash(envelope)
    meta_hash = IntegrityService.canonical_hash({"case_id": TEST_CASE_P7, "agent_id": TEST_AGENT_P7})

    db = SessionLocal()
    try:
        evidence = Evidence(
            id=f"EV-TEST-1-{uuid.uuid4().hex[:6]}",
            case_id=TEST_CASE_P7,
            agent_id=TEST_AGENT_P7,
            collector="process_collector",
            platform="Windows",
            sha256_hash=content_hash,
            content_hash=content_hash,
            metadata_hash=meta_hash,
            integrity_status="VALID",
            is_verified=True,
            envelope_data=envelope
        )
        db.add(evidence)
        db.commit()

        res = IntegrityService.verify_evidence_integrity(db, evidence.id)
        assert res["verified"] is True
        assert res["status"] == "VALID"
        assert res["content_hash"] == content_hash
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 2: Evidence Tamper Detection
# ---------------------------------------------------------------------------
def test_evidence_tamper_detection():
    """Verify that altering evidence envelope contents without updating the hash reports TAMPERED."""
    db = SessionLocal()
    try:
        original_data = {"key": "original_forensic_data"}
        legit_hash = IntegrityService.canonical_hash(original_data)

        evidence = Evidence(
            id=f"EV-TAMPER-{uuid.uuid4().hex[:6]}",
            case_id=TEST_CASE_P7,
            agent_id=TEST_AGENT_P7,
            collector="system_collector",
            platform="Windows",
            sha256_hash=legit_hash,
            content_hash=legit_hash,
            integrity_status="VALID",
            is_verified=True,
            envelope_data={"key": "tampered_data_injected"}  # Tampered payload!
        )
        db.add(evidence)
        db.commit()

        res = IntegrityService.verify_evidence_integrity(db, evidence.id)
        assert res["verified"] is False
        assert res["status"] == "TAMPERED"
        assert "Content hash mismatch" in res["details"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 3: Evidence Hash Chain Verification
# ---------------------------------------------------------------------------
def test_evidence_hash_chain_verification():
    """Verify that multiple evidence items linked via sequential previous_hash form a valid chain."""
    db = SessionLocal()
    try:
        chain_case = f"CASE-CHAIN-{uuid.uuid4().hex[:6]}"
        db.add(Case(id=chain_case, title="Chain Test", severity="medium", status="INVESTIGATING"))
        db.commit()

        # Item 1
        data1 = {"step": 1, "status": "init"}
        hash1 = IntegrityService.canonical_hash(data1)
        ev1 = Evidence(
            id=f"EV-CH-1-{uuid.uuid4().hex[:6]}",
            case_id=chain_case,
            agent_id=TEST_AGENT_P7,
            collector="collector_1",
            platform="Windows",
            sha256_hash=hash1,
            content_hash=hash1,
            previous_hash="0" * 64,
            integrity_status="VALID",
            is_verified=True,
            envelope_data=data1,
            collected_at=datetime.now(timezone.utc) - timedelta(minutes=5)
        )
        db.add(ev1)
        db.commit()

        # Item 2 chained to Item 1
        data2 = {"step": 2, "status": "running"}
        hash2 = IntegrityService.canonical_hash(data2)
        ev2 = Evidence(
            id=f"EV-CH-2-{uuid.uuid4().hex[:6]}",
            case_id=chain_case,
            agent_id=TEST_AGENT_P7,
            collector="collector_2",
            platform="Windows",
            sha256_hash=hash2,
            content_hash=hash2,
            previous_hash=hash1,
            integrity_status="VALID",
            is_verified=True,
            envelope_data=data2,
            collected_at=datetime.now(timezone.utc) - timedelta(minutes=3)
        )
        db.add(ev2)
        db.commit()

        # Item 3 chained to Item 2
        data3 = {"step": 3, "status": "done"}
        hash3 = IntegrityService.canonical_hash(data3)
        ev3 = Evidence(
            id=f"EV-CH-3-{uuid.uuid4().hex[:6]}",
            case_id=chain_case,
            agent_id=TEST_AGENT_P7,
            collector="collector_3",
            platform="Windows",
            sha256_hash=hash3,
            content_hash=hash3,
            previous_hash=hash2,
            integrity_status="VALID",
            is_verified=True,
            envelope_data=data3,
            collected_at=datetime.now(timezone.utc)
        )
        db.add(ev3)
        db.commit()

        is_chain_intact, findings = IntegrityService.verify_evidence_chain(db, chain_case)
        assert is_chain_intact is True
        assert len(findings) == 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 4: Audit Chain Creation & Linking
# ---------------------------------------------------------------------------
def test_audit_chain_creation_and_linking():
    """Verify that sequential AuditLog entries generated by IntegrityService chain previous_event_hash correctly."""
    db = SessionLocal()
    try:
        audit_case = f"CASE-AUD-{uuid.uuid4().hex[:6]}"

        entry1 = IntegrityService.record_audit_event(
            db, action="TASK_DISPATCH", actor="analyst@soc.gov",
            resource_type="task", resource_id="TASK-01",
            details={"action": "start"}, case_id=audit_case
        )
        assert entry1.event_hash is not None

        entry2 = IntegrityService.record_audit_event(
            db, action="EVIDENCE_INGEST", actor="agent@endpoint",
            resource_type="evidence", resource_id="EV-01",
            details={"collector": "process"}, case_id=audit_case
        )
        assert entry2.previous_event_hash == entry1.event_hash

        entry3 = IntegrityService.record_audit_event(
            db, action="REPORT_GENERATE", actor="lead@soc.gov",
            resource_type="report", resource_id="REP-01",
            details={"ver": "1.0"}, case_id=audit_case
        )
        assert entry3.previous_event_hash == entry2.event_hash

        is_valid, findings = IntegrityService.verify_audit_chain(db, audit_case)
        assert is_valid is True
        assert len(findings) == 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 5: Audit Chain Tamper Detection
# ---------------------------------------------------------------------------
def test_audit_chain_tamper_detection():
    """Verify that tampering with an intermediate audit log event breaks the chain and is detected."""
    db = SessionLocal()
    try:
        audit_case = f"CASE-AUD-TAMPER-{uuid.uuid4().hex[:6]}"

        entry1 = IntegrityService.record_audit_event(
            db, action="TASK_CREATE", actor="user1", resource_type="task",
            resource_id="T1", details={"data": 1}, case_id=audit_case
        )
        entry2 = IntegrityService.record_audit_event(
            db, action="TASK_EXECUTE", actor="user2", resource_type="task",
            resource_id="T1", details={"data": 2}, case_id=audit_case
        )

        # Tamper with entry 1's action in the database
        entry1.action = "TASK_MALICIOUS_TAMPER"
        db.commit()

        is_valid, findings = IntegrityService.verify_audit_chain(db, audit_case)
        assert is_valid is False
        assert len(findings) > 0
        assert "AUDIT_RECORD_TAMPERED" in [f.get("issue") for f in findings]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 6: Security Event Creation & Indexing
# ---------------------------------------------------------------------------
def test_security_event_creation_and_indexing():
    """Verify that SecurityEvent entries are correctly recorded with all integrity fields."""
    db = SessionLocal()
    try:
        sec_event = IntegrityService.record_security_event(
            db=db,
            case_id=TEST_CASE_P7,
            event_type="UNAUTHORIZED_ACCESS",
            severity="HIGH",
            details={"reason": "Role boundary violation on evidence seal"},
            actor="operator@subcontractor.local",
            resource_type="evidence",
            resource_id="EV-SEALED-01"
        )
        assert sec_event.id.startswith("SECEV-")
        assert sec_event.severity == "HIGH"
        assert sec_event.event_type == "UNAUTHORIZED_ACCESS"
        assert sec_event.resolved is False

        # Query back from DB
        fetched = db.query(SecurityEvent).filter(SecurityEvent.id == sec_event.id).first()
        assert fetched is not None
        assert fetched.event_type == "UNAUTHORIZED_ACCESS"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 7: Security Event Filtering API
# ---------------------------------------------------------------------------
def test_security_event_filtering_api():
    """Verify that the /api/security/events REST endpoint correctly filters by query parameters."""
    db = SessionLocal()
    try:
        filter_case = f"CASE-FILT-{uuid.uuid4().hex[:6]}"
        e1 = IntegrityService.record_security_event(
            db=db, case_id=filter_case, event_type="REPLAY_ATTACK",
            severity="CRITICAL", details={"reason": "Token replay"}, actor="tester"
        )
        e2 = IntegrityService.record_security_event(
            db=db, case_id=filter_case, event_type="CONFIG_TAMPER",
            severity="MEDIUM", details={"reason": "Config drift"}, actor="tester"
        )
    finally:
        db.close()

    # Filter by case_id
    resp = client.get(f"/api/security/events?case_id={filter_case}")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2

    # Filter by severity
    resp = client.get(f"/api/security/events?case_id={filter_case}&severity=CRITICAL")
    assert resp.status_code == 200
    crit_items = resp.json()
    assert len(crit_items) == 1
    assert crit_items[0]["event_type"] == "REPLAY_ATTACK"

    # Filter by event_type
    resp = client.get(f"/api/security/events?case_id={filter_case}&event_type=CONFIG_TAMPER")
    assert resp.status_code == 200
    config_items = resp.json()
    assert len(config_items) == 1
    assert config_items[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Test 8: Agent Identity Fingerprint Verification
# ---------------------------------------------------------------------------
def test_agent_identity_fingerprint_verification():
    """Verify deterministic calculation and validation of agent identity fingerprints."""
    fp1 = IntegrityService.compute_agent_fingerprint("A1", "HOST1", "Linux", "Ubuntu 22.04", "x86_64")
    fp2 = IntegrityService.compute_agent_fingerprint("A1", "HOST1", "Linux", "Ubuntu 22.04", "x86_64")
    assert fp1 == fp2
    assert len(fp1) == 64

    # Mismatch with different architecture
    fp3 = IntegrityService.compute_agent_fingerprint("A1", "HOST1", "Linux", "Ubuntu 22.04", "aarch64")
    assert fp1 != fp3


# ---------------------------------------------------------------------------
# Test 9: Agent Identity Mismatch Rejection
# ---------------------------------------------------------------------------
def test_agent_identity_mismatch_rejection():
    """Verify that an agent with forged identity or modified capabilities fails verification."""
    db = SessionLocal()
    try:
        agent_id = f"AGENT-SPOOF-{uuid.uuid4().hex[:6]}"
        legit_fp = IntegrityService.compute_agent_fingerprint(agent_id, "LEGIT-HOST", "Windows", "11", "x86_64")
        legit_cap = IntegrityService.compute_capability_fingerprint(["process_collector"])

        agent = Agent(
            id=agent_id,
            hostname="SPOOFED-HOST",  # Tampered hostname vs legit_fp
            platform="Windows",
            os_version="11",
            architecture="x86_64",
            status="online",
            identity_fingerprint=legit_fp,
            capability_fingerprint=legit_cap,
            capabilities=["process_collector", "unauthorized_collector"]  # Modified capabilities!
        )
        db.add(agent)
        db.commit()

        det_result = TamperDetectionService.check_agent_fingerprint_integrity(db, agent_id)
        assert det_result["verified"] is False
        assert det_result["tampered"] is True
        assert "mismatch" in det_result["details"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 10: Task Integrity Verification
# ---------------------------------------------------------------------------
def test_task_integrity_verification():
    """Verify that a valid task with authentic instructions matches its computed task_hash."""
    instructions = "script TestForensic { process.list(); }"
    params = {"target": "all"}
    task_hash = IntegrityService.compute_task_hash(instructions, params, TEST_CASE_P7)

    db = SessionLocal()
    try:
        task_id = f"TASK-INT-{uuid.uuid4().hex[:6]}"
        task = Task(
            id=task_id,
            name="Forensic Task",
            case_id=TEST_CASE_P7,
            agent_id=TEST_AGENT_P7,
            script_source=instructions,
            plan_payload=params,
            task_hash=task_hash,
            status="pending"
        )
        db.add(task)
        db.commit()

        tamper_res = TamperDetectionService.check_task_integrity(db, task_id)
        assert tamper_res["tampered"] is False
        assert tamper_res["status"] == "VALID"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 11: Task Tampering Rejection
# ---------------------------------------------------------------------------
def test_task_tampering_rejection():
    """Verify that tampering with task instructions causes a task hash mismatch."""
    instructions = "script LegitForensic { network.list(); }"
    params = {}
    original_hash = IntegrityService.compute_task_hash(instructions, params, TEST_CASE_P7)

    db = SessionLocal()
    try:
        task_id = f"TASK-TAMP-{uuid.uuid4().hex[:6]}"
        task = Task(
            id=task_id,
            name="Forensic Task",
            case_id=TEST_CASE_P7,
            agent_id=TEST_AGENT_P7,
            script_source=instructions,
            plan_payload=params,
            task_hash=original_hash,
            status="pending"
        )
        db.add(task)
        db.commit()

        # Tamper instructions
        task.script_source = "script InjectedMalice { system.steal(); }"
        db.commit()

        tamper_check = TamperDetectionService.check_task_integrity(db, task.id)
        assert tamper_check["tampered"] is True
        assert tamper_check["status"] == "TAMPERED"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 12: Replay Detection
# ---------------------------------------------------------------------------
def test_replay_detection():
    """Verify that reusing an execution token or replay envelope is flagged and rejected."""
    token = f"TOKEN-EXEC-{uuid.uuid4().hex}"
    first_attempt = TamperDetectionService.check_replay_attack(token)
    assert first_attempt["is_replay"] is False

    # Second attempt with the exact same execution token
    second_attempt = TamperDetectionService.check_replay_attack(token)
    assert second_attempt["is_replay"] is True
    assert "Replay attack detected" in second_attempt["details"]


# ---------------------------------------------------------------------------
# Test 13: Playbook Hash Verification
# ---------------------------------------------------------------------------
def test_playbook_hash_verification():
    """Verify that playbook content_hash and approval_hash are computed deterministically."""
    db = SessionLocal()
    try:
        actions = [
            {"step_number": 1, "action_type": "collect.processes", "target_agent_id": TEST_AGENT_P7, "parameters": {}}
        ]
        content_hash = IntegrityService.compute_playbook_hash("Isolate Malicious Endpoint", actions)
        pb_id = f"PB-VERIF-{uuid.uuid4().hex[:6]}"
        approval_hash = IntegrityService.compute_approval_hash(playbook_id=pb_id, content_hash=content_hash, approver_email="ciso@defense.gov")

        playbook = Playbook(
            id=pb_id,
            case_id=TEST_CASE_P7,
            name="Isolate Malicious Endpoint",
            description="Defensive isolation playbook",
            status="APPROVED",
            content_hash=content_hash,
            approval_hash=approval_hash,
            definition_json={"actions": actions}
        )
        db.add(playbook)
        db.commit()

        verif = IntegrityService.verify_playbook_integrity(db, playbook.id)
        assert verif["verified"] is True
        assert verif["content_hash"] == content_hash
        assert verif["approval_hash"] == approval_hash
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 14: Modified Playbook Execution Rejection
# ---------------------------------------------------------------------------
def test_modified_playbook_execution_rejection():
    """Verify that executing a playbook whose actions were tampered after approval raises PLAYBOOK_INTEGRITY_VIOLATION."""
    db = SessionLocal()
    try:
        # Create and approve a legitimate playbook via PlaybookService
        actions_data = [
            {"step_number": 1, "action_type": "collect.processes", "target_agent_id": TEST_AGENT_P7, "parameters": {}}
        ]
        pb = PlaybookService.create_playbook(
            db=db,
            case_id=TEST_CASE_P7,
            name="Tamper Test Playbook",
            actions_data=actions_data,
            description="Valid playbook to test tamper barrier"
        )
        PlaybookService.approve_playbook(db, pb, "approver@gov.local", comment="Approved for triage")

        # Now tamper with the playbook action in the database
        action = db.query(PlaybookAction).filter(PlaybookAction.playbook_id == pb.id).first()
        action.action_type = "collect.network"
        db.commit()

        # Attempt to execute tampered playbook
        with pytest.raises(ValueError) as exc_info:
            PlaybookService.execute_playbook(db, pb.id, "operator@gov.local")

        assert "PLAYBOOK_INTEGRITY_VIOLATION" in str(exc_info.value)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 15: Configuration Fingerprint Verification
# ---------------------------------------------------------------------------
def test_configuration_fingerprint_verification():
    """Verify that ConfigIntegrityService computes a reproducible canonical configuration baseline."""
    fp1 = ConfigIntegrityService.get_baseline_fingerprint()
    fp2 = ConfigIntegrityService.get_baseline_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64

    # Verify status
    status = ConfigIntegrityService.verify_configuration_posture()
    assert status["drift_detected"] is False
    assert status["status"] == "SECURE"


# ---------------------------------------------------------------------------
# Test 16: Configuration Tamper Detection
# ---------------------------------------------------------------------------
def test_configuration_tamper_detection():
    """Verify that drifting configuration parameters trigger tamper detection and drift reporting."""
    try:
        # Inject configuration modification
        ConfigIntegrityService.simulate_drift_event("session_timeout_minutes", 99999)

        status = ConfigIntegrityService.verify_configuration_posture()
        assert status["drift_detected"] is True
        assert status["status"] == "CONFIG_TAMPERED"
        assert "session_timeout_minutes" in status["modified_parameters"]
    finally:
        # Restore configuration
        ConfigIntegrityService.set_simulated_drift(False)


# ---------------------------------------------------------------------------
# Test 17: Timestamp Anomaly Detection
# ---------------------------------------------------------------------------
def test_timestamp_anomaly_detection():
    """Verify that events with future timestamps or backward time drift trigger anomaly detection."""
    now = datetime.now(timezone.utc)
    future_time = now + timedelta(hours=2)

    # Future timestamp check
    anomaly_res = TimeIntegrityService.check_temporal_ordering(now, future_time)
    assert anomaly_res["is_anomaly"] is True
    assert anomaly_res["anomaly_type"] == "FUTURE_TIMESTAMP"

    # Backward clock drift
    t_first = now
    t_second = now - timedelta(seconds=120)
    drift_res = TimeIntegrityService.check_temporal_ordering(t_first, t_second)
    assert drift_res["is_anomaly"] is True
    assert drift_res["anomaly_type"] == "BACKWARD_TIME_DRIFT"


# ---------------------------------------------------------------------------
# Test 18: Report Integrity Manifest Verification
# ---------------------------------------------------------------------------
def test_report_integrity_manifest_verification():
    """Verify canonical report manifest generation, hash binding, and verification."""
    db = SessionLocal()
    try:
        report_id = f"REP-P7-{uuid.uuid4().hex[:6]}"
        manifest = IntegrityService.generate_report_manifest(
            report_id=report_id,
            case_id=TEST_CASE_P7,
            report_content={"title": "Comprehensive Forensics Findings", "summary": "Evidence intact."},
            evidence_hashes=["hash1", "hash2"],
            audit_chain_hash="0" * 64,
            investigation_hash="0" * 64,
            cti_hash="0" * 64
        )
        assert manifest["manifest_hash"] is not None
        assert manifest["evidence_count"] == 2

        # Persist report with manifest
        rep = Report(
            id=report_id,
            case_id=TEST_CASE_P7,
            title="Comprehensive Digital Forensics Findings",
            content_json={"title": "Comprehensive Forensics Findings", "summary": "Evidence intact."},
            report_content_hash=manifest["content_sha256"],
            manifest_json=manifest
        )
        db.add(rep)
        db.commit()

        verif = IntegrityService.verify_report_integrity(db, report_id)
        assert verif["verified"] is True
        assert verif["content_hash"] == manifest["content_sha256"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 19: Role-Based Authorization Boundaries
# ---------------------------------------------------------------------------
def test_role_based_authorization_boundaries():
    """Verify strict access boundaries for ADMIN, ANALYST, OPERATOR, and AGENT roles."""
    # ADMIN has full access
    assert SecurityPolicyService.check_permission("ADMIN", "EVIDENCE_SEAL") is True
    assert SecurityPolicyService.check_permission("ADMIN", "PLAYBOOK_EXECUTE") is True

    # ANALYST can analyze and generate reports, but cannot approve playbooks without peer
    assert SecurityPolicyService.check_permission("ANALYST", "REPORT_GENERATE") is True
    assert SecurityPolicyService.check_permission("ANALYST", "CONFIG_MODIFY") is False

    # OPERATOR cannot seal evidence or approve playbooks
    assert SecurityPolicyService.check_permission("OPERATOR", "PLAYBOOK_EXECUTE") is True
    assert SecurityPolicyService.check_permission("OPERATOR", "PLAYBOOK_APPROVE") is False

    # AGENT has minimal submit permissions
    assert SecurityPolicyService.check_permission("AGENT", "EVIDENCE_SUBMIT") is True
    assert SecurityPolicyService.check_permission("AGENT", "TASK_CREATE") is False


# ---------------------------------------------------------------------------
# Test 20: Sensitive Data Redaction
# ---------------------------------------------------------------------------
def test_sensitive_data_redaction():
    """Verify that recursive redaction sanitizes API keys, passwords, and private tokens."""
    raw_payload = {
        "user": "analyst_1",
        "api_key": "sk-secret-token-12345",
        "credentials": {
            "password": "SuperSecretPassword!",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEv...",
        },
        "nested": [
            {"token": "bearer-token-abc"},
            {"safe_field": "forensic_log"}
        ]
    }
    redacted = SecurityPolicyService.redact_sensitive_data(raw_payload)

    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["credentials"]["password"] == "[REDACTED]"
    assert redacted["credentials"]["private_key"] == "[REDACTED]"
    assert redacted["nested"][0]["token"] == "[REDACTED]"
    assert redacted["nested"][1]["safe_field"] == "forensic_log"


# ---------------------------------------------------------------------------
# Test 21: Security Policy Allow
# ---------------------------------------------------------------------------
def test_security_policy_allow():
    """Verify that authorized operations with valid parameters return ALLOW."""
    decision = SecurityPolicyService.evaluate_action(
        actor_role="ANALYST",
        action="EVIDENCE_VERIFY",
        resource_type="evidence",
        resource_id="EV-100",
        context={"case_status": "INVESTIGATING"}
    )
    assert decision["decision"] == "ALLOW"


# ---------------------------------------------------------------------------
# Test 22: Security Policy Deny
# ---------------------------------------------------------------------------
def test_security_policy_deny():
    """Verify that unauthorized operations or attempts to alter immutable evidence return DENY."""
    # Operator attempting to modify security configuration
    decision = SecurityPolicyService.evaluate_action(
        actor_role="OPERATOR",
        action="CONFIG_MODIFY",
        resource_type="configuration",
        resource_id="global_settings",
        context={}
    )
    assert decision["decision"] == "DENY"
    assert "not authorized" in decision["reason"].lower()

    # Anyone attempting to delete sealed evidence
    tamper_decision = SecurityPolicyService.evaluate_action(
        actor_role="ADMIN",
        action="EVIDENCE_DELETE",
        resource_type="evidence",
        resource_id="EV-SEALED",
        context={"sealed": True}
    )
    assert tamper_decision["decision"] == "DENY"
    assert "Immutable resource" in tamper_decision["reason"]


# ---------------------------------------------------------------------------
# Test 23: Security Policy Requires Approval
# ---------------------------------------------------------------------------
def test_security_policy_requires_approval():
    """Verify that high-impact containment or isolation actions return REQUIRES_APPROVAL."""
    decision = SecurityPolicyService.evaluate_action(
        actor_role="ANALYST",
        action="HOST_ISOLATION",
        resource_type="endpoint",
        resource_id="HOST-WIN-01",
        context={"requires_dual_authorization": True}
    )
    assert decision["decision"] == "REQUIRES_APPROVAL"


# ---------------------------------------------------------------------------
# Test 24: JOCKY Integrity Primitive Compilation
# ---------------------------------------------------------------------------
def test_jocky_integrity_primitive_compilation():
    """Verify that JOCKY language parser and analyzer compile verify.* primitives correctly into execution plans."""
    script = '''
    script DefensiveIntegrityPipeline {
        evidence_id = "EV-2026-001";
        verify.evidence(evidence_id);
        verify.audit("CASE-2026-001");
        verify.agent("AGENT-01");
        evidence.collect();
    }
    '''
    tokens = Lexer(script).tokenize()
    program = Parser(tokens).parse()
    SemanticAnalyzer().analyze(program)

    codegen = SafeCodeGenerator()
    plan = codegen.generate_plan(program)

    assert len(plan["scripts"]) == 1
    steps = plan["scripts"][0]["steps"]
    step_functions = [s.get("function") for s in steps if s.get("function")]

    assert "verify.evidence" in step_functions
    assert "verify.audit" in step_functions
    assert "verify.agent" in step_functions
    step_types = [s.get("type") for s in steps]
    assert "seal_evidence" in step_types


# ---------------------------------------------------------------------------
# Test 25: Unsupported Security Primitive Rejection
# ---------------------------------------------------------------------------
def test_unsupported_security_primitive_rejection():
    """Verify that unauthorized, simulated, or malicious function invocations are rejected by SemanticAnalyzer."""
    malicious_script = '''
    script MaliciousIntegrityBypass {
        verify.bypass_kernel_audit();
    }
    '''
    tokens = Lexer(malicious_script).tokenize()
    program = Parser(tokens).parse()
    analyzer = SemanticAnalyzer()

    with pytest.raises(SemanticError) as exc_info:
        analyzer.analyze(program)
    assert "Unauthorized or unknown forensic function 'verify.bypass_kernel_audit'" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 26: Security API Authorization & Headers
# ---------------------------------------------------------------------------
def test_security_api_authorization_and_headers():
    """Verify that responses from FastAPI include secure defense-in-depth HTTP headers."""
    resp = client.get("/api/security/configuration")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


# ---------------------------------------------------------------------------
# Test 27: Simulated Tamper Event Generation
# ---------------------------------------------------------------------------
def test_simulated_tamper_event_generation():
    """Verify that the synthetic event generation script creates tagged [SIMULATED SECURITY EVENT] instances."""
    results = run_all_simulations(TEST_CASE_P7)
    assert len(results) == 7

    for event in results:
        assert event["id"].startswith("SECEV-")
        assert event["case_id"] == TEST_CASE_P7
        assert "[SIMULATED SECURITY EVENT]" in event["details"]["simulation_note"]
        assert event["details"]["defensive_response"] is not None

    # Verify that individual simulators execute deterministically
    ev_tamper = simulate_evidence_tamper(TEST_CASE_P7)
    assert ev_tamper["event_type"] == "EVIDENCE_TAMPER_DETECTED"

    replay = simulate_replay_attack(TEST_CASE_P7)
    assert replay["event_type"] == "REPLAY_ATTEMPT_DETECTED"


# ---------------------------------------------------------------------------
# Test 28: Complete Case Integrity Verification Workflow
# ---------------------------------------------------------------------------
def test_complete_case_integrity_verification_workflow():
    """Verify that the complete 7-control scorecard evaluates, reports all controls, and calculates an integrity score."""
    resp = client.get(f"/api/security/integrity/{TEST_CASE_P7}")
    assert resp.status_code == 200

    scorecard = resp.json()
    assert scorecard["case_id"] == TEST_CASE_P7
    assert "verified_controls" in scorecard
    assert "total_controls" in scorecard
    assert scorecard["total_controls"] == 7
    assert "score_label" in scorecard
    assert "status" in scorecard
    assert len(scorecard["controls"]) == 7

    control_keys = list(scorecard["controls"].keys())
    assert "evidence_integrity" in control_keys
    assert "audit_integrity" in control_keys
    assert "agent_identity" in control_keys
    assert "task_integrity" in control_keys
    assert "playbook_integrity" in control_keys
    assert "configuration_integrity" in control_keys
    assert "report_integrity" in control_keys
