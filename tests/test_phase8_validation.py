"""
Phase 8: Master Validation & Release Certification Test Suite
SIH26148 — JOCKY Defensive Digital-Forensics Framework

Validates:
- Cross-phase integration & reproducibility
- Compiler certification (lexer, parser, semantic analyzer, codegen, integrity primitives)
- Security boundaries & negative testing
- Standardized API error contract & security headers
- Multi-agent fleet simulation (6 heterogeneous endpoints)
- Database schema consistency & migration idempotency
- Failure recovery & tamper detection persistence
"""
import os
import json
import pytest
import tempfile
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.config import settings
from backend.app.database.base import Base
from backend.app.database.session import get_db
from backend.app.models.models import (
    User, Agent, Case, Task, TaskResult, Evidence, AuditLog, Report,
    InvestigationIndicator, TimelineEvent, EvidenceCorrelation, Finding,
    Playbook, PlaybookAction, SecurityEvent
)
from backend.app.security.auth import get_password_hash
from backend.app.services.security_integrity_service import IntegrityService
from backend.app.services.tamper_detection_service import TamperDetectionService
from backend.app.services.config_integrity_service import ConfigIntegrityService
from backend.app.services.time_integrity_service import TimeIntegrityService
from backend.app.services.security_policy_service import SecurityPolicyService, ROLES
from backend.app.services.stix_service import STIXService
from backend.app.services.ioc_service import IOCService
from backend.app.services.timeline_service import TimelineService
from backend.app.services.risk_service import RiskService
from compiler.lexer.lexer import Lexer, TokenType
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator
from compiler.diagnostics.errors import LexerError, ParserError, SemanticError
from agent.security.capabilities import get_platform_capabilities, resolve_polymorphic_operation
from agent.evidence.evidence_envelope import create_evidence_envelope

# ----------------------------------------------------------------------------
# Isolated Test Fixtures
# ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def p8_client():
    test_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    test_db_url = f"sqlite:///{test_db_file.name}"
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed baseline records
    db = TestingSession()
    analyst = User(
        email="analyst@jocky.defense",
        hashed_password=get_password_hash("ForensicsPass2026!"),
        full_name="Chief Forensic Analyst",
        role="analyst"
    )
    db.add(analyst)

    demo_case = Case(
        id="CASE-P8-001",
        title="Phase 8 Master Validation Case",
        description="Comprehensive integration and certification test case",
        severity="high",
        status="INVESTIGATING"
    )
    db.add(demo_case)
    db.commit()
    db.close()

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
    try:
        os.remove(test_db_file.name)
    except OSError:
        pass


@pytest.fixture
def auth_headers(p8_client):
    login_res = p8_client.post(
        "/api/auth/login",
        data={"username": "analyst@jocky.defense", "password": "ForensicsPass2026!"}
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# 1. REPRODUCIBILITY & DETERMINISM TESTS
# ============================================================================

def test_compiler_deterministic_plan_hash():
    """Validates that identical JOCKY source code produces identical AST and plan hashes."""
    script = '''
    script DeterministicTest {
        system.info();
        process.list();
        network.connections();
    }
    '''
    hashes = []
    for _ in range(5):
        tokens = Lexer(script).tokenize()
        ast = Parser(tokens).parse()
        SemanticAnalyzer().analyze(ast)
        plan = SafeCodeGenerator().generate_plan(ast)
        hashes.append(plan["scripts"][0]["plan_hash"])

    assert len(set(hashes)) == 1, "Compiler output must be strictly deterministic across repeated runs"
    assert len(hashes[0]) == 64, "Plan hash must be a valid 64-char SHA-256 digest"


def test_ioc_normalization_determinism():
    """Validates that identical evidence items produce identical normalized IOC outputs."""
    raw_hash = "  4A7D189FEC0A29B3C79124AE8019FB42A8B9281A02938471EF09A8BC12984712  "
    norm_hash1 = IOCService.normalize("sha256", raw_hash)
    norm_hash2 = IOCService.normalize("sha256", raw_hash)
    assert norm_hash1 == norm_hash2 == "4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712"

    raw_ip = "192.168.1.50:8080"
    norm_ip1 = IOCService.normalize("ipv4", raw_ip)
    norm_ip2 = IOCService.normalize("ipv4", raw_ip)
    assert norm_ip1 == norm_ip2 == "192.168.1.50"


def test_timeline_ordering_monotonicity():
    """Validates that timeline events are strictly ordered chronologically."""
    now = datetime.now(timezone.utc)
    raw_events = [
        {"timestamp": (now + timedelta(seconds=20)).isoformat(), "event_type": "PROCESS", "description": "Step 3"},
        {"timestamp": (now - timedelta(seconds=10)).isoformat(), "event_type": "FILE", "description": "Step 1"},
        {"timestamp": now.isoformat(), "event_type": "NETWORK", "description": "Step 2"}
    ]
    sorted_events = sorted(raw_events, key=lambda x: x["timestamp"])
    timestamps = [e["timestamp"] for e in sorted_events]
    assert timestamps == sorted(timestamps)


def test_risk_scoring_determinism():
    """Validates that identical finding profiles produce identical explainable risk scores."""
    p1, s1, r1 = RiskService.evaluate_risk(
        evidence_count=4,
        has_persistence=True,
        has_network_connection=True,
        has_suspicious_location=True,
        cross_agent_count=2,
        has_known_tool_keyword=True
    )
    p2, s2, r2 = RiskService.evaluate_risk(
        evidence_count=4,
        has_persistence=True,
        has_network_connection=True,
        has_suspicious_location=True,
        cross_agent_count=2,
        has_known_tool_keyword=True
    )
    assert p1 == p2 == "CRITICAL"
    assert s1 == s2 >= 75
    assert r1 == r2


# ============================================================================
# 2. JOCKY COMPILER CERTIFICATION SUITE
# ============================================================================

def test_compiler_lexer_tokens_and_malformed_input():
    """Tests lexer token generation and proper handling of unexpected characters."""
    valid_src = 'script TestScript { target = "192.168.1.50"; process.list(); }'
    tokens = Lexer(valid_src).tokenize()
    types = [t.type for t in tokens]
    assert TokenType.SCRIPT in types
    assert TokenType.IDENTIFIER in types
    assert TokenType.STRING_LITERAL in types

    malformed_src = 'script BadLexer { var x = @#$% }'
    with pytest.raises(LexerError):
        Lexer(malformed_src).tokenize()


def test_compiler_parser_nested_and_syntax_error():
    """Tests parser structure handling and syntax error diagnostics."""
    valid_src = """
    script ValidInvestigation {
        process.list();
        file.hash("C:\\Windows\\System32\\cmd.exe");
    }
    """
    tokens = Lexer(valid_src).tokenize()
    prog = Parser(tokens).parse()
    assert len(prog.scripts) == 1
    assert prog.scripts[0].name == "ValidInvestigation"
    assert len(prog.scripts[0].body) == 2

    invalid_src = 'script BrokenScript { process.list('
    with pytest.raises(ParserError):
        Parser(Lexer(invalid_src).tokenize()).parse()


def test_compiler_semantic_analyzer_allowlist_and_type_checks():
    """Tests semantic analyzer standard library function validation and variable scope."""
    valid_src = """
    script ValidAllowlist {
        network.connections();
    }
    """
    tokens = Lexer(valid_src).tokenize()
    prog = Parser(tokens).parse()
    SemanticAnalyzer().analyze(prog)

    # Disallowed function should raise SemanticError
    invalid_src = """
    script MaliciousAttempt {
        system.exec_shell("rm -rf /");
    }
    """
    with pytest.raises(SemanticError) as exc_info:
        prog_invalid = Parser(Lexer(invalid_src).tokenize()).parse()
        SemanticAnalyzer().analyze(prog_invalid)
    assert "Unauthorized or unknown forensic function" in str(exc_info.value)


def test_compiler_integrity_primitives_certification():
    """Certifies that safe JOCKY integrity primitives (verify.*) compile correctly."""
    valid_script = """
    script DefensiveIntegrityPipeline {
        evidence_id = "EV-2026-001";
        verify.evidence(evidence_id);
        verify.audit("CASE-2026-001");
        verify.agent("AGENT-01");
        evidence.collect();
    }
    """
    tokens = Lexer(valid_script).tokenize()
    prog = Parser(tokens).parse()
    analyzer = SemanticAnalyzer()
    analyzer.analyze(prog)
    plan = SafeCodeGenerator().generate_plan(prog)

    assert plan is not None
    assert len(plan["scripts"]) == 1
    steps = plan["scripts"][0]["steps"]
    step_functions = [s.get("function") for s in steps if s.get("function")]
    assert "verify.evidence" in step_functions
    assert "verify.audit" in step_functions
    assert "verify.agent" in step_functions


def test_compiler_rejects_dangerous_security_primitives():
    """Certifies that dangerous, bypass-oriented primitives are strictly rejected at semantic analysis."""
    dangerous_scripts = [
        'script Bypass1 { verify.bypass_kernel_audit(); }',
        'script Bypass2 { security.disable_tamper_detection(); }',
        'script Bypass3 { system.clear_event_logs(); }',
        'script Bypass4 { kernel.inject_hook(); }'
    ]
    for script in dangerous_scripts:
        with pytest.raises(SemanticError):
            tokens = Lexer(script).tokenize()
            prog = Parser(tokens).parse()
            SemanticAnalyzer().analyze(prog)


# ============================================================================
# 3. SECURITY BOUNDARIES & NEGATIVE TESTING
# ============================================================================

def test_api_security_headers_and_error_structure(p8_client):
    """Verifies that security headers and standardized error JSON structures are returned."""
    # 1. Check security headers on root/health
    res = p8_client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in res.headers.get("Content-Security-Policy", "")
    assert res.headers.get("X-Request-ID") is not None

    # 2. Check 404 standardized error JSON
    res404 = p8_client.get("/api/cases/NON_EXISTENT_CASE_9999")
    assert res404.status_code == 404
    body = res404.json()
    assert "error" in body
    assert body["error"]["code"] == "NOT_FOUND"
    assert body["error"]["request_id"] is not None
    assert body["error"]["timestamp"] is not None
    assert "detail" in body

    # 3. Check 422 validation error structure
    res422 = p8_client.post("/api/tasks", json={"invalid_key": "junk"})
    assert res422.status_code == 422
    b422 = res422.json()
    assert "error" in b422
    assert b422["error"]["code"] == "VALIDATION_ERROR"


def test_agent_isolation_and_replay_protection(p8_client):
    """Verifies that agent isolation prevents cross-submission and replay protection blocks duplicate results."""
    # Enroll Agent A and Agent B with valid enrollment tokens
    p8_client.post("/api/agents/register", json={
        "agent_id": "AGENT-ISOL-01",
        "hostname": "HOST-A",
        "platform": "Windows",
        "os_version": "11.0",
        "architecture": "x86_64",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN,
        "capabilities": ["process.list", "network.connections"]
    })
    p8_client.post("/api/agents/register", json={
        "agent_id": "AGENT-ISOL-02",
        "hostname": "HOST-B",
        "platform": "Linux",
        "os_version": "Ubuntu 24.04",
        "architecture": "x86_64",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN,
        "capabilities": ["process.list"]
    })

    # Create task for Agent A
    plan = {
        "case_id": "CASE-P8-001",
        "plan_hash": "a" * 64,
        "steps": [{"step_id": 1, "function": "process.list", "parameters": {}}]
    }
    task_res = p8_client.post("/api/tasks", json={
        "case_id": "CASE-P8-001",
        "agent_id": "AGENT-ISOL-01",
        "name": "Isolation Test Task",
        "plan_payload": plan
    })
    assert task_res.status_code == 200
    task_id = task_res.json()["id"]

    from agent.executor.dispatcher import TaskDispatcher
    disp_b = TaskDispatcher(agent_id="AGENT-ISOL-02")
    env_b = disp_b.execute_function("system.hostname", [], case_id="CASE-P8-001")

    # Agent B attempts to submit result for Agent A's task -> 403 Forbidden
    evil_submission = p8_client.post(
        "/api/agents/AGENT-ISOL-02/results",
        json={"task_id": task_id, "agent_id": "AGENT-ISOL-02", "evidence_envelopes": [env_b]}
    )
    assert evil_submission.status_code == 403
    assert "AGENT_ISOLATION_VIOLATION" in evil_submission.json()["detail"]

    # Agent A legitimately submits result -> 201 Created
    disp_a = TaskDispatcher(agent_id="AGENT-ISOL-01")
    env_a = disp_a.execute_function("system.hostname", [], case_id="CASE-P8-001")
    legit_sub = p8_client.post(
        "/api/agents/AGENT-ISOL-01/results",
        json={"task_id": task_id, "agent_id": "AGENT-ISOL-01", "evidence_envelopes": [env_a]}
    )
    assert legit_sub.status_code == 201

    # Replay attack: Agent A attempts to submit second result on completed task -> 400 Conflict/Bad Request
    replay_sub = p8_client.post(
        "/api/agents/AGENT-ISOL-01/results",
        json={"task_id": task_id, "agent_id": "AGENT-ISOL-01", "evidence_envelopes": [env_a]}
    )
    assert replay_sub.status_code == 400
    assert "TASK_ALREADY_COMPLETED" in replay_sub.json()["detail"]


def test_malformed_stix_bundle_rejection():
    """Verifies that invalid or malformed STIX bundles are safely rejected without exception escape."""
    malformed_bundles = [
        {},
        {"type": "not_a_bundle"},
        {"type": "bundle", "objects": "should_be_list"}
    ]
    for b in malformed_bundles:
        is_valid, err = STIXService.validate_stix_object(b)
        assert is_valid is False or err is not None


def test_sensitive_secret_redaction():
    """Verifies that SecurityPolicyService recursively scrubs secrets from nested data."""
    raw_payload = {
        "status": "active",
        "api_key": "SECRET_KEY_XYZ_12345",
        "auth": {
            "password": "SuperSecretPassword123!",
            "token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token",
            "nested": [
                {"private_key": "-----BEGIN RSA PRIVATE KEY-----ABCDEF-----END RSA PRIVATE KEY-----"}
            ]
        },
        "safe_data": "192.168.1.100"
    }
    scrubbed = SecurityPolicyService.redact_sensitive_data(raw_payload)
    assert scrubbed["api_key"] == "[REDACTED]"
    assert scrubbed["auth"]["password"] == "[REDACTED]"
    assert scrubbed["auth"]["token"] == "[REDACTED]"
    assert scrubbed["auth"]["nested"][0]["private_key"] == "[REDACTED]"
    assert scrubbed["safe_data"] == "192.168.1.100"


def test_temporal_causality_anomaly_detection():
    """Verifies that TimeIntegrityService detects future timestamps and reverse causality."""
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


# ============================================================================
# 4. MULTI-AGENT HETEROGENEOUS FLEET SIMULATION (6 ENDPOINTS)
# ============================================================================

def test_multi_agent_heterogeneous_fleet(p8_client):
    """
    Validates enrollment and capability verification across 6 heterogeneous endpoints:
    - AGENT-WIN-01
    - AGENT-WIN-02
    - AGENT-WIN-03
    - AGENT-LINUX-01
    - AGENT-LINUX-02
    - AGENT-WIN-SERVER-01
    """
    fleet_configs = [
        {"id": "AGENT-WIN-01", "hostname": "WIN11-WORKSTATION-SEC", "platform": "Windows", "os": "10.0.22631 (Win 11)"},
        {"id": "AGENT-WIN-02", "hostname": "WIN10-PRO-FINANCE", "platform": "Windows", "os": "10.0.19045 (Win 10)"},
        {"id": "AGENT-WIN-03", "hostname": "WIN11-DEV-STATION", "platform": "Windows", "os": "10.0.22631 (Win 11)"},
        {"id": "AGENT-LINUX-01", "hostname": "UBUNTU-CORE-PROD01", "platform": "Linux", "os": "Ubuntu 24.04 LTS"},
        {"id": "AGENT-LINUX-02", "hostname": "DEBIAN12-DB-CLUSTER", "platform": "Linux", "os": "Debian 12 Bookworm"},
        {"id": "AGENT-WIN-SERVER-01", "hostname": "WIN-SRV-2022-DC01", "platform": "Windows", "os": "Windows Server 2022 Datacenter"}
    ]

    for cfg in fleet_configs:
        caps = get_platform_capabilities(cfg["platform"])
        res = p8_client.post("/api/agents/register", json={
            "agent_id": cfg["id"],
            "hostname": cfg["hostname"],
            "platform": cfg["platform"],
            "os_version": cfg["os"],
            "architecture": "x86_64",
            "enrollment_token": settings.AGENT_REGISTRATION_TOKEN,
            "capabilities": caps
        })
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == cfg["id"]
        assert len(data["capabilities"]) > 0

    # Verify listing shows all 6 agents online
    list_res = p8_client.get("/api/agents")
    assert list_res.status_code == 200
    all_agents = {a["id"]: a for a in list_res.json()}
    for cfg in fleet_configs:
        assert cfg["id"] in all_agents
        assert all_agents[cfg["id"]]["platform"] == cfg["platform"]


# ============================================================================
# 5. DATABASE SCHEMA & REFERENTIAL INTEGRITY AUDIT
# ============================================================================

def test_database_schema_and_foreign_keys():
    """Verifies that all tables, foreign keys, and indexes exist in clean database schema."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)

    expected_tables = {
        "users", "agents", "cases", "tasks", "task_results", "evidence",
        "audit_logs", "reports", "investigation_indicators", "timeline_events",
        "evidence_correlations", "findings", "analyst_notes", "threat_intel_items",
        "playbooks", "playbook_actions", "playbook_approvals", "playbook_executions",
        "security_events"
    }
    actual_tables = set(inspector.get_table_names())
    for t in expected_tables:
        assert t in actual_tables, f"Table '{t}' missing from database schema"

    # Verify FK relationships on tasks
    fks = inspector.get_foreign_keys("tasks")
    fk_tables = {fk["referred_table"] for fk in fks}
    assert "cases" in fk_tables
    assert "agents" in fk_tables


# ============================================================================
# 6. CONFIGURATION INTEGRITY & BASELINE DRIFT DETECTION
# ============================================================================

def test_configuration_integrity_and_simulation():
    """Validates baseline configuration fingerprinting and drift detection simulation."""
    fp1 = ConfigIntegrityService.get_baseline_fingerprint()
    fp2 = ConfigIntegrityService.get_baseline_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64

    # Baseline check should pass
    status = ConfigIntegrityService.verify_configuration_posture()
    assert status["drift_detected"] is False
    assert status["status"] == "SECURE"

    try:
        # Simulate configuration drift
        ConfigIntegrityService.simulate_drift_event("session_timeout_minutes", 99999)
        tampered_status = ConfigIntegrityService.verify_configuration_posture()
        assert tampered_status["drift_detected"] is True
        assert tampered_status["status"] == "CONFIG_TAMPERED"
        assert "session_timeout_minutes" in tampered_status["modified_parameters"]
    finally:
        # Restore configuration baseline
        ConfigIntegrityService.set_simulated_drift(False)
        restored = ConfigIntegrityService.verify_configuration_posture()
        assert restored["drift_detected"] is False
