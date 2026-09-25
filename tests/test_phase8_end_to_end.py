"""
Phase 8: Complete End-to-End SIH Workflow Validation Test
SIH26148 — JOCKY Defensive Digital-Forensics Framework

Implements an automated 26-step complete workflow validating:
1. JOCKY source creation
2. JOCKY lexical analysis
3. Parsing
4. Semantic validation
5. Safe compilation
6. Task creation
7. Agent enrollment
8. Capability verification
9. Task dispatch
10. Synthetic evidence collection
11. Evidence sealing
12. Evidence hash verification
13. IOC extraction
14. Timeline generation
15. Investigation creation
16. Threat-intelligence correlation
17. Finding generation
18. Analyst note
19. Playbook creation
20. Analyst approval
21. Defensive simulated response
22. Audit logging
23. Integrity verification
24. Report generation
25. Report verification
26. Final case summary
"""
import os
import json
import pytest
import tempfile
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
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
from backend.app.services.ioc_service import IOCService
from backend.app.services.timeline_service import TimelineService
from backend.app.services.finding_service import FindingService
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService, DemoThreatIntelProvider
from backend.app.services.playbook_service import PlaybookService
from compiler.lexer.lexer import Lexer, TokenType
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator
from agent.security.capabilities import get_platform_capabilities
from agent.executor.dispatcher import TaskDispatcher


@pytest.fixture(scope="module")
def e2e_client():
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

    # Baseline seed
    db = TestingSession()
    analyst = User(
        email="analyst@jocky.defense",
        hashed_password=get_password_hash("ForensicsPass2026!"),
        full_name="Lead Forensic Analyst",
        role="analyst"
    )
    db.add(analyst)
    db.commit()
    db.close()

    with TestClient(app) as client:
        yield client, TestingSession

    app.dependency_overrides.clear()
    try:
        os.remove(test_db_file.name)
    except OSError:
        pass


def test_complete_26_step_sih_investigation_lifecycle(e2e_client):
    """Executes the full 26-step defensive digital forensics lifecycle."""
    client, TestingSession = e2e_client
    case_id = "CASE-2026-E2E"
    agent_id = "AGENT-WIN-E2E-01"

    # ========================================================================
    # Step 1: JOCKY Source Creation
    # ========================================================================
    jocky_source = '''
    script FullTriageWorkflow {
        system.info();
        process.list();
        network.connections();
        persistence.startup();
    }
    '''
    assert len(jocky_source.strip()) > 0

    # ========================================================================
    # Step 2: JOCKY Lexical Analysis
    # ========================================================================
    lexer = Lexer(jocky_source)
    tokens = lexer.tokenize()
    assert len(tokens) > 5
    assert tokens[0].type == TokenType.SCRIPT

    # ========================================================================
    # Step 3: Parsing (AST Generation)
    # ========================================================================
    parser = Parser(tokens)
    program = parser.parse()
    assert len(program.scripts) == 1
    assert program.scripts[0].name == "FullTriageWorkflow"
    assert len(program.scripts[0].body) == 4

    # ========================================================================
    # Step 4: Semantic Validation
    # ========================================================================
    analyzer = SemanticAnalyzer()
    analyzer.analyze(program)

    # ========================================================================
    # Step 5: Safe Compilation (Execution Plan)
    # ========================================================================
    codegen = SafeCodeGenerator()
    execution_plan = codegen.generate_plan(program)
    assert "scripts" in execution_plan
    plan_hash = execution_plan["scripts"][0]["plan_hash"]
    assert len(plan_hash) == 64

    # ========================================================================
    # Step 6: Case & Task Creation
    # ========================================================================
    # Create Case
    case_res = client.post("/api/cases", json={
        "id": case_id,
        "title": "Operation Sovereign Shield Triage",
        "description": "End-to-end multi-stage forensic analysis and response.",
        "severity": "high",
        "status": "OPEN"
    })
    assert case_res.status_code == 201

    # ========================================================================
    # Step 7: Agent Enrollment
    # ========================================================================
    caps = get_platform_capabilities("Windows")
    reg_res = client.post("/api/agents/register", json={
        "agent_id": agent_id,
        "hostname": "SEC-WORKSTATION-01",
        "platform": "Windows",
        "os_version": "Windows 11 Enterprise 23H2",
        "architecture": "x86_64",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN,
        "capabilities": caps
    })
    assert reg_res.status_code == 200
    agent_data = reg_res.json()
    assert agent_data["id"] == agent_id

    # Create Task assigned to enrolled agent
    task_res = client.post("/api/tasks", json={
        "case_id": case_id,
        "agent_id": agent_id,
        "name": "Live Forensic Triage",
        "plan_payload": execution_plan
    })
    assert task_res.status_code == 200
    task_id = task_res.json()["id"]

    # ========================================================================
    # Step 8: Capability Verification
    # ========================================================================
    caps_res = client.get(f"/api/agents/{agent_id}/capabilities")
    assert caps_res.status_code == 200
    declared_caps = caps_res.json()["capabilities"]
    assert "process.list" in declared_caps
    assert "network.connections" in declared_caps

    # ========================================================================
    # Step 9: Task Dispatch (Atomic Lease)
    # ========================================================================
    dispatched = client.get(f"/api/agents/{agent_id}/tasks")
    assert dispatched.status_code == 200
    tasks_leased = dispatched.json()
    assert len(tasks_leased) >= 1
    assert any(t["id"] == task_id for t in tasks_leased)

    # ========================================================================
    # Step 10: Synthetic Evidence Collection
    # ========================================================================
    dispatcher = TaskDispatcher(agent_id=agent_id)
    # Collect system information
    env_sys = dispatcher.execute_function("system.info", [], case_id=case_id)
    # Collect process list
    env_proc = dispatcher.execute_function("process.list", [], case_id=case_id)
    # Collect persistence artifacts
    env_persist = dispatcher.execute_function("persistence.startup", [], case_id=case_id)
    assert env_sys is not None
    assert env_proc is not None
    assert env_persist is not None

    # ========================================================================
    # Step 11: Evidence Sealing (Submission to Backend)
    # ========================================================================
    submit_res = client.post(f"/api/agents/{agent_id}/results", json={
        "task_id": task_id,
        "agent_id": agent_id,
        "evidence_envelopes": [env_sys, env_proc, env_persist]
    })
    assert submit_res.status_code == 201

    # Verify evidence stored in DB
    db = TestingSession()
    ev_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    assert len(ev_items) >= 2
    ev1 = ev_items[0]
    db.close()

    # ========================================================================
    # Step 12: Evidence Hash Verification
    # ========================================================================
    verify_ev_res = client.post(f"/api/security/verify/evidence/{ev1.id}")
    assert verify_ev_res.status_code == 200
    ev_verif = verify_ev_res.json()
    assert ev_verif["status"] == "VERIFIED"
    assert ev_verif["is_valid"] is True

    # ========================================================================
    # Step 13: IOC Extraction & Normalization
    # ========================================================================
    db = TestingSession()
    for ev in ev_items:
        IOCService.extract_from_evidence(ev, db)
    db.commit()

    iocs = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id).all()
    assert len(iocs) > 0
    db.close()

    # ========================================================================
    # Step 14: Timeline Generation
    # ========================================================================
    db = TestingSession()
    for ev in ev_items:
        TimelineService.synthesize_events_from_evidence(ev, db)
    db.commit()

    timeline = TimelineService.get_timeline(case_id=case_id, db=db)
    assert len(timeline) >= 2
    db.close()

    # ========================================================================
    # Step 15: Investigation Creation & Summary
    # ========================================================================
    summary_res = client.get(f"/api/investigations/{case_id}/summary")
    assert summary_res.status_code == 200
    inv_summary = summary_res.json()
    assert inv_summary["total_evidence"] >= 2
    assert inv_summary["total_indicators"] >= 1
    assert inv_summary["total_timeline_events"] >= 2

    # ========================================================================
    # Step 16: Threat-Intelligence Correlation
    # ========================================================================
    # Ingest synthetic demo threat intel
    demo_provider = DemoThreatIntelProvider()
    demo_items = demo_provider.fetch_items()
    db = TestingSession()
    ThreatIntelligenceService.import_intel_items(db, demo_items)
    db.commit()

    intel_matches = ThreatIntelligenceService.correlate_case_with_threat_intel(db, case_id)
    assert "matches" in intel_matches
    assert intel_matches["total_intel_items"] >= 1
    db.close()

    # ========================================================================
    # Step 17: Finding Generation
    # ========================================================================
    db = TestingSession()
    findings = FindingService.generate_findings_for_case(case_id, db)
    assert len(findings) >= 1
    finding_1 = findings[0]
    assert finding_1.priority in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert finding_1.priority_score > 0
    db.close()

    # ========================================================================
    # Step 18: Analyst Note
    # ========================================================================
    note_res = client.post(f"/api/investigations/{case_id}/notes", json={
        "analyst_name": "Chief Forensic Analyst",
        "note_type": "observation",
        "content": "Phase 8 automated lifecycle validation: artifacts verified untampered."
    })
    assert note_res.status_code == 201

    # ========================================================================
    # Step 19: Defensive Playbook Creation
    # ========================================================================
    db = TestingSession()
    pb_actions = [
        {"step_number": 1, "action_type": "collect.processes", "target_agent_id": agent_id, "parameters": {}},
        {"step_number": 2, "action_type": "isolate.endpoint.simulated", "target_agent_id": agent_id, "parameters": {}}
    ]
    playbook = PlaybookService.create_playbook(
        db=db,
        case_id=case_id,
        name="Defensive Endpoint Containment",
        actions_data=pb_actions,
        description="Simulated safe containment playbook for verified anomaly"
    )
    assert playbook.status == "PENDING_APPROVAL"
    pb_id = playbook.id
    db.close()

    # ========================================================================
    # Step 20: Analyst Dual-Control Approval
    # ========================================================================
    db = TestingSession()
    pb_obj = db.query(Playbook).filter(Playbook.id == pb_id).first()
    approval = PlaybookService.approve_playbook(
        db=db,
        playbook=pb_obj,
        approver_email="ciso@defense.gov",
        comment="Approved for simulated safe defensive containment"
    )
    assert approval.decision == "APPROVED"
    assert pb_obj.status == "APPROVED"
    assert pb_obj.approval_hash is not None
    db.close()

    # ========================================================================
    # Step 21: Defensive Simulated Response Execution
    # ========================================================================
    db = TestingSession()
    execution_result = PlaybookService.execute_playbook(
        db=db,
        playbook=pb_id,
        executor_email="analyst@jocky.defense"
    )
    assert execution_result.status == "COMPLETED"
    db.close()

    # ========================================================================
    # Step 22: Audit Logging Verification
    # ========================================================================
    audit_res = client.get(f"/api/audit?case_id={case_id}")
    assert audit_res.status_code == 200
    audits = audit_res.json()
    assert len(audits) >= 3

    # ========================================================================
    # Step 23: Complete Case Integrity Verification (7/7 Scorecard)
    # ========================================================================
    scorecard_res = client.post(f"/api/security/verify/case/{case_id}")
    assert scorecard_res.status_code == 200
    scorecard = scorecard_res.json()
    assert scorecard["status"] in ["VERIFIED", "WARNING"]
    assert "controls" in scorecard
    assert len(scorecard["controls"]) == 7

    # ========================================================================
    # Step 24: Report Generation (Multi-Format)
    # ========================================================================
    report_res = client.post("/api/reports/generate", json={
        "case_id": case_id,
        "report_type": "comprehensive"
    })
    assert report_res.status_code == 200
    report_data = report_res.json()
    report_id = report_data["id"]
    assert report_data["content_json"] is not None
    db = TestingSession()
    db_rep = db.query(Report).filter(Report.id == report_id).first()
    assert db_rep.manifest_json is not None
    db.close()

    # Export checks
    html_export = client.get(f"/api/reports/{case_id}/export?format=html")
    assert html_export.status_code == 200
    assert "JOCKY Forensic Investigation Report" in html_export.text

    json_export = client.get(f"/api/reports/{case_id}/export?format=json")
    assert json_export.status_code == 200
    assert json_export.json()["case_id"] == case_id

    # ========================================================================
    # Step 25: Report Manifest Verification
    # ========================================================================
    rep_verif_res = client.post(f"/api/security/verify/report/{report_id}")
    assert rep_verif_res.status_code == 200
    rep_verif = rep_verif_res.json()
    assert rep_verif["status"] == "VERIFIED"
    assert rep_verif["is_valid"] is True

    # ========================================================================
    # Step 26: Final Case Summary & Lifecycle Closure
    # ========================================================================
    case_patch = client.patch(f"/api/cases/{case_id}", json={
        "status": "CONTAINED",
        "description": "Lifecycle completed: Evidence sealed, playbooks executed, report certified."
    })
    assert case_patch.status_code == 200
    final_case = case_patch.json()
    assert final_case["status"] == "CONTAINED"
    assert final_case["id"] == case_id
