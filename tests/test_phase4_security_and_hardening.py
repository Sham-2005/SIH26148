"""
SIH26148 JOCKY Framework — Phase 4 Security, Capability, Isolation & Fleet Hardening Test Suite
Tests capability enforcement, agent isolation, replay prevention, plan integrity,
multi-format report exports (PDF, HTML, CSV, JSON), audit logging, and 5+ agent concurrency.
"""
import pytest
import concurrent.futures
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import engine
from backend.app.database.base import Base
from backend.app.config import settings
from agent.security.capabilities import get_platform_capabilities, resolve_polymorphic_operation
from agent.core.agent import ForensicAgent
from agent.executor.dispatcher import TaskDispatcher
from agent.evidence.evidence_envelope import verify_evidence_integrity

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_capability_registry_and_polymorphism_resolution():
    win_caps = get_platform_capabilities("Windows")
    linux_caps = get_platform_capabilities("Linux")

    assert "malware.pe_info" in win_caps
    assert "malware.pe_info" not in linux_caps
    assert "process.list" in win_caps
    assert "process.list" in linux_caps

    # Test resolution on Windows
    ok, res = resolve_polymorphic_operation("malware.pe_info", "Windows", win_caps)
    assert ok is True
    assert res == "malware.pe_info"

    # Test resolution on Linux (should cleanly reject with UNSUPPORTED_CAPABILITY)
    ok_lin, err_lin = resolve_polymorphic_operation("malware.pe_info", "Linux", linux_caps)
    assert ok_lin is False
    assert err_lin == "UNSUPPORTED_CAPABILITY"

def test_backend_rejects_unsupported_capability_task(client):
    # Enroll a Linux agent
    client.post("/api/agents/register", json={
        "agent_id": "TEST-LINUX-CAP-01",
        "hostname": "UBUNTU-TEST-CAP",
        "platform": "Linux",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })

    # Attempt to dispatch Windows-specific PE inspection task to the Linux agent
    incompatible_script = """
    script IncompatibleTask {
        malware.pe_info("/usr/bin/python3");
    }
    """
    res = client.post("/api/tasks", json={
        "case_id": "CASE-2026-001",
        "agent_id": "TEST-LINUX-CAP-01",
        "name": "Invalid PE Task for Linux",
        "jocky_script": incompatible_script
    })
    assert res.status_code == 400
    assert "UNSUPPORTED_CAPABILITY" in res.json()["detail"]

def test_agent_isolation_prevents_cross_submission(client):
    # Register Agent Alpha and Agent Bravo
    client.post("/api/agents/register", json={
        "agent_id": "AGENT-ISOL-ALPHA",
        "hostname": "ALPHA-BOX",
        "platform": "Windows",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })
    client.post("/api/agents/register", json={
        "agent_id": "AGENT-ISOL-BRAVO",
        "hostname": "BRAVO-BOX",
        "platform": "Windows",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })

    # Create task strictly assigned to Agent Alpha
    task_res = client.post("/api/tasks", json={
        "case_id": "CASE-2026-001",
        "agent_id": "AGENT-ISOL-ALPHA",
        "name": "Alpha Dedicated Task",
        "jocky_script": "script A { system.hostname(); }"
    })
    assert task_res.status_code == 200
    task_id = task_res.json()["id"]

    # Generate sample evidence envelope
    disp = TaskDispatcher(agent_id="AGENT-ISOL-BRAVO")
    env = disp.execute_function("system.hostname", [], case_id="CASE-2026-001")

    # MALICIOUS ATTEMPT: Agent Bravo attempts to submit results for Agent Alpha's task!
    breach_res = client.post("/api/agents/AGENT-ISOL-BRAVO/results", json={
        "task_id": task_id,
        "agent_id": "AGENT-ISOL-BRAVO",
        "evidence_envelopes": [env]
    })
    # MUST BE FORBIDDEN (403)
    assert breach_res.status_code == 403
    assert "AGENT_ISOLATION_VIOLATION" in breach_res.json()["detail"]

def test_task_replay_protection(client):
    # Register Agent
    client.post("/api/agents/register", json={
        "agent_id": "AGENT-REPLAY-01",
        "hostname": "REPLAY-BOX",
        "platform": "Windows",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })

    task_res = client.post("/api/tasks", json={
        "case_id": "CASE-2026-001",
        "agent_id": "AGENT-REPLAY-01",
        "name": "Single Execution Task",
        "jocky_script": "script S { system.hostname(); }"
    })
    task_id = task_res.json()["id"]

    disp = TaskDispatcher(agent_id="AGENT-REPLAY-01")
    env = disp.execute_function("system.hostname", [], case_id="CASE-2026-001")

    # 1. Legitimate first submission
    sub1 = client.post("/api/agents/AGENT-REPLAY-01/results", json={
        "task_id": task_id,
        "agent_id": "AGENT-REPLAY-01",
        "evidence_envelopes": [env]
    })
    assert sub1.status_code == 201

    # 2. Replay attempt: Submitting results for already completed task MUST be rejected!
    sub2 = client.post("/api/agents/AGENT-REPLAY-01/results", json={
        "task_id": task_id,
        "agent_id": "AGENT-REPLAY-01",
        "evidence_envelopes": [env]
    })
    assert sub2.status_code == 400
    assert "TASK_ALREADY_COMPLETED" in sub2.json()["detail"]

def test_agent_rejects_tampered_plan_hash():
    agent = ForensicAgent(agent_id="AGENT-INTEG-TEST", os_platform="Windows")

    tampered_task = {
        "id": "TASK-TAMPER-01",
        "case_id": "CASE-2026-001",
        "plan_payload": {
            "script_name": "TamperedPlan",
            "plan_hash": "fca1f4df5f250d6b28ac96383ea93bab88a1671ede22723e6c66d8d1f7ecc3eb",  # Mismatched hash
            "steps": [
                {"type": "forensic_call", "function": "system.info", "arguments": []},
                {"type": "forensic_call", "function": "file.hash", "arguments": ["/etc/shadow"]}  # injected step
            ]
        }
    }

    # Verify plan hash check detects mismatch
    is_valid = agent.verify_plan_integrity(tampered_task["plan_payload"])
    assert is_valid is False

def test_multi_format_report_export(client):
    case_id = "CASE-REPORT-EXPORT-01"
    client.post("/api/cases", json={
        "id": case_id,
        "title": "Comprehensive Export Test Case",
        "severity": "high",
        "status": "INVESTIGATING"
    })

    # 1. Export JSON
    json_res = client.get(f"/api/reports/{case_id}/export?format=json")
    assert json_res.status_code == 200
    assert "case_id" in json_res.json()

    # 2. Export HTML
    html_res = client.get(f"/api/reports/{case_id}/export?format=html")
    assert html_res.status_code == 200
    assert "<!DOCTYPE html>" in html_res.text
    assert "JOCKY FORENSIC INVESTIGATION REPORT" in html_res.text

    # 3. Export CSV
    csv_res = client.get(f"/api/reports/{case_id}/export?format=csv")
    assert csv_res.status_code == 200
    assert "Evidence ID,Case ID,Origin Agent" in csv_res.text

    # 4. Export PDF
    pdf_res = client.get(f"/api/reports/{case_id}/export?format=pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    # PDF files strictly begin with %PDF header
    assert pdf_res.content[:4] == b"%PDF"

def test_audit_logging_api(client):
    # Query audit logs
    audit_res = client.get("/api/audit")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert isinstance(logs, list)
    assert len(logs) > 0

    entry = logs[0]
    for k in ("actor", "actor_type", "action", "resource", "result", "timestamp"):
        assert k in entry

def test_concurrent_multi_agent_fleet_5_agents(client):
    fleet_ids = [
        "AGENT-FLEET-5-W1",
        "AGENT-FLEET-5-W2",
        "AGENT-FLEET-5-W3",
        "AGENT-FLEET-5-L1",
        "AGENT-FLEET-5-L2"
    ]

    task_map = {}
    for aid in fleet_ids:
        platform = "Windows" if "W" in aid else "Linux"
        client.post("/api/agents/register", json={
            "agent_id": aid,
            "hostname": f"HOST-{aid}",
            "platform": platform,
            "agent_version": "1.0.0",
            "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
        })
        # Dispatch 1 distinct task per agent
        t_res = client.post("/api/tasks", json={
            "case_id": "CASE-2026-001",
            "agent_id": aid,
            "name": f"Concurrent Triage on {aid}",
            "jocky_script": "script Conc { system.info(); evidence.collect(); }"
        })
        task_map[aid] = t_res.json()["id"]

    # Concurrently poll all 5 agents using ThreadPoolExecutor
    def poll_agent(aid):
        with TestClient(app) as local_c:
            res = local_c.get(f"/api/agents/{aid}/tasks")
            return aid, res.json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(poll_agent, fleet_ids))

    # Verify zero duplicate assignments and 100% accurate agent isolation
    received_tasks = set()
    for aid, tasks in results:
        assert len(tasks) == 1
        t_id = tasks[0]["id"]
        assert t_id == task_map[aid]
        assert tasks[0]["agent_id"] == aid
        assert t_id not in received_tasks
        received_tasks.add(t_id)

    assert len(received_tasks) == 5

def test_complete_end_to_end_sih_investigation_workflow(client):
    case_id = "CASE-SIH-DEMO-2026"
    agent_id = "AGENT-WIN-01"

    # 1. Create Case
    client.post("/api/cases", json={
        "id": case_id,
        "title": "Suspicious Endpoint Investigation",
        "severity": "high",
        "status": "INVESTIGATING"
    })

    # 2. Register Agent
    client.post("/api/agents/register", json={
        "agent_id": agent_id,
        "hostname": "WIN11-WORKSTATION-SEC",
        "platform": "Windows",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })

    # 3. Compile JOCKY script
    jocky_script = """
    script SentryInvestigation {
        system.info();
        process.list();
        persistence.startup();
        evidence.collect();
    }
    """
    # 4. Dispatch Task
    t_res = client.post("/api/tasks", json={
        "case_id": case_id,
        "agent_id": agent_id,
        "name": "SIH Demonstration Triage",
        "jocky_script": jocky_script
    })
    assert t_res.status_code == 200
    task_id = t_res.json()["id"]

    # 5. Agent claims task lease
    poll_res = client.get(f"/api/agents/{agent_id}/tasks")
    assert poll_res.status_code == 200
    tasks = poll_res.json()
    assert len(tasks) == 1
    assert tasks[0]["id"] == task_id

    # 6. Execute allowlisted collectors and seal evidence
    disp = TaskDispatcher(agent_id=agent_id)
    env1 = disp.execute_function("system.info", [], case_id=case_id)
    env2 = disp.execute_function("persistence.startup", [], case_id=case_id)
    assert verify_evidence_integrity(env1) is True
    assert verify_evidence_integrity(env2) is True

    # 7. Submit results
    submit_res = client.post(f"/api/agents/{agent_id}/results", json={
        "task_id": task_id,
        "agent_id": agent_id,
        "evidence_envelopes": [env1, env2]
    })
    assert submit_res.status_code == 201

    # 8. Cryptographic verification of evidence via API
    ver1 = client.post(f"/api/evidence/{env1['evidence_id']}/verify")
    assert ver1.status_code == 200
    assert ver1.json()["is_valid"] is True

    # 9. Generate & Export PDF Report
    pdf_res = client.get(f"/api/reports/{case_id}/export?format=pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.content[:4] == b"%PDF"
