"""
Multi-Agent Execution Pipeline & Case Management Integration Tests
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import engine
from backend.app.database.base import Base
from backend.app.config import settings

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_case_management_crud(client):
    # 1. Create Case
    payload = {
        "id": "CASE-TRIAGE-99",
        "title": "Malware Outbreak Investigation",
        "description": "Enterprise endpoint triage following suspicious lateral movement.",
        "severity": "critical",
        "status": "OPEN"
    }
    res = client.post("/api/cases", json=payload)
    assert res.status_code == 201
    case_data = res.json()
    assert case_data["id"] == "CASE-TRIAGE-99"
    assert case_data["severity"] == "critical"
    assert case_data["status"] == "OPEN"

    # 2. Query Case
    get_res = client.get("/api/cases/CASE-TRIAGE-99")
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "Malware Outbreak Investigation"

    # 3. Patch Case Status
    patch_res = client.patch("/api/cases/CASE-TRIAGE-99", json={"status": "INVESTIGATING"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"

def test_multi_agent_enrollment_and_isolation(client):
    # Enroll Agent A (Windows)
    res_a = client.post("/api/agents/register", json={
        "agent_id": "AGENT-FLEET-A",
        "hostname": "WORKSTATION-A",
        "platform": "Windows",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })
    assert res_a.status_code == 200

    # Enroll Agent B (Linux)
    res_b = client.post("/api/agents/register", json={
        "agent_id": "AGENT-FLEET-B",
        "hostname": "SERVER-B",
        "platform": "Linux",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    })
    assert res_b.status_code == 200

    # Test Agent Heartbeat
    hb_res = client.post("/api/agents/AGENT-FLEET-A/heartbeat", json={"status": "online"})
    assert hb_res.status_code == 200

    # Dispatch: Agent A -> Task 1
    t1 = client.post("/api/tasks", json={
        "case_id": "CASE-TRIAGE-99",
        "agent_id": "AGENT-FLEET-A",
        "name": "Process List Task 1",
        "jocky_script": "script T1 { process.list(); }"
    }).json()

    # Dispatch: Agent B -> Task 2
    t2 = client.post("/api/tasks", json={
        "case_id": "CASE-TRIAGE-99",
        "agent_id": "AGENT-FLEET-B",
        "name": "Network Conns Task 2",
        "jocky_script": "script T2 { network.connections(); }"
    }).json()

    # Dispatch: Agent A -> Task 3
    t3 = client.post("/api/tasks", json={
        "case_id": "CASE-TRIAGE-99",
        "agent_id": "AGENT-FLEET-A",
        "name": "System Info Task 3",
        "jocky_script": "script T3 { system.info(); }"
    }).json()

    # 1. Agent B Polls: MUST only receive Task 2 (and NOT Task 1 or 3)
    b_poll = client.get("/api/agents/AGENT-FLEET-B/tasks").json()
    assert len(b_poll) == 1
    assert b_poll[0]["id"] == t2["id"]
    assert b_poll[0]["agent_id"] == "AGENT-FLEET-B"

    # 2. Agent B Polls again immediately: MUST receive 0 tasks (prevent duplicate execution)
    b_poll_again = client.get("/api/agents/AGENT-FLEET-B/tasks").json()
    assert len(b_poll_again) == 0

    # 3. Agent A Polls: MUST receive Task 1 and Task 3
    a_poll = client.get("/api/agents/AGENT-FLEET-A/tasks").json()
    assert len(a_poll) == 2
    a_task_ids = [t["id"] for t in a_poll]
    assert t1["id"] in a_task_ids
    assert t3["id"] in a_task_ids

    # 4. Agent A Polls again: MUST receive 0 tasks
    assert len(client.get("/api/agents/AGENT-FLEET-A/tasks").json()) == 0

def test_agent_result_submission_and_report(client):
    from agent.executor.dispatcher import TaskDispatcher
    dispatcher = TaskDispatcher(agent_id="AGENT-FLEET-B")

    # Create task for Agent B
    task = client.post("/api/tasks", json={
        "case_id": "CASE-TRIAGE-99",
        "agent_id": "AGENT-FLEET-B",
        "name": "Collect Evidence Task",
        "jocky_script": "script E { system.hostname(); }"
    }).json()

    # Dispatcher produces sealed envelope
    envelope = dispatcher.execute_function("system.hostname", [], case_id="CASE-TRIAGE-99")
    ev_id = envelope["evidence_id"]

    # Submit via agent endpoint
    submit_res = client.post(f"/api/agents/AGENT-FLEET-B/results", json={
        "task_id": task["id"],
        "agent_id": "AGENT-FLEET-B",
        "evidence_envelopes": [envelope]
    })
    assert submit_res.status_code == 201

    # Verify evidence via POST endpoint
    verify_res = client.post(f"/api/evidence/{ev_id}/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True

    # Retrieve case report
    rep_res = client.get("/api/reports/CASE-TRIAGE-99")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["case_id"] == "CASE-TRIAGE-99"
    assert "forensic_findings" in rep_data["content_json"]

    # Check real-time event feed
    events_res = client.get("/api/events")
    assert events_res.status_code == 200
    assert len(events_res.json()) > 0
