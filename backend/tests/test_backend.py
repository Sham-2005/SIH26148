"""
Automated Integration Tests for JOCKY FastAPI Backend
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import engine, SessionLocal
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

def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"

def test_agent_registration(client):
    payload = {
        "agent_id": "TEST-AGENT-API-01",
        "hostname": "HOST-TEST-01",
        "platform": "Windows",
        "os_version": "10.0.19045",
        "architecture": "x86_64",
        "ip_address": "192.168.1.50",
        "agent_version": "1.0.0",
        "enrollment_token": settings.AGENT_REGISTRATION_TOKEN
    }
    res = client.post("/api/agents/register", json=payload)
    assert res.status_code == 200
    agent = res.json()
    assert agent["id"] == "TEST-AGENT-API-01"
    assert agent["hostname"] == "HOST-TEST-01"

def test_task_creation_with_jocky_script(client):
    jocky_script = """
    script ApiTriage {
        system.info();
        evidence.collect();
    }
    """
    payload = {
        "case_id": "CASE-TEST-001",
        "agent_id": "TEST-AGENT-API-01",
        "name": "Initial Triage",
        "jocky_script": jocky_script
    }
    res = client.post("/api/tasks", json=payload)
    assert res.status_code == 200
    task = res.json()
    assert task["case_id"] == "CASE-TEST-001"
    assert task["status"] == "pending"

def test_results_and_evidence_verification(client):
    # 1. Create task first
    task_res = client.post("/api/tasks", json={
        "case_id": "CASE-VERIFY-001",
        "agent_id": "TEST-AGENT-API-01",
        "name": "Verify Task",
        "jocky_script": "script T { system.hostname(); }"
    })
    task_id = task_res.json()["id"]

    # 2. Execute collector and build valid envelope
    from agent.executor.dispatcher import TaskDispatcher
    dispatcher = TaskDispatcher(agent_id="TEST-AGENT-API-01")
    envelope = dispatcher.execute_function("system.hostname", [], case_id="CASE-VERIFY-001")
    evidence_id = envelope["evidence_id"]

    # 3. Submit result
    submit_res = client.post("/api/results", json={
        "task_id": task_id,
        "agent_id": "TEST-AGENT-API-01",
        "evidence_envelopes": [envelope]
    })
    assert submit_res.status_code == 201

    # 4. Query evidence verification endpoint
    verify_res = client.get(f"/api/evidence/{evidence_id}/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["is_valid"] is True
    assert verify_data["claimed_hash"] == verify_data["recalculated_hash"]


def test_jocky_demo_execution_and_history_persistence(client):
    # 1. Clean history for deterministic test
    client.delete("/api/demo/history")

    # 2. Run investigation
    run_res = client.post("/api/demo/run", json={"script": 'CASE "CASE-2026-001"\nTARGET "WIN-TEST"\nCOLLECT registry\nREPORT'})
    assert run_res.status_code == 200
    result = run_res.json()
    assert "execution_id" in result
    assert result["execution_id"].startswith("EXE-")
    first_id = result["execution_id"]

    # 3. Retrieve history list
    hist_res = client.get("/api/demo/history")
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) >= 1
    assert history[0]["execution_id"] == first_id
    assert history[0]["status"] == "SUCCESS"
    assert history[0]["threat_score"] == 86
    assert history[0]["case_id"] == "CASE-2026-001"
    assert "script_content" in history[0]

    # 4. Fetch details
    detail_res = client.get(f"/api/demo/history/{first_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["execution_id"] == first_id
    assert detail["result_data"] is not None

    # 5. Re-run creates a NEW record without overwriting original
    rerun_res = client.post("/api/demo/run", json={"script": 'CASE "CASE-2026-001"\nTARGET "WIN-TEST"\nCOLLECT registry\nREPORT'})
    assert rerun_res.status_code == 200
    second_id = rerun_res.json()["execution_id"]
    assert second_id != first_id

    hist_res2 = client.get("/api/demo/history")
    history2 = hist_res2.json()
    assert len(history2) == 2
    assert history2[0]["execution_id"] == second_id
    assert history2[1]["execution_id"] == first_id
