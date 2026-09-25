"""
Automated End-to-End Fleet Simulation Test
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from scripts.simulate_agents import SIMULATED_FLEET
from agent.core.agent import ForensicAgent
from agent.evidence.evidence_envelope import verify_evidence_integrity

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_fleet_enrollment_and_execution_cycle(client):
    # Test all 3 simulated agents
    for cfg in SIMULATED_FLEET:
        agent_id = cfg["agent_id"]

        # 1. Enroll
        reg_res = client.post("/api/agents/register", json={
            "agent_id": agent_id,
            "hostname": cfg["hostname"],
            "platform": cfg["platform"],
            "os_version": cfg["os_version"],
            "agent_version": "1.0.0",
            "enrollment_token": "jocky-agent-enrollment-secret-2026"
        })
        assert reg_res.status_code == 200

        # 2. Heartbeat
        hb_res = client.post(f"/api/agents/{agent_id}/heartbeat", json={"status": "online"})
        assert hb_res.status_code == 200

        # 3. Dispatch forensic task to this agent
        task_res = client.post("/api/tasks", json={
            "case_id": "CASE-2026-001",
            "agent_id": agent_id,
            "name": f"Simulation Triage on {agent_id}",
            "jocky_script": "script Sim { system.info(); evidence.collect(); }"
        })
        assert task_res.status_code == 200
        task_id = task_res.json()["id"]

        # 4. Agent polls task
        poll_res = client.get(f"/api/agents/{agent_id}/tasks")
        assert poll_res.status_code == 200
        tasks = poll_res.json()
        assert len(tasks) == 1
        assert tasks[0]["id"] == task_id

        # 5. Local dispatcher execution
        from agent.executor.dispatcher import TaskDispatcher
        disp = TaskDispatcher(agent_id=agent_id)
        env = disp.execute_function("system.info", [], case_id="CASE-2026-001")
        assert verify_evidence_integrity(env) is True

        # 6. Submit results
        submit_res = client.post(f"/api/agents/{agent_id}/results", json={
            "task_id": task_id,
            "agent_id": agent_id,
            "evidence_envelopes": [env]
        })
        assert submit_res.status_code == 201

        # 7. Verify task is completed
        get_task = client.get(f"/api/tasks/{task_id}")
        assert get_task.json()["status"] == "completed"
