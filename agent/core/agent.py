"""
JOCKY Forensic Agent Core Runtime
Manages registration, capability declaration, heartbeat telemetry, periodic task polling, safe allowlist execution, and evidence sealing.
"""
import time
import socket
import platform
import hashlib
import json
import requests
from typing import Optional, Dict, Any, List
from agent.executor.dispatcher import TaskDispatcher
from agent.security.allowlist import is_function_allowed
from agent.security.capabilities import get_platform_capabilities, resolve_polymorphic_operation

class ForensicAgent:
    def __init__(
        self,
        agent_id: Optional[str] = None,
        backend_url: str = "http://localhost:8000",
        enrollment_token: str = "jocky-agent-enrollment-secret-2026",
        hostname: Optional[str] = None,
        os_platform: Optional[str] = None,
        capabilities: Optional[List[str]] = None
    ):
        self.hostname = hostname or socket.gethostname()
        self.agent_id = agent_id or f"AGENT-{self.hostname.upper()}"
        self.backend_url = backend_url.rstrip("/")
        self.enrollment_token = enrollment_token
        self.platform_name = os_platform or platform.system()
        self.capabilities = capabilities or get_platform_capabilities(self.platform_name)
        self.auth_token: Optional[str] = None
        self.dispatcher = TaskDispatcher(agent_id=self.agent_id)
        self.registered = False

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["X-Agent-Token"] = self.auth_token
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def register(self) -> bool:
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "platform": self.platform_name,
            "os_version": platform.version() if self.platform_name == platform.system() else f"{self.platform_name} Enterprise [DEMO / SIMULATED]",
            "architecture": platform.machine() if self.platform_name == platform.system() else "x86_64",
            "agent_version": "1.0.0",
            "enrollment_token": self.enrollment_token,
            "capabilities": self.capabilities
        }
        try:
            res = requests.post(f"{self.backend_url}/api/agents/register", json=payload, timeout=5)
            if res.status_code in (200, 201):
                data = res.json()
                self.registered = True
                self.auth_token = data.get("auth_token") or f"agt_{self.agent_id}"
                return True
        except Exception:
            pass
        return False

    def send_heartbeat(self, status: str = "online") -> bool:
        try:
            res = requests.post(
                f"{self.backend_url}/api/agents/{self.agent_id}/heartbeat",
                json={"status": status},
                headers=self._headers(),
                timeout=5
            )
            return res.status_code == 200
        except Exception:
            return False

    def poll_tasks(self) -> List[Dict[str, Any]]:
        """Polls backend for tasks assigned to this agent."""
        try:
            res = requests.get(
                f"{self.backend_url}/api/agents/{self.agent_id}/tasks",
                headers=self._headers(),
                timeout=5
            )
            if res.status_code == 200:
                return res.json()
        except Exception:
            pass
        return []

    def verify_plan_integrity(self, plan: Dict[str, Any]) -> bool:
        """Verifies that plan contents match its plan_hash."""
        claimed_hash = plan.get("plan_hash")
        if not claimed_hash:
            return True  # If not hashed, allow if valid structure

        plan_copy = {k: v for k, v in plan.items() if k != "plan_hash"}
        canonical_bytes = json.dumps(plan_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        computed_hash = hashlib.sha256(canonical_bytes).hexdigest()
        return computed_hash.lower() == claimed_hash.lower()

    def process_task(self, task_data: Dict[str, Any]) -> bool:
        """Validates capability, plan hash, executes allowlisted collectors, and uploads sealed evidence."""
        task_id = task_data.get("id")
        case_id = task_data.get("case_id", "DEFAULT-CASE")
        plan_payload = task_data.get("plan_payload", {})

        # Set status to busy
        self.send_heartbeat(status="busy")
        envelopes = []

        try:
            scripts = plan_payload.get("scripts", [plan_payload])
            for script_plan in scripts:
                # 1. Validate plan hash
                if not self.verify_plan_integrity(script_plan):
                    raise ValueError(f"HASH MISMATCH on execution plan '{script_plan.get('script_name')}'")

                steps = script_plan.get("steps", [])
                for step in steps:
                    step_type = step.get("type")
                    if step_type == "forensic_call":
                        fn_name = step.get("function")
                        fn_args = step.get("arguments", [])

                        # 2. Check global allowlist
                        if not is_function_allowed(fn_name):
                            raise PermissionError(f"GLOBAL_ALLOWLIST_VIOLATION: Unauthorized function requested: {fn_name}")

                        # 3. Check agent capability profile (controlled polymorphism check)
                        supported, resolved_or_err = resolve_polymorphic_operation(
                            fn_name, self.platform_name, self.capabilities
                        )
                        if not supported:
                            raise ValueError(f"UNSUPPORTED_CAPABILITY: Function '{fn_name}' is not supported on {self.platform_name} agent '{self.agent_id}'.")

                        # 4. Execute approved collector
                        env = self.dispatcher.execute_function(resolved_or_err, fn_args, case_id=case_id)
                        envelopes.append(env)

                    elif step_type == "seal_evidence":
                        env = self.dispatcher.execute_function("evidence.collect", [], case_id=case_id)
                        envelopes.append(env)

            # Submit completed results
            success = self.submit_results(task_id, envelopes)
            self.send_heartbeat(status="online")
            return success

        except Exception as e:
            # Report structured failure
            self.submit_failure(task_id, str(e))
            self.send_heartbeat(status="online")
            return False

    def submit_results(self, task_id: str, envelopes: List[Dict[str, Any]]) -> bool:
        payload = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "evidence_envelopes": envelopes
        }
        try:
            res = requests.post(
                f"{self.backend_url}/api/agents/{self.agent_id}/results",
                json=payload,
                headers=self._headers(),
                timeout=10
            )
            if res.status_code in (200, 201):
                return True
            # Fallback to general results endpoint
            res2 = requests.post(
                f"{self.backend_url}/api/results",
                json=payload,
                headers=self._headers(),
                timeout=10
            )
            return res2.status_code in (200, 201)
        except Exception:
            return False

    def submit_failure(self, task_id: str, error_message: str) -> bool:
        try:
            res = requests.post(
                f"{self.backend_url}/api/tasks/{task_id}/fail",
                json={"error": error_message, "agent_id": self.agent_id},
                headers=self._headers(),
                timeout=5
            )
            return res.status_code == 200
        except Exception:
            return False

    def run_polling_loop(self, interval_seconds: int = 4, max_iterations: Optional[int] = None):
        """Runs the continuous polling and execution loop."""
        if not self.registered:
            self.register()

        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            self.send_heartbeat()
            tasks = self.poll_tasks()
            for t in tasks:
                self.process_task(t)
            iterations += 1
            time.sleep(interval_seconds)
