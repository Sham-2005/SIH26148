"""
Automated Tests for Forensic Agent and Evidence Engine
"""
import pytest
from agent.security.allowlist import is_function_allowed, validate_task_function
from agent.evidence.evidence_envelope import (
    create_evidence_envelope,
    verify_evidence_integrity,
    canonical_json,
    calculate_sha256
)
from agent.executor.dispatcher import TaskDispatcher

def test_allowlist_enforcement():
    assert is_function_allowed("system.info") is True
    assert is_function_allowed("process.list") is True
    assert is_function_allowed("file.hash") is True
    assert is_function_allowed("shell.execute") is False

    with pytest.raises(PermissionError):
        validate_task_function("arbitrary.exploit")

def test_evidence_envelope_creation_and_verification():
    sample_results = {"sample_key": "sample_value", "counter": 42}
    envelope = create_evidence_envelope(
        case_id="TEST-CASE-01",
        agent_id="TEST-AGENT-01",
        collector="system.info",
        platform_name="TestPlatform",
        results=sample_results
    )

    assert envelope["case_id"] == "TEST-CASE-01"
    assert envelope["agent_id"] == "TEST-AGENT-01"
    assert "integrity" in envelope
    assert envelope["integrity"]["algorithm"] == "SHA-256"

    # Integrity verification
    assert verify_evidence_integrity(envelope) is True

def test_evidence_envelope_tamper_detection():
    envelope = create_evidence_envelope(
        case_id="TEST-CASE-01",
        agent_id="TEST-AGENT-01",
        collector="process.list",
        platform_name="TestPlatform",
        results=[{"pid": 1, "name": "systemd"}]
    )

    # Initial verification passes
    assert verify_evidence_integrity(envelope) is True

    # Malicious tampering of results in storage or transit
    envelope["results"].append({"pid": 9999, "name": "injected_rootkit"})

    # Tampered verification MUST fail
    assert verify_evidence_integrity(envelope) is False

def test_dispatcher_execution():
    dispatcher = TaskDispatcher(agent_id="AGENT-DISP-01")
    envelope = dispatcher.execute_function("system.hostname", [])

    assert envelope["collector"] == "system.hostname"
    assert isinstance(envelope["results"], str)
    assert verify_evidence_integrity(envelope) is True
