"""
Automated Tests for PE Header Parser and Persistence Collectors
"""
import os
import sys
import pytest
from agent.collectors.pe_collector import parse_pe_file
from agent.collectors.persistence_collector import (
    collect_persistence_startup,
    collect_persistence_services,
    collect_persistence_scheduled_tasks
)
from agent.executor.dispatcher import TaskDispatcher
from agent.evidence.evidence_envelope import verify_evidence_integrity

def test_pe_parser_valid_executable():
    # Parse current Python interpreter executable
    pe_info = parse_pe_file(sys.executable)
    assert pe_info["is_valid_pe"] is True
    assert pe_info["dos_header"]["magic"] == "MZ"
    assert "sections" in pe_info
    assert len(pe_info["sections"]) > 0
    assert "optional_header" in pe_info
    assert pe_info["pe_header"]["signature"] == "PE\\0\\0"

def test_pe_parser_non_pe_graceful_error():
    # Pass a markdown file to verify graceful structured error
    res = parse_pe_file("README.md")
    assert res["is_valid_pe"] is False
    assert "error" in res
    assert "Invalid DOS magic" in res["error"]

def test_pe_parser_missing_file():
    res = parse_pe_file("non_existent_file_path_12345.exe")
    assert res["is_valid_pe"] is False
    assert "File not found" in res["error"]

def test_persistence_startup_collector():
    findings = collect_persistence_startup()
    assert isinstance(findings, list)
    assert len(findings) > 0
    item = findings[0]
    for required_key in ("persistence_type", "location", "name", "path_target", "evidence", "risk_metadata", "timestamp"):
        assert required_key in item

def test_persistence_services_collector():
    findings = collect_persistence_services(limit=5)
    assert isinstance(findings, list)
    assert len(findings) > 0
    item = findings[0]
    assert "persistence_type" in item
    assert "evidence" in item

def test_persistence_scheduled_tasks_collector():
    findings = collect_persistence_scheduled_tasks(limit=5)
    assert isinstance(findings, list)
    assert len(findings) > 0
    item = findings[0]
    assert "persistence_type" in item

def test_dispatcher_pe_and_persistence_integration():
    dispatcher = TaskDispatcher(agent_id="AGENT-INTEG-01")

    # 1. PE inspection via dispatcher
    pe_env = dispatcher.execute_function("malware.pe_info", [sys.executable], case_id="CASE-PE-01")
    assert pe_env["collector"] == "malware.pe_info"
    assert pe_env["results"]["is_valid_pe"] is True
    assert verify_evidence_integrity(pe_env) is True

    # 2. Persistence startup via dispatcher
    start_env = dispatcher.execute_function("persistence.startup", [], case_id="CASE-PERSIST-01")
    assert start_env["collector"] == "persistence.startup"
    assert isinstance(start_env["results"], list)
    assert verify_evidence_integrity(start_env) is True
