"""
Tests for JOCKY One-Click Forensic Demo Execution
Verifies:
1. Parsing of declarative demo script
2. 5-artifact synthetic evidence collection
3. Evidence correlation
4. Exact 21-dimensional forensic vector with deterministic values
5. Threat score calculation: 86 / 100 HIGH
6. 12 deterministic tamper detectors (12 / 12 PASSED)
7. SHA-256 evidence hashing
8. Cryptographic chain of custody verification
9. Performance latency measurement
10. REST API endpoints (/api/demo/script, /api/demo/run, /api/demo/benchmark)
"""
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.session import SessionLocal
from backend.app.services.demo_service import JockyDemoService, JockyDemoParser


SAMPLE_DEMO_SCRIPT = """CASE "CASE-2026-001"

TARGET "DEMO-WINDOWS-ENDPOINT"

COLLECT registry
WHERE path MATCHES "Run|RunOnce"

COLLECT process
WHERE parent == "explorer.exe"

COLLECT eventlog
WHERE event_id IN [4688, 7045]

COLLECT network

COLLECT filesystem

CORRELATE
    registry
    WITH process
    WITH eventlog
    WITH network
    WITH filesystem

ANALYZE forensic_vector

CALCULATE threat_score

VERIFY tamper

HASH evidence

CHAIN evidence

REPORT"""


def test_demo_parser():
    parsed = JockyDemoParser.parse(SAMPLE_DEMO_SCRIPT)
    assert parsed["case_id"] == "CASE-2026-001"
    assert parsed["target"] == "DEMO-WINDOWS-ENDPOINT"
    assert len(parsed["collections"]) == 5
    categories = [c["category"] for c in parsed["collections"]]
    assert "registry" in categories
    assert "process" in categories
    assert "eventlog" in categories
    assert "network" in categories
    assert "filesystem" in categories
    assert len(parsed["actions"]) >= 5


def test_demo_service_execution():
    db = SessionLocal()
    try:
        result = JockyDemoService.execute_demo(SAMPLE_DEMO_SCRIPT, db=db)
        assert result["status"] == "SUCCESS"
        assert result["investigation"]["case_id"] == "CASE-2026-001"
        assert result["investigation"]["target"] == "DEMO-WINDOWS-ENDPOINT"

        # Evidence Collection
        ev_col = result["evidence_collection"]
        assert ev_col["total_categories"] == 5
        assert "registry" in ev_col["artifacts"]
        assert "process" in ev_col["artifacts"]
        assert "eventlog" in ev_col["artifacts"]
        assert "network" in ev_col["artifacts"]
        assert "filesystem" in ev_col["artifacts"]

        # Forensic Vector (21 dimensions)
        fv = result["forensic_vector"]
        assert fv["dimensions"] == 21
        assert len(fv["features"]) == 21
        feat_names = [f["name"] for f in fv["features"]]
        assert "Registry Persistence" in feat_names
        assert "Process Activity" in feat_names
        assert "Suspicious Network Connection" in feat_names
        assert "Evidence Integrity" in feat_names

        # Threat Score
        threat = result["threat_analysis"]
        assert threat["threat_score"] == 86
        assert threat["threat_score_display"] == "86 / 100"
        assert threat["risk_level"] == "HIGH"

        # 12 Tamper Detectors
        td = result["tamper_detection"]
        assert td["total_detectors"] == 12
        assert td["passed_detectors"] == 12
        assert td["display"] == "12 / 12 CHECKS PASSED"
        for det in td["detectors"]:
            assert det["status"] == "PASS"

        # Evidence Hashing
        eh = result["evidence_hashing"]
        assert eh["evidence_id"] == "EV-2026-001"
        assert eh["algorithm"] == "SHA-256"
        assert len(eh["sha256"]) == 64

        # Chain of Custody
        coc = result["chain_of_custody"]
        assert coc["chain_status"] == "VERIFIED"
        assert coc["total_blocks"] == 2
        assert coc["blocks"][0]["block_number"] == 1
        assert coc["blocks"][1]["block_number"] == 2
        assert coc["blocks"][1]["previous_hash"] == coc["blocks"][0]["current_hash"]

        # Performance latency
        perf = result["performance_metric"]
        assert perf["execution_time_ms"] > 0
        assert perf["artifacts_count"] == 5

        # Final Report
        rep = result["final_report"]
        assert rep["case_id"] == "CASE-2026-001"
        assert rep["threat_score"] == "86 / 100"
        assert rep["risk_level"] == "HIGH"
        assert rep["tamper_checks"] == "12 / 12"
        assert rep["evidence_integrity"] == "VERIFIED"
        assert rep["chain_of_custody"] == "VERIFIED"
    finally:
        db.close()


def test_demo_api_endpoints():
    client = TestClient(app)

    # 1. GET /api/demo/script
    script_res = client.get("/api/demo/script")
    assert script_res.status_code == 200
    script_data = script_res.json()
    assert "demo_persistence.jocky" in script_data["filename"]
    assert "COLLECT registry" in script_data["script"]

    # 2. POST /api/demo/run
    run_res = client.post("/api/demo/run", json={"script": SAMPLE_DEMO_SCRIPT})
    assert run_res.status_code == 200
    res_data = run_res.json()
    assert res_data["status"] == "SUCCESS"
    assert res_data["threat_analysis"]["threat_score"] == 86
    assert res_data["forensic_vector"]["dimensions"] == 21
    assert res_data["tamper_detection"]["passed_detectors"] == 12
    assert res_data["chain_of_custody"]["chain_status"] == "VERIFIED"

    # 3. POST /api/demo/benchmark
    bench_res = client.post("/api/demo/benchmark", json={"script": SAMPLE_DEMO_SCRIPT})
    assert bench_res.status_code == 200
    bench_data = bench_res.json()
    assert bench_data["status"] == "SUCCESS"
    assert bench_data["iterations"] == 5
    assert bench_data["average_latency_ms"] > 0
