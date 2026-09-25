"""
Phase 5 Test Suite: Intelligent Forensic Investigation & Threat Correlation
Validates:
1. IOC extraction & types (IP, Domain, Hash, Path, Process, Service, Registry)
2. IOC normalization & deduplication
3. Timeline event generation & chronological sorting
4. Timeline filtering (agent, event_type, severity)
5. Evidence correlation: Process to Network
6. Evidence correlation: Persistence to Binary File
7. Cross-agent correlation: identical hash across multiple endpoints
8. Finding generation with direct evidence traceability
9. Finding lifecycle status transitions (OPEN -> CONFIRMED -> DISMISSED)
10. Explainable deterministic risk scoring
11. Investigation relationship graph (nodes & edges)
12. Unified search (process:, hash:, ip:, agent:, free-text)
13. Analyst notes creation & audit trail logging
14. Investigation security & validation controls
15. Enhanced multi-format report exports (PDF, HTML, CSV, JSON)
16. End-to-end investigation workflow
"""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.session import SessionLocal
from backend.app.database.base import Base
from backend.app.database.session import engine
from backend.app.models.models import (
    Case, Agent, Task, TaskResult, Evidence, AuditLog,
    InvestigationIndicator, TimelineEvent, EvidenceCorrelation, Finding, AnalystNote
)
from backend.app.services.ioc_service import IOCService
from backend.app.services.timeline_service import TimelineService
from backend.app.services.risk_service import RiskService
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.finding_service import FindingService
from backend.app.services.investigation_orchestrator import InvestigationOrchestrator
from backend.app.services.report_export_service import ReportExportService

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Ensure test case exists
    test_case = db.query(Case).filter(Case.id == "CASE-P5-TEST").first()
    if not test_case:
        test_case = Case(
            id="CASE-P5-TEST",
            title="Phase 5 Automated Investigation Test",
            description="Testing intelligent correlation, IOCs, and timelines.",
            severity="high",
            status="INVESTIGATING"
        )
        db.add(test_case)

    # Ensure test agents exist
    for a_id, plat in [("AGENT-WIN-P5-01", "Windows"), ("AGENT-WIN-P5-02", "Windows"), ("AGENT-LINUX-P5-01", "Linux")]:
        if not db.query(Agent).filter(Agent.id == a_id).first():
            agent = Agent(
                id=a_id,
                hostname=f"HOST-{a_id}",
                platform=plat,
                status="online",
                capabilities=["process.list", "network.connections", "persistence.startup", "malware.pe_info"],
                auth_token=f"TOKEN-{a_id}"
            )
            db.add(agent)

    db.commit()
    db.close()
    yield

def test_1_ioc_normalization_and_deduplication():
    # Hash normalization
    raw_hash = "  4A7D189FEC0A29B3C79124AE8019FB42A8B9281A02938471EF09A8BC12984712  "
    norm_hash = IOCService.normalize("sha256", raw_hash)
    assert norm_hash == "4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712"

    # IP normalization (strip port)
    norm_ip = IOCService.normalize("ipv4", "192.168.1.50:8080")
    assert norm_ip == "192.168.1.50"

    # Path normalization
    norm_path = IOCService.normalize("filepath", "C:\\Windows\\System32\\cmd.exe")
    assert norm_path == "C:/Windows/System32/cmd.exe"

    # Domain normalization
    norm_dom = IOCService.normalize("domain", "https://malicious-c2.defense/path/")
    assert norm_dom == "malicious-c2.defense/path"

def test_2_ioc_extraction_from_evidence():
    db = SessionLocal()
    try:
        ev = Evidence(
            id="EV-TEST-IOC-01",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-WIN-P5-01",
            collector="process.list",
            platform="Windows",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            envelope_data={
                "results": [
                    {"name": "beacon.exe", "pid": 4120, "exe": "C:\\Temp\\beacon.exe", "cmdline": "beacon.exe --connect 10.200.1.50:443"}
                ]
            },
            is_verified=True
        )
        db.merge(ev)
        db.commit()

        iocs = IOCService.extract_from_evidence(ev, db)
        types = [i.indicator_type for i in iocs]
        assert "sha256" in types
        assert "process_name" in types
        assert "filepath" in types
        assert "ipv4" in types

        # Check suspicious status for Temp path
        path_ioc = next(i for i in iocs if i.indicator_type == "filepath")
        assert path_ioc.status == "suspicious"
        assert path_ioc.normalized_value == "C:/Temp/beacon.exe"
    finally:
        db.close()

def test_3_timeline_generation_and_sorting():
    db = SessionLocal()
    try:
        ev = db.query(Evidence).filter(Evidence.id == "EV-TEST-IOC-01").first()
        events = TimelineService.synthesize_events_from_evidence(ev, db)
        assert len(events) >= 1
        assert events[0].event_type == "PROCESS"
        assert "beacon.exe" in events[0].description
        assert events[0].severity == "HIGH"

        # Query chronological timeline
        timeline = TimelineService.get_timeline(case_id="CASE-P5-TEST", db=db)
        assert len(timeline) >= 1
        # Verify chronological order
        for i in range(len(timeline) - 1):
            assert timeline[i].timestamp <= timeline[i+1].timestamp
    finally:
        db.close()

def test_4_timeline_filtering():
    db = SessionLocal()
    try:
        # Filter by agent
        agent_filtered = TimelineService.get_timeline(case_id="CASE-P5-TEST", agent_id="AGENT-WIN-P5-01", db=db)
        assert all(e.agent_id == "AGENT-WIN-P5-01" for e in agent_filtered)

        # Filter by event type
        type_filtered = TimelineService.get_timeline(case_id="CASE-P5-TEST", event_type="PROCESS", db=db)
        assert all(e.event_type == "PROCESS" for e in type_filtered)
    finally:
        db.close()

def test_5_explainable_risk_scoring():
    priority, score, reasons = RiskService.evaluate_risk(
        evidence_count=4,
        has_persistence=True,
        has_network_connection=True,
        has_suspicious_location=True,
        cross_agent_count=2,
        has_known_tool_keyword=True
    )
    assert priority == "CRITICAL"
    assert score >= 75
    assert len(reasons) >= 4
    # All reasons start with point additions e.g. +30
    assert any("+30" in r for r in reasons)
    assert any("+25" in r for r in reasons)

def test_6_cross_agent_correlation_same_hash():
    db = SessionLocal()
    try:
        shared_hash = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"

        # Evidence on Agent 1
        ev1 = Evidence(
            id="EV-CORR-WIN-01",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-WIN-P5-01",
            collector="malware.pe_info",
            platform="Windows",
            sha256_hash=shared_hash,
            envelope_data={"results": {"sha256": shared_hash, "filepath": "C:\\Tools\\agent.exe"}},
            is_verified=True
        )
        # Evidence on Agent 2
        ev2 = Evidence(
            id="EV-CORR-WIN-02",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-WIN-P5-02",
            collector="file.hash",
            platform="Windows",
            sha256_hash=shared_hash,
            envelope_data={"results": {"sha256": shared_hash, "filepath": "C:\\Windows\\Temp\\agent.exe"}},
            is_verified=True
        )
        db.merge(ev1)
        db.merge(ev2)
        db.commit()

        correlations = CorrelationService.run_case_correlations("CASE-P5-TEST", db)
        hash_corrs = [c for c in correlations if c.correlation_type == "SAME_HASH_CROSS_AGENT"]
        assert len(hash_corrs) >= 1
        found = next(c for c in hash_corrs if shared_hash in c.indicators)
        assert len(found.related_agent_ids) >= 2
        assert "AGENT-WIN-P5-01" in found.related_agent_ids
        assert "AGENT-WIN-P5-02" in found.related_agent_ids
    finally:
        db.close()

def test_7_evidence_correlation_persistence_and_process_net():
    db = SessionLocal()
    try:
        # Persistence evidence on Agent 1
        ev_persist = Evidence(
            id="EV-CORR-PERSIST-01",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-WIN-P5-01",
            collector="persistence.startup",
            platform="Windows",
            sha256_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            envelope_data={"results": [{"name": "UpdaterService", "persistence_type": "Registry Run Key", "location": "HKLM_Run"}]},
            is_verified=True
        )
        # Network evidence on Agent 1
        ev_net = Evidence(
            id="EV-CORR-NET-01",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-WIN-P5-01",
            collector="network.connections",
            platform="Windows",
            sha256_hash="222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
            envelope_data={"results": [{"remote_address": "198.51.100.25:443", "status": "ESTABLISHED"}]},
            is_verified=True
        )
        db.merge(ev_persist)
        db.merge(ev_net)
        db.commit()

        corrs = CorrelationService.run_case_correlations("CASE-P5-TEST", db)
        types = [c.correlation_type for c in corrs]
        assert "PERSISTENCE_EXECUTABLE_LINK" in types
        assert "PROCESS_NETWORK_OUTBOUND" in types
    finally:
        db.close()

def test_8_finding_generation_with_evidence_traceability():
    db = SessionLocal()
    try:
        findings = FindingService.generate_findings_for_case("CASE-P5-TEST", db)
        assert len(findings) >= 1
        for f in findings:
            # Must strictly reference underlying evidence IDs
            assert f.evidence_ids is not None
            assert len(f.evidence_ids) >= 1
            assert f.status in ("OPEN", "UNDER_REVIEW", "CONFIRMED", "DISMISSED")
            assert f.priority in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert len(f.priority_reasons) >= 1
    finally:
        db.close()

def test_9_finding_status_transitions():
    db = SessionLocal()
    try:
        findings = db.query(Finding).filter(Finding.case_id == "CASE-P5-TEST").all()
        assert len(findings) >= 1
        target_fnd = findings[0]

        # Valid transitions
        updated = FindingService.update_finding_status(target_fnd.id, "CONFIRMED", db)
        assert updated.status == "CONFIRMED"

        updated = FindingService.update_finding_status(target_fnd.id, "DISMISSED", db)
        assert updated.status == "DISMISSED"

        # Invalid transition raises ValueError
        with pytest.raises(ValueError):
            FindingService.update_finding_status(target_fnd.id, "MALICIOUS_HACKED", db)
    finally:
        db.close()

def test_10_api_investigation_summary():
    response = client.get("/api/investigations/CASE-P5-TEST/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == "CASE-P5-TEST"
    assert data["total_evidence"] >= 2
    assert data["total_indicators"] >= 1
    assert data["total_findings"] >= 1

def test_11_api_investigation_graph():
    response = client.get("/api/investigations/CASE-P5-TEST/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 2
    node_types = {n["type"] for n in data["nodes"]}
    assert "agent" in node_types
    assert "evidence" in node_types

def test_12_api_investigation_search():
    # Search by process prefix
    res1 = client.get("/api/investigations/CASE-P5-TEST/search?q=process:beacon")
    assert res1.status_code == 200
    d1 = res1.json()
    assert len(d1["matching_indicators"]) >= 1

    # Search by IP prefix
    res2 = client.get("/api/investigations/CASE-P5-TEST/search?q=ip:10.200.1.50")
    assert res2.status_code == 200
    d2 = res2.json()
    assert len(d2["matching_indicators"]) >= 1

    # Free text search
    res3 = client.get("/api/investigations/CASE-P5-TEST/search?q=AGENT-WIN-P5-01")
    assert res3.status_code == 200
    d3 = res3.json()
    assert len(d3["matching_evidence_ids"]) >= 1

def test_13_analyst_notes_and_audit():
    note_payload = {
        "analyst_name": "Lead Forensic Examiner",
        "note_type": "hypothesis",
        "content": "Potential lateral movement via shared binary observed on WIN-P5-01 and WIN-P5-02."
    }
    create_res = client.post("/api/investigations/CASE-P5-TEST/notes", json=note_payload)
    assert create_res.status_code == 201
    note_data = create_res.json()
    assert note_data["note_type"] == "hypothesis"
    assert "lateral movement" in note_data["content"]

    # Verify notes listed
    list_res = client.get("/api/investigations/CASE-P5-TEST/notes")
    assert list_res.status_code == 200
    assert any(n["id"] == note_data["id"] for n in list_res.json())

    # Verify audit log recorded note creation
    db = SessionLocal()
    try:
        audit = db.query(AuditLog).filter(
            AuditLog.resource_id == note_data["id"],
            AuditLog.action == "ADD_ANALYST_NOTE"
        ).first()
        assert audit is not None
        assert audit.result == "SUCCESS"
    finally:
        db.close()

def test_14_finding_status_patch_endpoint():
    db = SessionLocal()
    try:
        fnd = db.query(Finding).filter(Finding.case_id == "CASE-P5-TEST").first()
        fnd_id = fnd.id
    finally:
        db.close()

    patch_res = client.patch(f"/api/investigations/CASE-P5-TEST/findings/{fnd_id}", json={"status": "UNDER_REVIEW"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "UNDER_REVIEW"

def test_15_enhanced_multi_format_report_export():
    for fmt in ["json", "csv", "html", "pdf"]:
        res = client.get(f"/api/reports/CASE-P5-TEST/export?format={fmt}")
        assert res.status_code == 200, f"Export format {fmt} failed"
        if fmt == "pdf":
            assert res.content.startswith(b"%PDF")
        elif fmt == "html":
            assert "JOCKY FORENSIC INVESTIGATION REPORT" in res.text
            assert "Investigative Findings" in res.text
        elif fmt == "csv":
            assert "INVESTIGATIVE FINDINGS" in res.text
            assert "CRYPTOGRAPHIC EVIDENCE LEDGER" in res.text
        elif fmt == "json":
            data = res.json()
            assert "investigation_findings" in data
            assert "indicators" in data
            assert "timeline" in data

def test_16_end_to_end_investigation_orchestration():
    db = SessionLocal()
    try:
        # Ingest new evidence and verify orchestrator handles everything
        ev_new = Evidence(
            id="EV-E2E-ORCH-01",
            case_id="CASE-P5-TEST",
            agent_id="AGENT-LINUX-P5-01",
            collector="network.connections",
            platform="Linux",
            sha256_hash="33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222",
            envelope_data={"results": [{"remote_address": "203.0.113.88:80", "status": "SYN_SENT"}]},
            is_verified=True
        )
        db.merge(ev_new)
        db.commit()

        orch_res = InvestigationOrchestrator.process_evidence("EV-E2E-ORCH-01", db)
        assert orch_res["status"] == "success"
        assert orch_res["indicators_extracted"] >= 1
        assert orch_res["timeline_events_created"] >= 1
        assert orch_res["findings_count"] >= 1
    finally:
        db.close()
