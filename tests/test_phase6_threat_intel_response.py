"""
Phase 6 Test Suite: Threat Intelligence, Incident Response & Advanced SOC Visualization
Validates:
1. STIX 2.1 bundle structure and validation
2. STIX pattern parsing and IOC extraction
3. Invalid STIX bundle rejection
4. LocalSTIXProvider operation
5. TAXIIProvider operation and connection test
6. DemoThreatIntelProvider simulation data and tagging
7. Threat intelligence database persistence and deduplication
8. Evidence and indicator threat intelligence cross-correlation
9. Playbook action allowlist validation (UNSUPPORTED_RESPONSE_ACTION)
10. Playbook creation with valid actions
11. Playbook approval lifecycle (PENDING_APPROVAL -> APPROVED)
12. Playbook rejection lifecycle (PENDING_APPROVAL -> REJECTED)
13. Execution of unapproved playbook blocked (HTTP 400)
14. Approved playbook sequential execution
15. REST API: /api/threat-intel/sources and /api/threat-intel/import
16. REST API: /api/investigations/{case_id}/intel
17. REST API: /api/investigations/{case_id}/heatmap
18. REST API: /api/investigations/{case_id}/attack-patterns
19. Multi-format report export with Threat Intel and Playbook sections
"""
import pytest
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import (
    Case, Agent, Evidence, InvestigationIndicator, TimelineEvent,
    ThreatIntelItem, Playbook, PlaybookAction, PlaybookApproval, PlaybookExecution,
    AuditLog
)
from backend.app.services.stix_service import STIXService
from backend.app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
    LocalSTIXProvider,
    TAXIIProvider,
    DemoThreatIntelProvider,
)
from backend.app.services.playbook_service import (
    PlaybookService,
    APPROVED_DEFENSIVE_ACTIONS,
)
from backend.app.services.report_export_service import ReportExportService

client = TestClient(app)

TEST_CASE_ID = "CASE-P6-TEST"
TEST_AGENT_ID = "AGENT-WIN-P6-01"


@pytest.fixture(scope="module", autouse=True)
def setup_phase6_test_env():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Create test case if not present
        test_case = db.query(Case).filter(Case.id == TEST_CASE_ID).first()
        if not test_case:
            test_case = Case(
                id=TEST_CASE_ID,
                title="Phase 6 Automated SOC Response & Threat Intel Test",
                description="Fleet test case for STIX 2.1, Playbooks, and Advanced Visualizations.",
                severity="critical",
                status="INVESTIGATING"
            )
            db.add(test_case)

        # Create test agent if not present
        test_agent = db.query(Agent).filter(Agent.id == TEST_AGENT_ID).first()
        if not test_agent:
            test_agent = Agent(
                id=TEST_AGENT_ID,
                hostname="SRV-WIN-SEC01",
                platform="Windows",
                os_version="Windows Server 2022 Datacenter",
                architecture="x86_64",
                ip_address="10.0.10.15",
                status="online",
                capabilities=["system_collector", "process_collector", "network_collector", "persistence_collector"]
            )
            db.add(test_agent)

        # Create sample evidence with known IOCs
        sample_evidence = db.query(Evidence).filter(Evidence.id == "EV-P6-001").first()
        if not sample_evidence:
            sample_evidence = Evidence(
                id="EV-P6-001",
                case_id=TEST_CASE_ID,
                agent_id=TEST_AGENT_ID,
                collector="network_collector",
                platform="Windows",
                sha256_hash="44d88612fea8a8f36de82e1278abb02f" * 2,
                is_verified=True,
                envelope_data={
                    "results": {
                        "connections": [
                            {"dest_ip": "198.51.100.42", "dest_port": 443, "pid": 4120, "process_name": "svchost32.exe"}
                        ]
                    }
                }
            )
            db.add(sample_evidence)

        # Create indicator
        sample_indicator = db.query(InvestigationIndicator).filter(InvestigationIndicator.id == "IOC-P6-001").first()
        if not sample_indicator:
            sample_indicator = InvestigationIndicator(
                id="IOC-P6-001",
                case_id=TEST_CASE_ID,
                indicator_type="ipv4",
                value="198.51.100.42",
                normalized_value="198.51.100.42",
                source_evidence_id="EV-P6-001",
                agent_id=TEST_AGENT_ID,
                status="observed"
            )
            db.add(sample_indicator)

        # Create timeline events for heatmap
        now = datetime.now(timezone.utc)
        for i in range(5):
            te_id = f"TLE-P6-{i}"
            if not db.query(TimelineEvent).filter(TimelineEvent.id == te_id).first():
                db.add(TimelineEvent(
                    id=te_id,
                    case_id=TEST_CASE_ID,
                    agent_id=TEST_AGENT_ID,
                    timestamp=now,
                    event_type="NETWORK" if i % 2 == 0 else "PROCESS",
                    severity="HIGH" if i == 0 else "INFO",
                    description=f"Automated test event #{i} for heatmap validation"
                ))

        db.commit()
    finally:
        db.close()


def test_1_stix_bundle_parsing_and_validation():
    """Validates STIX 2.1 bundle structure, object types, and required fields."""
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--5f8c86d8-912a-43cf-bc81-c74b78c8bc1e",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "name": "Malicious Beacon IP",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "pattern_type": "stix",
                "confidence": 85
            },
            {
                "type": "malware",
                "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
                "name": "DarkStag Backdoor",
                "labels": ["backdoor", "c2"]
            }
        ]
    }
    is_valid, err = STIXService.validate_stix_object(stix_bundle)
    assert is_valid is True
    assert err is None

    parsed_items = STIXService.parse_bundle_or_object(stix_bundle, source="TEST")
    assert len(parsed_items) == 2
    assert parsed_items[0]["intel_type"] == "indicator"
    assert parsed_items[0]["name"] == "Malicious Beacon IP"
    assert parsed_items[1]["intel_type"] == "malware"


def test_2_stix_pattern_ioc_extraction():
    """Tests parsing of complex STIX pattern expressions."""
    patterns = {
        "[file:hashes.'SHA-256' = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90']": ("sha256", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        "[ipv4-addr:value = '203.0.113.50']": ("ipv4", "203.0.113.50"),
        "[domain-name:value = 'command-and-control.test']": ("domain", "command-and-control.test"),
        "[process:name = 'backdoor.exe']": ("process_name", "backdoor.exe"),
    }
    for pat, (expected_type, expected_val) in patterns.items():
        extracted = STIXService.extract_iocs_from_pattern(pat)
        assert expected_val.lower() in extracted[expected_type]


def test_3_stix_invalid_bundle_rejection():
    """Rejects invalid STIX formats with descriptive error."""
    invalid_bundle = {"type": "bundle"}  # Missing objects list
    is_valid, err = STIXService.validate_stix_object(invalid_bundle)
    assert is_valid is False
    assert "must contain an 'objects' list" in err

    invalid_obj = {"type": "unknown_type"}
    is_valid_obj, err_obj = STIXService.validate_stix_object(invalid_obj)
    assert is_valid_obj is False
    assert "Unsupported or missing STIX" in err_obj


def test_4_local_stix_provider():
    """Loads local STIX objects and verifies parsed output."""
    raw_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--test-local-01",
                "name": "Local Threat Indicator",
                "pattern": "[domain-name:value = 'evil-corp.com']"
            }
        ]
    }
    provider = LocalSTIXProvider(raw_bundle_data=raw_bundle)
    test_conn = provider.test_connection()
    assert test_conn["status"] == "ready"
    items = provider.fetch_items()
    assert len(items) == 1
    assert items[0]["name"] == "Local Threat Indicator"


def test_5_taxii_provider_feed_fetch():
    """Exercises TAXIIProvider abstraction, tests connection and parses indicators."""
    provider = TAXIIProvider(server_url="https://taxii.jocky.defense/taxii2/")
    conn_info = provider.test_connection()
    assert conn_info["status"] == "connected"
    assert "taxii.jocky.defense" in conn_info["server_url"]

    items = provider.fetch_items()
    assert len(items) >= 2
    assert any("TAXII" in item["name"] for item in items)


def test_6_demo_threat_intel_provider():
    """Ensures DemoThreatIntelProvider produces high-fidelity STIX items marked with [DEMO THREAT INTELLIGENCE]."""
    provider = DemoThreatIntelProvider()
    items = provider.fetch_items()
    assert len(items) >= 4
    for item in items:
        assert "[DEMO THREAT INTELLIGENCE]" in item["name"] or "[DEMO THREAT INTELLIGENCE]" in (item.get("description") or "")


def test_7_threat_intel_database_storage():
    """Verifies importing into DB and deduplication by stix_id."""
    db = SessionLocal()
    try:
        # Clean up any previous test artifact
        db.query(ThreatIntelItem).filter(ThreatIntelItem.stix_id == "indicator--dedup-test-01").delete()
        db.commit()

        items = [
            {
                "stix_id": "indicator--dedup-test-01",
                "intel_type": "indicator",
                "name": "Dedup Test Indicator",
                "pattern": "[ipv4-addr:value = '192.0.2.1']",
                "indicators": {"ipv4": ["192.0.2.1"]}
            }
        ]
        imported_1 = ThreatIntelligenceService.import_intel_items(db, items)
        assert len(imported_1) == 1

        # Second import with same stix_id should skip duplicate
        imported_2 = ThreatIntelligenceService.import_intel_items(db, items)
        assert len(imported_2) == 0
    finally:
        db.close()


def test_8_evidence_threat_intel_correlation():
    """Cross-matches evidence IOCs (IP 198.51.100.42) with threat intel repository."""
    db = SessionLocal()
    try:
        overview = ThreatIntelligenceService.correlate_case_with_threat_intel(db, TEST_CASE_ID)
        assert overview["case_id"] == TEST_CASE_ID
        assert overview["total_intel_items"] > 0
        matches = overview["matches"]
        # The demo indicator matching 198.51.100.42 should be found
        ip_matches = [m for m in matches if m["matched_indicator"] == "198.51.100.42"]
        assert len(ip_matches) >= 1
        assert ip_matches[0]["severity"] in ("CRITICAL", "HIGH")
    finally:
        db.close()


def test_9_playbook_action_allowlist_validation():
    """Verifies APPROVED_DEFENSIVE_ACTIONS passes, and invalid actions fail with UNSUPPORTED_RESPONSE_ACTION."""
    # Test valid actions
    for act in APPROVED_DEFENSIVE_ACTIONS:
        valid, err = PlaybookService.validate_action(act)
        assert valid is True
        assert err is None

    # Test forbidden action (e.g. arbitrary command execution)
    forbidden = "execute.arbitrary_command"
    valid, err = PlaybookService.validate_action(forbidden)
    assert valid is False
    assert "UNSUPPORTED_RESPONSE_ACTION" in err


def test_10_playbook_creation_with_valid_actions():
    """Creates a playbook with collect.processes, isolate.endpoint.simulated, generate.report."""
    db = SessionLocal()
    try:
        # Clean up any existing playbook with this name to ensure idempotent test
        old_pbs = db.query(Playbook).filter(Playbook.name == "Ransomware Containment Playbook").all()
        for old_pb in old_pbs:
            db.delete(old_pb)
        db.commit()

        actions = [
            {"step_number": 1, "action_type": "collect.processes", "target_agent_id": TEST_AGENT_ID},
            {"step_number": 2, "action_type": "isolate.endpoint.simulated", "target_agent_id": TEST_AGENT_ID},
            {"step_number": 3, "action_type": "generate.report", "target_agent_id": None},
        ]
        pb = PlaybookService.create_playbook(
            db=db,
            case_id=TEST_CASE_ID,
            name="Ransomware Containment Playbook",
            actions_data=actions,
            description="Automated triage and containment",
            created_by="lead_analyst@jocky.defense"
        )
        assert pb.status == "PENDING_APPROVAL"
        assert len(pb.actions) == 3
    finally:
        db.close()


def test_11_playbook_approval_workflow():
    """Transitions PENDING_APPROVAL -> APPROVED via analyst approval, recording audit log and approval record."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.name == "Ransomware Containment Playbook").first()
        assert pb is not None
        assert pb.status == "PENDING_APPROVAL"

        approval = PlaybookService.approve_playbook(
            db=db,
            playbook=pb,
            approver_email="chief_analyst@jocky.defense",
            comment="Approved for immediate forensic triage"
        )
        assert approval.decision == "APPROVED"
        assert pb.status == "APPROVED"

        # Check audit log
        audit = db.query(AuditLog).filter(
            AuditLog.action == "APPROVE_PLAYBOOK",
            AuditLog.resource_id == pb.id
        ).first()
        assert audit is not None
        assert audit.result == "SUCCESS"
    finally:
        db.close()


def test_12_playbook_rejection_workflow():
    """Tests analyst rejection and audit logging."""
    db = SessionLocal()
    try:
        old_pbs = db.query(Playbook).filter(Playbook.name == "Rejected Playbook Test").all()
        for old_pb in old_pbs:
            db.delete(old_pb)
        db.commit()

        actions = [{"step_number": 1, "action_type": "collect.network"}]
        pb = PlaybookService.create_playbook(
            db=db,
            case_id=TEST_CASE_ID,
            name="Rejected Playbook Test",
            actions_data=actions
        )
        rejection = PlaybookService.reject_playbook(
            db=db,
            playbook=pb,
            approver_email="analyst@jocky.defense",
            comment="Rejected due to maintenance window"
        )
        assert rejection.decision == "REJECTED"
        assert pb.status == "REJECTED"
    finally:
        db.close()


def test_13_unapproved_playbook_execution_blocked():
    """Ensures executing a playbook in non-APPROVED state is blocked with ValueError."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.name == "Rejected Playbook Test").first()
        assert pb.status == "REJECTED"
        with pytest.raises(ValueError) as exc:
            PlaybookService.execute_playbook(db, pb, "analyst@jocky.defense")
        assert "Playbook not approved" in str(exc.value)
    finally:
        db.close()


def test_14_approved_playbook_sequential_execution():
    """Executes approved playbook, verifies sequential step execution and COMPLETED status."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.name == "Ransomware Containment Playbook").first()
        assert pb.status == "APPROVED"

        execution = PlaybookService.execute_playbook(db, pb, "lead_analyst@jocky.defense")
        assert execution.status == "COMPLETED"
        assert pb.status == "COMPLETED"
        for act in pb.actions:
            assert act.status == "COMPLETED"
            assert act.result_details is not None
    finally:
        db.close()


def test_15_api_threat_intel_sources_and_import():
    """Tests GET /api/threat-intel/sources and POST /api/threat-intel/import."""
    # 1. Sources endpoint
    res = client.get("/api/threat-intel/sources")
    assert res.status_code == 200
    sources = res.json().get("sources", [])
    assert len(sources) >= 3
    source_ids = [s["id"] for s in sources]
    assert "taxii-2.1" in source_ids
    assert "local-stix" in source_ids
    assert "demo-threat-intel" in source_ids

    # 2. Import demo feed
    import_res = client.post("/api/threat-intel/import", json={"source_type": "demo"})
    assert import_res.status_code == 201
    data = import_res.json()
    assert data["status"] == "SUCCESS"

    # 3. Disallowed/invalid source_type
    bad_res = client.post("/api/threat-intel/import", json={"source_type": "invalid_source"})
    assert bad_res.status_code == 400


def test_16_api_case_threat_intel_overview():
    """Tests GET /api/investigations/{case_id}/intel."""
    res = client.get(f"/api/investigations/{TEST_CASE_ID}/intel")
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == TEST_CASE_ID
    assert "matches" in data
    assert "mitre_coverage" in data


def test_17_api_timeline_heatmap():
    """Tests GET /api/investigations/{case_id}/heatmap and bucket aggregation."""
    res = client.get(f"/api/investigations/{TEST_CASE_ID}/heatmap")
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == TEST_CASE_ID
    assert "buckets" in data
    assert data["total_events"] >= 5
    if data["buckets"]:
        b = data["buckets"][0]
        assert "bucket" in b
        assert "count" in b
        assert "severities" in b
        assert "event_types" in b


def test_18_api_mitre_attack_patterns():
    """Tests GET /api/investigations/{case_id}/attack-patterns."""
    res = client.get(f"/api/investigations/{TEST_CASE_ID}/attack-patterns")
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == TEST_CASE_ID
    patterns = data.get("patterns", [])
    assert len(patterns) >= 1
    # Verify standard MITRE techniques are present
    tech_ids = [p["technique_id"] for p in patterns]
    assert "T1059" in tech_ids  # Command & Scripting Interpreter
    assert "T1547" in tech_ids  # Autostart Execution


def test_19_enhanced_report_with_threat_intel_and_playbooks():
    """Generates JSON, HTML, CSV, and PDF reports and confirms threat intel and playbook sections exist."""
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == TEST_CASE_ID).first()
        assert case is not None

        # 1. Report generation
        report_res = client.post("/api/reports/generate", json={"case_id": TEST_CASE_ID, "report_type": "comprehensive"})
        assert report_res.status_code in (200, 201)
        report_id = report_res.json()["id"]

        # Download HTML
        html_res = client.get(f"/api/reports/{TEST_CASE_ID}/export?format=html")
        assert html_res.status_code == 200
        html_content = html_res.text
        assert "<h1>JOCKY FORENSIC INVESTIGATION REPORT</h1>" in html_content
        assert "Threat Intelligence Correlation" in html_content
        assert "Defensive Playbooks & Response Actions" in html_content

        # Download CSV
        csv_res = client.get(f"/api/reports/{TEST_CASE_ID}/export?format=csv")
        assert csv_res.status_code == 200
        assert "=== THREAT INTELLIGENCE MATCHES ===" in csv_res.text
        assert "=== DEFENSIVE PLAYBOOKS & ACTIONS ===" in csv_res.text

        # Download PDF
        pdf_res = client.get(f"/api/reports/{TEST_CASE_ID}/export?format=pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers.get("content-type") == "application/pdf"
        assert len(pdf_res.content) > 1000  # Non-empty valid PDF bytes
    finally:
        db.close()
