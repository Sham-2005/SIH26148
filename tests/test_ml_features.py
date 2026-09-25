"""
Test Suite: Forensic Feature Extraction & Vector Schemas
Validates feature extraction from case artifacts, schema versioning,
ordering, and data type compliance.
"""
import pytest
from datetime import datetime, timezone
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import Case, Evidence, InvestigationIndicator, TimelineEvent, SecurityEvent
from backend.app.ml.schemas import ForensicFeatureVector, FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from backend.app.ml.feature_extractor import ForensicFeatureExtractor


@pytest.fixture(scope="module", autouse=True)
def setup_feature_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    case = db.query(Case).filter(Case.id == "CASE-FEAT-TEST").first()
    if not case:
        case = Case(
            id="CASE-FEAT-TEST",
            title="Feature Extraction Test Case",
            description="Case for validating deterministic feature extraction",
            severity="medium",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()

    # Add evidence with processes, network, persistence, PE info
    proc_ev = Evidence(
        id="EV-FEAT-PROC",
        case_id="CASE-FEAT-TEST",
        agent_id="AGENT-WIN-01",
        collector="process.list",
        platform="windows",
        envelope_data={
            "processes": [
                {"pid": 101, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"},
                {"pid": 102, "name": "powershell.exe", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\ps.exe"},
                {"pid": 103, "name": "mimikatz.exe", "path": "C:\\Temp\\mimi.exe"}
            ]
        },
        sha256_hash="a" * 64,
        is_verified=True
    )
    net_ev = Evidence(
        id="EV-FEAT-NET",
        case_id="CASE-FEAT-TEST",
        agent_id="AGENT-WIN-01",
        collector="network.sockets",
        platform="windows",
        envelope_data={
            "connections": [
                {"protocol": "TCP", "local_address": "192.168.1.10:49152", "remote_address": "10.0.0.5:445", "state": "ESTABLISHED"},
                {"protocol": "TCP", "local_address": "192.168.1.10:49153", "remote_address": "198.51.100.24:4444", "state": "ESTABLISHED"}
            ]
        },
        sha256_hash="b" * 64,
        is_verified=True
    )
    persist_ev = Evidence(
        id="EV-FEAT-PERSIST",
        case_id="CASE-FEAT-TEST",
        agent_id="AGENT-WIN-01",
        collector="persistence.autorun",
        platform="windows",
        envelope_data={
            "entries": [
                {"name": "BenignService", "path": "C:\\Program Files\\App\\app.exe"},
                {"name": "SuspiciousRun", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.bat"}
            ]
        },
        sha256_hash="c" * 64,
        is_verified=True
    )
    pe_ev = Evidence(
        id="EV-FEAT-PE",
        case_id="CASE-FEAT-TEST",
        agent_id="AGENT-WIN-01",
        collector="malware.pe_info",
        platform="windows",
        envelope_data={
            "pe_headers": {
                "entropy": 7.85,
                "sections": [{"name": ".text"}, {"name": ".upx0"}]
            }
        },
        sha256_hash="d" * 64,
        is_verified=True
    )

    for ev in [proc_ev, net_ev, persist_ev, pe_ev]:
        if not db.query(Evidence).filter(Evidence.id == ev.id).first():
            db.add(ev)

    # Add indicators
    ioc1 = InvestigationIndicator(
        id="IOC-FEAT-1",
        case_id="CASE-FEAT-TEST",
        indicator_type="HASH_SHA256",
        value="e" * 64,
        normalized_value="e" * 64,
        status="ACTIVE"
    )
    ioc2 = InvestigationIndicator(
        id="IOC-FEAT-2",
        case_id="CASE-FEAT-TEST",
        indicator_type="IPV4",
        value="198.51.100.24",
        normalized_value="198.51.100.24",
        status="ACTIVE"
    )
    for ioc in [ioc1, ioc2]:
        if not db.query(InvestigationIndicator).filter(InvestigationIndicator.id == ioc.id).first():
            db.add(ioc)

    # Add timeline event
    tl = TimelineEvent(
        id="TL-FEAT-1",
        case_id="CASE-FEAT-TEST",
        event_type="PROCESS_START",
        description="Suspicious binary started from temp",
        severity="HIGH",
        timestamp=datetime.now(timezone.utc)
    )
    if not db.query(TimelineEvent).filter(TimelineEvent.id == tl.id).first():
        db.add(tl)

    db.commit()
    db.close()


def test_feature_vector_dimension_and_schema():
    """Validates that ForensicFeatureVector matches the exact 21 features schema."""
    vec = ForensicFeatureVector()
    assert len(FEATURE_NAMES) == 21
    assert vec.feature_schema_version == FEATURE_SCHEMA_VERSION

    arr = vec.to_array()
    assert len(arr) == 21
    assert all(isinstance(val, float) for val in arr)

    feat_dict = vec.to_dict_features()
    assert len(feat_dict) == 21
    for name in FEATURE_NAMES:
        assert name in feat_dict


def test_feature_extractor_from_case():
    """Validates extraction of features from case evidence items and indicators."""
    db = SessionLocal()
    try:
        features = ForensicFeatureExtractor.extract_from_case("CASE-FEAT-TEST", db)
        assert isinstance(features, ForensicFeatureVector)
        d = features.to_dict_features()

        # Processes: 3 total, 2 suspicious (mimikatz, temp path)
        assert d["process_count"] == 3
        assert d["suspicious_process_count"] >= 1
        assert d["temp_path_process_count"] >= 1

        # Network: 2 connections, 1 external, 1 suspicious port (4444)
        assert d["connection_count"] == 2
        assert d["external_connection_count"] == 1
        assert d["suspicious_port_count"] >= 1

        # Persistence: 2 entries, 1 suspicious (in temp)
        assert d["persistence_count"] == 2
        assert d["suspicious_persistence_count"] >= 1

        # PE: high entropy anomaly
        assert d["pe_anomaly_count"] >= 1

        # IOCs: 2 indicators
        assert d["ioc_count"] == 2
        assert d["ip_ioc_count"] == 1
        assert d["hash_ioc_count"] == 1

        # Timeline
        assert d["timeline_event_count"] >= 1

    finally:
        db.close()
