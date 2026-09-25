"""
Phase 27 Comprehensive Test Suite
Tests for:
1. Canonical JSON & deterministic SHA-256 evidence hashing
2. Sequential evidence hash chaining
3. Merkle tree construction, root calculation, proof generation, and verification
4. Local Evidence Blockchain anchoring and ledger verification
5. Vertical Finding-to-Evidence traceability chain
6. Explainable ML factor attribution
7. All 8 Tampering Scenarios (Mandatory Section 28 & 35):
   - Test 1: Modify evidence structured data -> FAIL
   - Test 2: Modify evidence raw data -> FAIL
   - Test 3: Modify evidence composite hash -> FAIL
   - Test 4: Delete evidence -> FAIL
   - Test 5: Reorder evidence -> FAIL
   - Test 6: Modify JOCKY script -> SCRIPT HASH MISMATCH
   - Test 7: Modify blockchain anchor -> BLOCKCHAIN VERIFICATION FAILED
   - Test 8: Valid investigation -> ALL INTEGRITY CHECKS PASSED
8. API Endpoints verification
"""
import copy
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.session import SessionLocal
from backend.app.models.models import Case, Evidence, Finding, MerkleTreeRecord, BlockchainAnchorRecord, ExecutionHistory
from backend.app.services.security_integrity_service import canonical_json, calculate_sha256
from backend.app.services.merkle_service import MerkleService
from backend.app.services.blockchain_service import BlockchainService
from backend.app.services.provenance_service import ProvenanceService, GENESIS_EVIDENCE_HASH


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def test_client():
    return TestClient(app)


# ============================================================================
# 1. CANONICAL JSON & DETERMINISTIC HASHING TESTS
# ============================================================================

def test_canonical_json_key_sorting():
    obj1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    obj2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_json(obj1) == canonical_json(obj2)
    assert calculate_sha256(canonical_json(obj1)) == calculate_sha256(canonical_json(obj2))


def test_canonical_evidence_deterministic_hashes():
    now_str = "2026-09-25T10:30:00Z"
    host_meta = {"hostname": "HOST-01", "platform": "Windows"}
    raw_payload = {"pid": 4812, "name": "sample.exe"}
    norm_payload = {"type": "process", "pid": 4812, "name": "sample.exe"}

    canon1 = ProvenanceService.compute_canonical_evidence(
        evidence_id="EVD-TEST-001",
        investigation_id="INV-TEST-001",
        execution_id="EXE-TEST-001",
        collector_name="processes",
        collector_version="1.0.0",
        collector_source="Windows Process API",
        timestamp_iso=now_str,
        host_metadata=host_meta,
        script_id="SCR-001",
        script_hash="34bbbedb48a6c0cc73a0578b9e8c61b481067dd4752b267a80892717e31b0c2a",
        raw_data=raw_payload,
        normalized_data=norm_payload,
        previous_evidence_hash=GENESIS_EVIDENCE_HASH
    )

    canon2 = ProvenanceService.compute_canonical_evidence(
        evidence_id="EVD-TEST-001",
        investigation_id="INV-TEST-001",
        execution_id="EXE-TEST-001",
        collector_name="processes",
        collector_version="1.0.0",
        collector_source="Windows Process API",
        timestamp_iso=now_str,
        host_metadata=host_meta,
        script_id="SCR-001",
        script_hash="34bbbedb48a6c0cc73a0578b9e8c61b481067dd4752b267a80892717e31b0c2a",
        raw_data=raw_payload,
        normalized_data=norm_payload,
        previous_evidence_hash=GENESIS_EVIDENCE_HASH
    )

    assert canon1["evidence_hash"] == canon2["evidence_hash"]
    assert canon1["raw_data_hash"] == canon2["raw_data_hash"]
    assert canon1["normalized_data_hash"] == canon2["normalized_data_hash"]
    assert canon1["previous_evidence_hash"] == GENESIS_EVIDENCE_HASH


# ============================================================================
# 2. MERKLE TREE & AUDIT PROOF TESTS
# ============================================================================

def test_merkle_tree_even_and_odd_leaves():
    # 4 leaves (power of 2)
    leaves4 = [calculate_sha256(f"leaf_{i}".encode()) for i in range(4)]
    root4 = MerkleService.calculate_merkle_root(leaves4)
    assert len(root4) == 64

    # 3 leaves (odd count - duplicates final node)
    leaves3 = [calculate_sha256(f"leaf_{i}".encode()) for i in range(3)]
    root3 = MerkleService.calculate_merkle_root(leaves3)
    assert len(root3) == 64
    assert root3 != root4

    # Single leaf
    root1 = MerkleService.calculate_merkle_root([leaves4[0]])
    assert root1 == leaves4[0]


def test_merkle_audit_proof_generation_and_verification():
    leaves = [calculate_sha256(f"envelope_{i}".encode()) for i in range(7)]  # odd number
    expected_root = MerkleService.calculate_merkle_root(leaves)

    for idx, leaf in enumerate(leaves):
        proof = MerkleService.generate_merkle_proof(leaves, idx)
        assert proof is not None
        assert len(proof) > 0
        is_valid = MerkleService.verify_merkle_proof(leaf, proof, expected_root)
        assert is_valid is True

    # Tampered leaf hash must fail verification
    tampered_leaf = calculate_sha256(b"tampered_data")
    proof0 = MerkleService.generate_merkle_proof(leaves, 0)
    assert MerkleService.verify_merkle_proof(tampered_leaf, proof0, expected_root) is False


# ============================================================================
# 3. BLOCKCHAIN LEDGER TESTS
# ============================================================================

def test_blockchain_anchor_and_ledger_verification(db_session):
    case_id = "CASE-TEST-BLK-01"
    now_str = datetime.now(timezone.utc).isoformat()
    m_root = calculate_sha256(b"merkle_test_root")
    s_hash = calculate_sha256(b"script_test_hash")

    anchor = BlockchainService.anchor_investigation(
        case_id=case_id,
        merkle_root=m_root,
        evidence_count=10,
        script_hash=s_hash,
        execution_id="EXE-TEST-01",
        db=db_session
    )

    assert anchor.status == "ANCHORED"
    assert anchor.network == "Local Evidence Blockchain"
    assert len(anchor.block_hash) == 64

    valid, failures = BlockchainService.verify_blockchain_ledger(db_session, case_id=case_id)
    assert valid is True
    assert len(failures) == 0


# ============================================================================
# 4. DETERMINISTIC DEMO & FINDING PROVENANCE TESTS
# ============================================================================

def test_deterministic_investigation_creation(db_session):
    case_id = "CASE-TEST-PROV-01"
    result = ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    assert result["status"] == "SUCCESS"
    assert result["evidence_count"] >= 25
    assert result["findings_count"] >= 4
    assert result["merkle_root"] is not None
    assert result["blockchain_anchor"]["network"] == "Local Evidence Blockchain"

    # Verify findings are populated
    findings = db_session.query(Finding).filter(Finding.case_id == case_id).all()
    assert len(findings) >= 4

    # Test Finding Traceability chain
    fnd1 = findings[0]
    prov = ProvenanceService.get_finding_provenance(case_id, fnd1.id, db=db_session)
    assert prov is not None
    assert len(prov["supporting_evidence"]) > 0
    assert len(prov["traceability_chain"]) >= 7

    # Verify explainable ML attribution
    ml_fnd = next((f for f in findings if f.detection_type == "ml"), None)
    assert ml_fnd is not None
    assert ml_fnd.model_name == "JOCKY-Anomaly-v1"
    assert ml_fnd.confidence_score >= 0.90
    assert ml_fnd.explainable_factors is not None
    assert len(ml_fnd.explainable_factors) > 0


# ============================================================================
# 5. ALL 8 MANDATORY TAMPERING TESTS (Section 28)
# ============================================================================

def test_tampering_scenario_8_valid_investigation(db_session):
    """Test 8 — Valid investigation: ALL INTEGRITY CHECKS PASSED"""
    case_id = "CASE-TEST-TAMPER-08"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)
    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)

    assert verify["valid"] is True
    assert verify["evidence"]["failed"] == 0
    assert verify["hash_chain"]["valid"] is True
    assert verify["merkle"]["valid"] is True
    assert verify["blockchain"]["valid"] is True
    assert verify["script"]["valid"] is True
    assert len(verify["failures"]) == 0


def test_tampering_scenario_1_modify_evidence_structured_data(db_session):
    """Test 1 — Modify evidence structured data: Expected FAIL"""
    case_id = "CASE-TEST-TAMPER-01"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    # Tamper with normalized data
    t_res = ProvenanceService.tamper_evidence(case_id, tamper_field="normalized_data", new_value="TAMPERED_PID_9999", db=db_session)
    assert t_res["status"] == "TAMPERED"

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert len(verify["failures"]) > 0
    assert any("Normalized evidence hash mismatch" in f.get("reason", "") for f in verify["failures"])

    # Restore and verify back to valid
    r_res = ProvenanceService.restore_evidence(case_id, db=db_session)
    assert r_res["status"] == "RESTORED"
    v_clean = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert v_clean["valid"] is True


def test_tampering_scenario_2_modify_evidence_raw_data(db_session):
    """Test 2 — Modify raw evidence data: Expected FAIL"""
    case_id = "CASE-TEST-TAMPER-02"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    t_res = ProvenanceService.tamper_evidence(case_id, tamper_field="raw_data", new_value={"injected": "malicious_raw"}, db=db_session)
    assert t_res["status"] == "TAMPERED"

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert any("Raw evidence hash mismatch" in f.get("reason", "") for f in verify["failures"])

    # Restore
    ProvenanceService.restore_evidence(case_id, db=db_session)
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


def test_tampering_scenario_3_modify_evidence_hash(db_session):
    """Test 3 — Modify evidence composite hash: Expected FAIL"""
    case_id = "CASE-TEST-TAMPER-03"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    t_res = ProvenanceService.tamper_evidence(case_id, tamper_field="sha256_hash", new_value="deadbeef" * 8, db=db_session)
    assert t_res["status"] == "TAMPERED"

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert any("hash mismatch" in f.get("reason", "").lower() for f in verify["failures"])

    ProvenanceService.restore_evidence(case_id, db=db_session)
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


def test_tampering_scenario_4_delete_evidence(db_session):
    """Test 4 — Delete evidence: Expected FAIL"""
    case_id = "CASE-TEST-TAMPER-04"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    # Delete one evidence item
    t_res = ProvenanceService.tamper_evidence(case_id, tamper_field="delete", db=db_session)
    assert t_res["action"] == "DELETED"

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert any("Merkle root mismatch" in f.get("reason", "") or "Hash chain" in f.get("reason", "") for f in verify["failures"])

    # Restore
    ProvenanceService.restore_evidence(case_id, db=db_session)
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


def test_tampering_scenario_5_reorder_evidence(db_session):
    """Test 5 — Reorder evidence timestamps/chain: Expected FAIL"""
    from datetime import timedelta
    case_id = "CASE-TEST-TAMPER-05"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    # Modify collected_at of first evidence record to be after the second
    evs = db_session.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.id.asc()).limit(2).all()
    assert len(evs) == 2
    t0 = evs[0].collected_at
    t1 = evs[1].collected_at
    evs[0].collected_at = t1 + timedelta(seconds=10)
    db_session.commit()

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert any("Chronological order violation" in f.get("reason", "") or "non-monotonic" in f.get("reason", "") for f in verify["failures"])

    # Restore original time
    evs[0].collected_at = t0
    db_session.commit()
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


def test_tampering_scenario_6_modify_script(db_session):
    """Test 6 — Modify JOCKY script: SCRIPT HASH MISMATCH"""
    case_id = "CASE-TEST-TAMPER-06"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    ex = db_session.query(ExecutionHistory).filter(ExecutionHistory.case_id == case_id).order_by(ExecutionHistory.started_at.desc()).first()
    orig_script = ex.script_content
    ex.script_content = orig_script + "\n// INJECTED ATTACKER BYPASS COMMAND"
    db_session.commit()

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert verify["script"]["valid"] is False
    assert any("Script hash mismatch" in f.get("reason", "") for f in verify["failures"])

    # Restore script
    ex.script_content = orig_script
    db_session.commit()
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


def test_tampering_scenario_7_modify_blockchain_anchor(db_session):
    """Test 7 — Modify blockchain anchor: BLOCKCHAIN VERIFICATION FAILED"""
    case_id = "CASE-TEST-TAMPER-07"
    ProvenanceService.run_deterministic_investigation(case_id, db=db_session)

    anchor = db_session.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case_id).first()
    orig_root = anchor.merkle_root
    anchor.merkle_root = calculate_sha256(b"fake_tampered_merkle_root")
    db_session.commit()

    verify = ProvenanceService.verify_investigation_integrity(case_id, db=db_session)
    assert verify["valid"] is False
    assert verify["blockchain"]["valid"] is False
    assert any("Blockchain" in f.get("reason", "") for f in verify["failures"])

    # Restore anchor
    anchor.merkle_root = orig_root
    db_session.commit()
    assert ProvenanceService.verify_investigation_integrity(case_id, db=db_session)["valid"] is True


# ============================================================================
# 6. API ENDPOINTS INTEGRATION TESTS
# ============================================================================

def test_api_investigations_evidence(test_client, db_session):
    ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db_session)
    res = test_client.get("/api/investigations/CASE-DEMO-01/evidence")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 25
    first_ev = data[0]
    assert "evidence_id" in first_ev or "id" in first_ev
    assert "sha256_hash" in first_ev
    assert "raw_data_hash" in first_ev
    assert "normalized_data_hash" in first_ev


def test_api_investigations_merkle_and_proof(test_client, db_session):
    ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db_session)
    res_ev = test_client.get("/api/investigations/CASE-DEMO-01/evidence")
    assert res_ev.status_code == 200
    first_ev_id = res_ev.json()[0]["id"]

    res_m = test_client.get("/api/investigations/CASE-DEMO-01/merkle")
    assert res_m.status_code == 200
    m_data = res_m.json()
    assert "merkle_root" in m_data
    assert m_data["evidence_count"] >= 25

    # Proof
    res_p = test_client.get(f"/api/investigations/CASE-DEMO-01/merkle/proof?evidence_id={first_ev_id}")
    assert res_p.status_code == 200
    p_data = res_p.json()
    assert p_data["is_verified"] is True
    assert len(p_data["proof_steps"]) > 0


def test_api_investigations_blockchain(test_client, db_session):
    ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db_session)
    res = test_client.get("/api/investigations/CASE-DEMO-01/blockchain")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert data[0]["network"] == "Local Evidence Blockchain"
    assert data[0]["status"] == "ANCHORED"


def test_api_investigations_provenance_trace(test_client, db_session):
    ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db_session)
    res_fnd = test_client.get("/api/investigations/CASE-DEMO-01/findings")
    assert res_fnd.status_code == 200
    findings = res_fnd.json()
    assert len(findings) > 0
    first_fid = findings[0]["id"]

    res = test_client.get(f"/api/investigations/CASE-DEMO-01/provenance/{first_fid}")
    assert res.status_code == 200
    data = res.json()
    assert "finding" in data
    assert "supporting_evidence" in data
    assert "traceability_chain" in data
    assert len(data["traceability_chain"]) >= 7


def test_api_investigations_integrity_tamper_and_restore(test_client, db_session):
    ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db_session)

    # 1. Verify before tamper
    v0 = test_client.post("/api/investigations/CASE-DEMO-01/integrity/verify").json()
    assert v0["valid"] is True

    # 2. Tamper
    t = test_client.post("/api/investigations/CASE-DEMO-01/integrity/tamper-demo?tamper_field=data").json()
    assert t["status"] == "TAMPERED"

    # 3. Verify -> Must Fail
    v1 = test_client.post("/api/investigations/CASE-DEMO-01/integrity/verify").json()
    assert v1["valid"] is False
    assert len(v1["failures"]) > 0

    # 4. Restore
    r = test_client.post("/api/investigations/CASE-DEMO-01/integrity/restore-demo").json()
    assert r["status"] == "RESTORED"

    # 5. Verify -> Must Pass again
    v2 = test_client.post("/api/investigations/CASE-DEMO-01/integrity/verify").json()
    assert v2["valid"] is True

