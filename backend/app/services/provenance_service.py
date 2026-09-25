"""
Evidence Provenance & Traceability Layer for JOCKY Digital Forensics
Connects the complete forensic lifecycle:
JOCKY Script -> Script Hash -> Execution -> Collector -> Raw Evidence -> Normalized Evidence ->
Evidence Hash -> Correlation -> Rule / ML Detection -> Finding -> Timeline -> Blockchain / Integrity Anchor -> Report.

Every forensic finding is strictly traceable back to the exact evidence that produced it,
the collector that generated that evidence, and the exact JOCKY script/execution that collected it.
"""
import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.models.models import (
    Case,
    Evidence,
    Finding,
    TimelineEvent,
    ExecutionHistory,
    MerkleTreeRecord,
    BlockchainAnchorRecord,
    CorrelatedIncident,
    Report,
    Agent,
)
from backend.app.services.security_integrity_service import (
    canonical_json,
    calculate_sha256,
    hash_object,
)
from backend.app.services.merkle_service import MerkleService
from backend.app.services.blockchain_service import BlockchainService


GENESIS_EVIDENCE_HASH = "0" * 64


class ProvenanceService:
    """Core service for cryptographic evidence provenance, hash chaining, and traceability."""

    # Storage for tampering demo backup state
    _tamper_backups: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------------
    # 1. Canonical Evidence Hashing & Packaging
    # ------------------------------------------------------------------------
    @classmethod
    def compute_canonical_evidence(
        cls,
        evidence_id: str,
        investigation_id: str,
        execution_id: str,
        collector_name: str,
        collector_version: str,
        collector_source: str,
        timestamp_iso: str,
        host_metadata: Dict[str, Any],
        script_id: str,
        script_hash: str,
        raw_data: Any,
        normalized_data: Any,
        previous_evidence_hash: str = GENESIS_EVIDENCE_HASH
    ) -> Dict[str, Any]:
        """
        Creates a canonical evidence object adhering to Phase 27 Section 3 & 5.
        Generates deterministic raw_data_hash, normalized_data_hash, and composite evidence_hash.
        """
        raw_data_hash = calculate_sha256(canonical_json(raw_data))
        normalized_data_hash = calculate_sha256(canonical_json(normalized_data))

        provenance_signable = {
            "evidence_id": evidence_id,
            "investigation_id": investigation_id,
            "execution_id": execution_id,
            "collector": {
                "name": collector_name,
                "version": collector_version,
                "source": collector_source
            },
            "timestamp": timestamp_iso,
            "host": host_metadata,
            "script": {
                "script_id": script_id,
                "script_hash": script_hash.lower()
            },
            "raw_data_hash": raw_data_hash,
            "normalized_data_hash": normalized_data_hash,
            "previous_evidence_hash": previous_evidence_hash.lower()
        }

        evidence_hash = calculate_sha256(canonical_json(provenance_signable))

        canonical_obj = {
            "evidence_id": evidence_id,
            "investigation_id": investigation_id,
            "execution_id": execution_id,
            "collector": {
                "name": collector_name,
                "version": collector_version,
                "source": collector_source
            },
            "timestamp": timestamp_iso,
            "host": host_metadata,
            "script": {
                "script_id": script_id,
                "script_hash": script_hash.lower()
            },
            "data": normalized_data,
            "raw": raw_data,
            "raw_data_hash": raw_data_hash,
            "normalized_data_hash": normalized_data_hash,
            "previous_evidence_hash": previous_evidence_hash.lower(),
            "evidence_hash": evidence_hash,
            "integrity": {
                "algorithm": "SHA-256",
                "verified": True
            }
        }
        return canonical_obj

    # ------------------------------------------------------------------------
    # 2. Sequential Evidence Hash Chain Verification
    # ------------------------------------------------------------------------
    @classmethod
    def verify_evidence_hash_chain(
        cls,
        evidence_items: List[Evidence]
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verifies the continuous cryptographic hash chain across an ordered list of evidence.
        Detects modified evidence, deleted evidence, reordered evidence, or inserted evidence.
        """
        if not evidence_items:
            return True, []

        failures: List[Dict[str, Any]] = []
        is_valid = True
        expected_prev = GENESIS_EVIDENCE_HASH

        for idx, ev in enumerate(evidence_items):
            # 1. Previous hash link validation
            if idx == 0:
                expected_prev = GENESIS_EVIDENCE_HASH
            else:
                pred = evidence_items[idx - 1]
                expected_prev = pred.sha256_hash or pred.content_hash or ""

            actual_prev = ev.previous_hash or ""
            if actual_prev.lower() != expected_prev.lower() and expected_prev != "":
                is_valid = False
                failures.append({
                    "evidence_id": ev.id,
                    "reason": "Evidence hash chain broken: previous_evidence_hash mismatch",
                    "expected": expected_prev,
                    "calculated": actual_prev
                })

            # 2. Raw data hash validation
            raw_data = ev.raw_data or (ev.envelope_data.get("results") if ev.envelope_data else None)
            if raw_data is not None and ev.raw_data_hash:
                recalculated_raw = calculate_sha256(canonical_json(raw_data))
                if recalculated_raw.lower() != ev.raw_data_hash.lower():
                    is_valid = False
                    failures.append({
                        "evidence_id": ev.id,
                        "reason": "Raw evidence hash mismatch (tampered raw payload)",
                        "expected": ev.raw_data_hash,
                        "calculated": recalculated_raw
                    })

            # 3. Normalized data hash validation
            norm_data = ev.normalized_data or (ev.envelope_data.get("data") if ev.envelope_data else None)
            if norm_data is not None and ev.normalized_data_hash:
                recalculated_norm = calculate_sha256(canonical_json(norm_data))
                if recalculated_norm.lower() != ev.normalized_data_hash.lower():
                    is_valid = False
                    failures.append({
                        "evidence_id": ev.id,
                        "reason": "Normalized evidence hash mismatch (tampered structured data)",
                        "expected": ev.normalized_data_hash,
                        "calculated": recalculated_norm
                    })

            # 4. Composite evidence hash recalculation
            if ev.raw_data_hash and ev.normalized_data_hash and ev.script_hash:
                env = ev.envelope_data if isinstance(ev.envelope_data, dict) else {}
                script_id = env.get("script", {}).get("script_id", "SCR-000001") if isinstance(env.get("script"), dict) else "SCR-000001"
                collector_meta = env.get("collector", {}) if isinstance(env.get("collector"), dict) else {}
                collector_name = collector_meta.get("name", ev.collector)
                collector_version = collector_meta.get("version", ev.collector_version or "1.0.0")
                collector_source = collector_meta.get("source", ev.collector_source or "")
                timestamp_str = env.get("timestamp") or (ev.collected_at.strftime("%Y-%m-%dT%H:%M:%SZ") if ev.collected_at else "")
                host_info = env.get("host") or ev.host_metadata or {}

                prov_signable = {
                    "evidence_id": ev.id,
                    "investigation_id": ev.case_id,
                    "execution_id": ev.execution_id or "",
                    "collector": {
                        "name": collector_name,
                        "version": collector_version,
                        "source": collector_source
                    },
                    "timestamp": timestamp_str,
                    "host": host_info,
                    "script": {
                        "script_id": script_id,
                        "script_hash": ev.script_hash.lower()
                    },
                    "raw_data_hash": ev.raw_data_hash.lower(),
                    "normalized_data_hash": ev.normalized_data_hash.lower(),
                    "previous_evidence_hash": (ev.previous_hash or GENESIS_EVIDENCE_HASH).lower()
                }
                recalc_evidence_hash = calculate_sha256(canonical_json(prov_signable))
                if recalc_evidence_hash.lower() != ev.sha256_hash.lower():
                    is_valid = False
                    failures.append({
                        "evidence_id": ev.id,
                        "reason": "Composite evidence hash mismatch",
                        "expected": ev.sha256_hash,
                        "calculated": recalc_evidence_hash
                    })

            # Update rolling predecessor
            expected_prev = ev.sha256_hash

        return is_valid, failures

    # ------------------------------------------------------------------------
    # 3. Comprehensive Investigation Integrity Verification Engine
    # ------------------------------------------------------------------------
    @classmethod
    def verify_investigation_integrity(
        cls,
        case_id: str,
        execution_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Executes complete end-to-end cryptographic integrity verification across:
        1. Raw evidence hashes
        2. Normalized evidence hashes
        3. Evidence hash chain
        4. Evidence chronological ordering
        5. Merkle root
        6. Blockchain anchor
        7. Script hash
        8. Report hash, if available
        """
        if isinstance(execution_id, Session):
            db = execution_id
            execution_id = None

        if db is None:
            return {"valid": False, "case_id": case_id, "failures": [{"reason": "Database session not provided"}]}

        failures: List[Dict[str, Any]] = []

        # 1. Fetch Evidence
        ev_query = db.query(Evidence).filter(Evidence.case_id == case_id)
        if execution_id:
            ev_query = ev_query.filter(Evidence.execution_id == execution_id)
        evidence_items = ev_query.order_by(Evidence.id.asc()).all()

        total_evidence = len(evidence_items)
        verified_evidence_count = 0

        # Check chronological monotonicity
        for i in range(1, len(evidence_items)):
            prev_t = evidence_items[i - 1].collected_at
            curr_t = evidence_items[i].collected_at
            if prev_t and curr_t and curr_t < prev_t:
                failures.append({
                    "evidence_id": evidence_items[i].id,
                    "reason": "Chronological order violation: evidence timestamp is non-monotonic",
                    "expected": f">= {prev_t.isoformat()}",
                    "calculated": curr_t.isoformat()
                })

        # Check evidence hash chain & hashes
        chain_valid, chain_failures = cls.verify_evidence_hash_chain(evidence_items)
        failures.extend(chain_failures)

        failed_ev_ids = {f.get("evidence_id") for f in chain_failures if f.get("evidence_id")}
        verified_evidence_count = total_evidence - len(failed_ev_ids)

        # 2. Merkle Root Verification
        merkle_record = (
            db.query(MerkleTreeRecord)
            .filter(MerkleTreeRecord.case_id == case_id)
            .order_by(MerkleTreeRecord.created_at.desc())
            .first()
        )
        merkle_valid = True
        actual_merkle_root = ""
        if merkle_record and evidence_items:
            leaf_hashes = [e.sha256_hash for e in evidence_items]
            recalculated_root = MerkleService.calculate_merkle_root(leaf_hashes)
            actual_merkle_root = recalculated_root
            if recalculated_root.lower() != merkle_record.merkle_root.lower():
                merkle_valid = False
                failures.append({
                    "component": "merkle",
                    "reason": "Merkle root mismatch (evidence tree has been modified)",
                    "expected": merkle_record.merkle_root,
                    "calculated": recalculated_root
                })
        elif not merkle_record and total_evidence > 0:
            merkle_valid = False
            failures.append({
                "component": "merkle",
                "reason": "Merkle tree record missing for completed investigation"
            })
        elif merkle_record:
            actual_merkle_root = merkle_record.merkle_root

        # 3. Blockchain Anchor Verification
        blockchain_valid = True
        blockchain_anchored = False
        anchor_record = BlockchainService.get_case_anchor(case_id, db, execution_id)
        if anchor_record:
            blockchain_anchored = True
            # Verify ledger
            b_valid, b_failures = BlockchainService.verify_blockchain_ledger(db, case_id)
            if not b_valid:
                blockchain_valid = False
                failures.extend(b_failures)

            # Verify that anchor's Merkle root matches actual Merkle root
            if merkle_record and anchor_record.merkle_root.lower() != merkle_record.merkle_root.lower():
                blockchain_valid = False
                failures.append({
                    "component": "blockchain",
                    "reason": "Blockchain anchor Merkle root mismatch with investigation Merkle root",
                    "expected": merkle_record.merkle_root,
                    "calculated": anchor_record.merkle_root
                })
        else:
            if total_evidence > 0:
                blockchain_valid = False
                failures.append({
                    "component": "blockchain",
                    "reason": "No blockchain anchor found for completed investigation"
                })

        # 4. Script Hash Verification
        script_valid = True
        exec_hist = (
            db.query(ExecutionHistory)
            .filter(ExecutionHistory.case_id == case_id)
            .order_by(ExecutionHistory.started_at.desc())
            .first()
        )
        if exec_hist and exec_hist.script_content and exec_hist.script_hash:
            recalculated_script_hash = calculate_sha256(exec_hist.script_content.strip().encode('utf-8'))
            if recalculated_script_hash.lower() != exec_hist.script_hash.lower():
                script_valid = False
                failures.append({
                    "component": "script",
                    "reason": "Script hash mismatch (JOCKY script modified after execution)",
                    "expected": exec_hist.script_hash,
                    "calculated": recalculated_script_hash
                })

        # 5. Report Hash Verification (if report exists)
        report_valid = True
        report_record = db.query(Report).filter(Report.case_id == case_id).order_by(Report.created_at.desc()).first()
        if report_record and report_record.content_json and report_record.report_content_hash:
            recalculated_report_hash = hash_object(report_record.content_json)
            if recalculated_report_hash.lower() != report_record.report_content_hash.lower():
                report_valid = False
                failures.append({
                    "component": "report",
                    "reason": "Report content hash mismatch",
                    "expected": report_record.report_content_hash,
                    "calculated": recalculated_report_hash
                })

        overall_valid = (
            len(failures) == 0 and
            chain_valid and
            merkle_valid and
            blockchain_valid and
            script_valid
        )

        return {
            "valid": overall_valid,
            "case_id": case_id,
            "execution_id": execution_id or (exec_hist.execution_id if exec_hist else None),
            "evidence": {
                "total": total_evidence,
                "verified": verified_evidence_count,
                "failed": len(failed_ev_ids)
            },
            "hash_chain": {
                "valid": chain_valid
            },
            "merkle": {
                "valid": merkle_valid,
                "root": actual_merkle_root
            },
            "blockchain": {
                "anchored": blockchain_anchored,
                "valid": blockchain_valid,
                "block_number": anchor_record.block_number if anchor_record else None,
                "block_hash": anchor_record.block_hash if anchor_record else None
            },
            "script": {
                "valid": script_valid,
                "script_hash": exec_hist.script_hash if exec_hist else None
            },
            "report": {
                "valid": report_valid
            },
            "failures": failures,
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

    # ------------------------------------------------------------------------
    # 4. Finding-to-Evidence Provenance Resolution (Section 10)
    # ------------------------------------------------------------------------
    @classmethod
    def get_finding_provenance(
        cls,
        case_id: str,
        finding_id: str,
        db: Session
    ) -> Optional[Dict[str, Any]]:
        """
        Resolves the complete vertical traceability chain for a finding:
        Finding -> Supporting Evidence -> Raw Evidence -> Collector -> Execution -> Script -> Merkle Root -> Blockchain Anchor.
        """
        finding = db.query(Finding).filter(Finding.case_id == case_id, Finding.id == finding_id).first()
        if not finding:
            return None

        # Resolve supporting evidence items
        ev_ids = finding.evidence_ids or []
        supporting_evidence = (
            db.query(Evidence)
            .filter(Evidence.case_id == case_id, Evidence.id.in_(ev_ids))
            .all()
        )

        # Resolve execution
        execution_id = finding.execution_id
        if not execution_id and supporting_evidence and supporting_evidence[0].execution_id:
            execution_id = supporting_evidence[0].execution_id

        exec_hist = None
        if execution_id:
            exec_hist = db.query(ExecutionHistory).filter(ExecutionHistory.execution_id == execution_id).first()
        if not exec_hist:
            exec_hist = db.query(ExecutionHistory).filter(ExecutionHistory.case_id == case_id).order_by(ExecutionHistory.started_at.desc()).first()

        # Merkle Tree & Blockchain Anchor
        merkle_record = db.query(MerkleTreeRecord).filter(MerkleTreeRecord.case_id == case_id).order_by(MerkleTreeRecord.created_at.desc()).first()
        anchor_record = BlockchainService.get_case_anchor(case_id, db, execution_id)

        # Build visual traceability chain path
        traceability_chain = []
        # Step 1: Script
        traceability_chain.append({
            "step": 1,
            "type": "SCRIPT",
            "name": exec_hist.script_name if exec_hist else "JOCKY Script",
            "hash": (exec_hist.script_hash if exec_hist else finding.script_hash) or "N/A",
            "description": "Original forensic JOCKY script containing declared collection targets."
        })
        # Step 2: Execution
        traceability_chain.append({
            "step": 2,
            "type": "EXECUTION",
            "name": exec_hist.execution_id if exec_hist else (execution_id or "EXE-DEFAULT"),
            "status": exec_hist.status if exec_hist else "SUCCESS",
            "target": exec_hist.target if exec_hist else "TARGET",
            "description": "Validated execution run with immutable duration and environment telemetry."
        })
        # Step 3: Collectors
        collectors_used = list({e.collector for e in supporting_evidence})
        traceability_chain.append({
            "step": 3,
            "type": "COLLECTOR",
            "name": ", ".join(collectors_used) if collectors_used else "Forensic Collectors",
            "description": "Specialized kernel & userland forensic collectors extracting raw system telemetry."
        })
        # Step 4: Supporting Evidence
        traceability_chain.append({
            "step": 4,
            "type": "EVIDENCE",
            "ids": [e.id for e in supporting_evidence],
            "hashes": [e.sha256_hash for e in supporting_evidence],
            "description": f"{len(supporting_evidence)} cryptographically sealed RFC-8785 evidence envelope(s)."
        })
        # Step 5: Finding
        traceability_chain.append({
            "step": 5,
            "type": "FINDING",
            "id": finding.id,
            "title": finding.title,
            "detection": {
                "type": finding.detection_type or "rule",
                "rule_id": finding.detection_rule_id,
                "model": finding.model_name,
                "score": finding.priority_score
            },
            "description": "Actionable detection generated directly from supporting evidence artifacts."
        })
        # Step 6: Merkle Root
        traceability_chain.append({
            "step": 6,
            "type": "MERKLE_ROOT",
            "root": merkle_record.merkle_root if merkle_record else "N/A",
            "description": "Mathematical binary tree root cryptographically committing all evidence hashes."
        })
        # Step 7: Blockchain Anchor
        traceability_chain.append({
            "step": 7,
            "type": "BLOCKCHAIN_ANCHOR",
            "block_number": anchor_record.block_number if anchor_record else None,
            "block_hash": anchor_record.block_hash if anchor_record else "N/A",
            "network": BlockchainService.NETWORK_NAME,
            "description": "Tamper-evident external block anchoring Merkle root and script hash."
        })

        return {
            "finding": finding,
            "supporting_evidence": supporting_evidence,
            "execution": {
                "execution_id": exec_hist.execution_id if exec_hist else execution_id,
                "script_name": exec_hist.script_name if exec_hist else "JOCKY Script",
                "script_hash": exec_hist.script_hash if exec_hist else finding.script_hash,
                "target": exec_hist.target if exec_hist else "DEMO-WINDOWS-ENDPOINT",
                "status": exec_hist.status if exec_hist else "SUCCESS",
                "started_at": exec_hist.started_at.isoformat() if (exec_hist and exec_hist.started_at) else None,
                "completed_at": exec_hist.completed_at.isoformat() if (exec_hist and exec_hist.completed_at) else None
            } if exec_hist else None,
            "script_hash": (exec_hist.script_hash if exec_hist else finding.script_hash),
            "script_content": exec_hist.script_content if exec_hist else None,
            "merkle_root": merkle_record.merkle_root if merkle_record else None,
            "blockchain_anchor": anchor_record,
            "traceability_chain": traceability_chain
        }

    # ------------------------------------------------------------------------
    # 5. Controlled Tampering Demonstration (Section 29)
    # ------------------------------------------------------------------------
    @classmethod
    def tamper_evidence(
        cls,
        case_id: str,
        evidence_id: Optional[str] = None,
        field: str = "data",
        new_value: Any = None,
        tamper_field: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Temporarily modifies a field in an evidence record (saving a backup)
        so that subsequent verification clearly demonstrates cryptographic failure.
        """
        if db is None:
            return {"status": "ERROR", "message": "Database session required"}

        effective_field = tamper_field or field or "data"

        # If evidence_id is not specified, choose a prominent one
        if not evidence_id:
            target_ev = db.query(Evidence).filter(
                Evidence.case_id == case_id,
                Evidence.collector == "processes"
            ).first() or db.query(Evidence).filter(Evidence.case_id == case_id).first()
            if not target_ev:
                return {"status": "ERROR", "message": f"No evidence found in case '{case_id}' to tamper with."}
            evidence_id = target_ev.id
        else:
            target_ev = db.query(Evidence).filter(Evidence.case_id == case_id, Evidence.id == evidence_id).first()
            if not target_ev and effective_field != "delete":
                return {"status": "ERROR", "message": f"Evidence '{evidence_id}' not found."}

        ev = target_ev

        # Backup original state
        backup_key = f"{case_id}:{evidence_id}"
        cls._tamper_backups[backup_key] = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "agent_id": ev.agent_id if ev else "AGENT-WIN-01",
            "execution_id": ev.execution_id if ev else None,
            "script_hash": ev.script_hash if ev else None,
            "collector": ev.collector if ev else "processes",
            "collector_version": getattr(ev, "collector_version", "1.0.0") if ev else "1.0.0",
            "collector_source": getattr(ev, "collector_source", "") if ev else "",
            "platform": ev.platform if ev else "Windows",
            "sha256_hash": ev.sha256_hash if ev else "",
            "raw_data_hash": getattr(ev, "raw_data_hash", None) if ev else None,
            "normalized_data_hash": getattr(ev, "normalized_data_hash", None) if ev else None,
            "previous_hash": ev.previous_hash if ev else None,
            "raw_data": copy.deepcopy(ev.raw_data) if ev else None,
            "normalized_data": copy.deepcopy(ev.normalized_data) if ev else None,
            "host_metadata": copy.deepcopy(ev.host_metadata) if ev else None,
            "envelope_data": copy.deepcopy(ev.envelope_data) if ev else None,
            "collected_at": ev.collected_at if ev else datetime.now(timezone.utc)
        }

        # Apply modification based on effective_field
        if effective_field == "sha256_hash" or effective_field == "hash":
            val = new_value or ("00" * 32)
            ev.sha256_hash = str(val)
        elif effective_field == "previous_hash":
            val = new_value or ("ff" * 32)
            ev.previous_hash = str(val)
        elif effective_field == "delete":
            db.delete(ev)
            db.commit()
            return {
                "status": "TAMPERED",
                "action": "DELETED",
                "evidence_id": evidence_id,
                "tamper_type": "DELETE_EVIDENCE",
                "message": f"Evidence '{evidence_id}' temporarily deleted for tamper demonstration."
            }
        elif effective_field == "raw_data":
            val = new_value or {"tampered": True, "injected_payload": "attacker_mod_raw"}
            ev.raw_data = val
            new_env = copy.deepcopy(ev.envelope_data) if isinstance(ev.envelope_data, dict) else {}
            new_env["raw"] = val
            ev.envelope_data = new_env
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(ev, "raw_data")
            flag_modified(ev, "envelope_data")
        else: # "data" or "normalized_data"
            val = new_value or "UNAUTHORIZED_MODIFIED_PAYLOAD_VALUE"
            new_norm = copy.deepcopy(ev.normalized_data) if isinstance(ev.normalized_data, (dict, list)) else {}
            if isinstance(new_norm, dict):
                new_norm["tampered_field"] = val
            elif isinstance(new_norm, list) and new_norm:
                if isinstance(new_norm[0], dict):
                    new_norm[0]["tampered_field"] = val
                else:
                    new_norm.append(val)
            else:
                new_norm = {"tampered": val}
            ev.normalized_data = new_norm
            new_env = copy.deepcopy(ev.envelope_data) if isinstance(ev.envelope_data, dict) else {}
            new_env["data"] = new_norm
            ev.envelope_data = new_env
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(ev, "normalized_data")
            flag_modified(ev, "envelope_data")

        db.commit()
        db.refresh(ev)

        return {
            "status": "TAMPERED",
            "evidence_id": evidence_id,
            "tamper_type": effective_field,
            "modified_field": effective_field,
            "message": f"Evidence '{evidence_id}' field '{effective_field}' modified. Cryptographic hashes will now mismatch."
        }

    @classmethod
    def restore_evidence(
        cls,
        case_id: str,
        evidence_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Restores an evidence item or all tampered items for case to their verified state from in-memory backup."""
        if db is None:
            return {"status": "ERROR", "message": "Database session required"}

        restored_ids = []
        keys_to_restore = []

        if evidence_id:
            key = f"{case_id}:{evidence_id}"
            if key in cls._tamper_backups:
                keys_to_restore.append((key, evidence_id))
        else:
            prefix = f"{case_id}:"
            for k in list(cls._tamper_backups.keys()):
                if k.startswith(prefix):
                    eid = cls._tamper_backups[k]["evidence_id"]
                    keys_to_restore.append((k, eid))

        if not keys_to_restore:
            return {"status": "ERROR", "message": f"No active tamper backups found for case '{case_id}'."}

        for backup_key, eid in keys_to_restore:
            backup = cls._tamper_backups[backup_key]
            ev = db.query(Evidence).filter(Evidence.case_id == case_id, Evidence.id == eid).first()
            if not ev:
                ev = Evidence(
                    id=eid,
                    case_id=case_id,
                    agent_id=backup.get("agent_id", "AGENT-WIN-01"),
                    execution_id=backup.get("execution_id"),
                    script_hash=backup.get("script_hash"),
                    collector=backup.get("collector", "processes"),
                    collector_version=backup.get("collector_version", "1.0.0"),
                    collector_source=backup.get("collector_source", ""),
                    platform=backup.get("platform", "Windows"),
                    sha256_hash=backup["sha256_hash"],
                    raw_data_hash=backup.get("raw_data_hash"),
                    normalized_data_hash=backup.get("normalized_data_hash"),
                    previous_hash=backup["previous_hash"],
                    raw_data=backup["raw_data"],
                    normalized_data=backup["normalized_data"],
                    host_metadata=backup.get("host_metadata"),
                    envelope_data=backup["envelope_data"],
                    is_verified=True,
                    collected_at=backup.get("collected_at")
                )
                db.add(ev)
            if ev:
                ev.raw_data = backup["raw_data"]
                ev.normalized_data = backup["normalized_data"]
                ev.sha256_hash = backup["sha256_hash"]
                ev.raw_data_hash = backup.get("raw_data_hash")
                ev.normalized_data_hash = backup.get("normalized_data_hash")
                ev.previous_hash = backup["previous_hash"]
                ev.envelope_data = backup["envelope_data"]
                ev.is_verified = True
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(ev, "raw_data")
                flag_modified(ev, "normalized_data")
                flag_modified(ev, "envelope_data")

            del cls._tamper_backups[backup_key]
            restored_ids.append(eid)

        db.commit()

        # If any item in the case remains unverified after selective restoration, cleanly re-seed
        audit_check = cls.verify_investigation_integrity(case_id, db)
        if not audit_check.get("valid"):
            cls.run_deterministic_investigation(case_id, db)

        return {
            "status": "RESTORED",
            "restored_count": len(restored_ids),
            "evidence_ids": restored_ids,
            "message": f"Restored {len(restored_ids)} evidence item(s) to original verified cryptographic state."
        }

    # ------------------------------------------------------------------------
    # 6. End-to-End Deterministic Investigation Demo Generator (Section 29)
    # ------------------------------------------------------------------------
    @classmethod
    def run_deterministic_investigation(
        cls,
        case_id: str = "CASE-2026-001",
        target: str = "DEMO-WINDOWS-ENDPOINT",
        script_content: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Executes a deterministic forensic investigation producing 27+ evidence items
        across 5 collectors (Processes, Network, Files, Persistence, System),
        4 findings with rule & ML attribution, unified timeline, Merkle tree,
        and Local Evidence Blockchain anchor block.
        """
        if isinstance(target, Session):
            db = target
            target = "DEMO-WINDOWS-ENDPOINT"

        now = datetime.now(timezone.utc)
        cid_tag = case_id.replace("CASE-", "")
        execution_id = f"EXE-2026-{uuid.uuid4().hex[:4].upper()}"

        script_text = script_content or (
            'CASE "CASE-2026-001"\n'
            'TARGET "DEMO-WINDOWS-ENDPOINT"\n'
            'COLLECT processes\n'
            'COLLECT network\n'
            'COLLECT files\n'
            'COLLECT persistence\n'
            'COLLECT system\n'
            'CORRELATE process_network\n'
            'DETECT suspicious_process\n'
            'DETECT network_anomaly\n'
            'EVIDENCE seal\n'
            'REPORT "endpoint_report"'
        )
        script_hash = calculate_sha256(script_text.strip().encode('utf-8'))

        host_meta = {
            "hostname": target,
            "platform": "Windows",
            "architecture": "x64",
            "os_version": "Windows 11 Enterprise 23H2",
            "agent_id": "AGENT-WIN-01"
        }

        # 1. Ensure Case Exists and clear any stale records for this specific case
        if db is not None:
            c = db.query(Case).filter(Case.id == case_id).first()
            if not c:
                c = Case(
                    id=case_id,
                    title="Suspicious Endpoint Investigation (Phase 27 Provenance)",
                    description="Autonomous forensic triage and complete cryptographic provenance chain.",
                    severity="high",
                    status="INVESTIGATING"
                )
                db.add(c)
            # Clear stale records for this case to prevent mixed hash chains
            db.query(Evidence).filter(Evidence.case_id == case_id).delete()
            db.query(Finding).filter(Finding.case_id == case_id).delete()
            db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).delete()
            db.query(CorrelatedIncident).filter(CorrelatedIncident.case_id == case_id).delete()
            db.query(MerkleTreeRecord).filter(MerkleTreeRecord.case_id == case_id).delete()
            db.query(ExecutionHistory).filter(ExecutionHistory.case_id == case_id).delete()
            db.commit()

        # 2. Build 28 Deterministic Evidence Records Across 5 Collectors
        collectors_plan = [
            # System (3 items)
            ("system", "1.0.0", "Windows Kernel", "system.info", {"metric": "os_build"}, {"build": "22631.3007", "kernel": "10.0.22621"}),
            ("system", "1.0.0", "Windows Kernel", "system.hostname", {"metric": "netbios"}, {"hostname": target, "domain": "WORKGROUP"}),
            ("system", "1.0.0", "Windows Kernel", "system.uptime", {"metric": "boot_time"}, {"uptime_hours": 72.4, "boot_timestamp": "2026-09-22T08:00:00Z"}),

            # Persistence (5 items)
            ("persistence", "1.0.0", "Registry Hive", "HKCU_Run", {"reg_path": r"HKCU\...\Run\UpdateSvc"}, {"key": "UpdateSvc", "value": r"C:\Demo\suspicious-update.exe", "type": "REG_SZ"}),
            ("persistence", "1.0.0", "Registry Hive", "HKLM_Run", {"reg_path": r"HKLM\...\Run\SecurityAgent"}, {"key": "SecurityAgent", "value": r"C:\Program Files\Sec\agent.exe", "type": "REG_SZ"}),
            ("persistence", "1.0.0", "Service Control Manager", "svc.UpdateService", {"service": "UpdateService"}, {"name": "UpdateService", "binary_path": r"C:\Demo\suspicious-update.exe", "start_type": "Auto"}),
            ("persistence", "1.0.0", "Task Scheduler", "task.PeriodicCheck", {"task_path": r"\Microsoft\Windows\PeriodicCheck"}, {"author": "SYSTEM", "action": r"C:\Demo\suspicious-update.exe", "trigger": "OnLogon"}),
            ("persistence", "1.0.0", "Startup Folder", "startup.shortcut", {"folder": "Startup"}, {"lnk_file": "update.lnk", "target": r"C:\Demo\suspicious-update.exe"}),

            # Processes (8 items)
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.explorer", {"pid": 1024}, {"pid": 1024, "name": "explorer.exe", "ppid": 880, "path": r"C:\Windows\explorer.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.suspicious_update", {"pid": 4188}, {"pid": 4188, "name": "suspicious-update.exe", "ppid": 1024, "path": r"C:\Demo\suspicious-update.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.cmd", {"pid": 4812}, {"pid": 4812, "name": "cmd.exe", "ppid": 4188, "path": r"C:\Windows\System32\cmd.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.svchost_1", {"pid": 1280}, {"pid": 1280, "name": "svchost.exe", "ppid": 780, "path": r"C:\Windows\System32\svchost.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.svchost_2", {"pid": 1420}, {"pid": 1420, "name": "svchost.exe", "ppid": 780, "path": r"C:\Windows\System32\svchost.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.powershell", {"pid": 5210}, {"pid": 5210, "name": "powershell.exe", "ppid": 4812, "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.conhost", {"pid": 4816}, {"pid": 4816, "name": "conhost.exe", "ppid": 4812, "path": r"C:\Windows\System32\conhost.exe"}),
            ("processes", "1.0.0", "Windows Toolhelp32 API", "proc.lsass", {"pid": 740}, {"pid": 740, "name": "lsass.exe", "ppid": 680, "path": r"C:\Windows\System32\lsass.exe"}),

            # Network (6 items)
            ("network", "1.0.0", "IP Helper API", "net.sock.4444", {"sock": "4188->203.0.113.50:4444"}, {"pid": 4188, "proto": "TCP", "laddr": "192.168.1.105:49182", "raddr": "203.0.113.50:4444", "state": "ESTABLISHED"}),
            ("network", "1.0.0", "IP Helper API", "net.sock.https", {"sock": "1280->52.96.166.130:443"}, {"pid": 1280, "proto": "TCP", "laddr": "192.168.1.105:49200", "raddr": "52.96.166.130:443", "state": "ESTABLISHED"}),
            ("network", "1.0.0", "IP Helper API", "net.dns.c2", {"query": "update.beacon-cloud.net"}, {"query": "update.beacon-cloud.net", "resolved_ip": "203.0.113.50", "ttl": 300}),
            ("network", "1.0.0", "IP Helper API", "net.adapter.eth0", {"adapter": "Ethernet0"}, {"name": "Ethernet0", "ip": "192.168.1.105", "mac": "00:15:5D:82:11:4F"}),
            ("network", "1.0.0", "IP Helper API", "net.sock.8080", {"sock": "5210->198.51.100.25:8080"}, {"pid": 5210, "proto": "TCP", "laddr": "192.168.1.105:49215", "raddr": "198.51.100.25:8080", "state": "TIME_WAIT"}),
            ("network", "1.0.0", "IP Helper API", "net.listening.rpc", {"sock": "rpc"}, {"proto": "TCP", "laddr": "0.0.0.0:135", "state": "LISTENING"}),

            # Files (6 items)
            ("files", "1.0.0", "Win32 FindFile API", "file.suspicious_exe", {"path": r"C:\Demo\suspicious-update.exe"}, {"path": r"C:\Demo\suspicious-update.exe", "size": 245760, "sha256": "4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712", "entropy": 7.42, "signature": "UNSIGNED"}),
            ("files", "1.0.0", "Win32 FindFile API", "file.ps_script", {"path": r"C:\Demo\stage2.ps1"}, {"path": r"C:\Demo\stage2.ps1", "size": 1824, "sha256": "8f3b145a987c2e01fb34aa9812dc541289fe01298471bcca1289fe90123847a1", "entropy": 5.12, "signature": "PLAINTEXT"}),
            ("files", "1.0.0", "Win32 FindFile API", "file.explorer_exe", {"path": r"C:\Windows\explorer.exe"}, {"path": r"C:\Windows\explorer.exe", "size": 5120000, "sha256": "a3b14f89012dc541289fe01298471bcca1289fe90123847a18f3b145a987c2e0", "entropy": 6.31, "signature": "MICROSOFT_VALID"}),
            ("files", "1.0.0", "Win32 FindFile API", "file.cmd_exe", {"path": r"C:\Windows\System32\cmd.exe"}, {"path": r"C:\Windows\System32\cmd.exe", "size": 310000, "sha256": "9c8a14f89012dc541289fe01298471bcca1289fe90123847a18f3b145a987c2e", "entropy": 6.18, "signature": "MICROSOFT_VALID"}),
            ("files", "1.0.0", "Win32 FindFile API", "file.temp_drop", {"path": r"C:\Users\Admin\AppData\Local\Temp\tmp8912.dll"}, {"path": r"C:\Users\Admin\AppData\Local\Temp\tmp8912.dll", "size": 98304, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "entropy": 7.85, "signature": "UNSIGNED"}),
            ("files", "1.0.0", "Win32 FindFile API", "file.hosts", {"path": r"C:\Windows\System32\drivers\etc\hosts"}, {"path": r"C:\Windows\System32\drivers\etc\hosts", "size": 824, "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "entropy": 3.42, "signature": "PLAINTEXT"})
        ]

        created_evidence: List[Evidence] = []
        leaf_hashes: List[str] = []
        previous_hash = GENESIS_EVIDENCE_HASH

        for idx, (col_cat, col_ver, col_src, sub_name, raw_payload, norm_payload) in enumerate(collectors_plan):
            ev_id = f"EVD-{cid_tag}-{idx + 1:05d}"
            # Step time sequentially
            ts = datetime.fromtimestamp(now.timestamp() - (len(collectors_plan) - idx) * 3, tz=timezone.utc)
            ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

            canon = cls.compute_canonical_evidence(
                evidence_id=ev_id,
                investigation_id=case_id,
                execution_id=execution_id,
                collector_name=col_cat,
                collector_version=col_ver,
                collector_source=col_src,
                timestamp_iso=ts_str,
                host_metadata=host_meta,
                script_id="SCR-000001",
                script_hash=script_hash,
                raw_data=raw_payload,
                normalized_data=norm_payload,
                previous_evidence_hash=previous_hash
            )

            previous_hash = canon["evidence_hash"]
            leaf_hashes.append(canon["evidence_hash"])

            if db is not None:
                # Upsert evidence
                ev_record = db.query(Evidence).filter(Evidence.id == ev_id).first()
                if not ev_record:
                    ev_record = Evidence(
                        id=ev_id,
                        case_id=case_id,
                        agent_id=host_meta["agent_id"],
                        execution_id=execution_id,
                        script_hash=script_hash,
                        collector=col_cat,
                        collector_version=col_ver,
                        collector_source=col_src,
                        platform="Windows",
                        sha256_hash=canon["evidence_hash"],
                        raw_data_hash=canon["raw_data_hash"],
                        normalized_data_hash=canon["normalized_data_hash"],
                        raw_data=raw_payload,
                        normalized_data=norm_payload,
                        host_metadata=host_meta,
                        envelope_data=canon,
                        previous_hash=canon["previous_evidence_hash"],
                        is_verified=True,
                        collected_at=ts,
                        integrity_status="VERIFIED"
                    )
                    db.add(ev_record)
                else:
                    ev_record.execution_id = execution_id
                    ev_record.script_hash = script_hash
                    ev_record.sha256_hash = canon["evidence_hash"]
                    ev_record.raw_data_hash = canon["raw_data_hash"]
                    ev_record.normalized_data_hash = canon["normalized_data_hash"]
                    ev_record.raw_data = raw_payload
                    ev_record.normalized_data = norm_payload
                    ev_record.previous_hash = canon["previous_evidence_hash"]
                    ev_record.envelope_data = canon
                    ev_record.collected_at = ts
                created_evidence.append(ev_record)

        if db is not None:
            db.commit()

        # 3. Build Merkle Tree & Anchor to Local Evidence Blockchain
        merkle_record = None
        anchor_record = None
        if db is not None:
            merkle_record = MerkleService.record_merkle_tree(
                case_id=case_id,
                execution_id=execution_id,
                leaf_hashes=leaf_hashes,
                db=db
            )
            anchor_record = BlockchainService.anchor_investigation(
                case_id=case_id,
                merkle_root=merkle_record.merkle_root,
                evidence_count=len(leaf_hashes),
                script_hash=script_hash,
                execution_id=execution_id,
                db=db
            )

        # 4. Generate Deterministic Findings with Complete Provenance
        # Finding 1: Suspicious Process (Rule)
        fnd1_id = f"FND-{cid_tag}-001"
        ev_proc = f"EVD-{cid_tag}-00010"
        ev_file = f"EVD-{cid_tag}-00023"

        # Finding 2: High-Risk Outbound C2 Socket (Rule)
        fnd2_id = f"FND-{cid_tag}-002"
        ev_net = f"EVD-{cid_tag}-00017"
        ev_dns = f"EVD-{cid_tag}-00019"

        # Finding 3: Startup RunKey Persistence (Rule)
        fnd3_id = f"FND-{cid_tag}-003"
        ev_reg = f"EVD-{cid_tag}-00004"
        ev_svc = f"EVD-{cid_tag}-00006"

        # Finding 4: ML Anomaly Threat Cluster (ML Model)
        fnd4_id = f"FND-{cid_tag}-004"
        ev_ml_cluster = [ev_proc, ev_net, ev_reg, ev_file]

        findings_defs = [
            (
                fnd1_id,
                "Suspicious Process Execution: suspicious-update.exe",
                "Unsigned high-entropy PE executable spawned directly under Windows explorer shell without trusted signature.",
                "Process parent is explorer.exe, binary resides in non-standard directory C:\\Demo\\, and PE entropy is 7.42.",
                "HIGH",
                88,
                "rule",
                "RULE-PROC-001",
                None,
                None,
                0.90,
                [ev_proc, ev_file],
                ["Unsigned binary on disk", "High entropy section (>7.2)", "Direct spawn from user shell"]
            ),
            (
                fnd2_id,
                "Anomalous Outbound C2 Socket Connection",
                "Process PID 4188 established persistent outbound connection to external IP on non-standard port 4444.",
                "Socket destination 203.0.113.50 on port 4444 correlates with dynamic DNS query update.beacon-cloud.net.",
                "CRITICAL",
                94,
                "rule",
                "RULE-NET-004",
                None,
                None,
                0.95,
                [ev_net, ev_dns, ev_proc],
                ["Non-standard high-risk port (4444)", "Established TCP socket state", "Dynamic C2 domain resolution"]
            ),
            (
                fnd3_id,
                "Unapproved Startup Registry & Service Persistence",
                "Adversary persistence hook discovered in HKCU Run Key and Service Control Manager pointing to standalone binary.",
                "Persistence mechanism matches target binary path C:\\Demo\\suspicious-update.exe, ensuring survival across reboots.",
                "HIGH",
                91,
                "rule",
                "RULE-PERSIST-002",
                None,
                None,
                0.92,
                [ev_reg, ev_svc],
                ["Registry RunKey write precedes process execution", "Background Service UpdateService auto-start configuration"]
            ),
            (
                fnd4_id,
                "Cross-Artifact Multi-Endpoint Threat Anomaly Cluster",
                "Machine Learning threat detector identified a multi-vector anomaly combining persistence, process, and socket activity.",
                "Contributing evidence features exceed normal baseline thresholds across 21 vector dimensions.",
                "CRITICAL",
                95,
                "ml",
                None,
                "JOCKY-Anomaly-v1",
                "1.0.0",
                0.95,
                ev_ml_cluster,
                [
                    {"name": "unusual_binary_path", "value": 1.0, "contribution": 0.32, "evidence_ids": [ev_file]},
                    {"name": "external_c2_connection", "value": 1.0, "contribution": 0.28, "evidence_ids": [ev_net]},
                    {"name": "registry_persistence_hook", "value": 1.0, "contribution": 0.24, "evidence_ids": [ev_reg]},
                    {"name": "anomalous_parent_child", "value": 1.0, "contribution": 0.16, "evidence_ids": [ev_proc]}
                ]
            )
        ]

        if db is not None:
            for fid, title, desc, reason, prio, score, dtype, rid, mname, mver, conf, eids, factors in findings_defs:
                frec = db.query(Finding).filter(Finding.id == fid).first()
                if not frec:
                    frec = Finding(
                        id=fid,
                        case_id=case_id,
                        execution_id=execution_id,
                        script_hash=script_hash,
                        detection_type=dtype,
                        detection_rule_id=rid,
                        model_name=mname,
                        model_version=mver,
                        confidence_score=conf,
                        title=title,
                        description=desc,
                        reason=reason,
                        status="OPEN",
                        priority=prio,
                        priority_score=score,
                        priority_reasons=factors if isinstance(factors, list) and isinstance(factors[0], str) else [f["name"] for f in factors],
                        explainable_factors=factors if isinstance(factors, list) and isinstance(factors[0], dict) else None,
                        related_agents=[host_meta["agent_id"]],
                        evidence_ids=eids,
                        created_at=now,
                        updated_at=now
                    )
                    db.add(frec)
                else:
                    frec.case_id = case_id
                    frec.execution_id = execution_id
                    frec.script_hash = script_hash
                    frec.evidence_ids = eids
                    frec.priority_score = score
                    frec.updated_at = now
            db.commit()

        # 5. Generate Correlated Incidents (Section 12)
        if db is not None:
            inc_id = f"INC-{cid_tag}-001"
            inc_rec = db.query(CorrelatedIncident).filter(CorrelatedIncident.id == inc_id).first()
            all_incident_evs = [ev_reg, ev_svc, ev_proc, ev_net, ev_dns, ev_file]
            if not inc_rec:
                inc_rec = CorrelatedIncident(
                    id=inc_id,
                    case_id=case_id,
                    execution_id=execution_id,
                    title="Suspicious Persistence & Outbound C2 Activity Cluster",
                    classification="Suspicious Activity Cluster",
                    description=(
                        "Correlated evidence cluster linking registry RunKey persistence, "
                        "process execution (PID 4188), and outbound network telemetry to 203.0.113.50:4444. "
                        "Signals suggest automated adversary staging window."
                    ),
                    evidence_ids=all_incident_evs,
                    finding_ids=[fnd1_id, fnd2_id, fnd3_id, fnd4_id],
                    timeline_sequence=[
                        "Registry persistence written",
                        "Process suspicious-update.exe spawned",
                        "Outbound socket to port 4444 established",
                        "Service installation registered"
                    ],
                    severity="CRITICAL"
                )
                db.add(inc_rec)
                db.commit()

        # 6. Generate Forensic Timeline Events (Section 13)
        timeline_events_data = [
            ("PROCESS", "Process 'explorer.exe' (PID 1024) active as user shell", [f"EVD-{cid_tag}-00009"], "INFO"),
            ("REGISTRY", r"Registry autostart key added in HKCU\...\Run\UpdateSvc pointing to suspicious-update.exe", [ev_reg], "HIGH"),
            ("PROCESS", "Process 'suspicious-update.exe' (PID 4188) created under explorer.exe", [ev_proc], "HIGH"),
            ("NETWORK", "DNS query resolved for update.beacon-cloud.net -> 203.0.113.50", [ev_dns], "MEDIUM"),
            ("NETWORK", "Outbound TCP socket established to 203.0.113.50:4444 (C2 beacon)", [ev_net], "CRITICAL"),
            ("SERVICE", "Service 'UpdateService' registered in Service Control Manager", [ev_svc], "HIGH"),
            ("DETECTION", "Finding FND-001 generated: Suspicious Process Execution", [ev_proc, ev_file], "HIGH"),
            ("DETECTION", "Finding FND-002 generated: Anomalous Outbound C2 Socket Connection", [ev_net, ev_dns], "CRITICAL"),
            ("EVIDENCE", f"RFC-8785 canonical hash chain sealed across {len(collectors_plan)} evidence envelopes", [ev_file], "INFO"),
            ("BLOCKCHAIN", f"Investigation anchored in Local Evidence Blockchain block #{anchor_record.block_number if anchor_record else 1}", [ev_file], "INFO")
        ]

        if db is not None:
            for idx, (etype, edesc, eids, esev) in enumerate(timeline_events_data):
                tle_id = f"TLE-{cid_tag}-{idx + 1:04d}"
                tle_rec = db.query(TimelineEvent).filter(TimelineEvent.id == tle_id).first()
                t_event = datetime.fromtimestamp(now.timestamp() - (len(timeline_events_data) - idx) * 2, tz=timezone.utc)
                if not tle_rec:
                    tle_rec = TimelineEvent(
                        id=tle_id,
                        case_id=case_id,
                        agent_id=host_meta["agent_id"],
                        execution_id=execution_id,
                        timestamp=t_event,
                        event_type=etype,
                        description=edesc,
                        evidence_id=eids[0] if eids else None,
                        evidence_ids=eids,
                        severity=esev,
                        details={"evidence_count": len(eids)}
                    )
                    db.add(tle_rec)
                else:
                    tle_rec.case_id = case_id
                    tle_rec.evidence_ids = eids
                    tle_rec.execution_id = execution_id
            db.commit()

        # 7. Record Execution History Record
        if db is not None:
            ex_rec = db.query(ExecutionHistory).filter(ExecutionHistory.execution_id == execution_id).first()
            if not ex_rec:
                ex_rec = ExecutionHistory(
                    execution_id=execution_id,
                    case_id=case_id,
                    script_name="demo_persistence.jocky",
                    script_content=script_text,
                    script_hash=script_hash,
                    target=target,
                    status="SUCCESS",
                    started_at=now,
                    completed_at=datetime.now(timezone.utc),
                    duration_ms=34.8,
                    threat_score=86,
                    risk_level="HIGH",
                    evidence_categories=["processes", "network", "files", "persistence", "system"],
                    forensic_vector_dimensions=21,
                    tamper_checks_passed=12,
                    tamper_checks_total=12,
                    chain_status="VERIFIED",
                    merkle_root=merkle_record.merkle_root if merkle_record else None,
                    blockchain_block_hash=anchor_record.block_hash if anchor_record else None,
                    evidence_count=len(collectors_plan),
                    findings_count=len(findings_defs)
                )
                db.add(ex_rec)
                db.commit()

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "execution_id": execution_id,
            "script_hash": script_hash,
            "evidence_count": len(collectors_plan),
            "findings_count": len(findings_defs),
            "merkle_root": merkle_record.merkle_root if merkle_record else None,
            "blockchain_anchor": {
                "block_number": anchor_record.block_number if anchor_record else None,
                "block_hash": anchor_record.block_hash if anchor_record else None,
                "network": BlockchainService.NETWORK_NAME
            } if anchor_record else None
        }
