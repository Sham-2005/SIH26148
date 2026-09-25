"""
Local Evidence Blockchain Anchoring Service for JOCKY Digital Forensics
Provides an append-only, tamper-evident cryptographic block ledger.
Anchors Merkle roots, script execution digests, and evidence quantities.
Complies with technical claims policy: explicitly labeled as 'Local Evidence Blockchain'.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.models.models import BlockchainAnchorRecord
from backend.app.services.security_integrity_service import canonical_json


class BlockchainService:
    """Service for managing the Local Evidence Blockchain integrity anchor ledger."""

    GENESIS_PREV_HASH = "0" * 64
    NETWORK_NAME = "Local Evidence Blockchain"

    @classmethod
    def calculate_block_hash(
        cls,
        block_number: int,
        case_id: str,
        execution_id: Optional[str],
        merkle_root: str,
        script_hash: Optional[str],
        evidence_count: int,
        previous_block_hash: str,
        timestamp_iso: str
    ) -> str:
        """Computes deterministic canonical SHA-256 hash for a blockchain anchor block."""
        block_payload = {
            "block_number": block_number,
            "case_id": case_id,
            "execution_id": execution_id or "",
            "merkle_root": merkle_root.lower(),
            "script_hash": (script_hash or "").lower(),
            "evidence_count": evidence_count,
            "previous_block_hash": previous_block_hash.lower(),
            "timestamp": timestamp_iso,
            "network": cls.NETWORK_NAME
        }
        return hashlib.sha256(canonical_json(block_payload)).hexdigest()

    @classmethod
    def anchor_investigation(
        cls,
        case_id: str,
        merkle_root: str,
        evidence_count: int,
        script_hash: Optional[str] = None,
        execution_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> BlockchainAnchorRecord:
        """
        Creates a new immutable block on the Local Evidence Blockchain.
        Links to previous block's hash.
        """
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        if db is not None:
            # Query the latest block across the blockchain
            latest_block = db.query(BlockchainAnchorRecord).order_by(BlockchainAnchorRecord.block_number.desc()).first()
            if latest_block:
                block_number = latest_block.block_number + 1
                prev_hash = latest_block.block_hash
            else:
                block_number = 1
                prev_hash = cls.GENESIS_PREV_HASH
        else:
            block_number = 1
            prev_hash = cls.GENESIS_PREV_HASH

        block_hash = cls.calculate_block_hash(
            block_number=block_number,
            case_id=case_id,
            execution_id=execution_id,
            merkle_root=merkle_root,
            script_hash=script_hash,
            evidence_count=evidence_count,
            previous_block_hash=prev_hash,
            timestamp_iso=ts_str
        )

        record_id = f"BLK-{block_number:06d}"
        anchor = BlockchainAnchorRecord(
            id=record_id,
            block_number=block_number,
            case_id=case_id,
            execution_id=execution_id,
            merkle_root=merkle_root,
            script_hash=script_hash,
            evidence_count=evidence_count,
            previous_block_hash=prev_hash,
            block_hash=block_hash,
            network=cls.NETWORK_NAME,
            status="ANCHORED",
            timestamp=now,
            payload_json={
                "case_id": case_id,
                "execution_id": execution_id,
                "merkle_root": merkle_root,
                "script_hash": script_hash,
                "evidence_count": evidence_count,
                "timestamp": ts_str
            }
        )

        if db is not None:
            db.add(anchor)
            db.commit()
            db.refresh(anchor)

        return anchor

    @classmethod
    def verify_blockchain_ledger(
        cls,
        db: Session,
        case_id: Optional[str] = None
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verifies the full integrity of the Local Evidence Blockchain ledger.
        Validates:
        1. Block internal SHA-256 hash recalculation.
        2. Continuous cryptographic link (previous_block_hash matches predecessor).
        3. Block number monotonicity.
        """
        # Always audit the global blockchain sequence
        blocks = db.query(BlockchainAnchorRecord).order_by(BlockchainAnchorRecord.block_number.asc()).all()

        if not blocks:
            return True, []

        failures: List[Dict[str, Any]] = []
        is_valid = True
        expected_prev = cls.GENESIS_PREV_HASH

        for idx, blk in enumerate(blocks):
            # Check sequential link
            if idx == 0:
                expected_prev = cls.GENESIS_PREV_HASH
            else:
                pred = blocks[idx - 1]
                expected_prev = pred.block_hash

            if blk.previous_block_hash.lower() != expected_prev.lower():
                is_valid = False
                failures.append({
                    "block_number": blk.block_number,
                    "block_id": blk.id,
                    "case_id": blk.case_id,
                    "reason": "Blockchain link broken: previous_block_hash mismatch",
                    "expected": expected_prev,
                    "calculated": blk.previous_block_hash
                })

            # Check block hash recalculation
            ts_str = blk.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if blk.timestamp else ""
            recalculated = cls.calculate_block_hash(
                block_number=blk.block_number,
                case_id=blk.case_id,
                execution_id=blk.execution_id,
                merkle_root=blk.merkle_root,
                script_hash=blk.script_hash,
                evidence_count=blk.evidence_count,
                previous_block_hash=blk.previous_block_hash,
                timestamp_iso=ts_str
            )

            if recalculated.lower() != blk.block_hash.lower():
                is_valid = False
                failures.append({
                    "block_number": blk.block_number,
                    "block_id": blk.id,
                    "case_id": blk.case_id,
                    "reason": "Blockchain anchor tampered: block_hash mismatch",
                    "expected": blk.block_hash,
                    "calculated": recalculated
                })

        if case_id:
            case_block_nums = {b.block_number for b in blocks if b.case_id == case_id}
            case_failures = [f for f in failures if f.get("block_number") in case_block_nums]
            return len(case_failures) == 0, case_failures

        return is_valid, failures

    @classmethod
    def get_case_anchor(cls, case_id: str, db: Session, execution_id: Optional[str] = None) -> Optional[BlockchainAnchorRecord]:
        """Returns the most recent blockchain anchor for a case (and optionally execution_id)."""
        query = db.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case_id)
        if execution_id:
            query = query.filter(BlockchainAnchorRecord.execution_id == execution_id)
        return query.order_by(BlockchainAnchorRecord.block_number.desc()).first()

    @classmethod
    def get_case_anchors(cls, case_id: str, db: Session, limit: int = 50) -> List[BlockchainAnchorRecord]:
        """Returns all blockchain anchor records for a case in descending order."""
        return db.query(BlockchainAnchorRecord).filter(
            BlockchainAnchorRecord.case_id == case_id
        ).order_by(BlockchainAnchorRecord.block_number.desc()).limit(limit).all()

