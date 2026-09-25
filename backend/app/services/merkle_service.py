"""
Merkle Tree Engine for JOCKY Digital Forensics
Implements cryptographic binary Merkle tree generation, root calculation,
audit proof generation, and proof verification for evidence integrity commitment.
Adheres to deterministic rules:
- Leaf nodes are SHA-256 hashes of canonical evidence objects.
- Intermediate nodes are SHA-256 of left + right child hashes: SHA256(left_hex + right_hex).
- If odd number of nodes at any level, duplicates the final node deterministically.
"""
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from backend.app.models.models import MerkleTreeRecord


def sha256_combine(left: str, right: str) -> str:
    """Computes deterministic SHA-256 digest of concatenated hexadecimal child hashes."""
    combined = (left + right).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


class MerkleService:
    """Cryptographic Merkle Tree construction and proof verification service."""

    EMPTY_ROOT = "0" * 64

    @classmethod
    def calculate_merkle_root(cls, leaf_hashes: List[str]) -> str:
        """
        Calculates the 64-character SHA-256 Merkle root from a list of leaf hashes.
        If leaf_hashes is empty, returns EMPTY_ROOT (64 zeros).
        """
        if not leaf_hashes:
            return cls.EMPTY_ROOT
        
        levels = cls.build_merkle_tree(leaf_hashes)
        return levels[-1][0] if levels and levels[-1] else cls.EMPTY_ROOT

    @classmethod
    def build_merkle_tree(cls, leaf_hashes: List[str]) -> List[List[str]]:
        """
        Constructs all levels of the Merkle tree from leaves to root.
        Returns a list of levels, where levels[0] is the leaf list and levels[-1] is [merkle_root].
        """
        if not leaf_hashes:
            return [[cls.EMPTY_ROOT]]

        current_level = [h.lower() for h in leaf_hashes]
        levels = [current_level]

        while len(current_level) > 1:
            next_level: List[str] = []
            # If odd number of items, duplicate the final item
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                parent = sha256_combine(left, right)
                next_level.append(parent)

            levels.append(next_level)
            current_level = next_level

        return levels

    @classmethod
    def generate_merkle_proof(
        cls,
        leaf_hashes_or_case_id: Any,
        target_hash_or_index: Any,
        db: Optional[Session] = None
    ) -> Optional[Any]:
        """
        Generates an audit proof path for a leaf in the Merkle tree.
        Can be called with:
        1. (leaf_hashes: List[str], target_hash_or_index) -> List[Dict[str, str]]
        2. (case_id: str, target_hash_or_index, db: Session) -> Dict[str, Any]
        """
        if isinstance(leaf_hashes_or_case_id, str) and db is not None:
            case_id = leaf_hashes_or_case_id
            rec = cls.get_case_merkle_tree(case_id, db)
            if not rec or not rec.evidence_hashes:
                return None
            leaves = rec.evidence_hashes
            proof = cls.generate_merkle_proof(leaves, target_hash_or_index)
            if proof is None:
                return None
            if isinstance(target_hash_or_index, int):
                l_idx = target_hash_or_index
            else:
                try:
                    l_idx = [h.lower() for h in leaves].index(str(target_hash_or_index).lower())
                except ValueError:
                    l_idx = 0
            return {
                "proof": proof,
                "leaf_index": l_idx,
                "merkle_root": rec.merkle_root
            }

        leaf_hashes = leaf_hashes_or_case_id
        if not leaf_hashes or not isinstance(leaf_hashes, list):
            return None

        # Resolve index
        if isinstance(target_hash_or_index, int):
            index = target_hash_or_index
            if index < 0 or index >= len(leaf_hashes):
                return None
        elif isinstance(target_hash_or_index, str):
            target_norm = target_hash_or_index.lower()
            try:
                index = [h.lower() for h in leaf_hashes].index(target_norm)
            except ValueError:
                return None
        else:
            return None

        levels = cls.build_merkle_tree(leaf_hashes)
        proof: List[Dict[str, str]] = []
        curr_idx = index

        # Traverse levels up to the level right below the root
        for lvl_idx in range(len(levels) - 1):
            level = levels[lvl_idx]
            # Account for duplicated odd element if needed
            if len(level) % 2 == 1:
                level_work = level + [level[-1]]
            else:
                level_work = level

            if curr_idx % 2 == 0:
                # Target is left, sibling is right
                sibling_idx = curr_idx + 1
                sibling_hash = level_work[sibling_idx]
                proof.append({"position": "right", "hash": sibling_hash})
            else:
                # Target is right, sibling is left
                sibling_idx = curr_idx - 1
                sibling_hash = level_work[sibling_idx]
                proof.append({"position": "left", "hash": sibling_hash})

            curr_idx = curr_idx // 2

        return proof

    @classmethod
    def verify_merkle_proof(cls, leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """
        Verifies that a leaf hash belongs to the Merkle tree with root expected_root
        using the supplied audit proof path.
        """
        if not leaf_hash or not expected_root:
            return False

        current = leaf_hash.lower()
        for step in proof:
            sibling = step["hash"].lower()
            pos = step["position"].lower()
            if pos == "right":
                current = sha256_combine(current, sibling)
            elif pos == "left":
                current = sha256_combine(sibling, current)
            else:
                return False

        return current.lower() == expected_root.lower()

    @classmethod
    def record_merkle_tree(
        cls,
        case_id: str,
        execution_id: Optional[str],
        leaf_hashes: List[str],
        db: Session
    ) -> MerkleTreeRecord:
        """Constructs and persists a Merkle tree record for an investigation execution."""
        levels = cls.build_merkle_tree(leaf_hashes)
        root = levels[-1][0] if levels and levels[-1] else cls.EMPTY_ROOT
        record_id = f"MRK-{case_id}-{execution_id or 'DEFAULT'}"

        existing = db.query(MerkleTreeRecord).filter(MerkleTreeRecord.id == record_id).first()
        if existing:
            existing.merkle_root = root
            existing.evidence_count = len(leaf_hashes)
            existing.evidence_hashes = leaf_hashes
            existing.tree_structure = levels
            db.commit()
            db.refresh(existing)
            return existing

        record = MerkleTreeRecord(
            id=record_id,
            case_id=case_id,
            execution_id=execution_id,
            merkle_root=root,
            evidence_count=len(leaf_hashes),
            evidence_hashes=leaf_hashes,
            tree_structure=levels,
            algorithm="SHA-256"
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def get_case_merkle_tree(
        cls,
        case_id: str,
        db: Session,
        execution_id: Optional[str] = None
    ) -> Optional[MerkleTreeRecord]:
        """Retrieves latest Merkle tree record for case, optionally filtering by execution ID."""
        q = db.query(MerkleTreeRecord).filter(MerkleTreeRecord.case_id == case_id)
        if execution_id:
            q = q.filter(MerkleTreeRecord.execution_id == execution_id)
        return q.order_by(MerkleTreeRecord.created_at.desc()).first()

