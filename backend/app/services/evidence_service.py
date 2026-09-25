"""
Evidence Service
Handles cryptographic verification, storage, and chain-of-custody tracking.
"""
from typing import Dict, Any, Tuple
from agent.evidence.evidence_envelope import verify_evidence_integrity, calculate_sha256, canonical_json

class EvidenceService:
    @staticmethod
    def verify_envelope(envelope: Dict[str, Any]) -> Tuple[bool, str, str, str]:
        """Returns (is_valid, claimed_hash, recalculated_hash, message)."""
        claimed_hash = envelope.get("integrity", {}).get("hash", "")
        signable = {
            "evidence_id": envelope.get("evidence_id"),
            "case_id": envelope.get("case_id"),
            "agent_id": envelope.get("agent_id"),
            "timestamp": envelope.get("timestamp"),
            "collector": envelope.get("collector"),
            "platform": envelope.get("platform"),
            "parameters": envelope.get("parameters", {}),
            "results": envelope.get("results")
        }
        recalculated_hash = calculate_sha256(canonical_json(signable))
        is_valid = (claimed_hash.lower() == recalculated_hash.lower()) and bool(claimed_hash)
        msg = "Cryptographic integrity verified. Evidence is untampered." if is_valid else "Hash mismatch! Evidence tampering detected."
        return is_valid, claimed_hash, recalculated_hash, msg
