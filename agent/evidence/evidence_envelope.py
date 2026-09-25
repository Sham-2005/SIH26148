"""
JOCKY Forensic Evidence Envelope & Cryptographic Integrity Sealer
Implements RFC 8785 style deterministic JSON canonicalization and SHA-256 evidence integrity hashing.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

def canonical_json(data: Any) -> bytes:
    """Produces deterministic canonical UTF-8 bytes for JSON data."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':')
    ).encode('utf-8')

def calculate_sha256(data: bytes) -> str:
    """Returns hexadecimal SHA-256 digest of input bytes."""
    return hashlib.sha256(data).hexdigest()

def create_evidence_envelope(
    case_id: str,
    agent_id: str,
    collector: str,
    platform_name: str,
    results: Any,
    parameters: Optional[Dict[str, Any]] = None,
    evidence_id: Optional[str] = None
) -> Dict[str, Any]:
    """Wraps raw collector findings into an immutable, cryptographically sealed Evidence Envelope."""
    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = evidence_id or f"EV-{uuid.uuid4().hex[:12].upper()}"

    payload_for_signing = {
        "evidence_id": ev_id,
        "case_id": case_id,
        "agent_id": agent_id,
        "timestamp": now_iso,
        "collector": collector,
        "platform": platform_name,
        "parameters": parameters or {},
        "results": results
    }

    canonical_bytes = canonical_json(payload_for_signing)
    integrity_hash = calculate_sha256(canonical_bytes)

    envelope = {
        **payload_for_signing,
        "integrity": {
            "algorithm": "SHA-256",
            "hash": integrity_hash,
            "canonicalization": "RFC-8785-JSON"
        }
    }
    return envelope

def verify_evidence_integrity(envelope: Dict[str, Any]) -> bool:
    """Verifies that the envelope has not been tampered with since creation."""
    if "integrity" not in envelope or "hash" not in envelope["integrity"]:
        return False

    claimed_hash = envelope["integrity"]["hash"]

    # Reconstruct exact signable payload
    signable_payload = {
        "evidence_id": envelope.get("evidence_id"),
        "case_id": envelope.get("case_id"),
        "agent_id": envelope.get("agent_id"),
        "timestamp": envelope.get("timestamp"),
        "collector": envelope.get("collector"),
        "platform": envelope.get("platform"),
        "parameters": envelope.get("parameters", {}),
        "results": envelope.get("results")
    }

    computed_hash = calculate_sha256(canonical_json(signable_payload))
    return computed_hash.lower() == claimed_hash.lower()
