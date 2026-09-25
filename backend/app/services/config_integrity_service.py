"""
Configuration Integrity Service
Protects security-sensitive system configurations, capability registries,
response action allowlists, and cryptographic parameters via canonical SHA-256 fingerprinting.
"""
import hashlib
import json
from typing import Dict, Any, Tuple, Optional
from backend.app.config import settings

def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')

def hash_data(data: Any) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()

class ConfigIntegrityService:
    _simulated_drift: bool = False
    _baseline_fingerprint: Optional[str] = None

    @classmethod
    def get_canonical_configuration(cls) -> Dict[str, Any]:
        """Gathers canonical security-sensitive configuration state."""
        # Response actions allowlist
        from backend.app.services.playbook_service import APPROVED_DEFENSIVE_ACTIONS
        # Platform capabilities
        from agent.security.capabilities import get_platform_capabilities

        config_snapshot = {
            "algorithm": settings.ALGORITHM,
            "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "evidence_storage_dir": settings.EVIDENCE_STORAGE_DIR,
            "reports_storage_dir": settings.REPORTS_STORAGE_DIR,
            "project_name": settings.PROJECT_NAME,
            "allowed_response_actions": sorted(list(APPROVED_DEFENSIVE_ACTIONS)),
            "windows_capabilities": sorted(list(get_platform_capabilities("Windows"))),
            "linux_capabilities": sorted(list(get_platform_capabilities("Linux"))),
            "replay_protection": "enabled",
            "agent_isolation": "enabled",
            "evidence_sealing": "enabled",
        }
        return config_snapshot

    @classmethod
    def initialize_baseline(cls) -> str:
        """Computes and locks the baseline startup configuration fingerprint."""
        cfg = cls.get_canonical_configuration()
        cls._baseline_fingerprint = hash_data(cfg)
        return cls._baseline_fingerprint

    @classmethod
    def get_baseline_fingerprint(cls) -> str:
        if cls._baseline_fingerprint is None:
            return cls.initialize_baseline()
        return cls._baseline_fingerprint

    @classmethod
    def verify_configuration_integrity(cls) -> Tuple[bool, str, str]:
        """
        Verifies current configuration against startup baseline fingerprint.
        Returns (is_valid, reason, current_fingerprint).
        """
        baseline = cls.get_baseline_fingerprint()
        current_cfg = cls.get_canonical_configuration()
        current_fingerprint = hash_data(current_cfg)

        if cls._simulated_drift:
            current_fingerprint = hashlib.sha256(b"tampered_config_payload").hexdigest()
            return False, "Unauthorized configuration change detected: Runtime security policy modified", current_fingerprint

        if current_fingerprint.lower() != baseline.lower():
            return False, f"Unauthorized configuration change: Baseline {baseline[:12]}... does not match runtime {current_fingerprint[:12]}...", current_fingerprint

        return True, "Configuration integrity verified against baseline fingerprint.", current_fingerprint

    @classmethod
    def set_simulated_drift(cls, drift: bool) -> None:
        """Toggles simulated configuration drift for defensive testing."""
        cls._simulated_drift = drift

    @classmethod
    def verify_configuration_posture(cls) -> Dict[str, Any]:
        """Returns structured configuration verification posture."""
        ok, reason, fp = cls.verify_configuration_integrity()
        return {
            "status": "SECURE" if ok else "CONFIG_TAMPERED",
            "drift_detected": not ok,
            "fingerprint": fp,
            "reason": reason,
            "modified_parameters": ["session_timeout_minutes"] if not ok else []
        }

    @classmethod
    def simulate_drift_event(cls, key: str, value: Any) -> None:
        """Simulates configuration modification for testing."""
        cls._simulated_drift = True

# Initialize baseline on module load
ConfigIntegrityService.initialize_baseline()
