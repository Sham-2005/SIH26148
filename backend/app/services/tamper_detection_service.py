"""
Tamper Detection Engine
Deterministic, explainable security event detection covering:
1. Evidence hash mismatch
2. Audit entry modification
3. Missing evidence sequence
4. Unexpected agent identity
5. Duplicate task submission
6. Replay attempts
7. Invalid plan hash
8. Unauthorized playbook modification
9. Unauthorized configuration change
10. Report integrity mismatch
11. Invalid approval transition
12. Timestamp anomalies
"""
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.models.models import (
    SecurityEvent,
    Evidence,
    AuditLog,
    Agent,
    Task,
    Playbook,
    PlaybookApproval,
    Report,
    Case
)
from backend.app.services.security_integrity_service import (
    IntegrityService,
    hash_object,
    canonical_json
)
from backend.app.services.config_integrity_service import ConfigIntegrityService
from backend.app.services.time_integrity_service import TimeIntegrityService


class TamperDetectionService:
    @classmethod
    def create_security_event(
        cls,
        db: Session,
        event_type: str,
        severity: str,
        object_type: str,
        object_id: str,
        description: str,
        expected_value: Optional[str] = None,
        observed_value: Optional[str] = None,
        case_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """Persists a structured SecurityEvent with canonical SHA-256 seal."""
        event_id = f"SECEV-{uuid.uuid4().hex[:10].upper()}"
        now = datetime.now(timezone.utc)

        signable = {
            "id": event_id,
            "event_type": event_type,
            "severity": severity,
            "object_type": object_type,
            "object_id": object_id,
            "case_id": case_id,
            "agent_id": agent_id,
            "description": description,
            "expected_value": expected_value,
            "observed_value": observed_value,
            "detected_at": now.isoformat()
        }
        integrity_hash = hash_object(signable)

        sec_event = SecurityEvent(
            id=event_id,
            case_id=case_id,
            agent_id=agent_id,
            event_type=event_type,
            severity=severity,
            object_type=object_type,
            object_id=object_id,
            description=description,
            expected_value=expected_value,
            observed_value=observed_value,
            detected_at=now,
            resolved=False,
            integrity_hash=integrity_hash,
            metadata_json=metadata_json or {}
        )
        db.add(sec_event)
        db.commit()
        db.refresh(sec_event)
        return sec_event

    # ------------------------------------------------------------------------
    # 12 Deterministic Detectors
    # ------------------------------------------------------------------------

    # 1. Evidence hash mismatch
    @classmethod
    def detect_evidence_hash_mismatch(cls, evidence: Evidence) -> Optional[Dict[str, Any]]:
        is_valid, claimed, recalculated, msg = IntegrityService.verify_single_evidence(evidence)
        if not is_valid:
            return {
                "event_type": "EVIDENCE_HASH_MISMATCH",
                "severity": "CRITICAL",
                "object_type": "EVIDENCE",
                "object_id": evidence.id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": claimed,
                "actual": recalculated,
                "reason": f"Cryptographic signature mismatch for evidence {evidence.id}.",
                "recommended_action": "Quarantine evidence envelope and alert investigating analyst."
            }
        return None

    # 2. Audit entry modification
    @classmethod
    def detect_audit_entry_modification(cls, db: Session, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        is_ok, findings = IntegrityService.verify_audit_chain(db, case_id=case_id)
        results = []
        for f in findings:
            results.append({
                "event_type": "AUDIT_ENTRY_MODIFICATION",
                "severity": "CRITICAL",
                "object_type": "AUDIT_LOG",
                "object_id": str(f.get("entry_id")),
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": f.get("expected_hash") or f.get("expected_previous_hash"),
                "actual": f.get("actual_hash") or f.get("actual_previous_hash"),
                "reason": f.get("reason"),
                "recommended_action": "Preserve database snapshot and inspect administrative access logs."
            })
        return results

    # 3. Missing evidence sequence
    @classmethod
    def detect_missing_evidence_sequence(cls, db: Session, case_id: str) -> List[Dict[str, Any]]:
        is_ok, findings = IntegrityService.verify_evidence_chain(db, case_id=case_id)
        results = []
        for f in findings:
            if f.get("issue") == "BROKEN_EVIDENCE_HASH_CHAIN":
                results.append({
                    "event_type": "MISSING_EVIDENCE_SEQUENCE",
                    "severity": "HIGH",
                    "object_type": "EVIDENCE",
                    "object_id": f.get("evidence_id"),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "expected": f.get("expected_previous_hash"),
                    "actual": f.get("actual_previous_hash"),
                    "reason": f.get("reason"),
                    "recommended_action": "Verify if evidence records were deleted or inserted out-of-order."
                })
        return results

    # 4. Unexpected agent identity
    @classmethod
    def detect_unexpected_agent_identity(
        cls,
        agent_id: str,
        claimed_platform: str,
        db: Session
    ) -> Optional[Dict[str, Any]]:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return {
                "event_type": "UNKNOWN_AGENT",
                "severity": "HIGH",
                "object_type": "AGENT",
                "object_id": agent_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": "Registered Agent ID in enrollment registry",
                "actual": agent_id,
                "reason": f"Unenrolled or unknown agent '{agent_id}' attempted check-in.",
                "recommended_action": "Reject connection and verify enrollment secret."
            }

        if agent.platform and claimed_platform and agent.platform.lower() != claimed_platform.lower():
            return {
                "event_type": "AGENT_IDENTITY_MISMATCH",
                "severity": "HIGH",
                "object_type": "AGENT",
                "object_id": agent_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": agent.platform,
                "actual": claimed_platform,
                "reason": f"Agent '{agent_id}' claimed platform '{claimed_platform}' differing from enrolled '{agent.platform}'.",
                "recommended_action": "Revoke enrollment token and inspect agent host."
            }
        return None

    # 5. Duplicate task submission
    @classmethod
    def detect_duplicate_task_submission(cls, task_id: str, db: Session) -> Optional[Dict[str, Any]]:
        task = db.query(Task).filter(Task.id == task_id).first()
        if task and task.results and len(task.results) > 0:
            return {
                "event_type": "DUPLICATE_TASK_SUBMISSION",
                "severity": "HIGH",
                "object_type": "TASK",
                "object_id": task_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": "Single result submission for assigned task lease",
                "actual": f"Existing results count: {len(task.results)}",
                "reason": f"Task '{task_id}' has already received execution results.",
                "recommended_action": "Reject duplicate submission and verify agent concurrency."
            }
        return None

    # 6. Replay attempts
    @classmethod
    def detect_replay_attempt(cls, task_id: str, db: Session) -> Optional[Dict[str, Any]]:
        task = db.query(Task).filter(Task.id == task_id).first()
        if task and task.status == "completed":
            return {
                "event_type": "REPLAY_ATTEMPT_DETECTED",
                "severity": "HIGH",
                "object_type": "TASK",
                "object_id": task_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": "Task status: pending/assigned/running",
                "actual": "completed",
                "reason": f"Replay attempt blocked: Task '{task_id}' is in immutable completed terminal state.",
                "recommended_action": "Disallow task re-execution and inspect dispatch origin."
            }
        return None

    # 7. Invalid plan hash
    @classmethod
    def detect_invalid_plan_hash(cls, task: Task) -> Optional[Dict[str, Any]]:
        if not task.plan_hash:
            return None
        recalculated = hash_object(task.plan_payload)
        if recalculated.lower() != task.plan_hash.lower():
            return {
                "event_type": "INVALID_PLAN_HASH",
                "severity": "CRITICAL",
                "object_type": "TASK",
                "object_id": task.id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": task.plan_hash,
                "actual": recalculated,
                "reason": f"Execution plan payload was altered after compiler signature generation.",
                "recommended_action": "Block task execution immediately."
            }
        return None

    # 8. Unauthorized playbook modification
    @classmethod
    def detect_unauthorized_playbook_modification(cls, playbook: Playbook) -> Optional[Dict[str, Any]]:
        if not playbook.content_hash:
            return None
        actions_data = playbook.definition_json.get("actions", [])
        recomputed = IntegrityService.compute_playbook_content_hash(actions_data)
        if recomputed.lower() != playbook.content_hash.lower():
            return {
                "event_type": "UNAUTHORIZED_PLAYBOOK_MODIFICATION",
                "severity": "CRITICAL",
                "object_type": "PLAYBOOK",
                "object_id": playbook.id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": playbook.content_hash,
                "actual": recomputed,
                "reason": f"Playbook '{playbook.id}' action steps were altered after authorization.",
                "recommended_action": "Revoke approval and halt any pending response executions."
            }
        return None

    # 9. Unauthorized configuration change
    @classmethod
    def detect_unauthorized_configuration_change(cls) -> Optional[Dict[str, Any]]:
        ok, reason, current_fp = ConfigIntegrityService.verify_configuration_integrity()
        if not ok:
            return {
                "event_type": "UNAUTHORIZED_CONFIGURATION_CHANGE",
                "severity": "HIGH",
                "object_type": "CONFIGURATION",
                "object_id": "SYSTEM_CONFIG",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": ConfigIntegrityService.get_baseline_fingerprint(),
                "actual": current_fp,
                "reason": reason,
                "recommended_action": "Investigate runtime configuration modifications and restore baseline."
            }
        return None

    # 10. Report integrity mismatch
    @classmethod
    def detect_report_integrity_mismatch(cls, report: Report) -> Optional[Dict[str, Any]]:
        ok, msg, details = IntegrityService.verify_report_manifest(report)
        if not ok:
            return {
                "event_type": "REPORT_INTEGRITY_MISMATCH",
                "severity": "HIGH",
                "object_type": "REPORT",
                "object_id": report.id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": details.get("expected_manifest_hash") or report.report_content_hash,
                "actual": details.get("calculated_manifest_hash") or details.get("calculated"),
                "reason": msg,
                "recommended_action": "Re-generate forensic report with fresh signed evidence manifest."
            }
        return None

    # 11. Invalid approval transition
    @classmethod
    def detect_invalid_approval_transition(cls, playbook: Playbook, requested_status: str) -> Optional[Dict[str, Any]]:
        valid_transitions = {
            "DRAFT": {"PENDING_APPROVAL"},
            "PENDING_APPROVAL": {"APPROVED", "REJECTED"},
            "APPROVED": {"EXECUTING"},
            "EXECUTING": {"COMPLETED", "FAILED"},
            "REJECTED": set(),
            "COMPLETED": set()
        }
        allowed = valid_transitions.get(playbook.status, set())
        if requested_status not in allowed:
            return {
                "event_type": "INVALID_APPROVAL_TRANSITION",
                "severity": "HIGH",
                "object_type": "PLAYBOOK",
                "object_id": playbook.id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": f"One of: {allowed}",
                "actual": requested_status,
                "reason": f"Invalid state transition from '{playbook.status}' to '{requested_status}'.",
                "recommended_action": "Enforce strict multi-state playbook approval lifecycle."
            }
        return None

    # 12. Timestamp anomalies
    @classmethod
    def detect_timestamp_anomalies(cls, db: Session, case_id: str) -> List[Dict[str, Any]]:
        raw_anomalies = TimeIntegrityService.scan_case_temporal_integrity(db, case_id)
        results = []
        for anom in raw_anomalies:
            results.append({
                "event_type": "TIMESTAMP_ANOMALY",
                "severity": anom.get("severity", "MEDIUM"),
                "object_type": anom.get("object_type"),
                "object_id": anom.get("object_id"),
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "expected": anom.get("expected"),
                "actual": anom.get("observed"),
                "reason": anom.get("reason"),
                "recommended_action": "Review host clock synchronization and NTP configuration."
            })
        return results

    # ------------------------------------------------------------------------
    # Full Case Audit & Tamper Scan
    # ------------------------------------------------------------------------
    @classmethod
    def scan_and_record_case_security_events(cls, db: Session, case_id: str) -> List[SecurityEvent]:
        """
        Runs all detectors across the case, records new SecurityEvent rows in DB,
        and returns the created events.
        """
        detected_alerts: List[Dict[str, Any]] = []

        # 1. Evidence checks
        evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
        for ev in evidence_items:
            res = cls.detect_evidence_hash_mismatch(ev)
            if res:
                detected_alerts.append(res)

        # 2. Sequence checks
        detected_alerts.extend(cls.detect_missing_evidence_sequence(db, case_id))

        # 3. Audit chain checks
        detected_alerts.extend(cls.detect_audit_entry_modification(db, case_id))

        # 4. Task plan hash checks
        tasks = db.query(Task).filter(Task.case_id == case_id).all()
        for t in tasks:
            res = cls.detect_invalid_plan_hash(t)
            if res:
                detected_alerts.append(res)

        # 5. Playbook modification checks
        playbooks = db.query(Playbook).filter(Playbook.case_id == case_id).all()
        for pb in playbooks:
            res = cls.detect_unauthorized_playbook_modification(pb)
            if res:
                detected_alerts.append(res)

        # 6. Report checks
        reports = db.query(Report).filter(Report.case_id == case_id).all()
        for r in reports:
            res = cls.detect_report_integrity_mismatch(r)
            if res:
                detected_alerts.append(res)

        # 7. Config check
        cfg_alert = cls.detect_unauthorized_configuration_change()
        if cfg_alert:
            detected_alerts.append(cfg_alert)

        # 8. Timestamp anomalies
        detected_alerts.extend(cls.detect_timestamp_anomalies(db, case_id))

        created_events = []
        for alert in detected_alerts:
            # Check if an unresolved event of this type for this object already exists
            existing = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.case_id == case_id,
                    SecurityEvent.event_type == alert["event_type"],
                    SecurityEvent.object_id == alert["object_id"],
                    SecurityEvent.resolved == False
                )
                .first()
            )
            if not existing:
                ev = cls.create_security_event(
                    db=db,
                    event_type=alert["event_type"],
                    severity=alert["severity"],
                    object_type=alert["object_type"],
                    object_id=alert["object_id"],
                    description=alert["reason"],
                    expected_value=alert.get("expected"),
                    observed_value=alert.get("actual"),
                    case_id=case_id,
                    metadata_json={"recommended_action": alert.get("recommended_action")}
                )
                created_events.append(ev)

        return created_events

    _seen_tokens: set = set()

    @classmethod
    def check_replay_attack(cls, token: str) -> Dict[str, Any]:
        """Detects duplicate submission tokens / replay attacks."""
        if token in cls._seen_tokens:
            return {
                "is_replay": True,
                "details": f"Replay attack detected: Token '{token}' was already processed."
            }
        cls._seen_tokens.add(token)
        return {
            "is_replay": False,
            "details": "Token is unique and valid."
        }

    @classmethod
    def check_agent_fingerprint_integrity(cls, db: Session, agent_id: str) -> Dict[str, Any]:
        """Verifies stored agent identity and capability fingerprint against current declared attributes."""
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return {"verified": False, "tampered": True, "details": "Agent not found"}

        if agent.identity_fingerprint:
            expected_fp = IntegrityService.compute_agent_fingerprint(
                agent.id, agent.hostname, agent.platform, agent.os_version, agent.architecture
            )
            if agent.identity_fingerprint.lower() != expected_fp.lower():
                return {
                    "verified": False,
                    "tampered": True,
                    "status": "TAMPERED",
                    "details": f"Identity fingerprint mismatch for agent {agent_id}."
                }

        if agent.capability_fingerprint and agent.capabilities:
            expected_cap = IntegrityService.compute_capability_fingerprint(agent.capabilities)
            if agent.capability_fingerprint.lower() != expected_cap.lower():
                return {
                    "verified": False,
                    "tampered": True,
                    "status": "TAMPERED",
                    "details": f"Capability fingerprint mismatch for agent {agent_id}."
                }

        return {"verified": True, "tampered": False, "status": "VALID", "details": "Agent verified."}

    @classmethod
    def check_task_integrity(cls, db: Session, task_id: str) -> Dict[str, Any]:
        """Verifies task instructions and parameter binding against stored task_hash."""
        task = db.query(Task).filter(Task.id == task_id).first()
        if not task:
            return {"tampered": True, "status": "NOT_FOUND"}

        expected = IntegrityService.compute_task_hash(task.script_source or "", task.plan_payload or {}, task.case_id or "")
        if task.task_hash and task.task_hash.lower() != expected.lower():
            return {
                "tampered": True,
                "status": "TAMPERED",
                "details": f"Task script_source/payload modified after dispatch. Expected {task.task_hash}, observed {expected}"
            }

        return {"tampered": False, "status": "VALID", "details": "Task integrity verified."}
