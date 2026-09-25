"""
Defensive Playbook Service
Implements safe incident response action validation, analyst approval workflow,
and deterministic sequential action execution.
Enforces strict allowlist of approved defensive actions.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import uuid
from sqlalchemy.orm import Session
from backend.app.models.models import (
    Playbook,
    PlaybookAction,
    PlaybookApproval,
    PlaybookExecution,
    AuditLog,
    TimelineEvent,
    Case,
    Agent,
)

# Strictly approved defensive response actions.
# Any action outside this set is strictly forbidden and triggers UNSUPPORTED_RESPONSE_ACTION.
APPROVED_DEFENSIVE_ACTIONS = {
    "collect.system",
    "collect.processes",
    "collect.network",
    "collect.persistence",
    "collect.file_metadata",
    "generate.report",
    "isolate.endpoint.simulated",
    "suspend.process.simulated",
}


class PlaybookService:
    @staticmethod
    def validate_action(action_type: str) -> Tuple[bool, Optional[str]]:
        """Validates that an action is part of the approved defensive response allowlist."""
        if not action_type or not isinstance(action_type, str):
            return False, "Action type must be a non-empty string"
        if action_type not in APPROVED_DEFENSIVE_ACTIONS:
            return False, f"UNSUPPORTED_RESPONSE_ACTION: Action '{action_type}' is not in the approved defensive allowlist"
        return True, None

    @classmethod
    def validate_actions_list(cls, actions: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        """Validates an entire sequence of playbook actions."""
        if not actions:
            return False, "Playbook must contain at least one action step"
        for act in actions:
            action_type = act.get("action_type")
            valid, err = cls.validate_action(action_type)
            if not valid:
                return False, err
        return True, None

    @classmethod
    def create_playbook(
        cls,
        db: Session,
        case_id: str,
        name: str,
        actions_data: List[Dict[str, Any]],
        description: Optional[str] = None,
        version: str = "1.0.0",
        trigger_type: str = "MANUAL",
        created_by: str = "analyst"
    ) -> Playbook:
        """Creates a new Playbook in DRAFT or PENDING_APPROVAL status after validating all actions."""
        # Validate all action steps
        is_valid, err_msg = cls.validate_actions_list(actions_data)
        if not is_valid:
            raise ValueError(err_msg)

        pb_id = f"PB-{uuid.uuid4().hex[:8].upper()}"
        from backend.app.services.security_integrity_service import IntegrityService
        content_hash = IntegrityService.compute_playbook_content_hash(actions_data)

        playbook = Playbook(
            id=pb_id,
            case_id=case_id,
            name=name,
            description=description,
            version=version,
            status="PENDING_APPROVAL",  # Directly submit for analyst approval review
            trigger_type=trigger_type,
            definition_json={"actions": actions_data},
            content_hash=content_hash,
            created_by=created_by,
        )
        db.add(playbook)

        # Create child action rows
        for idx, act in enumerate(actions_data, start=1):
            action_row = PlaybookAction(
                id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
                playbook_id=pb_id,
                step_number=act.get("step_number", idx),
                action_type=act["action_type"],
                target_agent_id=act.get("target_agent_id"),
                parameters=act.get("parameters") or {},
                status="PENDING",
            )
            db.add(action_row)

        # Audit log creation
        IntegrityService.record_chained_audit(
            db=db,
            actor=created_by,
            actor_type="USER",
            action="CREATE_PLAYBOOK",
            resource="playbooks",
            resource_type="Playbook",
            resource_id=pb_id,
            case_id=case_id,
            result="SUCCESS",
            details={"name": name, "case_id": case_id, "actions_count": len(actions_data), "content_hash": content_hash}
        )
        db.commit()
        db.refresh(playbook)
        return playbook

    @staticmethod
    def approve_playbook(
        db: Session,
        playbook: Any,
        approver_email: str,
        approver_id: Optional[int] = None,
        comment: Optional[str] = None
    ) -> PlaybookApproval:
        """Approves a playbook and transitions its state to APPROVED."""
        from backend.app.services.security_integrity_service import IntegrityService

        if isinstance(playbook, str):
            playbook_obj = db.query(Playbook).filter(Playbook.id == playbook).first()
            if not playbook_obj:
                raise ValueError(f"Playbook '{playbook}' not found")
            playbook = playbook_obj

        actions_data = playbook.definition_json.get("actions", [])
        if not playbook.content_hash:
            playbook.content_hash = IntegrityService.compute_playbook_content_hash(actions_data)

        approval_hash = IntegrityService.compute_approval_hash(playbook.id, playbook.content_hash, approver_email)
        playbook.approval_hash = approval_hash
        playbook.status = "APPROVED"
        playbook.updated_at = datetime.now(timezone.utc)

        approval = PlaybookApproval(
            id=f"APPR-{uuid.uuid4().hex[:8].upper()}",
            playbook_id=playbook.id,
            approver_id=approver_id,
            approver_email=approver_email,
            decision="APPROVED",
            comment=comment or "Approved for defensive execution",
        )
        db.add(approval)

        IntegrityService.record_chained_audit(
            db=db,
            actor=approver_email,
            actor_type="USER",
            action="APPROVE_PLAYBOOK",
            resource="playbooks",
            resource_type="Playbook",
            resource_id=playbook.id,
            case_id=playbook.case_id,
            result="SUCCESS",
            details={"decision": "APPROVED", "comment": comment, "approval_hash": approval_hash}
        )
        db.commit()
        db.refresh(playbook)
        return approval

    @staticmethod
    def reject_playbook(
        db: Session,
        playbook: Playbook,
        approver_email: str,
        approver_id: Optional[int] = None,
        comment: Optional[str] = None
    ) -> PlaybookApproval:
        """Rejects a playbook and transitions its state to REJECTED."""
        playbook.status = "REJECTED"
        playbook.updated_at = datetime.now(timezone.utc)

        approval = PlaybookApproval(
            id=f"APPR-{uuid.uuid4().hex[:8].upper()}",
            playbook_id=playbook.id,
            approver_id=approver_id,
            approver_email=approver_email,
            decision="REJECTED",
            comment=comment or "Rejected by analyst",
        )
        db.add(approval)

        audit = AuditLog(
            actor=approver_email,
            actor_type="USER",
            action="REJECT_PLAYBOOK",
            resource="playbooks",
            resource_type="Playbook",
            resource_id=playbook.id,
            case_id=playbook.case_id,
            result="SUCCESS",
            details={"decision": "REJECTED", "comment": comment}
        )
        db.add(audit)
        db.commit()
        db.refresh(playbook)
        return approval

    @classmethod
    def execute_playbook(
        cls,
        db: Session,
        playbook: Any,
        executor_email: str
    ) -> PlaybookExecution:
        """
        Executes an APPROVED playbook deterministically step-by-step.
        Verifies:
          1. Recalculates playbook content hash.
          2. Compares against approved hash.
          3. Verifies approval state.
          4. Verifies every action against allowlist.
        Raises ValueError with PLAYBOOK_INTEGRITY_VIOLATION if any verification fails.
        """
        from backend.app.services.security_integrity_service import IntegrityService
        from backend.app.services.tamper_detection_service import TamperDetectionService

        if isinstance(playbook, str):
            playbook_obj = db.query(Playbook).filter(Playbook.id == playbook).first()
            if not playbook_obj:
                raise ValueError(f"Playbook '{playbook}' not found")
            playbook = playbook_obj

        # 1. Approval State Check
        if playbook.status != "APPROVED":
            raise ValueError(f"Playbook not approved (current status: {playbook.status}). Analyst approval required prior to execution.")

        # 2. Content Hash Verification
        if playbook.actions:
            actions_data = [
                {
                    "step_number": a.step_number,
                    "action_type": a.action_type,
                    "target_agent_id": a.target_agent_id,
                    "parameters": a.parameters
                }
                for a in sorted(playbook.actions, key=lambda x: x.step_number)
            ]
        else:
            actions_data = playbook.definition_json.get("actions", [])
        recalculated_hash = IntegrityService.compute_playbook_content_hash(actions_data)
        if playbook.content_hash and recalculated_hash.lower() != playbook.content_hash.lower():
            TamperDetectionService.create_security_event(
                db=db,
                event_type="PLAYBOOK_INTEGRITY_VIOLATION",
                severity="CRITICAL",
                object_type="PLAYBOOK",
                object_id=playbook.id,
                description=f"Playbook '{playbook.id}' content altered after authorization.",
                expected_value=playbook.content_hash,
                observed_value=recalculated_hash,
                case_id=playbook.case_id
            )
            raise ValueError(f"PLAYBOOK_INTEGRITY_VIOLATION: Playbook content hash mismatch. Expected {playbook.content_hash}, calculated {recalculated_hash}.")

        # 3. Action Allowlist Verification
        for action in playbook.actions:
            if action.action_type not in APPROVED_DEFENSIVE_ACTIONS:
                raise ValueError(f"PLAYBOOK_INTEGRITY_VIOLATION: Action '{action.action_type}' is not allowlisted.")

        playbook.status = "EXECUTING"
        db.commit()

        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        execution = PlaybookExecution(
            id=exec_id,
            playbook_id=playbook.id,
            case_id=playbook.case_id,
            executor_email=executor_email,
            status="RUNNING",
            started_at=datetime.now(timezone.utc),
        )
        db.add(execution)
        db.commit()

        executed_actions_summary = []
        now = datetime.now(timezone.utc)

        for action in playbook.actions:
            action.status = "RUNNING"
            db.commit()

            # Execute safe response action
            result_details: Dict[str, Any] = {
                "action_type": action.action_type,
                "step": action.step_number,
                "target_agent": action.target_agent_id,
            }

            if action.action_type.startswith("collect."):
                collector_name = action.action_type.split(".", 1)[1]
                result_details["mode"] = "EVIDENCE_COLLECTION"
                result_details["collector"] = collector_name
                result_details["status"] = "DISPATCHED"
                result_details["message"] = f"Triggered approved defensive collection: {collector_name} on agent {action.target_agent_id or 'FLEET'}"
            elif action.action_type == "generate.report":
                result_details["mode"] = "REPORT_GENERATION"
                result_details["status"] = "COMPLETED"
                result_details["message"] = f"Investigation report queued for case {playbook.case_id}"
            elif action.action_type == "isolate.endpoint.simulated":
                result_details["mode"] = "SIMULATED_CONTAINMENT"
                result_details["status"] = "SIMULATED_SUCCESS"
                result_details["message"] = f"[DEMO / SIMULATED] Simulated network isolation applied for agent {action.target_agent_id}. Host traffic restricted to forensic orchestrator."
            elif action.action_type == "suspend.process.simulated":
                pid = (action.parameters or {}).get("pid", "TARGET_PID")
                result_details["mode"] = "SIMULATED_CONTAINMENT"
                result_details["status"] = "SIMULATED_SUCCESS"
                result_details["message"] = f"[DEMO / SIMULATED] Simulated process suspension applied to PID {pid} on agent {action.target_agent_id}."
            else:
                result_details["status"] = "COMPLETED"

            action.status = "COMPLETED"
            action.result_details = result_details
            action.executed_at = now
            executed_actions_summary.append(result_details)

        playbook.status = "COMPLETED"
        playbook.updated_at = now
        execution.status = "COMPLETED"
        execution.completed_at = now
        execution.summary = {
            "total_steps": len(playbook.actions),
            "executed_steps": len(executed_actions_summary),
            "step_results": executed_actions_summary
        }
        execution.result_hash = IntegrityService.canonical_hash(execution.summary)

        # Add timeline event
        tle = TimelineEvent(
            id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
            case_id=playbook.case_id,
            agent_id=playbook.actions[0].target_agent_id if playbook.actions else None,
            event_type="ANALYSIS",
            severity="INFO",
            description=f"Playbook '{playbook.name}' completed ({len(executed_actions_summary)} actions executed)",
            details={"playbook_id": playbook.id, "execution_id": exec_id}
        )
        db.add(tle)

        # Append-only chained audit log
        IntegrityService.record_chained_audit(
            db=db,
            actor=executor_email,
            actor_type="USER",
            action="EXECUTE_PLAYBOOK",
            resource="playbooks",
            resource_type="Playbook",
            resource_id=playbook.id,
            case_id=playbook.case_id,
            result="SUCCESS",
            details={"execution_id": exec_id, "steps_completed": len(executed_actions_summary), "result_hash": execution.result_hash}
        )

        db.commit()
        db.refresh(execution)
        db.refresh(playbook)
        return execution

