"""
Time & Temporal Integrity Service
Detects chronological and temporal causality anomalies across forensic lifecycles.
Flags anomalies with neutral, explainable TIMESTAMP_ANOMALY findings without premature attribution.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import Task, Playbook, PlaybookApproval, PlaybookExecution, Evidence, Report, Case


class TimeIntegrityService:
    @staticmethod
    def verify_task_temporal_causality(task: Task) -> List[Dict[str, Any]]:
        """
        Verifies chronological consistency of task lifecycle timestamps:
        created_at <= assigned_at <= started_at <= completed_at
        """
        anomalies = []

        if task.assigned_at and task.created_at and task.assigned_at < task.created_at:
            anomalies.append({
                "event_type": "TIMESTAMP_ANOMALY",
                "object_type": "TASK",
                "object_id": task.id,
                "anomaly_type": "ASSIGNMENT_BEFORE_CREATION",
                "reason": f"Task '{task.id}' assigned timestamp ({task.assigned_at}) precedes creation ({task.created_at}).",
                "severity": "MEDIUM",
                "expected": f">= {task.created_at.isoformat()}",
                "observed": task.assigned_at.isoformat()
            })

        if task.completed_at and task.created_at and task.completed_at < task.created_at:
            anomalies.append({
                "event_type": "TIMESTAMP_ANOMALY",
                "object_type": "TASK",
                "object_id": task.id,
                "anomaly_type": "COMPLETION_BEFORE_CREATION",
                "reason": f"Task '{task.id}' completed timestamp ({task.completed_at}) precedes creation ({task.created_at}).",
                "severity": "HIGH",
                "expected": f">= {task.created_at.isoformat()}",
                "observed": task.completed_at.isoformat()
            })

        if task.completed_at and task.started_at and task.completed_at < task.started_at:
            anomalies.append({
                "event_type": "TIMESTAMP_ANOMALY",
                "object_type": "TASK",
                "object_id": task.id,
                "anomaly_type": "COMPLETION_BEFORE_START",
                "reason": f"Task '{task.id}' completed timestamp ({task.completed_at}) precedes execution start ({task.started_at}).",
                "severity": "HIGH",
                "expected": f">= {task.started_at.isoformat()}",
                "observed": task.completed_at.isoformat()
            })

        return anomalies

    @staticmethod
    def verify_playbook_temporal_causality(playbook: Playbook) -> List[Dict[str, Any]]:
        """
        Verifies chronological consistency of playbook lifecycle timestamps:
        playbook.created_at <= approval.created_at <= execution.started_at <= execution.completed_at
        """
        anomalies = []

        # Check approvals
        latest_approval_time = None
        for appr in playbook.approvals:
            if appr.created_at and playbook.created_at and appr.created_at < playbook.created_at:
                anomalies.append({
                    "event_type": "TIMESTAMP_ANOMALY",
                    "object_type": "PLAYBOOK",
                    "object_id": playbook.id,
                    "anomaly_type": "APPROVAL_BEFORE_CREATION",
                    "reason": f"Playbook approval '{appr.id}' timestamp ({appr.created_at}) precedes playbook creation ({playbook.created_at}).",
                    "severity": "HIGH",
                    "expected": f">= {playbook.created_at.isoformat()}",
                    "observed": appr.created_at.isoformat()
                })
            if appr.decision == "APPROVED":
                latest_approval_time = appr.created_at

        # Check executions
        for exec_row in playbook.executions:
            if latest_approval_time and exec_row.started_at and exec_row.started_at < latest_approval_time:
                anomalies.append({
                    "event_type": "TIMESTAMP_ANOMALY",
                    "object_type": "PLAYBOOK_EXECUTION",
                    "object_id": exec_row.id,
                    "anomaly_type": "EXECUTION_BEFORE_APPROVAL",
                    "reason": f"Playbook execution started ({exec_row.started_at}) prior to analyst approval ({latest_approval_time}).",
                    "severity": "CRITICAL",
                    "expected": f">= {latest_approval_time.isoformat()}",
                    "observed": exec_row.started_at.isoformat()
                })

            if exec_row.completed_at and exec_row.started_at and exec_row.completed_at < exec_row.started_at:
                anomalies.append({
                    "event_type": "TIMESTAMP_ANOMALY",
                    "object_type": "PLAYBOOK_EXECUTION",
                    "object_id": exec_row.id,
                    "anomaly_type": "EXECUTION_COMPLETION_BEFORE_START",
                    "reason": f"Playbook execution completed ({exec_row.completed_at}) prior to starting ({exec_row.started_at}).",
                    "severity": "HIGH",
                    "expected": f">= {exec_row.started_at.isoformat()}",
                    "observed": exec_row.completed_at.isoformat()
                })

        return anomalies

    @staticmethod
    def verify_report_temporal_causality(db: Session, report: Report) -> List[Dict[str, Any]]:
        """
        Verifies that report generation timestamp is later than the evidence collection timestamps.
        """
        anomalies = []
        if not report.created_at:
            return anomalies

        evidence_items = db.query(Evidence).filter(Evidence.case_id == report.case_id).all()
        for ev in evidence_items:
            if ev.collected_at and ev.collected_at > report.created_at:
                anomalies.append({
                    "event_type": "TIMESTAMP_ANOMALY",
                    "object_type": "REPORT",
                    "object_id": report.id,
                    "anomaly_type": "REPORT_PRECEEDS_EVIDENCE",
                    "reason": f"Report '{report.id}' timestamp ({report.created_at}) is earlier than evidence '{ev.id}' collection ({ev.collected_at}).",
                    "severity": "MEDIUM",
                    "expected": f">= {ev.collected_at.isoformat()}",
                    "observed": report.created_at.isoformat()
                })

        return anomalies

    @classmethod
    def scan_case_temporal_integrity(cls, db: Session, case_id: str) -> List[Dict[str, Any]]:
        """Performs comprehensive temporal anomaly detection across all objects in a case."""
        anomalies = []

        # Tasks
        tasks = db.query(Task).filter(Task.case_id == case_id).all()
        for t in tasks:
            anomalies.extend(cls.verify_task_temporal_causality(t))

        # Playbooks
        playbooks = db.query(Playbook).filter(Playbook.case_id == case_id).all()
        for pb in playbooks:
            anomalies.extend(cls.verify_playbook_temporal_causality(pb))

        # Reports
        reports = db.query(Report).filter(Report.case_id == case_id).all()
        for rep in reports:
            anomalies.extend(cls.verify_report_temporal_causality(db, rep))

        return anomalies

    @classmethod
    def check_temporal_ordering(cls, t_earlier: datetime, t_later: datetime) -> Dict[str, Any]:
        """Checks temporal causality between two timestamps for anomalies."""
        from datetime import timezone, timedelta
        now = datetime.now(timezone.utc)
        if t_later.tzinfo is None:
            t_later_cmp = t_later.replace(tzinfo=timezone.utc)
        else:
            t_later_cmp = t_later

        # Check if t_later is far in the future
        if t_later_cmp > now + timedelta(minutes=5):
            return {
                "is_anomaly": True,
                "anomaly_type": "FUTURE_TIMESTAMP",
                "reason": f"Observed timestamp {t_later} is in the future relative to current server time."
            }

        if t_later < t_earlier:
            return {
                "is_anomaly": True,
                "anomaly_type": "BACKWARD_TIME_DRIFT",
                "reason": f"Observed timestamp {t_later} precedes antecedent timestamp {t_earlier}."
            }

        return {
            "is_anomaly": False,
            "anomaly_type": None,
            "reason": "Timestamps are chronologically consistent."
        }
