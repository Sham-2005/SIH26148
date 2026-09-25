"""
Finding Generation & Lifecycle Engine
Converts correlated evidence into analyst-reviewable investigative findings.
Every finding is strictly traceable to underlying Evidence IDs.
Supports lifecycle states: OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import Evidence, EvidenceCorrelation, Finding
from backend.app.services.risk_service import RiskService

class FindingService:
    @classmethod
    def generate_findings_for_case(cls, case_id: str, db: Session) -> List[Finding]:
        """Synthesizes high-confidence findings from correlations and evidence for a case."""
        correlations = db.query(EvidenceCorrelation).filter(EvidenceCorrelation.case_id == case_id).all()
        evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()

        findings: List[Finding] = []
        now = datetime.now(timezone.utc)

        seen_finding_ids = set()

        # 1. Generate Findings from Correlations
        for corr in correlations:
            finding_id = f"FND-{corr.id.replace('CORR-', '')}"
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)

            existing = db.query(Finding).filter(
                Finding.case_id == case_id,
                Finding.id == finding_id
            ).first()

            ev_ids = corr.evidence_ids or []
            agents = corr.related_agent_ids or ([corr.primary_agent_id] if corr.primary_agent_id else [])

            has_persist = corr.correlation_type == "PERSISTENCE_EXECUTABLE_LINK"
            has_net = corr.correlation_type == "PROCESS_NETWORK_OUTBOUND"
            cross_count = len(agents)

            priority, score, reasons = RiskService.evaluate_risk(
                evidence_count=len(ev_ids),
                has_persistence=has_persist,
                has_network_connection=has_net,
                cross_agent_count=cross_count
            )

            if existing:
                existing.priority = priority
                existing.priority_score = score
                existing.priority_reasons = reasons
                existing.updated_at = now
                findings.append(existing)
            else:
                new_finding = Finding(
                    id=finding_id,
                    case_id=case_id,
                    title=f"Investigative Finding: {corr.title}",
                    description=corr.description,
                    reason=f"Correlated via {corr.correlation_type} across {len(agents)} endpoint(s).",
                    status="OPEN",
                    priority=priority,
                    priority_score=score,
                    priority_reasons=reasons,
                    related_agents=agents,
                    evidence_ids=ev_ids,
                    created_at=now,
                    updated_at=now
                )
                db.add(new_finding)
                findings.append(new_finding)

        # 2. Generate Findings for any Persistence evidence items not yet correlated
        persist_evs = [ev for ev in evidence_items if "persistence" in ev.collector]
        for pev in persist_evs:
            pev_suffix = pev.id.split("-")[-1]
            finding_id = f"FND-PERSIST-{pev.agent_id}-{pev_suffix}"
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)

            existing = db.query(Finding).filter(Finding.id == finding_id).first()
            if not existing:
                priority, score, reasons = RiskService.evaluate_risk(
                    evidence_count=1,
                    has_persistence=True,
                    cross_agent_count=1
                )
                new_fnd = Finding(
                    id=finding_id,
                    case_id=case_id,
                    title=f"Persistence Mechanism Identified on {pev.agent_id}",
                    description=f"Defensive persistence collector ({pev.collector}) identified startup or daemon registrations on {pev.agent_id}.",
                    reason=f"Defensive forensic scan discovered persistence artifact in evidence {pev.id}.",
                    status="OPEN",
                    priority=priority,
                    priority_score=score,
                    priority_reasons=reasons,
                    related_agents=[pev.agent_id],
                    evidence_ids=[pev.id],
                    created_at=now,
                    updated_at=now
                )
                db.add(new_fnd)
                findings.append(new_fnd)
            else:
                findings.append(existing)

        db.commit()
        return findings

    @classmethod
    def update_finding_status(cls, finding_id: str, new_status: str, db: Session) -> Optional[Finding]:
        """Updates finding lifecycle status (OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED)."""
        valid_statuses = {"OPEN", "UNDER_REVIEW", "CONFIRMED", "DISMISSED"}
        if new_status.upper() not in valid_statuses:
            raise ValueError(f"Invalid finding status '{new_status}'. Allowed: {valid_statuses}")

        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if finding:
            finding.status = new_status.upper()
            finding.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(finding)
        return finding
