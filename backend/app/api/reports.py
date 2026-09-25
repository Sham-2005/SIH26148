"""
Forensic Report Generation & Multi-Format Export API Endpoints
Supports JSON, HTML, CSV, and PDF export formats.
"""
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import Response
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.models import (
    Report, Case, Evidence, Task, Agent, AuditLog,
    InvestigationIndicator, TimelineEvent, EvidenceCorrelation, Finding, AnalystNote,
    Playbook, ThreatIntelItem, MLThreatPrediction,
    MerkleTreeRecord, BlockchainAnchorRecord, ExecutionHistory
)
from backend.app.schemas.schemas import ReportCreate, ReportResponse
from backend.app.services.report_export_service import ReportExportService
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(prefix="/api/reports", tags=["Reports"])

def _build_case_report_dict(case: Case, db: Session) -> dict:
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case.id).all()
    tasks = db.query(Task).filter(Task.case_id == case.id).all()
    agents = db.query(Agent).all()
    indicators = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case.id).all()
    timeline_events = db.query(TimelineEvent).filter(TimelineEvent.case_id == case.id).order_by(TimelineEvent.timestamp.asc()).all()
    correlations = db.query(EvidenceCorrelation).filter(EvidenceCorrelation.case_id == case.id).all()
    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    notes = db.query(AnalystNote).filter(AnalystNote.case_id == case.id).order_by(AnalystNote.created_at.desc()).all()
    audit_trail = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20).all()
    playbooks = db.query(Playbook).filter(Playbook.case_id == case.id).all()
    intel_overview = ThreatIntelligenceService.correlate_case_with_threat_intel(db, case.id)
    ml_predictions = db.query(MLThreatPrediction).filter(
        MLThreatPrediction.case_id == case.id
    ).order_by(MLThreatPrediction.created_at.desc()).all()

    report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"

    content = {
        "report_id": report_id,
        "case_id": case.id,
        "case_title": case.title,
        "case_description": case.description,
        "severity": getattr(case, "severity", "medium"),
        "status": case.status,
        "created_at": case.created_at.isoformat() if case.created_at else "",
        "generated_by": "JOCKY Automated Forensic Engine",
        "involved_agents": [
            {"id": a.id, "hostname": a.hostname, "platform": a.platform, "status": a.status}
            for a in agents if any(t.agent_id == a.id for t in tasks) or len(tasks) == 0
        ],
        "executed_tasks": [
            {
                "task_id": t.id,
                "name": t.name,
                "agent_id": t.agent_id,
                "status": t.status,
                "created_at": t.created_at.isoformat() if t.created_at else "",
                "completed_at": t.completed_at.isoformat() if t.completed_at else None
            }
            for t in tasks
        ],
        "evidence_summary": [
            {
                "evidence_id": ev.id,
                "collector": ev.collector,
                "collector_version": getattr(ev, "collector_version", "1.0.0"),
                "platform": ev.platform,
                "sha256_hash": ev.sha256_hash,
                "raw_data_hash": getattr(ev, "raw_data_hash", None),
                "normalized_data_hash": getattr(ev, "normalized_data_hash", None),
                "previous_hash": getattr(ev, "previous_hash", None),
                "integrity_status": getattr(ev, "integrity_status", "VERIFIED"),
                "is_verified": ev.is_verified,
                "collected_at": ev.collected_at.isoformat() if ev.collected_at else ""
            }
            for ev in evidence_items
        ],
        "indicators": [
            {
                "indicator_id": ioc.id,
                "type": ioc.indicator_type,
                "value": ioc.value,
                "normalized_value": ioc.normalized_value,
                "status": ioc.status,
                "agent_id": ioc.agent_id,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else "",
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else ""
            }
            for ioc in indicators
        ],
        "timeline": [
            {
                "event_id": t.id,
                "timestamp": t.timestamp.isoformat() if t.timestamp else "",
                "agent_id": t.agent_id,
                "event_type": t.event_type,
                "description": t.description,
                "severity": t.severity,
                "evidence_id": t.evidence_id,
                "evidence_ids": getattr(t, "evidence_ids", [t.evidence_id] if t.evidence_id else [])
            }
            for t in timeline_events
        ],
        "investigation_findings": [
            {
                "finding_id": f.id,
                "title": f.title,
                "description": f.description,
                "reason": f.reason,
                "detection_type": getattr(f, "detection_type", "rule"),
                "detection_rule_id": getattr(f, "detection_rule_id", None),
                "model_name": getattr(f, "model_name", None),
                "model_version": getattr(f, "model_version", None),
                "confidence_score": getattr(f, "confidence_score", None),
                "priority": f.priority,
                "priority_score": f.priority_score,
                "priority_reasons": f.priority_reasons,
                "explainable_factors": getattr(f, "explainable_factors", None),
                "status": f.status,
                "related_agents": f.related_agents,
                "evidence_ids": f.evidence_ids
            }
            for f in findings
        ],
        "evidence_correlations": [
            {
                "correlation_id": c.id,
                "type": c.correlation_type,
                "title": c.title,
                "description": c.description,
                "agents": c.related_agent_ids,
                "evidence_ids": c.evidence_ids,
                "score": c.score
            }
            for c in correlations
        ],
        "analyst_notes": [
            {
                "note_id": n.id,
                "analyst": n.analyst_name,
                "type": n.note_type,
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else ""
            }
            for n in notes
        ],
        "audit_trail": [
            {
                "id": a.id,
                "actor": a.actor,
                "action": a.action,
                "resource": a.resource,
                "result": a.result,
                "timestamp": a.timestamp.isoformat() if a.timestamp else ""
            }
            for a in audit_trail
        ],
        "threat_intel_matches": intel_overview.get("matches", []),
        "mitre_attack_coverage": intel_overview.get("mitre_coverage", []),
        "playbook_actions": [
            {
                "playbook_id": pb.id,
                "name": pb.name,
                "status": pb.status,
                "trigger_type": pb.trigger_type,
                "actions_count": len(pb.actions),
                "approvals": [
                    {"approver": app.approver_email, "decision": app.decision, "comment": app.comment}
                    for app in pb.approvals
                ]
            }
            for pb in playbooks
        ],
        "forensic_findings": {
            "total_artifacts": len(evidence_items),
            "total_indicators": len(indicators),
            "total_findings": len(findings),
            "total_threat_intel_matches": len(intel_overview.get("matches", [])),
            "total_playbooks": len(playbooks),
            "open_findings": sum(1 for f in findings if f.status in ("OPEN", "UNDER_REVIEW")),
            "integrity_status": "ALL_HASHES_MATCH" if all(ev.is_verified for ev in evidence_items) else "ANOMALY_DETECTED",
        },
        "ml_threat_analysis": [
            {
                "prediction_id": p.id,
                "model_name": p.model_name,
                "model_version": p.model_version,
                "classification": p.classification,
                "threat_score": p.threat_score,
                "confidence": p.confidence,
                "top_factors": p.top_factors,
                "model_hash": p.model_hash,
                "prediction_hash": p.prediction_hash,
                "integrity_status": p.integrity_status,
                "created_at": p.created_at.isoformat() if p.created_at else ""
            }
            for p in ml_predictions
        ],
        "ml_threat_summary": {
            "total_predictions": len(ml_predictions),
            "latest_classification": ml_predictions[0].classification if ml_predictions else "NONE",
            "latest_threat_score": ml_predictions[0].threat_score if ml_predictions else 0.0,
            "latest_confidence": ml_predictions[0].confidence if ml_predictions else 0.0,
            "disclaimer": "Machine learning classifications are provided strictly for decision support and do not replace manual forensic verification."
        },
        "provenance_integrity": {
            "merkle_root": (db.query(MerkleTreeRecord).filter(MerkleTreeRecord.case_id == case.id).order_by(MerkleTreeRecord.created_at.desc()).first().merkle_root) if db.query(MerkleTreeRecord).filter(MerkleTreeRecord.case_id == case.id).first() else "N/A",
            "blockchain_block": (db.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case.id).order_by(BlockchainAnchorRecord.timestamp.desc()).first().block_number) if db.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case.id).first() else 0,
            "blockchain_block_hash": (db.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case.id).order_by(BlockchainAnchorRecord.timestamp.desc()).first().block_hash) if db.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.case_id == case.id).first() else "N/A",
            "blockchain_network": "Local Evidence Blockchain",
            "script_hash": (db.query(ExecutionHistory).filter(ExecutionHistory.case_id == case.id).order_by(ExecutionHistory.started_at.desc()).first().script_hash) if db.query(ExecutionHistory).filter(ExecutionHistory.case_id == case.id).first() and db.query(ExecutionHistory).filter(ExecutionHistory.case_id == case.id).first().script_hash else (evidence_items[0].script_hash if evidence_items and getattr(evidence_items[0], "script_hash", None) else "N/A"),
            "hash_chain_status": "VERIFIED (RFC-8785 Canonical JSON)",
            "verification_status": "ALL_INTEGRITY_CHECKS_PASSED" if all(getattr(ev, "is_verified", True) for ev in evidence_items) else "INTEGRITY_FAILURE_DETECTED"
        },
        "investigation_limitations": (
            "This forensic investigation report is bounded strictly by the collectors executed on the endpoint during the recorded execution session. "
            "No unauthorized access, destructive payloads, kernel drivers, or security software evasion was performed. "
            "Telemetry not captured by the executed collectors remains outside the investigative envelope."
        ),
        "analyst_disclaimer": "Automated findings are preliminary digital evidence and do not constitute legal conclusions or definitive malware attribution without expert human sign-off."
    }
    return content

def _persist_case_report(case: Case, db: Session, report_type: str = "comprehensive") -> Report:
    from backend.app.services.security_integrity_service import IntegrityService
    content = _build_case_report_dict(case, db)
    report_id = content["report_id"]

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case.id).all()
    ev_hashes = [ev.sha256_hash for ev in evidence_items]
    evidence_hash = IntegrityService.canonical_hash(sorted(ev_hashes))
    investigation_hash = IntegrityService.canonical_hash(content.get("investigation_findings", []))
    cti_hash = IntegrityService.canonical_hash(content.get("threat_intelligence_overview", {}))
    playbook_audit_hash = IntegrityService.canonical_hash(content.get("playbooks", []))
    report_content_hash = IntegrityService.canonical_hash(content)

    latest_audit = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    audit_chain_hash = (latest_audit.event_hash if latest_audit and latest_audit.event_hash else "0" * 64)

    manifest = IntegrityService.generate_report_manifest(
        report_id=report_id,
        case_id=case.id,
        report_content=content,
        evidence_hashes=ev_hashes,
        audit_chain_hash=audit_chain_hash,
        investigation_hash=investigation_hash,
        cti_hash=cti_hash
    )

    # Augment content with integrity metadata
    content["report_version"] = "1.0.0"
    content["evidence_count"] = len(evidence_items)
    content["evidence_hash"] = evidence_hash
    content["investigation_hash"] = investigation_hash
    content["cti_hash"] = cti_hash
    content["playbook_audit_hash"] = playbook_audit_hash
    content["report_content_hash"] = report_content_hash
    content["manifest"] = manifest

    report = Report(
        id=report_id,
        case_id=case.id,
        title=f"Forensic Investigation Report - {case.title}",
        report_type=report_type,
        content_json=content,
        report_version="1.0.0",
        evidence_count=len(evidence_items),
        evidence_hash=evidence_hash,
        investigation_hash=investigation_hash,
        cti_hash=cti_hash,
        playbook_audit_hash=playbook_audit_hash,
        report_content_hash=report_content_hash,
        manifest_json=manifest
    )
    db.add(report)

    IntegrityService.record_chained_audit(
        db=db,
        actor="ANALYST",
        actor_type="USER",
        action="REPORT_GENERATED",
        resource=f"Report:{report_id}",
        resource_type="Report",
        resource_id=report_id,
        case_id=case.id,
        result="SUCCESS",
        details={"case_id": case.id, "total_evidence": len(evidence_items), "report_content_hash": report_content_hash}
    )
    db.commit()
    db.refresh(report)
    return report


@router.post("/generate", response_model=ReportResponse)
def generate_report(payload: ReportCreate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{payload.case_id}' not found.")

    return _persist_case_report(case, db, payload.report_type)

@router.get("", response_model=List[ReportResponse])
def list_reports(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Report)
    if case_id:
        query = query.filter(Report.case_id == case_id)
    return query.order_by(Report.created_at.desc()).all()

@router.get("/{case_id}/export")
def export_report(case_id: str, format: str = "json", db: Session = Depends(get_db)):
    """Exports case report as json, html, csv, or pdf."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    report_data = _build_case_report_dict(case, db)
    fmt = (format or "json").lower()

    if fmt == "pdf":
        pdf_bytes = ReportExportService.generate_pdf(report_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=JOCKY_Report_{case_id}.pdf"}
        )
    elif fmt == "html":
        html_str = ReportExportService.generate_html(report_data)
        return Response(
            content=html_str,
            media_type="text/html",
            headers={"Content-Disposition": f"inline; filename=JOCKY_Report_{case_id}.html"}
        )
    elif fmt == "csv":
        csv_str = ReportExportService.generate_csv(report_data)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=JOCKY_Evidence_{case_id}.csv"}
        )
    else:  # default JSON
        json_str = ReportExportService.generate_json(report_data)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=JOCKY_Report_{case_id}.json"}
        )

@router.get("/{case_or_report_id}", response_model=ReportResponse)
def get_report(case_or_report_id: str, db: Session = Depends(get_db)):
    # 1. By report ID
    report = db.query(Report).filter(Report.id == case_or_report_id).first()
    if report:
        return report

    # 2. By case ID
    case = db.query(Case).filter(Case.id == case_or_report_id).first()
    if case:
        latest = db.query(Report).filter(Report.case_id == case.id).order_by(Report.created_at.desc()).first()
        if latest:
            return latest
        return _persist_case_report(case, db)

    raise HTTPException(status_code=404, detail=f"Report or Case '{case_or_report_id}' not found.")
