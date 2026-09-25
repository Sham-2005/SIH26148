"""
Investigation Management & Threat Correlation REST API Endpoints
Provides endpoints for Timeline, Indicators, Correlations, Findings, Graphs, Search, and Analyst Notes.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.database.session import get_db
from backend.app.models.models import (
    Case, Evidence, InvestigationIndicator, TimelineEvent,
    EvidenceCorrelation, Finding, AnalystNote, AuditLog, Agent,
    MerkleTreeRecord, BlockchainAnchorRecord, CorrelatedIncident,
    ExecutionHistory
)
from backend.app.schemas.schemas import (
    IndicatorResponse, TimelineEventResponse, CorrelationResponse,
    FindingResponse, FindingStatusUpdate, AnalystNoteCreate, AnalystNoteResponse,
    InvestigationSummaryResponse, InvestigationGraphResponse, GraphNode, GraphEdge,
    InvestigationSearchResponse, TimelineHeatmapResponse, AttackPatternResponse,
    EvidenceResponse, MerkleTreeResponse, BlockchainAnchorResponse,
    FindingProvenanceResponse, InvestigationIntegrityVerifyResponse,
    CorrelatedIncidentResponse
)
from backend.app.services.timeline_service import TimelineService
from backend.app.services.finding_service import FindingService
from backend.app.services.investigation_orchestrator import InvestigationOrchestrator
from backend.app.services.provenance_service import ProvenanceService
from backend.app.services.merkle_service import MerkleService
from backend.app.services.blockchain_service import BlockchainService

router = APIRouter(prefix="/api/investigations", tags=["Investigations"])

@router.get("/{case_id}/summary", response_model=InvestigationSummaryResponse)
def get_investigation_summary(case_id: str, db: Session = Depends(get_db)):
    """Provides high-level investigation metrics for SOC command view."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    evidence_count = db.query(Evidence).filter(Evidence.case_id == case_id).count()
    indicators_count = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id).count()
    timeline_count = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).count()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    notes_count = db.query(AnalystNote).filter(AnalystNote.case_id == case_id).count()

    # Determine unique agents involved
    involved_agent_ids = db.query(Evidence.agent_id).filter(Evidence.case_id == case_id).distinct().all()
    agent_count = len(involved_agent_ids) if involved_agent_ids else db.query(Agent).count()

    open_findings = sum(1 for f in findings if f.status in ("OPEN", "UNDER_REVIEW"))

    return InvestigationSummaryResponse(
        case_id=case.id,
        case_title=case.title,
        severity=case.severity,
        status=case.status,
        total_agents=agent_count,
        total_evidence=evidence_count,
        total_indicators=indicators_count,
        total_timeline_events=timeline_count,
        total_findings=len(findings),
        open_findings=open_findings,
        total_notes=notes_count,
        last_updated=datetime.now(timezone.utc).isoformat()
    )

@router.get("/{case_id}/timeline", response_model=List[TimelineEventResponse])
def get_investigation_timeline(
    case_id: str,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves chronological investigation timeline with optional filters."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    return TimelineService.get_timeline(
        case_id=case_id,
        db=db,
        agent_id=agent_id,
        event_type=event_type,
        severity=severity,
        limit=limit
    )

@router.get("/{case_id}/indicators", response_model=List[IndicatorResponse])
def get_investigation_indicators(
    case_id: str,
    type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves normalized IOCs observed in this investigation."""
    query = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id)
    if type:
        query = query.filter(InvestigationIndicator.indicator_type == type.lower())
    if status:
        query = query.filter(InvestigationIndicator.status == status.lower())
    return query.order_by(InvestigationIndicator.last_seen.desc()).all()

@router.get("/{case_id}/correlations", response_model=List[CorrelationResponse])
def get_investigation_correlations(case_id: str, db: Session = Depends(get_db)):
    """Retrieves multi-dimensional evidence correlations."""
    return db.query(EvidenceCorrelation).filter(EvidenceCorrelation.case_id == case_id).order_by(EvidenceCorrelation.detected_at.desc()).all()

@router.get("/{case_id}/findings", response_model=List[FindingResponse])
def get_investigation_findings(
    case_id: str,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves actionable findings for this case."""
    query = db.query(Finding).filter(Finding.case_id == case_id)
    if status:
        query = query.filter(Finding.status == status.upper())
    if priority:
        query = query.filter(Finding.priority == priority.upper())
    return query.order_by(Finding.priority_score.desc()).all()

@router.patch("/{case_id}/findings/{finding_id}", response_model=FindingResponse)
def update_finding_status_endpoint(
    case_id: str,
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    """Updates finding lifecycle status (OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED) with audit logging."""
    try:
        updated = FindingService.update_finding_status(finding_id, payload.status, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    # Audit log
    audit = AuditLog(
        actor="Forensic Analyst",
        actor_type="USER",
        action="UPDATE_FINDING_STATUS",
        resource=f"Finding:{finding_id}",
        resource_id=finding_id,
        result="SUCCESS",
        details={"case_id": case_id, "new_status": payload.status}
    )
    db.add(audit)
    db.commit()

    return updated

@router.get("/{case_id}/graph", response_model=InvestigationGraphResponse)
def get_investigation_graph(case_id: str, db: Session = Depends(get_db)):
    """Generates node-edge relationship topology for visual correlation in SOC UI."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    indicators = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id).all()
    correlations = db.query(EvidenceCorrelation).filter(EvidenceCorrelation.case_id == case_id).all()

    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    # 1. Add Evidence and Agents
    for ev in evidence_items:
        agent_node_id = f"agent:{ev.agent_id}"
        if agent_node_id not in nodes:
            nodes[agent_node_id] = GraphNode(
                id=agent_node_id,
                label=ev.agent_id,
                type="agent",
                data={"platform": ev.platform}
            )

        ev_node_id = f"ev:{ev.id}"
        if ev_node_id not in nodes:
            nodes[ev_node_id] = GraphNode(
                id=ev_node_id,
                label=f"{ev.collector}",
                type="evidence",
                data={"sha256": ev.sha256_hash[:12]}
            )
            edges.append(GraphEdge(source=agent_node_id, target=ev_node_id, label="collected"))

    # 2. Add Indicator Nodes
    for ioc in indicators:
        ioc_node_id = f"ioc:{ioc.indicator_type}:{ioc.normalized_value[:32]}"
        if ioc_node_id not in nodes:
            nodes[ioc_node_id] = GraphNode(
                id=ioc_node_id,
                label=ioc.value if len(ioc.value) < 28 else ioc.value[:25] + "...",
                type=ioc.indicator_type,
                data={"status": ioc.status, "type": ioc.indicator_type}
            )

        if ioc.source_evidence_id:
            ev_node_id = f"ev:{ioc.source_evidence_id}"
            if ev_node_id in nodes:
                edges.append(GraphEdge(source=ev_node_id, target=ioc_node_id, label="contains"))

    # 3. Add Cross-Agent Correlation Edges
    for corr in correlations:
        if corr.correlation_type == "SAME_HASH_CROSS_AGENT" and corr.related_agent_ids:
            # Connect all related agents
            for a_id in corr.related_agent_ids:
                a_node = f"agent:{a_id}"
                if corr.indicators:
                    h_val = corr.indicators[0]
                    h_node = f"ioc:sha256:{h_val[:32]}"
                    if a_node in nodes and h_node in nodes:
                        edges.append(GraphEdge(source=a_node, target=h_node, label="shared_hash"))

    return InvestigationGraphResponse(
        case_id=case_id,
        nodes=list(nodes.values()),
        edges=edges
    )

@router.get("/{case_id}/search", response_model=InvestigationSearchResponse)
def search_investigation(
    case_id: str,
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db)
):
    """
    Unified search across indicators, findings, timeline events, and evidence.
    Supports prefixes: 'process:', 'hash:', 'ip:', 'agent:', 'type:'.
    """
    term = q.strip()
    prefix = ""
    clean_val = term

    if ":" in term:
        parts = term.split(":", 1)
        prefix = parts[0].lower()
        clean_val = parts[1].strip()

    # 1. Search Indicators
    ioc_query = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id)
    if prefix in ("ip", "ipv4"):
        ioc_query = ioc_query.filter(InvestigationIndicator.indicator_type.in_(["ipv4", "ipv6"]), InvestigationIndicator.normalized_value.contains(clean_val))
    elif prefix == "hash":
        ioc_query = ioc_query.filter(InvestigationIndicator.indicator_type.in_(["sha256", "md5"]), InvestigationIndicator.normalized_value.contains(clean_val.lower()))
    elif prefix == "process":
        ioc_query = ioc_query.filter(InvestigationIndicator.indicator_type == "process_name", InvestigationIndicator.normalized_value.contains(clean_val.lower()))
    elif prefix == "agent":
        ioc_query = ioc_query.filter(InvestigationIndicator.agent_id.contains(clean_val))
    else:
        ioc_query = ioc_query.filter(
            or_(
                InvestigationIndicator.value.contains(clean_val),
                InvestigationIndicator.normalized_value.contains(clean_val.lower())
            )
        )
    matched_iocs = ioc_query.limit(50).all()

    # 2. Search Findings
    fnd_query = db.query(Finding).filter(Finding.case_id == case_id)
    if prefix == "agent":
        fnd_query = fnd_query.filter(Finding.related_agents.contains(clean_val))
    else:
        fnd_query = fnd_query.filter(
            or_(
                Finding.title.contains(clean_val),
                Finding.description.contains(clean_val),
                Finding.reason.contains(clean_val)
            )
        )
    matched_fnds = fnd_query.limit(20).all()

    # 3. Search Timeline Events
    tle_query = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id)
    if prefix == "agent":
        tle_query = tle_query.filter(TimelineEvent.agent_id.contains(clean_val))
    elif prefix == "type":
        tle_query = tle_query.filter(TimelineEvent.event_type.contains(clean_val.upper()))
    else:
        tle_query = tle_query.filter(TimelineEvent.description.contains(clean_val))
    matched_tles = tle_query.limit(30).all()

    # 4. Search Evidence IDs
    ev_query = db.query(Evidence.id).filter(Evidence.case_id == case_id)
    if prefix == "agent":
        ev_query = ev_query.filter(Evidence.agent_id.contains(clean_val))
    elif prefix == "hash":
        ev_query = ev_query.filter(Evidence.sha256_hash.contains(clean_val.lower()))
    else:
        ev_query = ev_query.filter(
            or_(
                Evidence.id.contains(clean_val),
                Evidence.agent_id.contains(clean_val),
                Evidence.collector.contains(clean_val),
                Evidence.sha256_hash.contains(clean_val.lower())
            )
        )
    matched_ev_ids = [e[0] for e in ev_query.limit(20).all()]

    return InvestigationSearchResponse(
        case_id=case_id,
        query=q,
        matching_indicators=matched_iocs,
        matching_findings=matched_fnds,
        matching_timeline_events=matched_tles,
        matching_evidence_ids=matched_ev_ids
    )

@router.post("/{case_id}/notes", response_model=AnalystNoteResponse, status_code=status.HTTP_201_CREATED)
def add_analyst_note(
    case_id: str,
    payload: AnalystNoteCreate,
    db: Session = Depends(get_db)
):
    """Appends an analyst note (observation, hypothesis, conclusion) to the case with audit logging."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    note_id = f"NOTE-{uuid.uuid4().hex[:8].upper()}"
    note = AnalystNote(
        id=note_id,
        case_id=case_id,
        analyst_name=payload.analyst_name or "Forensic Analyst",
        note_type=payload.note_type or "investigation_note",
        content=payload.content,
        created_at=datetime.now(timezone.utc)
    )
    db.add(note)

    audit = AuditLog(
        actor=payload.analyst_name or "Forensic Analyst",
        actor_type="USER",
        action="ADD_ANALYST_NOTE",
        resource=f"AnalystNote:{note_id}",
        resource_id=note_id,
        result="SUCCESS",
        details={"case_id": case_id, "note_type": note.note_type}
    )
    db.add(audit)
    db.commit()
    db.refresh(note)

    return note

@router.get("/{case_id}/notes", response_model=List[AnalystNoteResponse])
def list_analyst_notes(case_id: str, db: Session = Depends(get_db)):
    """Retrieves all analyst notes for the specified investigation."""
    return db.query(AnalystNote).filter(AnalystNote.case_id == case_id).order_by(AnalystNote.created_at.desc()).all()

@router.post("/{case_id}/analyze")
def trigger_case_analysis(case_id: str, db: Session = Depends(get_db)):
    """Triggers on-demand execution of IOC extraction, timeline, correlation, and finding synthesis."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    result = InvestigationOrchestrator.run_full_case_analysis(case_id, db)
    return {"status": "success", "analysis": result}


@router.get("/{case_id}/heatmap", response_model=TimelineHeatmapResponse)
def get_investigation_heatmap(case_id: str, db: Session = Depends(get_db)):
    """Aggregates timeline events into time buckets for temporal heatmap visualization."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    events = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).order_by(TimelineEvent.timestamp.asc()).all()
    if not events:
        return TimelineHeatmapResponse(case_id=case_id, buckets=[], peak_bucket=None, total_events=0)

    bucket_map: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        ts_str = ev.timestamp.strftime("%Y-%m-%d %H:00") if ev.timestamp else "UNKNOWN"
        if ts_str not in bucket_map:
            bucket_map[ts_str] = {
                "bucket": ts_str,
                "count": 0,
                "severities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "event_types": {}
            }
        b = bucket_map[ts_str]
        b["count"] += 1
        sev = (ev.severity or "INFO").upper()
        b["severities"][sev] = b["severities"].get(sev, 0) + 1
        etype = ev.event_type or "OTHER"
        b["event_types"][etype] = b["event_types"].get(etype, 0) + 1

    sorted_buckets = sorted(bucket_map.values(), key=lambda x: x["bucket"])
    peak = max(sorted_buckets, key=lambda x: x["count"]) if sorted_buckets else None

    return TimelineHeatmapResponse(
        case_id=case_id,
        buckets=sorted_buckets,
        peak_bucket=peak["bucket"] if peak else None,
        total_events=len(events)
    )


@router.get("/{case_id}/attack-patterns", response_model=AttackPatternResponse)
def get_investigation_attack_patterns(case_id: str, db: Session = Depends(get_db)):
    """Maps observed timeline events, findings, and indicators to MITRE ATT&CK techniques and tactics."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    ATTACK_CATALOG = {
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "keywords": ["powershell", "cmd.exe", "bash", "sh", "python", "script", "shell"],
            "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
        },
        "T1547": {
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "keywords": ["run", "runonce", "startup", "init.d", "systemd", "registry", "autostart"],
            "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon."
        },
        "T1053": {
            "name": "Scheduled Task/Job",
            "tactic": "Persistence & Execution",
            "keywords": ["schtasks", "cron", "crontab", "at", "task", "scheduled"],
            "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code."
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "keywords": ["http", "https", "dns", "c2", "beacon", "outbound", "port 443", "port 80"],
            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic."
        },
        "T1082": {
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "keywords": ["system", "whoami", "hostname", "uname", "ipconfig", "ifconfig"],
            "description": "An adversary may attempt to get detailed information about the operating system and hardware."
        },
        "T1036": {
            "name": "Masquerading",
            "tactic": "Defense Evasion",
            "keywords": ["svchost", "disguised", "hidden", "masquerad", "mimic"],
            "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate to users or security tools."
        }
    }

    events = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    indicators = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id).all()

    patterns_output = []

    for tech_id, meta in ATTACK_CATALOG.items():
        matched_events = 0
        matched_indicators = []
        sample_descriptions = []

        for ev in events:
            text = f"{ev.description} {ev.event_type} {str(ev.details)}".lower()
            if any(k in text for k in meta["keywords"]):
                matched_events += 1
                if len(sample_descriptions) < 3:
                    sample_descriptions.append(ev.description)

        for f in findings:
            text = f"{f.title} {f.description} {str(f.reason)}".lower()
            if any(k in text for k in meta["keywords"]):
                matched_events += 1
                if len(sample_descriptions) < 3:
                    sample_descriptions.append(f.title)

        for ind in indicators:
            norm = ind.normalized_value.lower()
            if any(k in norm for k in meta["keywords"]):
                matched_indicators.append(ind.value)

        patterns_output.append({
            "technique_id": tech_id,
            "technique_name": meta["name"],
            "tactic": meta["tactic"],
            "description": meta["description"],
            "matched_count": matched_events + len(matched_indicators),
            "matched_events": matched_events,
            "sample_descriptions": sample_descriptions,
            "matched_indicators": list(dict.fromkeys(matched_indicators))[:5]
        })

    return AttackPatternResponse(
        case_id=case_id,
        patterns=patterns_output
    )


# ============================================================================
# PHASE 27 — Evidence Provenance, Traceability, Merkle & Integrity Endpoints
# ============================================================================

@router.get("/{case_id}/evidence", response_model=List[EvidenceResponse])
def get_investigation_evidence(
    case_id: str,
    collector: Optional[str] = None,
    platform: Optional[str] = None,
    integrity: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Retrieves canonical evidence envelopes for the specified investigation.
    Supports filtering by collector, platform, and integrity status.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if collector:
        query = query.filter(Evidence.collector == collector.lower())
    if platform:
        query = query.filter(Evidence.platform == platform)
    if integrity:
        query = query.filter(Evidence.integrity_status == integrity.upper())

    return query.order_by(Evidence.collected_at.asc()).limit(limit).all()


@router.get("/{case_id}/evidence/{evidence_id}", response_model=EvidenceResponse)
def get_single_evidence_item(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """
    Retrieves a single canonical evidence item including raw evidence,
    normalized evidence, collector provenance, and cryptographic hashes.
    """
    ev = db.query(Evidence).filter(
        Evidence.case_id == case_id,
        Evidence.id == evidence_id
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence item '{evidence_id}' not found in case '{case_id}'.")
    return ev


@router.get("/{case_id}/provenance/{finding_id}", response_model=FindingProvenanceResponse)
def get_finding_provenance(
    case_id: str,
    finding_id: str,
    db: Session = Depends(get_db)
):
    """
    Vertical forensic traceability resolver.
    Navigates: Finding -> Supporting Evidence -> Raw Evidence -> Collector -> Execution -> Script -> Merkle Root -> Blockchain Anchor.
    """
    provenance = ProvenanceService.get_finding_provenance(case_id, finding_id, db)
    if not provenance:
        raise HTTPException(status_code=404, detail=f"Provenance chain could not be resolved for finding '{finding_id}'.")
    return provenance


@router.get("/{case_id}/integrity", response_model=InvestigationIntegrityVerifyResponse)
def get_investigation_integrity(case_id: str, db: Session = Depends(get_db)):
    """
    Returns current cryptographic integrity status, Merkle root, and Blockchain anchor status.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    verification_result = ProvenanceService.verify_investigation_integrity(case_id, db)
    return verification_result


@router.post("/{case_id}/integrity/verify", response_model=InvestigationIntegrityVerifyResponse)
def verify_investigation_integrity_endpoint(case_id: str, db: Session = Depends(get_db)):
    """
    Active cryptographic verification engine.
    Audits raw hashes, normalized hashes, evidence hash chain, Merkle root, blockchain anchor, and script hash.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    result = ProvenanceService.verify_investigation_integrity(case_id, db)

    # Record verification in audit log
    audit = AuditLog(
        actor="System Verifier",
        actor_type="SYSTEM",
        action="INTEGRITY_VERIFICATION",
        resource=f"Case:{case_id}",
        resource_id=case_id,
        result="SUCCESS" if result["valid"] else "FAILURE",
        details={
            "valid": result["valid"],
            "evidence_total": result["evidence"]["total"],
            "evidence_verified": result["evidence"]["verified"],
            "hash_chain_valid": result["hash_chain"]["valid"],
            "merkle_valid": result["merkle"]["valid"],
            "blockchain_anchored": result["blockchain"]["anchored"],
            "blockchain_valid": result["blockchain"]["valid"]
        }
    )
    db.add(audit)
    db.commit()

    return result


@router.post("/{case_id}/integrity/tamper-demo")
def tamper_investigation_demo(
    case_id: str,
    evidence_id: Optional[str] = None,
    tamper_field: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db)
):
    """
    Controlled tampering simulator for SIH demonstration.
    Modifies an evidence record in place and records backup state for restoration.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    eff_field = tamper_field
    eff_eid = evidence_id
    if payload:
        eff_field = payload.get("tamper_type") or payload.get("tamper_field") or eff_field
        eff_eid = payload.get("evidence_id") or eff_eid

    eff_field = eff_field or "data"

    res = ProvenanceService.tamper_evidence(case_id, evidence_id=eff_eid, tamper_field=eff_field, db=db)
    
    # Run active verification immediately so caller gets the updated verification outcome
    audit_res = ProvenanceService.verify_investigation_integrity(case_id, db)
    audit_res["status"] = res.get("status", "TAMPERED")
    audit_res["tamper_action"] = res
    audit_res["scenario"] = eff_field
    return audit_res


@router.post("/{case_id}/integrity/restore-demo")
def restore_investigation_demo(case_id: str, db: Session = Depends(get_db)):
    """
    Restores tampered evidence records back to their authenticated cryptographic state.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    res = ProvenanceService.restore_evidence(case_id, db=db)
    audit_res = ProvenanceService.verify_investigation_integrity(case_id, db)
    audit_res["status"] = res.get("status", "RESTORED")
    audit_res["restore_action"] = res
    return audit_res


@router.get("/{case_id}/merkle", response_model=Optional[MerkleTreeResponse])
def get_case_merkle_tree(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieves the Merkle tree record (root, count, leaf hashes, full tree structure) for an investigation.
    """
    record = MerkleService.get_case_merkle_tree(case_id, db)
    if not record:
        raise HTTPException(status_code=404, detail=f"No Merkle tree record found for case '{case_id}'.")
    return record


@router.get("/{case_id}/merkle/proof")
def get_evidence_merkle_proof(
    case_id: str,
    evidence_id: str = Query(..., description="ID of the evidence item to generate proof for"),
    db: Session = Depends(get_db)
):
    """
    Generates a cryptographic Merkle audit proof for a single evidence item and verifies it.
    """
    ev = db.query(Evidence).filter(Evidence.case_id == case_id, Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found in case '{case_id}'.")

    target_hash = ev.sha256_hash
    proof_data = MerkleService.generate_merkle_proof(case_id, target_hash, db)
    if not proof_data:
        raise HTTPException(status_code=400, detail=f"Could not compute Merkle proof for evidence '{evidence_id}'.")

    is_valid = MerkleService.verify_merkle_proof(
        leaf_hash=target_hash,
        proof=proof_data["proof"],
        expected_root=proof_data["merkle_root"]
    )

    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "leaf_hash": target_hash,
        "leaf_index": proof_data["leaf_index"],
        "merkle_root": proof_data["merkle_root"],
        "proof_steps": proof_data["proof"],
        "is_verified": is_valid
    }


@router.get("/{case_id}/blockchain", response_model=List[BlockchainAnchorResponse])
def get_case_blockchain_anchors(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieves the Local Evidence Blockchain anchor blocks for the specified case.
    """
    anchors = BlockchainService.get_case_anchors(case_id, db)
    return anchors


@router.get("/{case_id}/incidents", response_model=List[CorrelatedIncidentResponse])
def get_correlated_incidents(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieves correlated incident clusters that group multi-source evidence across time.
    """
    incidents = db.query(CorrelatedIncident).filter(CorrelatedIncident.case_id == case_id).order_by(CorrelatedIncident.created_at.desc()).all()
    return incidents


@router.post("/{case_id}/execute-provenance-demo")
def execute_provenance_demo(case_id: str, db: Session = Depends(get_db)):
    """
    Populates full Phase 27 deterministic investigation state:
    28 canonical evidence records across 5 collectors, 4 findings with ML/rule attribution,
    10 timeline events, Merkle tree, and Local Evidence Blockchain anchor.
    """
    result = ProvenanceService.run_deterministic_investigation(case_id, db=db)
    return result


