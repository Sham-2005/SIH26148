"""
Investigation Orchestrator
Coordinates automated intelligence pipeline:
Evidence Ingestion -> IOC Extraction -> Timeline Assembly -> Correlation -> Finding Synthesis -> WebSocket Broadcast.
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.app.models.models import Evidence, Case
from backend.app.services.ioc_service import IOCService
from backend.app.services.timeline_service import TimelineService
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.finding_service import FindingService
from backend.app.services.event_broadcaster import broadcaster

class InvestigationOrchestrator:
    @classmethod
    def process_evidence(cls, evidence_id: str, db: Session) -> Dict[str, Any]:
        """Runs automated pipeline on newly ingested evidence item."""
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            return {"status": "error", "message": f"Evidence '{evidence_id}' not found"}

        case_id = evidence.case_id

        # 1. IOC Extraction
        iocs = IOCService.extract_from_evidence(evidence, db)

        # 2. Timeline Assembly
        timeline_events = TimelineService.synthesize_events_from_evidence(evidence, db)

        # 3. Correlation Engine
        correlations = CorrelationService.run_case_correlations(case_id, db)

        # 4. Finding Synthesis & Explainable Risk
        findings = FindingService.generate_findings_for_case(case_id, db)

        # 5. Machine Learning Threat Analysis (Decision Support)
        ml_prediction = None
        try:
            from backend.app.ml.threat_detector import ThreatDetectionService
            ml_prediction = ThreatDetectionService.analyze_case(
                case_id=case_id,
                db=db,
                evidence_id=evidence_id,
                agent_id=evidence.agent_id
            )
        except Exception:
            pass

        # 6. Broadcast Real-Time Investigation Update
        broadcaster.broadcast(
            event_type="INVESTIGATION_UPDATED",
            message=f"Investigation for {case_id} updated: {len(iocs)} IOCs, {len(findings)} findings.",
            data={
                "case_id": case_id,
                "new_iocs": len(iocs),
                "new_events": len(timeline_events),
                "correlations_count": len(correlations),
                "findings_count": len(findings),
                "ml_classification": ml_prediction.classification if ml_prediction else None,
                "ml_threat_score": ml_prediction.threat_score if ml_prediction else None
            }
        )

        return {
            "status": "success",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "indicators_extracted": len(iocs),
            "timeline_events_created": len(timeline_events),
            "correlations_detected": len(correlations),
            "findings_count": len(findings),
            "ml_classification": ml_prediction.classification if ml_prediction else None,
            "ml_threat_score": ml_prediction.threat_score if ml_prediction else None
        }

    @classmethod
    def run_full_case_analysis(cls, case_id: str, db: Session) -> Dict[str, Any]:
        """Executes full correlation and analysis pipeline across all evidence in a case."""
        evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()

        total_iocs = 0
        total_events = 0
        for ev in evidence_items:
            iocs = IOCService.extract_from_evidence(ev, db)
            events = TimelineService.synthesize_events_from_evidence(ev, db)
            total_iocs += len(iocs)
            total_events += len(events)

        correlations = CorrelationService.run_case_correlations(case_id, db)
        findings = FindingService.generate_findings_for_case(case_id, db)

        # ML Threat Analysis (Decision Support)
        ml_prediction = None
        try:
            from backend.app.ml.threat_detector import ThreatDetectionService
            ml_prediction = ThreatDetectionService.analyze_case(
                case_id=case_id,
                db=db
            )
        except Exception:
            pass

        broadcaster.broadcast(
            event_type="INVESTIGATION_ANALYZED",
            message=f"Full investigation analysis completed for {case_id}.",
            data={
                "case_id": case_id,
                "correlations": len(correlations),
                "findings": len(findings),
                "ml_classification": ml_prediction.classification if ml_prediction else None,
                "ml_threat_score": ml_prediction.threat_score if ml_prediction else None
            }
        )

        return {
            "case_id": case_id,
            "evidence_analyzed": len(evidence_items),
            "total_indicators": total_iocs,
            "total_timeline_events": total_events,
            "correlations_count": len(correlations),
            "findings_count": len(findings),
            "ml_classification": ml_prediction.classification if ml_prediction else None,
            "ml_threat_score": ml_prediction.threat_score if ml_prediction else None
        }
