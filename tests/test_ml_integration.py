"""
Test Suite: End-to-End ML Integration & Multi-Format Report Verification
Validates end-to-end integration between Evidence Ingestion -> Investigation Orchestrator
-> Automated ML Threat Detection -> Cryptographic Verification -> Multi-Format Reports (JSON, HTML, PDF, CSV),
and JOCKY DSL stdlib registry primitives.
"""
import pytest
from datetime import datetime, timezone
from backend.app.database.session import SessionLocal, engine
from backend.app.database.base import Base
from backend.app.models.models import Case, Evidence, MLThreatPrediction, Finding
from backend.app.services.investigation_orchestrator import InvestigationOrchestrator
from backend.app.services.report_export_service import ReportExportService
from backend.app.api.reports import _build_case_report_dict
from language.stdlib.stdlib_registry import is_stdlib_function, get_stdlib_spec


@pytest.fixture(scope="module", autouse=True)
def setup_integration_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    case = db.query(Case).filter(Case.id == "CASE-INTEG-E2E").first()
    if not case:
        case = Case(
            id="CASE-INTEG-E2E",
            title="End-to-End ML Integration Case",
            description="Testing automated ML detection across pipeline and report generation",
            severity="critical",
            status="INVESTIGATING"
        )
        db.add(case)
        db.commit()

    ev = Evidence(
        id="EV-INTEG-E2E-01",
        case_id="CASE-INTEG-E2E",
        agent_id="AGENT-WIN-01",
        collector="process.list",
        platform="windows",
        envelope_data={
            "processes": [
                {"pid": 401, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe"},
                {"pid": 402, "name": "procdump.exe", "path": "C:\\Temp\\procdump.exe"}
            ]
        },
        sha256_hash="0" * 64,
        is_verified=True
    )
    if not db.query(Evidence).filter(Evidence.id == ev.id).first():
        db.add(ev)
    db.commit()
    db.close()


def test_investigation_orchestrator_triggers_ml():
    """Validates that InvestigationOrchestrator automatically invokes ML threat detection."""
    db = SessionLocal()
    try:
        result = InvestigationOrchestrator.process_evidence("EV-INTEG-E2E-01", db)
        assert result["status"] == "success"
        assert "ml_classification" in result
        assert "ml_threat_score" in result

        # Check ML prediction was created
        preds = db.query(MLThreatPrediction).filter(
            MLThreatPrediction.case_id == "CASE-INTEG-E2E"
        ).all()
        assert len(preds) >= 1
        assert preds[0].integrity_status == "VERIFIED"
    finally:
        db.close()


def test_report_export_includes_ml_section():
    """Validates that multi-format reports include ML threat detection section."""
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == "CASE-INTEG-E2E").first()
        report_data = _build_case_report_dict(case, db)

        # 1. JSON Report
        assert "ml_threat_analysis" in report_data
        assert "ml_threat_summary" in report_data
        json_str = ReportExportService.generate_json(report_data)
        assert "ml_threat_analysis" in json_str

        # 2. CSV Report
        csv_str = ReportExportService.generate_csv(report_data)
        assert "=== MACHINE LEARNING THREAT PREDICTIONS ===" in csv_str

        # 3. HTML Report
        html_str = ReportExportService.generate_html(report_data)
        assert "Machine Learning Threat Analysis" in html_str

        # 4. PDF Report
        pdf_bytes = ReportExportService.generate_pdf(report_data)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()


def test_stdlib_ml_primitives_registered():
    """Validates that JOCKY DSL stdlib registry includes all 6 Level 3 ML primitives."""
    ml_primitives = [
        "ml.analyze",
        "ml.prediction",
        "ml.score",
        "ml.explain",
        "ml.verify",
        "ml.model_status"
    ]
    for prim in ml_primitives:
        assert is_stdlib_function(prim) is True
        spec = get_stdlib_spec(prim)
        assert spec is not None
        assert "description" in spec
        assert "return_type" in spec
