"""
Threat Intelligence API Endpoints
Provides endpoints for Threat Intel sources, STIX 2.1 ingestion, and case correlation.
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.models import ThreatIntelItem, Case
from backend.app.schemas.schemas import (
    ThreatIntelItemResponse,
    ThreatIntelImportRequest,
    ThreatIntelCaseOverview,
)
from backend.app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
    LocalSTIXProvider,
    TAXIIProvider,
    DemoThreatIntelProvider,
)
from backend.app.services.stix_service import STIXService

router = APIRouter(tags=["Threat Intelligence"])


@router.get("/api/threat-intel/sources")
def get_threat_intel_sources():
    """Returns available Threat Intelligence feed providers and their connection status."""
    demo_provider = DemoThreatIntelProvider()
    taxii_provider = TAXIIProvider(server_url="https://taxii.jocky.defense/taxii2/")
    local_provider = LocalSTIXProvider()

    return {
        "sources": [
            {
                "id": "taxii-2.1",
                "name": "TAXII 2.1 Feed Provider",
                "type": "TAXII",
                "status": "ONLINE",
                "supported_types": ["indicator", "attack-pattern", "malware"],
                "description": "Standard TAXII 2.1 feed consumer supporting TLS mutual authentication and collection polling.",
                "details": taxii_provider.test_connection()
            },
            {
                "id": "local-stix",
                "name": "Local STIX 2.1 Importer",
                "type": "LOCAL",
                "status": "ONLINE",
                "supported_types": ["bundle", "indicator", "threat-actor", "malware", "attack-pattern", "relationship"],
                "description": "Parses local JSON STIX 2.1 bundles and custom analyst intelligence feeds.",
                "details": local_provider.test_connection()
            },
            {
                "id": "demo-threat-intel",
                "name": "Simulated High-Fidelity Threat Feed",
                "type": "DEMO",
                "status": "ONLINE",
                "supported_types": ["indicator", "malware", "attack-pattern"],
                "description": "[DEMO THREAT INTELLIGENCE] Curated threat feed aligned with simulated fleet adversary behaviors and C2 infrastructures.",
                "details": demo_provider.test_connection()
            }
        ]
    }


@router.post("/api/threat-intel/import", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def import_threat_intel(payload: ThreatIntelImportRequest, db: Session = Depends(get_db)):
    """Imports threat intelligence from a STIX 2.1 bundle, TAXII server, or demo provider."""
    items_to_import: List[Dict[str, Any]] = []

    if payload.source_type == "demo":
        provider = DemoThreatIntelProvider()
        items_to_import = provider.fetch_items()
    elif payload.source_type == "taxii":
        url = payload.taxii_url or "https://taxii.jocky.defense/taxii2/"
        provider = TAXIIProvider(server_url=url, collection_id=payload.collection_id)
        items_to_import = provider.fetch_items()
    elif payload.source_type == "bundle":
        if not payload.bundle_json:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="bundle_json is required when source_type is 'bundle'"
            )
        try:
            items_to_import = STIXService.parse_bundle_or_object(payload.bundle_json, source="LOCAL_STIX")
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"STIX parsing error: {str(err)}"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported source_type: {payload.source_type}"
        )

    saved_items = ThreatIntelligenceService.import_intel_items(db, items_to_import)
    return {
        "status": "SUCCESS",
        "imported_count": len(saved_items),
        "total_parsed": len(items_to_import),
        "message": f"Successfully ingested {len(saved_items)} threat intelligence items into defensive repository."
    }


@router.get("/api/threat-intel/items", response_model=List[ThreatIntelItemResponse])
def get_threat_intel_items(
    intel_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Lists threat intelligence items stored in the repository."""
    query = db.query(ThreatIntelItem)
    if intel_type:
        query = query.filter(ThreatIntelItem.intel_type == intel_type)
    return query.order_by(ThreatIntelItem.created_at.desc()).limit(limit).all()


@router.get("/api/investigations/{case_id}/intel", response_model=ThreatIntelCaseOverview)
def get_case_threat_intel(case_id: str, db: Session = Depends(get_db)):
    """Correlates threat intelligence against observed forensic evidence in the given case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    overview = ThreatIntelligenceService.correlate_case_with_threat_intel(db, case_id)
    return overview
