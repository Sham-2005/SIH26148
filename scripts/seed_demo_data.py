#!/usr/bin/env python3
"""
scripts/seed_demo_data.py — JOCKY Forensic Platform Demo Seeder
================================================================
Initializes database tables, creates default analyst user, and seeds
both CASE-2026-001 and CASE-DEMO-01 (Phase 27 Evidence Provenance).

Usage:
    python scripts/seed_demo_data.py
"""
import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database.session import engine, SessionLocal
from backend.app.database.base import Base
from backend.app.database.migrations import ensure_schema_upgrades
from backend.app.models.models import User, Case
from backend.app.security.auth import get_password_hash
from backend.app.services.provenance_service import ProvenanceService


def seed_database():
    """Initializes tables and seeds baseline demonstration data."""
    print("[JOCKY] Initializing database tables and schema migrations...")
    Base.metadata.create_all(bind=engine)
    ensure_schema_upgrades(engine, Base.metadata)

    db = SessionLocal()
    try:
        # 1. Analyst user
        analyst = db.query(User).filter(User.email == "analyst@jocky.defense").first()
        if not analyst:
            print("[JOCKY] Creating chief forensic analyst user (analyst@jocky.defense)...")
            analyst = User(
                email="analyst@jocky.defense",
                hashed_password=get_password_hash("ForensicsPass2026!"),
                full_name="Chief Forensic Analyst",
                role="analyst"
            )
            db.add(analyst)
            db.commit()
            print("  [+] Analyst created successfully.")
        else:
            print("  [+] Analyst user already present.")

        # 2. Baseline demo case CASE-2026-001
        case1 = db.query(Case).filter(Case.id == "CASE-2026-001").first()
        if not case1:
            print("[JOCKY] Creating case CASE-2026-001 (Enterprise Triage & Persistence Analysis)...")
            case1 = Case(
                id="CASE-2026-001",
                title="Enterprise Triage & Persistence Analysis",
                description="Fleet-wide investigation of unauthorized persistence artifacts and anomalous processes.",
                severity="high",
                status="INVESTIGATING"
            )
            db.add(case1)
            db.commit()
            print("  [+] CASE-2026-001 created.")
        else:
            print("  [+] CASE-2026-001 already present.")

        # 3. Phase 27 Evidence Provenance case CASE-DEMO-01
        print("[JOCKY] Seeding Phase 27 Provenance & Traceability demonstration (CASE-DEMO-01)...")
        demo_info = ProvenanceService.run_deterministic_investigation("CASE-DEMO-01", db=db)
        print(f"  [+] CASE-DEMO-01 generated: {demo_info.get('evidence_count', 28)} evidence records, {demo_info.get('findings_count', 4)} findings, Merkle root & blockchain anchored.")

        print("\n[JOCKY] Database seeding complete! All forensic demonstration assets ready.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
