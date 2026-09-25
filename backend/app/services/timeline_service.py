"""
Unified Timeline Engine
Converts evidence timestamps into a unified, chronologically ordered investigation timeline.
Supports filtering by agent, event type, severity, and date range.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_
from backend.app.models.models import Evidence, TimelineEvent

class TimelineService:
    @classmethod
    def synthesize_events_from_evidence(cls, evidence: Evidence, db: Session) -> List[TimelineEvent]:
        """Generates timeline events from an evidence item and commits to DB."""
        envelope = evidence.envelope_data or {}
        collector = evidence.collector
        case_id = evidence.case_id
        agent_id = evidence.agent_id
        ev_id = evidence.id
        results = envelope.get("results")

        collected_at_raw = envelope.get("timestamp") or evidence.collected_at
        if isinstance(collected_at_raw, str):
            try:
                base_time = datetime.fromisoformat(collected_at_raw.replace('Z', '+00:00'))
            except Exception:
                base_time = datetime.now(timezone.utc)
        elif isinstance(collected_at_raw, datetime):
            base_time = collected_at_raw
        else:
            base_time = datetime.now(timezone.utc)

        events: List[TimelineEvent] = []

        if collector == "process.list":
            procs = results if isinstance(results, list) else (results.get("processes", []) if isinstance(results, dict) else [])
            for p in procs[:25]:  # Process representative sample
                if isinstance(p, dict):
                    name = p.get("name") or "unknown_proc"
                    pid = p.get("pid", "?")
                    sev = "HIGH" if any(s in str(name).lower() for s in ["mimikatz", "meterpreter", "beacon", "nc.exe"]) else "INFO"
                    evt = TimelineEvent(
                        id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case_id,
                        agent_id=agent_id,
                        timestamp=base_time,
                        event_type="PROCESS",
                        description=f"Process observed: '{name}' (PID: {pid}) on {agent_id}",
                        evidence_id=ev_id,
                        severity=sev,
                        details={"process": p}
                    )
                    events.append(evt)
                    db.add(evt)

        elif collector == "network.connections":
            conns = results if isinstance(results, list) else (results.get("connections", []) if isinstance(results, dict) else [])
            for c in conns[:25]:
                if isinstance(c, dict):
                    raddr = c.get("remote_address") or c.get("raddr") or "N/A"
                    status = c.get("status", "ESTABLISHED")
                    sev = "MEDIUM" if raddr not in ("N/A", "0.0.0.0", "127.0.0.1") else "INFO"
                    evt = TimelineEvent(
                        id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case_id,
                        agent_id=agent_id,
                        timestamp=base_time,
                        event_type="NETWORK",
                        description=f"Network socket {status}: remote {raddr} on {agent_id}",
                        evidence_id=ev_id,
                        severity=sev,
                        details={"connection": c}
                    )
                    events.append(evt)
                    db.add(evt)

        elif "persistence" in collector:
            items = results if isinstance(results, list) else (results.get("findings", []) if isinstance(results, dict) else [])
            for item in items:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("service_name") or "PersistenceEntry"
                    ptype = item.get("persistence_type", "Persistence")
                    evt = TimelineEvent(
                        id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case_id,
                        agent_id=agent_id,
                        timestamp=base_time,
                        event_type="PERSISTENCE",
                        description=f"Persistence hook observed ({ptype}): '{name}' on {agent_id}",
                        evidence_id=ev_id,
                        severity="HIGH",
                        details={"persistence": item}
                    )
                    events.append(evt)
                    db.add(evt)

        elif collector in ("malware.pe_info", "file.hash"):
            path = envelope.get("parameters", {}).get("target_path") or "inspected_binary"
            h = evidence.sha256_hash[:16] + "..." if evidence.sha256_hash else "unknown_hash"
            evt = TimelineEvent(
                id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                case_id=case_id,
                agent_id=agent_id,
                timestamp=base_time,
                event_type="FILE",
                description=f"Binary file inspected: '{path}' (SHA-256: {h}) on {agent_id}",
                evidence_id=ev_id,
                severity="MEDIUM",
                details={"envelope_summary": str(results)[:200]}
            )
            events.append(evt)
            db.add(evt)

        else:
            # Generic collector event
            evt = TimelineEvent(
                id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                case_id=case_id,
                agent_id=agent_id,
                timestamp=base_time,
                event_type="SYSTEM",
                description=f"Forensic collection completed ({collector}) on {agent_id}",
                evidence_id=ev_id,
                severity="INFO",
                details={"collector": collector}
            )
            events.append(evt)
            db.add(evt)

        db.commit()
        return events

    @staticmethod
    def get_timeline(
        case_id: str,
        db: Session,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[TimelineEvent]:
        """Queries timeline events sorted chronologically with optional filters."""
        query = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id)

        if agent_id:
            query = query.filter(TimelineEvent.agent_id == agent_id)
        if event_type:
            query = query.filter(TimelineEvent.event_type == event_type.upper())
        if severity:
            query = query.filter(TimelineEvent.severity == severity.upper())
        if start_time:
            query = query.filter(TimelineEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(TimelineEvent.timestamp <= end_time)

        # Chronological sort (oldest to newest for timeline review)
        return query.order_by(TimelineEvent.timestamp.asc()).limit(limit).all()
