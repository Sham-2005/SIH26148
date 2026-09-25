"""
Forensic Feature Extraction Engine
Converts JOCKY forensic evidence envelopes, IOCs, timeline events, CTI matches,
and security events into a normalized, deterministic numeric feature vector.
"""
import re
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.app.ml.schemas import ForensicFeatureVector, FEATURE_SCHEMA_VERSION
from backend.app.models.models import (
    Case,
    Evidence,
    InvestigationIndicator,
    TimelineEvent,
    SecurityEvent,
)
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "meterpreter", "nc.exe", "ncat.exe", "beacon.exe",
    "cobaltstrike", "psexec.exe", "procdump.exe", "rubeus.exe", "lazagne.exe"
}

SUSPICIOUS_PORTS = {4444, 1337, 8888, 31337, 5555, 6667, 8088, 9001}


def is_external_ip(ip_str: str) -> bool:
    """Checks if an IPv4 string is non-loopback and non-private RFC1918."""
    if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "localhost", "::1"):
        return False
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        b0, b1 = int(parts[0]), int(parts[1])
        if b0 == 10:
            return False
        if b0 == 172 and (16 <= b1 <= 31):
            return False
        if b0 == 192 and b1 == 168:
            return False
        if b0 == 169 and b1 == 254:
            return False
        return True
    except (ValueError, IndexError):
        return False


class ForensicFeatureExtractor:
    """Extracts standardized numeric features from forensic evidence artifacts."""

    @classmethod
    def extract_from_case(cls, case_id: str, db: Session) -> ForensicFeatureVector:
        """Extracts features by querying all artifacts associated with case_id."""
        evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
        indicators = db.query(InvestigationIndicator).filter(InvestigationIndicator.case_id == case_id).all()
        timeline_events = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).all()
        security_events = db.query(SecurityEvent).filter(SecurityEvent.case_id == case_id).all()

        # Query CTI correlation
        cti_overview = ThreatIntelligenceService.correlate_case_with_threat_intel(db, case_id)

        raw_evidence_list = []
        for ev in evidence_items:
            env = dict(ev.envelope_data or {})
            if "collector" not in env and ev.collector:
                env["collector"] = ev.collector
            raw_evidence_list.append(env)

        raw_indicators = [
            {"type": ioc.indicator_type, "value": ioc.value, "status": ioc.status}
            for ioc in indicators
        ]

        return cls.extract_from_artifacts(
            raw_evidence=raw_evidence_list,
            indicators=raw_indicators,
            timeline_count=len(timeline_events),
            security_events=[{"type": se.event_type, "severity": se.severity} for se in security_events],
            cti_matches=cti_overview.get("matches", []),
            mitre_techniques=cti_overview.get("mitre_coverage", [])
        )

    @classmethod
    def extract_from_artifacts(
        cls,
        raw_evidence: List[Dict[str, Any]],
        indicators: Optional[List[Dict[str, Any]]] = None,
        timeline_count: int = 0,
        security_events: Optional[List[Dict[str, Any]]] = None,
        cti_matches: Optional[List[Dict[str, Any]]] = None,
        mitre_techniques: Optional[List[Any]] = None
    ) -> ForensicFeatureVector:
        """Pure extractor operating on raw dictionaries (for testing and offline usage)."""
        indicators = indicators or []
        security_events = security_events or []
        cti_matches = cti_matches or []
        mitre_techniques = mitre_techniques or []

        # Process metrics
        process_count = 0
        suspicious_process_count = 0
        temp_path_process_count = 0

        # Network metrics
        connection_count = 0
        external_connection_count = 0
        suspicious_port_count = 0

        # Persistence metrics
        persistence_count = 0
        suspicious_persistence_count = 0

        # File metrics
        file_count = 0
        pe_anomaly_count = 0
        suspicious_file_count = 0

        for envelope in raw_evidence:
            collector = envelope.get("collector", "")
            results = envelope.get("results") if envelope.get("results") is not None else envelope

            # 1. Process Collectors
            if "process" in collector or collector == "process.list":
                procs = results if isinstance(results, list) else (results.get("processes", []) if isinstance(results, dict) else [])
                for p in procs:
                    if isinstance(p, dict):
                        process_count += 1
                        name = (p.get("name") or p.get("process_name") or "").lower()
                        exe = (p.get("exe") or p.get("exe_path") or p.get("executable_path") or p.get("path") or "").lower()
                        cmdline = (p.get("cmdline") or "").lower()

                        if any(sp in name for sp in SUSPICIOUS_PROCESS_NAMES) or any(sp in cmdline for sp in SUSPICIOUS_PROCESS_NAMES):
                            suspicious_process_count += 1

                        if any(t in exe for t in ("\\temp\\", "\\tmp\\", "\\appdata\\", "/temp/", "/tmp/")):
                            temp_path_process_count += 1

            # 2. Network Collectors
            if "network" in collector or collector in ("network.connections", "network.sockets"):
                conns = results if isinstance(results, list) else (results.get("connections", []) if isinstance(results, dict) else [])
                for c in conns:
                    if isinstance(c, dict):
                        connection_count += 1
                        raddr = c.get("remote_address") or c.get("raddr") or ""
                        if raddr and ":" in str(raddr):
                            ip = str(raddr).split(":")[0]
                            port_str = str(raddr).split(":")[1]
                            if is_external_ip(ip):
                                external_connection_count += 1
                            try:
                                port = int(port_str)
                                if port in SUSPICIOUS_PORTS:
                                    suspicious_port_count += 1
                            except ValueError:
                                pass

            # 3. Persistence Collectors
            if "persistence" in collector:
                items = results if isinstance(results, list) else (
                    results.get("entries", []) or results.get("findings", []) if isinstance(results, dict) else []
                )
                for item in items:
                    if isinstance(item, dict):
                        persistence_count += 1
                        val_str = str(item).lower()
                        if any(kw in val_str for kw in ("temp", "appdata", "powershell", "cmd.exe", "rundll32", "regsvr32", "beacon")):
                            suspicious_persistence_count += 1

            # 4. File / PE Collectors
            if "file" in collector or "malware" in collector:
                pe_data = results.get("pe_headers") if isinstance(results, dict) and "pe_headers" in results else results
                if isinstance(pe_data, dict):
                    file_count += 1
                    target_path = str(envelope.get("parameters", {}).get("target_path") or pe_data.get("filepath") or "").lower()
                    if any(t in target_path for t in ("temp", "tmp", "appdata")):
                        suspicious_file_count += 1

                    # Check PE anomalies
                    sections = pe_data.get("sections") or []
                    entropy = pe_data.get("entropy") or 0.0
                    imports = pe_data.get("imports") or []
                    if entropy > 7.0 or any(s in str(sections).lower() for s in ("upx", "packed")):
                        pe_anomaly_count += 1
                    elif any(imp in str(imports).lower() for imp in ("virtualalloc", "writeprocessmemory", "createremotethread")):
                        pe_anomaly_count += 1
                elif isinstance(pe_data, list):
                    file_count += len(pe_data)

        # IOC Metrics
        ioc_count = len(indicators)
        malicious_ioc_count = sum(1 for ioc in indicators if any(s in str(ioc.get("status", "")).lower() for s in ("matched", "malicious")))
        suspicious_ioc_count = sum(1 for ioc in indicators if any(s in str(ioc.get("status", "")).lower() for s in ("suspicious", "correlated")))
        ip_ioc_count = sum(1 for ioc in indicators if "ip" in str(ioc.get("type", "")).lower())
        hash_ioc_count = sum(1 for ioc in indicators if any(h in str(ioc.get("type", "")).lower() for h in ("sha", "md5", "hash")))

        # Security & Tamper Metrics
        security_event_count = len(security_events)
        tamper_event_count = sum(1 for se in security_events if "tamper" in str(se.get("type", "")).lower() or "break" in str(se.get("type", "")).lower())

        # CTI Metrics
        cti_match_count = len(cti_matches)
        mitre_technique_count = len(mitre_techniques)

        return ForensicFeatureVector(
            process_count=process_count,
            suspicious_process_count=suspicious_process_count,
            temp_path_process_count=temp_path_process_count,
            connection_count=connection_count,
            external_connection_count=external_connection_count,
            suspicious_port_count=suspicious_port_count,
            persistence_count=persistence_count,
            suspicious_persistence_count=suspicious_persistence_count,
            file_count=file_count,
            pe_anomaly_count=pe_anomaly_count,
            suspicious_file_count=suspicious_file_count,
            ioc_count=ioc_count,
            malicious_ioc_count=malicious_ioc_count,
            suspicious_ioc_count=suspicious_ioc_count,
            ip_ioc_count=ip_ioc_count,
            hash_ioc_count=hash_ioc_count,
            timeline_event_count=timeline_count,
            security_event_count=security_event_count,
            cti_match_count=cti_match_count,
            mitre_technique_count=mitre_technique_count,
            tamper_event_count=tamper_event_count,
            feature_schema_version=FEATURE_SCHEMA_VERSION
        )
