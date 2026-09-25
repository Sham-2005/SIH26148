"""
IOC Extraction & Normalization Service
Extracts, normalizes, and categorizes indicators of compromise from forensic evidence envelopes.
Supports IPv4, IPv6, domains, URLs, file paths, SHA-256, MD5, process names, service names, and registry paths.
Uses neutral terminology: observed, suspicious, matched, correlated.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import Evidence, InvestigationIndicator

IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')

class IOCService:
    @staticmethod
    def normalize(indicator_type: str, value: str) -> str:
        """Deterministically normalizes indicator values for reliable matching."""
        if not value:
            return ""
        val = str(value).strip()

        if indicator_type in ("sha256", "md5"):
            return val.lower()
        elif indicator_type in ("ipv4", "ipv6"):
            # Strip port if present e.g. 192.168.1.10:443 -> 192.168.1.10
            if ":" in val and "." in val:
                val = val.split(":")[0]
            return val.strip().lower()
        elif indicator_type in ("domain", "url"):
            # Strip protocol
            val = re.sub(r'^https?://', '', val, flags=re.IGNORECASE)
            return val.rstrip('/').lower()
        elif indicator_type == "filepath":
            # Normalize path slashes
            val = val.replace('\\', '/')
            if len(val) > 1 and val[1] == ':':
                val = val[0].upper() + val[1:]
            return val
        elif indicator_type == "registry_path":
            val = val.replace('/', '\\').strip('\\')
            return val.upper()
        elif indicator_type in ("process_name", "service_name"):
            return val.lower()

        return val

    @classmethod
    def extract_from_evidence(cls, evidence: Evidence, db: Session) -> List[InvestigationIndicator]:
        """Extracts normalized IOCs from an Evidence model and updates database."""
        envelope = evidence.envelope_data or {}
        results = envelope.get("results")
        collector = evidence.collector
        case_id = evidence.case_id
        agent_id = evidence.agent_id
        ev_id = evidence.id
        now = datetime.now(timezone.utc)

        extracted_raw: List[Tuple[str, str, str, Optional[Dict[str, Any]]]] = [] # (type, value, status, context)

        # 1. SHA-256 Envelope Hash itself
        if evidence.sha256_hash:
            extracted_raw.append(("sha256", evidence.sha256_hash, "observed", {"source": "envelope_sha256"}))

        # 2. Extract based on collector
        if collector == "process.list":
            procs = results if isinstance(results, list) else (results.get("processes", []) if isinstance(results, dict) else [])
            for p in procs:
                if isinstance(p, dict):
                    name = p.get("name") or p.get("process_name")
                    if name:
                        status = "suspicious" if any(s in str(name).lower() for s in ["mimikatz", "meterpreter", "nc.exe", "beacon"]) else "observed"
                        extracted_raw.append(("process_name", str(name), status, {"pid": p.get("pid")}))

                    exe = p.get("exe") or p.get("executable_path")
                    if exe:
                        status = "suspicious" if any(sub in str(exe).lower() for sub in ["temp", "appdata", "tmp"]) else "observed"
                        extracted_raw.append(("filepath", str(exe), status, {"process_name": name, "pid": p.get("pid")}))

                    cmdline = p.get("cmdline")
                    if cmdline:
                        # Extract any IPs in cmdline
                        for ip in IPV4_REGEX.findall(str(cmdline)):
                            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                                extracted_raw.append(("ipv4", ip, "observed", {"cmdline": cmdline}))

        elif collector == "network.connections":
            conns = results if isinstance(results, list) else (results.get("connections", []) if isinstance(results, dict) else [])
            for c in conns:
                if isinstance(c, dict):
                    remote = c.get("remote_address") or c.get("raddr") or c.get("peer")
                    if remote and remote != "0.0.0.0" and remote != "127.0.0.1":
                        ip_match = IPV4_REGEX.search(str(remote))
                        if ip_match:
                            extracted_raw.append(("ipv4", ip_match.group(0), "observed", {"connection": c}))
                    local = c.get("local_address") or c.get("laddr")
                    if local:
                        ip_match = IPV4_REGEX.search(str(local))
                        if ip_match and ip_match.group(0) not in ("0.0.0.0", "127.0.0.1"):
                            extracted_raw.append(("ipv4", ip_match.group(0), "observed", {"local_socket": c}))

        elif collector in ("malware.pe_info", "file.hash", "file.entropy"):
            if isinstance(results, dict):
                # Hashes
                for htype in ["sha256", "md5"]:
                    hval = results.get(htype) or (results.get("hashes", {}).get(htype) if isinstance(results.get("hashes"), dict) else None)
                    if hval:
                        extracted_raw.append((htype, str(hval), "observed", {"collector": collector}))
                # Target path
                target = envelope.get("parameters", {}).get("target_path") or results.get("filepath") or results.get("path")
                if target:
                    status = "suspicious" if any(sub in str(target).lower() for sub in ["temp", "appdata", "tmp"]) else "observed"
                    extracted_raw.append(("filepath", str(target), status, {"collector": collector}))

        elif "persistence" in collector:
            items = results if isinstance(results, list) else (results.get("findings", []) if isinstance(results, dict) else [])
            for item in items:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("service_name") or item.get("task_name")
                    if name:
                        extracted_raw.append(("service_name", str(name), "suspicious", {"persistence_type": item.get("persistence_type")}))
                    loc = item.get("location") or item.get("registry_path") or item.get("key")
                    if loc:
                        extracted_raw.append(("registry_path", str(loc), "suspicious", {"item": item}))
                    cmd = item.get("command") or item.get("path") or item.get("binary_path")
                    if cmd:
                        extracted_raw.append(("filepath", str(cmd), "suspicious", {"name": name}))

        # General text regex scan over envelope string for any hashes / IPs
        env_str = str(results)
        for ip in IPV4_REGEX.findall(env_str):
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and not any(r[1] == ip for r in extracted_raw):
                extracted_raw.append(("ipv4", ip, "observed", {"extracted_by": "regex_fallback"}))

        # Save or update indicators
        saved_indicators: List[InvestigationIndicator] = []
        for itype, raw_val, status, context in extracted_raw:
            norm_val = cls.normalize(itype, raw_val)
            if not norm_val:
                continue

            existing = db.query(InvestigationIndicator).filter(
                InvestigationIndicator.case_id == case_id,
                InvestigationIndicator.indicator_type == itype,
                InvestigationIndicator.normalized_value == norm_val
            ).first()

            if existing:
                existing.last_seen = now
                if status == "suspicious" and existing.status == "observed":
                    existing.status = "suspicious"
                saved_indicators.append(existing)
            else:
                new_ioc = InvestigationIndicator(
                    id=f"IOC-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case_id,
                    indicator_type=itype,
                    value=raw_val,
                    normalized_value=norm_val,
                    source_evidence_id=ev_id,
                    agent_id=agent_id,
                    first_seen=now,
                    last_seen=now,
                    status=status,
                    context_data=context
                )
                db.add(new_ioc)
                saved_indicators.append(new_ioc)

        db.commit()
        return saved_indicators
