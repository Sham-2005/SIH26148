"""
STIX 2.1 Ingestion & Parsing Service
Handles STIX 2.1 objects (indicator, malware, threat-actor, attack-pattern, relationship, bundle),
pattern parsing, IOC extraction, and conversion to ThreatIntelItem records.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

SUPPORTED_STIX_TYPES = {
    "bundle",
    "indicator",
    "malware",
    "threat-actor",
    "attack-pattern",
    "relationship",
}

# Regexes for parsing STIX pattern expressions
# e.g. [file:hashes.'SHA-256' = 'a1b2...']
# e.g. [ipv4-addr:value = '192.168.1.10']
# e.g. [domain-name:value = 'malicious.biz']
# e.g. [process:name = 'svchost32.exe']
STIX_PATTERN_REGEX = re.compile(r"\[([\w\-]+):([\w\.\'\"]+)\s*=\s*['\"]([^'\"]+)['\"]\]")


class STIXService:
    @staticmethod
    def validate_stix_object(obj: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validates that an object conforms to minimum STIX 2.1 requirements."""
        if not isinstance(obj, dict):
            return False, "STIX object must be a JSON object"

        obj_type = obj.get("type")
        if not obj_type or obj_type not in SUPPORTED_STIX_TYPES:
            return False, f"Unsupported or missing STIX object type: {obj_type}"

        if obj_type == "bundle":
            objects = obj.get("objects")
            if not isinstance(objects, list):
                return False, "STIX bundle must contain an 'objects' list"
            return True, None

        if not obj.get("id"):
            return False, f"STIX {obj_type} missing required 'id' field"

        return True, None

    @staticmethod
    def extract_iocs_from_pattern(pattern: str) -> Dict[str, List[str]]:
        """
        Parses STIX pattern string and extracts typed IOCs.
        Returns a dict mapping indicator_type -> list of normalized values.
        """
        iocs: Dict[str, List[str]] = {
            "sha256": [],
            "md5": [],
            "ipv4": [],
            "domain": [],
            "url": [],
            "process_name": [],
            "filepath": [],
            "registry_path": [],
        }
        if not pattern:
            return iocs

        matches = STIX_PATTERN_REGEX.findall(pattern)
        for obj_class, prop, val in matches:
            clean_prop = prop.strip("'\"").lower()
            val = val.strip()

            if "hash" in clean_prop or obj_class == "file":
                if "sha-256" in clean_prop or "sha256" in clean_prop or len(val) == 64:
                    iocs["sha256"].append(val.lower())
                elif "md5" in clean_prop or len(val) == 32:
                    iocs["md5"].append(val.lower())
                elif "name" in clean_prop:
                    iocs["filepath"].append(val)
            elif obj_class in ("ipv4-addr", "network-traffic"):
                iocs["ipv4"].append(val.lower())
            elif obj_class == "domain-name":
                iocs["domain"].append(val.lower())
            elif obj_class == "url":
                iocs["url"].append(val.lower())
            elif obj_class == "process":
                iocs["process_name"].append(val.lower())
            elif obj_class == "windows-registry-key":
                iocs["registry_path"].append(val.upper())

        # Fallback regex extraction if pattern was not in strict STIX brackets
        if not any(iocs.values()):
            # Check SHA-256
            for m in re.findall(r"\b[a-fA-F0-9]{64}\b", pattern):
                iocs["sha256"].append(m.lower())
            # Check MD5
            for m in re.findall(r"\b[a-fA-F0-9]{32}\b", pattern):
                iocs["md5"].append(m.lower())
            # Check IPv4
            for m in re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", pattern):
                iocs["ipv4"].append(m)

        # Deduplicate
        for k in iocs:
            iocs[k] = list(dict.fromkeys(iocs[k]))

        return iocs

    @staticmethod
    def extract_mitre_attack_id(obj: Dict[str, Any]) -> Optional[str]:
        """Extracts MITRE ATT&CK technique ID (e.g. T1059) from external_references."""
        ext_refs = obj.get("external_references", [])
        if isinstance(ext_refs, list):
            for ref in ext_refs:
                if isinstance(ref, dict):
                    source = ref.get("source_name", "").lower()
                    if "mitre" in source or "attack" in source:
                        ext_id = ref.get("external_id")
                        if ext_id:
                            return ext_id.strip().upper()
        # Fallback: check labels or name for T-code
        name = obj.get("name", "")
        t_match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", name)
        if t_match:
            return t_match.group(1).upper()
        return None

    @classmethod
    def parse_stix_object_to_item_dict(cls, obj: Dict[str, Any], source: str = "LOCAL") -> Dict[str, Any]:
        """Converts a single STIX 2.1 SDO/SRO into a dictionary ready for ThreatIntelItem."""
        obj_type = obj.get("type", "indicator")
        stix_id = obj.get("id") or f"{obj_type}--{uuid.uuid4()}"
        name = obj.get("name") or obj.get("relationship_type") or f"STIX {obj_type.capitalize()}"
        desc = obj.get("description")
        pattern = obj.get("pattern")
        pattern_type = obj.get("pattern_type", "stix")
        confidence = obj.get("confidence", 75)
        labels = obj.get("labels") or []
        if isinstance(labels, str):
            labels = [labels]

        # Extract indicators
        indicators = cls.extract_iocs_from_pattern(pattern or desc or "")

        # Extract MITRE ATT&CK ID
        mitre_id = cls.extract_mitre_attack_id(obj)

        # Date parsing
        valid_from = None
        if obj.get("valid_from"):
            try:
                valid_from = datetime.fromisoformat(obj["valid_from"].replace("Z", "+00:00"))
            except Exception:
                pass

        valid_until = None
        if obj.get("valid_until"):
            try:
                valid_until = datetime.fromisoformat(obj["valid_until"].replace("Z", "+00:00"))
            except Exception:
                pass

        return {
            "id": f"INTEL-{uuid.uuid4().hex[:8].upper()}",
            "stix_id": stix_id,
            "intel_type": obj_type,
            "name": name,
            "description": desc,
            "pattern": pattern,
            "pattern_type": pattern_type,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "confidence": confidence,
            "source": source,
            "labels": labels,
            "indicators": indicators,
            "mitre_attack_id": mitre_id,
            "raw_stix": obj,
        }

    @classmethod
    def parse_bundle_or_object(cls, data: Dict[str, Any], source: str = "LOCAL") -> List[Dict[str, Any]]:
        """Parses a STIX bundle or individual STIX object into a list of ThreatIntel item dicts."""
        is_valid, err = cls.validate_stix_object(data)
        if not is_valid:
            raise ValueError(f"Invalid STIX object: {err}")

        items = []
        if data.get("type") == "bundle":
            objects = data.get("objects", [])
            for obj in objects:
                if isinstance(obj, dict):
                    valid, _ = cls.validate_stix_object(obj)
                    if valid:
                        items.append(cls.parse_stix_object_to_item_dict(obj, source=source))
        else:
            items.append(cls.parse_stix_object_to_item_dict(data, source=source))

        return items
