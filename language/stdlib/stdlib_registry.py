"""
JOCKY Forensic Standard Library Registry
Defines all authorized namespaces, functions, expected parameter types, and descriptions.
"""
from typing import Dict, Any, List, Optional

STDLIB_REGISTRY: Dict[str, Dict[str, Any]] = {
    # System Analysis
    "system.info": {
        "params": [],
        "description": "Collect OS details, architecture, CPU count, uptime, and memory statistics.",
        "return_type": "object"
    },
    "system.hostname": {
        "params": [],
        "description": "Retrieve host name and fully qualified domain name.",
        "return_type": "string"
    },
    "system.os": {
        "params": [],
        "description": "Operating system distribution, release, and kernel version.",
        "return_type": "object"
    },
    "system.users": {
        "params": [],
        "description": "Enumerate local user accounts, active sessions, and privilege levels.",
        "return_type": "list"
    },

    # Process Inspection
    "process.list": {
        "params": [],
        "description": "Enumerate all running processes with PID, PPID, executable path, command line, and memory usage.",
        "return_type": "list"
    },
    "process.info": {
        "params": ["int"],
        "description": "Inspect detailed thread, user, and execution state for a specific process ID.",
        "return_type": "object"
    },
    "process.modules": {
        "params": ["int"],
        "description": "Enumerate loaded dynamic link libraries (DLLs) or shared objects for target PID.",
        "return_type": "list"
    },

    # File & Filesystem Forensics
    "file.hash": {
        "params": ["str"],
        "description": "Calculate MD5, SHA-1, and SHA-256 hashes of a target file.",
        "return_type": "object"
    },
    "file.metadata": {
        "params": ["str"],
        "description": "Extract file timestamps (Modified, Accessed, Created), file size, and permissions.",
        "return_type": "object"
    },
    "file.strings": {
        "params": ["str"],
        "description": "Extract ASCII and UTF-16 printable strings from a target binary or text file.",
        "return_type": "list"
    },
    "file.entropy": {
        "params": ["str"],
        "description": "Calculate Shannon entropy (0.0 to 8.0) to evaluate compression/encryption.",
        "return_type": "float"
    },
    "filesystem.scan": {
        "params": ["str"],
        "description": "Enumerate directory contents recursively up to safety depth.",
        "return_type": "list"
    },

    # Network Forensics
    "network.connections": {
        "params": [],
        "description": "Enumerate active TCP/UDP connections and listening sockets with associated PIDs.",
        "return_type": "list"
    },
    "network.interfaces": {
        "params": [],
        "description": "Enumerate network adapters, MAC addresses, IPv4, and IPv6 assignments.",
        "return_type": "list"
    },
    "network.dns": {
        "params": [],
        "description": "Query configured DNS resolvers and local DNS cache.",
        "return_type": "object"
    },

    # Persistence Forensics
    "persistence.startup": {
        "params": [],
        "description": "Scan startup folders and Windows registry run keys.",
        "return_type": "list"
    },
    "persistence.scheduled_tasks": {
        "params": [],
        "description": "Enumerate Windows Task Scheduler jobs or Linux cron/systemd timers.",
        "return_type": "list"
    },
    "persistence.services": {
        "params": [],
        "description": "Enumerate system background services and daemon definitions.",
        "return_type": "list"
    },

    # Malware Indicators
    "malware.hash": {
        "params": ["str"],
        "description": "Evaluate file against known indicator hash sets.",
        "return_type": "object"
    },
    "malware.entropy": {
        "params": ["str"],
        "description": "Evaluate binary section entropy for packed indicator detection.",
        "return_type": "float"
    },
    "malware.strings": {
        "params": ["str"],
        "description": "Extract suspicious indicator patterns (IPs, URLs, registry paths).",
        "return_type": "list"
    },
    "malware.pe_info": {
        "params": ["str"],
        "description": "Parse PE/ELF headers, section names, and Import Address Table (IAT).",
        "return_type": "object"
    },

    # Evidence Envelope
    "evidence.collect": {
        "params": [],
        "description": "Explicit evidence sealing barrier and telemetry flush.",
        "return_type": "object"
    },

    # Phase 7 Safe Forensic Integrity Primitives
    "verify.evidence": {
        "params": ["str"],
        "description": "Verify cryptographic SHA-256 seal and sequential hash-chain for case evidence.",
        "return_type": "object"
    },
    "verify.audit": {
        "params": ["str"],
        "description": "Verify append-only cryptographic audit hash-chain integrity.",
        "return_type": "object"
    },
    "verify.agent": {
        "params": ["str"],
        "description": "Verify endpoint identity fingerprint and capability profile.",
        "return_type": "object"
    },
    "verify.playbook": {
        "params": ["str"],
        "description": "Verify playbook content hash and authorized analyst approval signature.",
        "return_type": "object"
    },
    "verify.report": {
        "params": ["str"],
        "description": "Verify canonical forensic report manifest and content hash.",
        "return_type": "object"
    },
    "security.events": {
        "params": ["str"],
        "description": "Scan and enumerate active security and tamper detection alerts for case.",
        "return_type": "list"
    },

    # Level 3 Machine Learning Threat Detection Primitives
    "ml.analyze": {
        "params": ["str"],
        "description": "Execute ML forensic feature extraction, Random Forest classification, and explainability for a case.",
        "return_type": "object"
    },
    "ml.prediction": {
        "params": ["str"],
        "description": "Retrieve the latest cryptographically sealed ML threat prediction for a case.",
        "return_type": "object"
    },
    "ml.score": {
        "params": ["str"],
        "description": "Compute continuous forensic threat score [0.0 - 1.0] for a case.",
        "return_type": "float"
    },
    "ml.explain": {
        "params": ["str"],
        "description": "Extract top explainable forensic factors contributing to threat classification.",
        "return_type": "list"
    },
    "ml.verify": {
        "params": ["str"],
        "description": "Cryptographically verify prediction RFC-8785 canonical SHA-256 seal integrity.",
        "return_type": "object"
    },
    "ml.model_status": {
        "params": [],
        "description": "Query ML model operational state, algorithm, and SHA-256 binary hash integrity.",
        "return_type": "object"
    }
}


def is_stdlib_function(name: str) -> bool:
    return name in STDLIB_REGISTRY

def get_stdlib_spec(name: str) -> Optional[Dict[str, Any]]:
    return STDLIB_REGISTRY.get(name)
