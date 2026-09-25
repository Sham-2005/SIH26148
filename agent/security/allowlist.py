"""
JOCKY Agent Security & Function Allowlist
Guarantees that the agent only executes approved forensic collectors and blocks any arbitrary execution attempts.
"""
from typing import Set

ALLOWED_FORENSIC_FUNCTIONS: Set[str] = {
    # System
    "system.info",
    "system.hostname",
    "system.os",
    "system.users",

    # Process
    "process.list",
    "process.info",
    "process.modules",

    # File & Filesystem
    "file.hash",
    "file.metadata",
    "file.strings",
    "file.entropy",
    "filesystem.scan",

    # Network
    "network.connections",
    "network.interfaces",
    "network.dns",

    # Persistence
    "persistence.startup",
    "persistence.scheduled_tasks",
    "persistence.services",

    # Malware Indicators
    "malware.hash",
    "malware.entropy",
    "malware.strings",
    "malware.pe_info",

    # Sealing
    "evidence.collect"
}

def is_function_allowed(function_name: str) -> bool:
    return function_name in ALLOWED_FORENSIC_FUNCTIONS

def validate_task_function(function_name: str) -> None:
    if not is_function_allowed(function_name):
        raise PermissionError(
            f"Security Violation: Function '{function_name}' is not in the authorized forensic allowlist."
        )
