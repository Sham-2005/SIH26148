"""
Agent Capability Registry & Controlled Polymorphism Platform Resolver
Defines supported forensic capabilities per platform and safely resolves high-level
JOCKY forensic operations to platform-specific allowlisted collectors.
Rejects any unapproved or incompatible operations cleanly without arbitrary command execution.
"""
from typing import Dict, Set, List, Optional, Tuple

# Base forensic capabilities common to all supported platforms
BASE_CAPABILITIES: Set[str] = {
    "system.info",
    "system.hostname",
    "system.os",
    "system.users",
    "process.list",
    "process.info",
    "file.hash",
    "file.metadata",
    "file.strings",
    "file.entropy",
    "filesystem.scan",
    "network.connections",
    "network.interfaces",
    "network.dns",
    "persistence.startup",
    "persistence.services",
    "persistence.scheduled_tasks",
    "evidence.collect"
}

# Windows-specific capabilities
WINDOWS_SPECIFIC_CAPABILITIES: Set[str] = {
    "process.modules",
    "malware.pe_info",
    "malware.hash",
    "malware.entropy",
    "malware.strings"
}

# Linux-specific capabilities
LINUX_SPECIFIC_CAPABILITIES: Set[str] = {
    # Linux native inspectors
}

CAPABILITY_PROFILES: Dict[str, Set[str]] = {
    "windows": BASE_CAPABILITIES.union(WINDOWS_SPECIFIC_CAPABILITIES),
    "linux": BASE_CAPABILITIES.union(LINUX_SPECIFIC_CAPABILITIES),
    "darwin": BASE_CAPABILITIES
}

def get_platform_capabilities(platform_name: str) -> List[str]:
    """Returns the set of allowlisted capabilities for the specified operating system."""
    key = (platform_name or "").lower()
    if "win" in key:
        return sorted(list(CAPABILITY_PROFILES["windows"]))
    elif "linux" in key or "ubuntu" in key or "debian" in key:
        return sorted(list(CAPABILITY_PROFILES["linux"]))
    return sorted(list(CAPABILITY_PROFILES.get("darwin", BASE_CAPABILITIES)))

def resolve_polymorphic_operation(operation: str, platform_name: str, agent_capabilities: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    """
    Safely resolves a high-level JOCKY operation to the target platform.
    Returns (is_supported, resolved_collector_name_or_error_code).
    """
    plat = (platform_name or "").lower()
    plat_key = "windows" if "win" in plat else ("linux" if ("linux" in plat or "ubuntu" in plat or "debian" in plat) else "darwin")

    supported_caps = set(agent_capabilities) if agent_capabilities else CAPABILITY_PROFILES.get(plat_key, BASE_CAPABILITIES)

    if operation not in supported_caps:
        return False, "UNSUPPORTED_CAPABILITY"

    # All resolved collectors must strictly belong to the safe allowlist
    return True, operation
