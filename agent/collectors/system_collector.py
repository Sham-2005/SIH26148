"""
System Forensic Collector
Collects non-invasive, read-only system telemetry (OS, architecture, hardware info, local users).
"""
import platform
import socket
import os
import psutil
from typing import Dict, Any, List

def collect_system_info() -> Dict[str, Any]:
    boot_time = psutil.boot_time()
    virtual_mem = psutil.virtual_memory()

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "memory_total_bytes": virtual_mem.total,
        "memory_available_bytes": virtual_mem.available,
        "boot_timestamp": boot_time
    }

def collect_system_hostname() -> str:
    return socket.gethostname()

def collect_system_os() -> Dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "edition": getattr(platform, 'win32_edition', lambda: "N/A")() if platform.system() == "Windows" else "N/A"
    }

def collect_system_users() -> List[Dict[str, Any]]:
    users = []
    try:
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal or "console",
                "host": u.host or "local",
                "started": u.started
            })
    except Exception as e:
        users.append({"error": str(e)})
    return users
