"""
Process Forensic Collector
Read-only enumeration of active processes, threads, memory footprints, and loaded modules.
"""
import psutil
from typing import List, Dict, Any, Optional

def collect_process_list(limit: int = 200) -> List[Dict[str, Any]]:
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline', 'create_time', 'memory_percent']):
        try:
            info = proc.info
            processes.append({
                "pid": info['pid'],
                "ppid": info['ppid'],
                "name": info['name'],
                "username": info['username'],
                "exe_path": info['exe'],
                "cmdline": " ".join(info['cmdline']) if info['cmdline'] else "",
                "created_at": info['create_time'],
                "memory_percent": round(info['memory_percent'] or 0.0, 2)
            })
            if len(processes) >= limit:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def collect_process_info(pid: int) -> Dict[str, Any]:
    try:
        proc = psutil.Process(pid)
        mem_info = proc.memory_info()
        return {
            "pid": proc.pid,
            "ppid": proc.ppid(),
            "name": proc.name(),
            "status": proc.status(),
            "username": proc.username(),
            "exe": proc.exe(),
            "cwd": proc.cwd(),
            "cmdline": proc.cmdline(),
            "rss_bytes": mem_info.rss,
            "vms_bytes": mem_info.vms,
            "num_threads": proc.num_threads(),
            "created_at": proc.create_time()
        }
    except Exception as e:
        return {"error": str(e), "pid": pid}

def collect_process_modules(pid: int) -> List[Dict[str, Any]]:
    try:
        proc = psutil.Process(pid)
        maps = proc.memory_maps()
        modules = []
        for m in maps:
            modules.append({
                "path": m.path,
                "rss_bytes": m.rss,
                "size_bytes": m.size
            })
        return modules
    except Exception as e:
        return [{"error": str(e), "pid": pid}]
