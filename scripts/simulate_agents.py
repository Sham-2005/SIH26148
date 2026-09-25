"""
Multi-Agent Fleet Simulator for SIH26148 JOCKY Demonstration
Simulates a 5+ agent distributed fleet across Windows and Linux platforms:
- AGENT-WIN-01: Windows 11 Enterprise Workstation
- AGENT-WIN-02: Windows 10 Pro Endpoint
- AGENT-WIN-03: Windows 11 Developer Workstation
- AGENT-LINUX-01: Ubuntu 24.04 LTS Core Server
- AGENT-LINUX-02: Debian 12 Minimal Server
- AGENT-WIN-SERVER-01: Windows Server 2022 Domain Controller

All generated telemetry is deterministically tagged with [DEMO / SIMULATED].
"""
import time
import argparse
import threading
from typing import List, Dict, Any
from agent.core.agent import ForensicAgent
from agent.security.capabilities import get_platform_capabilities

SIMULATED_FLEET: List[Dict[str, Any]] = [
    {
        "agent_id": "AGENT-WIN-01",
        "hostname": "WIN11-WORKSTATION-SEC",
        "platform": "Windows",
        "os_version": "10.0.22631 (Windows 11 Enterprise) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.1.14"
    },
    {
        "agent_id": "AGENT-WIN-02",
        "hostname": "WIN10-PRO-FINANCE",
        "platform": "Windows",
        "os_version": "10.0.19045 (Windows 10 Pro) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.1.22"
    },
    {
        "agent_id": "AGENT-WIN-03",
        "hostname": "WIN11-DEV-STATION",
        "platform": "Windows",
        "os_version": "10.0.22631 (Windows 11 Enterprise) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.1.35"
    },
    {
        "agent_id": "AGENT-LINUX-01",
        "hostname": "UBUNTU-CORE-PROD01",
        "platform": "Linux",
        "os_version": "Linux 6.8.0-40-generic (Ubuntu 24.04 LTS) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.2.55"
    },
    {
        "agent_id": "AGENT-LINUX-02",
        "hostname": "DEBIAN12-DB-CLUSTER",
        "platform": "Linux",
        "os_version": "Linux 6.1.0-21-amd64 (Debian 12 Bookworm) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.2.60"
    },
    {
        "agent_id": "AGENT-WIN-SERVER-01",
        "hostname": "WIN-SRV-2022-DC01",
        "platform": "Windows",
        "os_version": "10.0.20348 (Windows Server 2022 Datacenter) [DEMO / SIMULATED]",
        "architecture": "x86_64",
        "ip": "10.100.1.10"
    }
]

def run_agent_worker(cfg: Dict[str, Any], backend_url: str, iterations=None, interval=4):
    caps = get_platform_capabilities(cfg["platform"])
    agent = ForensicAgent(
        agent_id=cfg["agent_id"],
        hostname=cfg["hostname"],
        os_platform=cfg["platform"],
        backend_url=backend_url,
        capabilities=caps
    )
    print(f"[*] Enrolling {cfg['agent_id']} ({cfg['hostname']} / {cfg['platform']}) with {len(caps)} capabilities ...")
    agent.register()
    agent.send_heartbeat(status="online")

    count = 0
    while iterations is None or count < iterations:
        agent.send_heartbeat(status="online")
        tasks = agent.poll_tasks()
        if tasks:
            print(f"[+] {cfg['agent_id']} claimed {len(tasks)} assigned task(s)")
            for t in tasks:
                agent.process_task(t)
        count += 1
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="JOCKY 5+ Multi-Agent Fleet Simulator")
    parser.add_argument("--backend", default="http://localhost:8000", help="Backend URL")
    parser.add_argument("--agents", type=int, default=5, help="Number of agents to simulate (5 or 6)")
    parser.add_argument("--once", action="store_true", help="Run a single registration & heartbeat cycle")
    parser.add_argument("--interval", type=int, default=4, help="Heartbeat interval in seconds")
    args = parser.parse_args()

    selected_fleet = SIMULATED_FLEET[:max(args.agents, 5)]
    iters = 1 if args.once else None
    threads = []

    print(f"[*] Starting JOCKY 5+ Multi-Agent Fleet Simulation ({len(selected_fleet)} agents) -> Backend: {args.backend}")
    for cfg in selected_fleet:
        t = threading.Thread(target=run_agent_worker, args=(cfg, args.backend, iters, args.interval), daemon=True)
        t.start()
        threads.append(t)

    if args.once:
        for t in threads:
            t.join()
        print(f"[+] All {len(selected_fleet)} agents successfully completed single cycle.")
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Fleet simulator stopped.")

if __name__ == "__main__":
    main()
