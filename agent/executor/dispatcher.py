"""
JOCKY Forensic Function Dispatcher
Executes allowlisted forensic functions safely and bundles results into verifiable evidence envelopes.
"""
import platform
from typing import Dict, Any, List, Callable
from agent.security.allowlist import validate_task_function
from agent.evidence.evidence_envelope import create_evidence_envelope
from agent.collectors.system_collector import (
    collect_system_info,
    collect_system_hostname,
    collect_system_os,
    collect_system_users,
)
from agent.collectors.process_collector import (
    collect_process_list,
    collect_process_info,
    collect_process_modules,
)
from agent.collectors.file_collector import (
    collect_file_hash,
    collect_file_metadata,
    collect_file_strings,
    calculate_file_entropy,
    collect_filesystem_scan,
)
from agent.collectors.network_collector import (
    collect_network_connections,
    collect_network_interfaces,
    collect_network_dns,
)
from agent.collectors.pe_collector import parse_pe_file
from agent.collectors.persistence_collector import (
    collect_persistence_startup,
    collect_persistence_services,
    collect_persistence_scheduled_tasks,
)

COLLECTOR_REGISTRY: Dict[str, Callable] = {
    # System
    "system.info": collect_system_info,
    "system.hostname": collect_system_hostname,
    "system.os": collect_system_os,
    "system.users": collect_system_users,

    # Process
    "process.list": collect_process_list,
    "process.info": collect_process_info,
    "process.modules": collect_process_modules,

    # File & Filesystem
    "file.hash": collect_file_hash,
    "file.metadata": collect_file_metadata,
    "file.strings": collect_file_strings,
    "file.entropy": calculate_file_entropy,
    "filesystem.scan": collect_filesystem_scan,

    # Network
    "network.connections": collect_network_connections,
    "network.interfaces": collect_network_interfaces,
    "network.dns": collect_network_dns,

    # Persistence
    "persistence.startup": collect_persistence_startup,
    "persistence.scheduled_tasks": collect_persistence_scheduled_tasks,
    "persistence.services": collect_persistence_services,

    # Malware Indicators & PE Analysis
    "malware.hash": collect_file_hash,
    "malware.entropy": calculate_file_entropy,
    "malware.strings": collect_file_strings,
    "malware.pe_info": parse_pe_file,
}

class TaskDispatcher:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.platform_name = platform.system()

    def execute_function(
        self,
        function_name: str,
        arguments: List[Any],
        case_id: str = "DEFAULT-CASE"
    ) -> Dict[str, Any]:
        """Validates function allowlist, executes safe collector, and seals in evidence envelope."""
        # 1. Security Check
        validate_task_function(function_name)

        if function_name == "evidence.collect":
            return create_evidence_envelope(
                case_id=case_id,
                agent_id=self.agent_id,
                collector="evidence.collect",
                platform_name=self.platform_name,
                results={"status": "sealed", "message": "Forensic collection checkpoint reached"}
            )

        collector = COLLECTOR_REGISTRY.get(function_name)
        if not collector:
            raise NotImplementedError(f"Forensic collector '{function_name}' is not implemented.")

        # 2. Execution
        results = collector(*arguments)

        # 3. Evidence Packaging & Cryptographic Sealing
        params_dict = {f"arg_{i}": arg for i, arg in enumerate(arguments)}
        envelope = create_evidence_envelope(
            case_id=case_id,
            agent_id=self.agent_id,
            collector=function_name,
            platform_name=self.platform_name,
            results=results,
            parameters=params_dict
        )
        return envelope
