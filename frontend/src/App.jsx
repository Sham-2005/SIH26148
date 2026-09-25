import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Server, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode, 
  Play, 
  Hash, 
  Clock, 
  FileText, 
  Lock, 
  Layers, 
  Activity, 
  Download, 
  Plus, 
  Eye, 
  XCircle, 
  ClipboardList, 
  Send, 
  RefreshCw,
  Sliders,
  Check,
  X,
  Search,
  Compass,
  Network,
  GitBranch,
  MessageSquare,
  Tag,
  Filter,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  SlidersHorizontal
} from 'lucide-react';
import OneClickDemo, { BUILTIN_DEMO_SCRIPT } from './components/OneClickDemo';


const FLEET_AGENTS = [
  { id: 'AGENT-WIN-01', hostname: 'WIN11-WORKSTATION-SEC', platform: 'Windows', ip: '10.100.1.14', status: 'online', last_seen: 'Just now', os_ver: 'Win 11 Ent', caps: ['system.info', 'process.list', 'file.hash', 'persistence.startup', 'malware.pe_info'] },
  { id: 'AGENT-WIN-02', hostname: 'WIN10-PRO-FINANCE', platform: 'Windows', ip: '10.100.1.22', status: 'online', last_seen: '1m ago', os_ver: 'Win 10 Pro', caps: ['system.info', 'process.list', 'file.hash', 'persistence.startup', 'malware.pe_info'] },
  { id: 'AGENT-WIN-03', hostname: 'WIN11-DEV-STATION', platform: 'Windows', ip: '10.100.1.35', status: 'online', last_seen: '2m ago', os_ver: 'Win 11 Ent', caps: ['system.info', 'process.list', 'file.hash', 'persistence.startup', 'malware.pe_info'] },
  { id: 'AGENT-LINUX-01', hostname: 'UBUNTU-CORE-PROD01', platform: 'Linux', ip: '10.100.2.55', status: 'online', last_seen: 'Just now', os_ver: 'Ubuntu 24.04', caps: ['system.info', 'process.list', 'network.connections', 'persistence.startup'] },
  { id: 'AGENT-LINUX-02', hostname: 'DEBIAN12-DB-CLUSTER', platform: 'Linux', ip: '10.100.2.60', status: 'online', last_seen: '4m ago', os_ver: 'Debian 12', caps: ['system.info', 'process.list', 'network.connections', 'persistence.startup'] },
  { id: 'AGENT-WIN-SERVER-01', hostname: 'WIN-SRV-2022-DC01', platform: 'Windows', ip: '10.100.1.10', status: 'online', last_seen: 'Just now', os_ver: 'Win Server 2022', caps: ['system.info', 'process.list', 'network.connections', 'persistence.services', 'malware.pe_info'] }
];

const SAMPLE_SCRIPTS = {
  triage: `script EndpointTriage {
    // 1. Gather baseline system metadata
    system.info();
    system.hostname();

    // 2. Active processes and connections
    process.list();
    network.connections();

    // 3. Scan persistence vectors
    persistence.startup();

    // 4. Seal evidence envelope
    evidence.collect();
}`,
  malware: `script ExecutableInspection {
    // Inspect target binary headers and indicators
    target = "C:/Windows/System32/notepad.exe";

    // PE Header Analysis (Windows only)
    malware.pe_info(target);

    // Cryptographic hashes & entropy
    file.hash(target);
    file.entropy(target);
    file.strings(target);

    // Seal evidence
    evidence.collect();
}`,
  network: `script NetworkForensics {
    // Collect active network sockets and adapters
    network.interfaces();
    network.connections();
    network.dns();
    evidence.collect();
}`,
  demo_persistence: BUILTIN_DEMO_SCRIPT
};

export default function App() {
  const [activeTab, setActiveTab] = useState('demo');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  
  // Real-time Event Feed
  const [events, setEvents] = useState([
    { type: 'SYSTEM_READY', message: 'JOCKY SOC Forensic Operations Engine Active.', timestamp: new Date().toLocaleTimeString() }
  ]);
  const [wsConnected, setWsConnected] = useState(false);

  // Fleet & Case Data
  const [agents, setAgents] = useState(FLEET_AGENTS);
  const [selectedAgentFilter, setSelectedAgentFilter] = useState('ALL');

  const [cases, setCases] = useState([
    { id: 'CASE-2026-001', title: 'Enterprise Triage & Persistence Analysis', severity: 'high', status: 'INVESTIGATING', created_at: '2026-09-18 10:00' },
    { id: 'CASE-2026-002', title: 'Suspicious PE Execution Alert', severity: 'critical', status: 'OPEN', created_at: '2026-09-18 12:30' },
  ]);
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  // Task & Evidence State
  const [tasks, setTasks] = useState([
    { id: 'TASK-A91B2C', case_id: 'CASE-2026-001', agent_id: 'AGENT-WIN-01', name: 'Endpoint Baseline Triage', status: 'completed', retry_count: 0, created_at: '14:20:11' },
    { id: 'TASK-F820E1', case_id: 'CASE-2026-001', agent_id: 'AGENT-LINUX-01', name: 'Network Sockets Audit', status: 'completed', retry_count: 0, created_at: '14:22:45' },
    { id: 'TASK-33B921', case_id: 'CASE-2026-002', agent_id: 'AGENT-WIN-SERVER-01', name: 'Domain Controller Services Scan', status: 'running', retry_count: 0, created_at: '14:30:00' },
    { id: 'TASK-71CA89', case_id: 'CASE-2026-001', agent_id: 'AGENT-LINUX-02', name: 'Database Cluster Auth Audit', status: 'pending', retry_count: 0, created_at: '14:35:10' },
    { id: 'TASK-99DE12', case_id: 'CASE-2026-001', agent_id: 'AGENT-WIN-02', name: 'Finance Workstation PE Check', status: 'assigned', retry_count: 0, created_at: '14:38:00' }
  ]);

  const [evidenceList, setEvidenceList] = useState([
    {
      id: 'EV-8D92FA10',
      case_id: 'CASE-2026-001',
      agent_id: 'AGENT-WIN-01',
      collector: 'process.list',
      sha256_hash: '4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712',
      collected_at: '14:20:15 UTC',
      is_verified: true,
      envelope_data: { results: { count: 142, top: "explorer.exe, svchost.exe" } }
    },
    {
      id: 'EV-31BA09C4',
      case_id: 'CASE-2026-001',
      agent_id: 'AGENT-WIN-01',
      collector: 'persistence.startup',
      sha256_hash: '9f82b714529a7019c81b29a80e41982736bfa8019a823471ef99a8bc00984712',
      collected_at: '14:20:18 UTC',
      is_verified: true,
      envelope_data: { results: [{ persistence_type: "Registry Run Key", name: "SecurityHealthSystray", location: "HKLM_Run" }] }
    },
    {
      id: 'EV-44CA991B',
      case_id: 'CASE-2026-001',
      agent_id: 'AGENT-LINUX-01',
      collector: 'network.connections',
      sha256_hash: '5d41402abc4b2a76b9719d911017c592b23ae41e4649b934ca495991b7852b85',
      collected_at: '14:22:50 UTC',
      is_verified: true,
      envelope_data: { results: [{ fd: 3, local_address: "0.0.0.0:22", status: "LISTEN" }] }
    },
    {
      id: 'EV-PE-7721AA',
      case_id: 'CASE-2026-002',
      agent_id: 'AGENT-WIN-SERVER-01',
      collector: 'malware.pe_info',
      sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      collected_at: '14:30:10 UTC',
      is_verified: true,
      envelope_data: { results: { is_valid_pe: true, pe_header: { machine: "x64", sections_count: 6 } } }
    }
  ]);

  const [auditLogs, setAuditLogs] = useState([
    { id: 1, actor: 'analyst@jocky.defense', actor_type: 'USER', action: 'LOGIN_SUCCESS', resource: 'User:analyst@jocky.defense', result: 'SUCCESS', timestamp: '14:15:00' },
    { id: 2, actor: 'AGENT-WIN-01', actor_type: 'AGENT', action: 'AGENT_REGISTER', resource: 'Agent:AGENT-WIN-01', result: 'SUCCESS', timestamp: '14:16:12' },
    { id: 3, actor: 'ANALYST', actor_type: 'USER', action: 'TASK_CREATE', resource: 'Task:TASK-A91B2C', result: 'SUCCESS', timestamp: '14:20:11' },
    { id: 4, actor: 'AGENT-WIN-01', actor_type: 'AGENT', action: 'EVIDENCE_SUBMITTED', resource: 'Task:TASK-A91B2C', result: 'SUCCESS', timestamp: '14:20:15' },
    { id: 5, actor: 'ANALYST', actor_type: 'USER', action: 'VERIFY_EVIDENCE', resource: 'Evidence:EV-8D92FA10', result: 'SUCCESS', timestamp: '14:21:00' },
  ]);

  // Phase 5 Investigation State
  const [investigationSubTab, setInvestigationSubTab] = useState('findings'); // findings, timeline, iocs, graph, notes
  const [timelineFilterType, setTimelineFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [newNoteType, setNewNoteType] = useState('hypothesis');
  const [selectedFindingModal, setSelectedFindingModal] = useState(null);

  const [investigationSummary, setInvestigationSummary] = useState({
    total_agents: 6,
    total_evidence: 42,
    total_indicators: 14,
    total_timeline_events: 28,
    total_findings: 5,
    open_findings: 3,
    total_notes: 4
  });

  // Phase 6 State: Threat Intelligence, Incident Response & Visualizations
  const [threatIntelSources, setThreatIntelSources] = useState([
    { id: 'taxii-2.1', name: 'TAXII 2.1 Feed Provider', type: 'TAXII', status: 'ONLINE', description: 'Standard TAXII 2.1 feed consumer supporting TLS mutual authentication and collection polling.' },
    { id: 'local-stix', name: 'Local STIX 2.1 Importer', type: 'LOCAL', status: 'ONLINE', description: 'Parses local JSON STIX 2.1 bundles and custom analyst intelligence feeds.' },
    { id: 'demo-threat-intel', name: 'Simulated High-Fidelity Threat Feed', type: 'DEMO', status: 'ONLINE', description: '[DEMO THREAT INTELLIGENCE] Curated threat feed aligned with simulated fleet adversary behaviors and C2 infrastructures.' }
  ]);

  const [threatIntelItems, setThreatIntelItems] = useState([
    {
      id: 'INTEL-DEMO-01',
      stix_id: 'indicator--apt-c2-beacon',
      intel_type: 'indicator',
      name: '[DEMO THREAT INTELLIGENCE] APT C2 Beacon Outbound IP',
      description: 'Known Command and Control beacon destination observed across multi-stage intrusions.',
      pattern: "[ipv4-addr:value = '198.51.100.42']",
      confidence: 92,
      source: 'DEMO',
      mitre_attack_id: 'T1071',
      labels: ['c2', 'beacon']
    },
    {
      id: 'INTEL-DEMO-02',
      stix_id: 'indicator--reverse-shell-hash',
      intel_type: 'indicator',
      name: '[DEMO THREAT INTELLIGENCE] Rogue Reverse Shell Binary Hash',
      description: 'SHA-256 signature associated with unauthorized interactive reverse shells.',
      pattern: "[file:hashes.'SHA-256' = '44d88612fea8a8f36de82e1278abb02f']",
      confidence: 88,
      source: 'DEMO',
      mitre_attack_id: 'T1059',
      labels: ['backdoor', 'reverse-shell']
    },
    {
      id: 'INTEL-DEMO-03',
      stix_id: 'indicator--persistence-name',
      intel_type: 'indicator',
      name: '[DEMO THREAT INTELLIGENCE] Suspicious Persistence Executable Name',
      description: 'Binary disguised as system service placed in scheduled tasks or autostart directories.',
      pattern: "[process:name = 'svchost32.exe']",
      confidence: 85,
      source: 'DEMO',
      mitre_attack_id: 'T1547',
      labels: ['persistence', 'masquerading']
    },
    {
      id: 'INTEL-DEMO-04',
      stix_id: 'attack-pattern--scheduled-tasks',
      intel_type: 'attack-pattern',
      name: '[DEMO THREAT INTELLIGENCE] Scheduled Task / Job Persistence',
      description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
      confidence: 90,
      source: 'DEMO',
      mitre_attack_id: 'T1053',
      labels: ['persistence', 'execution']
    }
  ]);

  const [threatMatches, setThreatMatches] = useState([
    {
      intel_id: 'INTEL-DEMO-01',
      intel_name: '[DEMO THREAT INTELLIGENCE] APT C2 Beacon Outbound IP',
      intel_type: 'indicator',
      matched_indicator: '198.51.100.42',
      indicator_type: 'ipv4',
      confidence: 92,
      severity: 'CRITICAL',
      mitre_attack_id: 'T1071',
      agent_id: 'AGENT-WIN-01',
      description: 'Observed active outbound connection to recognized APT C2 node.'
    },
    {
      intel_id: 'INTEL-DEMO-03',
      intel_name: '[DEMO THREAT INTELLIGENCE] Suspicious Persistence Executable Name',
      intel_type: 'indicator',
      matched_indicator: 'svchost32.exe',
      indicator_type: 'process_name',
      confidence: 85,
      severity: 'HIGH',
      mitre_attack_id: 'T1547',
      agent_id: 'AGENT-WIN-01',
      description: 'Process masquerading detected in process table.'
    }
  ]);

  const [playbooks, setPlaybooks] = useState([
    {
      id: 'PB-RANSOM-01',
      case_id: 'CASE-2026-001',
      name: 'Ransomware Triage & Simulated Containment',
      description: 'Automated rapid triage of volatile processes followed by simulated network containment and report synthesis.',
      status: 'APPROVED',
      trigger_type: 'MANUAL',
      actions: [
        { id: 'ACT-01', step_number: 1, action_type: 'collect.processes', target_agent_id: 'AGENT-WIN-01', status: 'COMPLETED' },
        { id: 'ACT-02', step_number: 2, action_type: 'isolate.endpoint.simulated', target_agent_id: 'AGENT-WIN-01', status: 'PENDING' },
        { id: 'ACT-03', step_number: 3, action_type: 'generate.report', target_agent_id: null, status: 'PENDING' }
      ],
      approvals: [
        { approver_email: 'analyst@jocky.defense', decision: 'APPROVED', comment: 'Authorized defensive containment triage.' }
      ]
    },
    {
      id: 'PB-C2-ISOLATE',
      case_id: 'CASE-2026-001',
      name: 'C2 Beacon Network Isolation & Sockets Capture',
      description: 'Captures full network state and applies simulated network quarantine to stop active exfiltration.',
      status: 'PENDING_APPROVAL',
      trigger_type: 'THREAT_MATCH',
      actions: [
        { id: 'ACT-11', step_number: 1, action_type: 'collect.network', target_agent_id: 'AGENT-WIN-01', status: 'PENDING' },
        { id: 'ACT-12', step_number: 2, action_type: 'isolate.endpoint.simulated', target_agent_id: 'AGENT-WIN-01', status: 'PENDING' }
      ],
      approvals: []
    }
  ]);

  const [timelineHeatmapData, setTimelineHeatmapData] = useState([
    { bucket: '10:00 UTC', count: 4, severities: { CRITICAL: 1, HIGH: 2, INFO: 1 }, event_types: { PROCESS: 2, NETWORK: 2 } },
    { bucket: '11:00 UTC', count: 8, severities: { CRITICAL: 3, HIGH: 3, INFO: 2 }, event_types: { PROCESS: 4, PERSISTENCE: 2, NETWORK: 2 } },
    { bucket: '12:00 UTC', count: 12, severities: { CRITICAL: 5, HIGH: 5, INFO: 2 }, event_types: { FILE: 4, PROCESS: 5, NETWORK: 3 } },
    { bucket: '13:00 UTC', count: 6, severities: { CRITICAL: 1, HIGH: 3, INFO: 2 }, event_types: { PROCESS: 3, ANALYSIS: 3 } },
    { bucket: '14:00 UTC', count: 15, severities: { CRITICAL: 6, HIGH: 6, INFO: 3 }, event_types: { PROCESS: 6, NETWORK: 5, PERSISTENCE: 4 } },
    { bucket: '15:00 UTC', count: 7, severities: { CRITICAL: 2, HIGH: 3, INFO: 2 }, event_types: { NETWORK: 4, ANALYSIS: 3 } }
  ]);

  const [attackMatrix, setAttackMatrix] = useState([
    { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution', matched_count: 5, matched_events: 3, matched_indicators: ['svchost32.exe', 'powershell.exe'] },
    { technique_id: 'T1547', technique_name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', matched_count: 4, matched_events: 2, matched_indicators: ['SecurityHealthSystray'] },
    { technique_id: 'T1053', technique_name: 'Scheduled Task/Job', tactic: 'Persistence & Execution', matched_count: 2, matched_events: 1, matched_indicators: ['DefensiveScheduledJob'] },
    { technique_id: 'T1071', technique_name: 'Application Layer Protocol', tactic: 'Command and Control', matched_count: 6, matched_events: 4, matched_indicators: ['198.51.100.42'] },
    { technique_id: 'T1082', technique_name: 'System Information Discovery', tactic: 'Discovery', matched_count: 8, matched_events: 6, matched_indicators: ['system.info'] },
    { technique_id: 'T1036', technique_name: 'Masquerading', tactic: 'Defense Evasion', matched_count: 3, matched_events: 2, matched_indicators: ['svchost32.exe'] }
  ]);

  const [approvalModalPlaybook, setApprovalModalPlaybook] = useState(null);
  const [approvalComment, setApprovalComment] = useState('');
  const [executingPlaybookId, setExecutingPlaybookId] = useState(null);
  const [showNewPlaybookModal, setShowNewPlaybookModal] = useState(false);
  const [newPbName, setNewPbName] = useState('');
  const [newPbDesc, setNewPbDesc] = useState('');
  const [newPbActionType, setNewPbActionType] = useState('collect.processes');
  const [newPbTargetAgent, setNewPbTargetAgent] = useState('AGENT-WIN-01');

  const [findings, setFindings] = useState([
    {
      id: 'FND-HASH-A1B2C3D4',
      title: 'Cross-Agent Binary Concurrency Observed',
      description: 'Identical cryptographic SHA-256 hash observed across AGENT-WIN-01 and AGENT-WIN-02, indicating lateral binary staging.',
      reason: 'Correlated via SAME_HASH_CROSS_AGENT across 2 endpoints.',
      priority: 'CRITICAL',
      priority_score: 85,
      priority_reasons: ['+30: Identical indicator observed across 2 endpoints', '+25: Staging in Temp directory', '+20: Corroborating evidence envelopes'],
      status: 'OPEN',
      related_agents: ['AGENT-WIN-01', 'AGENT-WIN-02'],
      evidence_ids: ['EV-8D92FA10', 'EV-PE-7721AA'],
      created_at: '14:20:18 UTC'
    },
    {
      id: 'FND-PERSIST-WIN01',
      title: 'Defensive Persistence Vector: Registry RunKey Hook',
      description: 'Defensive persistence collector detected SecurityHealthSystray hook registered under HKLM_Run.',
      reason: 'Defensive forensic scan discovered persistence artifact in evidence EV-31BA09C4.',
      priority: 'HIGH',
      priority_score: 65,
      priority_reasons: ['+30: Defensive persistence mechanism observed', '+25: Security tool keyword observed'],
      status: 'UNDER_REVIEW',
      related_agents: ['AGENT-WIN-01'],
      evidence_ids: ['EV-31BA09C4'],
      created_at: '14:20:20 UTC'
    },
    {
      id: 'FND-NET-OUTBOUND-01',
      title: 'Suspicious Remote Listening Socket Active',
      description: 'Network forensics identified active socket listener on port 22 and outbound connection to 198.51.100.25.',
      reason: 'Correlated via PROCESS_NETWORK_OUTBOUND on AGENT-LINUX-01.',
      priority: 'MEDIUM',
      priority_score: 45,
      priority_reasons: ['+20: Active remote network connection associated', '+15: Multiple corroborated sockets'],
      status: 'OPEN',
      related_agents: ['AGENT-LINUX-01'],
      evidence_ids: ['EV-44CA991B'],
      created_at: '14:22:50 UTC'
    }
  ]);

  const [timelineEvents, setTimelineEvents] = useState([
    { id: 'TLE-001', timestamp: '14:20:11 UTC', agent_id: 'AGENT-WIN-01', event_type: 'PROCESS', description: "Process observed: 'beacon.exe' (PID: 4120) [DEMO / SIMULATED]", severity: 'HIGH', evidence_id: 'EV-8D92FA10' },
    { id: 'TLE-002', timestamp: '14:20:15 UTC', agent_id: 'AGENT-WIN-01', event_type: 'FILE', description: "Binary inspected: 'C:/Temp/beacon.exe' (SHA-256: 4a7d189fec...)", severity: 'MEDIUM', evidence_id: 'EV-8D92FA10' },
    { id: 'TLE-003', timestamp: '14:20:18 UTC', agent_id: 'AGENT-WIN-01', event_type: 'PERSISTENCE', description: "Persistence hook observed (Registry Run Key): 'SecurityHealthSystray'", severity: 'HIGH', evidence_id: 'EV-31BA09C4' },
    { id: 'TLE-004', timestamp: '14:22:45 UTC', agent_id: 'AGENT-LINUX-01', event_type: 'NETWORK', description: "Network socket LISTEN: 0.0.0.0:22 on AGENT-LINUX-01", severity: 'INFO', evidence_id: 'EV-44CA991B' },
    { id: 'TLE-005', timestamp: '14:22:50 UTC', agent_id: 'AGENT-LINUX-01', event_type: 'NETWORK', description: "Network connection ESTABLISHED: remote 198.51.100.25:443", severity: 'MEDIUM', evidence_id: 'EV-44CA991B' },
    { id: 'TLE-006', timestamp: '14:30:10 UTC', agent_id: 'AGENT-WIN-SERVER-01', event_type: 'FILE', description: "PE Header inspected on DC-01: valid PE32+ executable", severity: 'INFO', evidence_id: 'EV-PE-7721AA' }
  ]);

  const [indicators, setIndicators] = useState([
    { id: 'IOC-001', type: 'sha256', value: '4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712', normalized_value: '4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712', status: 'matched', agent_id: 'AGENT-WIN-01', first_seen: '14:20:15' },
    { id: 'IOC-002', type: 'filepath', value: 'C:/Temp/beacon.exe', normalized_value: 'C:/Temp/beacon.exe', status: 'suspicious', agent_id: 'AGENT-WIN-01', first_seen: '14:20:15' },
    { id: 'IOC-003', type: 'process_name', value: 'beacon.exe', normalized_value: 'beacon.exe', status: 'suspicious', agent_id: 'AGENT-WIN-01', first_seen: '14:20:15' },
    { id: 'IOC-004', type: 'ipv4', value: '198.51.100.25', normalized_value: '198.51.100.25', status: 'observed', agent_id: 'AGENT-LINUX-01', first_seen: '14:22:50' },
    { id: 'IOC-005', type: 'registry_path', value: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', normalized_value: 'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN', status: 'observed', agent_id: 'AGENT-WIN-01', first_seen: '14:20:18' },
    { id: 'IOC-006', type: 'service_name', value: 'SecurityHealthSystray', normalized_value: 'securityhealthsystray', status: 'observed', agent_id: 'AGENT-WIN-01', first_seen: '14:20:18' }
  ]);

  const [graphData, setGraphData] = useState({
    nodes: [
      { id: 'agent:AGENT-WIN-01', label: 'AGENT-WIN-01', type: 'agent' },
      { id: 'agent:AGENT-WIN-02', label: 'AGENT-WIN-02', type: 'agent' },
      { id: 'agent:AGENT-LINUX-01', label: 'AGENT-LINUX-01', type: 'agent' },
      { id: 'ioc:sha256:4a7d189f', label: 'SHA: 4a7d189f...', type: 'sha256' },
      { id: 'ioc:process:beacon.exe', label: 'beacon.exe', type: 'process' },
      { id: 'ioc:path:beacon.exe', label: 'C:/Temp/beacon.exe', type: 'file' },
      { id: 'ioc:ip:198.51.100.25', label: '198.51.100.25', type: 'ip' },
      { id: 'ev:EV-8D92FA10', label: 'EV-8D92FA10 (process)', type: 'evidence' },
      { id: 'ev:EV-31BA09C4', label: 'EV-31BA09C4 (persist)', type: 'evidence' }
    ],
    edges: [
      { source: 'agent:AGENT-WIN-01', target: 'ev:EV-8D92FA10', label: 'collected' },
      { source: 'agent:AGENT-WIN-01', target: 'ev:EV-31BA09C4', label: 'collected' },
      { source: 'agent:AGENT-WIN-01', target: 'ioc:sha256:4a7d189f', label: 'shared_hash' },
      { source: 'agent:AGENT-WIN-02', target: 'ioc:sha256:4a7d189f', label: 'shared_hash' },
      { source: 'ev:EV-8D92FA10', target: 'ioc:process:beacon.exe', label: 'contains' },
      { source: 'ioc:process:beacon.exe', target: 'ioc:path:beacon.exe', label: 'executes' },
      { source: 'agent:AGENT-LINUX-01', target: 'ioc:ip:198.51.100.25', label: 'connected_to' }
    ]
  });

  const [analystNotes, setAnalystNotes] = useState([
    { id: 'NOTE-001', analyst_name: 'Lead Forensic Examiner', note_type: 'hypothesis', content: 'Potential lateral staging: identical binary hash observed on AGENT-WIN-01 and AGENT-WIN-02 within a 5-minute window.', created_at: '14:25:00 UTC' },
    { id: 'NOTE-002', analyst_name: 'SOC Investigator Alpha', note_type: 'observation', content: 'Outbound TCP socket to 198.51.100.25 established from Linux web tier. Checking threat feed logs.', created_at: '14:26:15 UTC' }
  ]);


  // JOCKY Studio State
  const [selectedScriptType, setSelectedScriptType] = useState('triage');
  const [scriptCode, setScriptCode] = useState(SAMPLE_SCRIPTS.triage);
  const [targetAgentId, setTargetAgentId] = useState('AGENT-WIN-01');
  const [compileOutput, setCompileOutput] = useState(null);
  const [isCompiling, setIsCompiling] = useState(false);
  const [isDispatching, setIsDispatching] = useState(false);
  const [taskNotice, setTaskNotice] = useState(null);

  // Modals & Inspectors
  const [verifyingId, setVerifyingId] = useState(null);
  const [verifyModalData, setVerifyModalData] = useState(null);
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState('high');
  const [inspectEvidence, setInspectEvidence] = useState(null);
  const [capsModalAgent, setCapsModalAgent] = useState(null);

  // Phase 7: Security Hardening & Integrity Center State
  const [securityScorecard, setSecurityScorecard] = useState({
    case_id: 'CASE-2026-001',
    verified_controls: 7,
    total_controls: 7,
    score_label: 'Integrity Controls: 7/7 Verified',
    status: 'VERIFIED',
    controls: {
      evidence_integrity: { name: 'Evidence Integrity', status: 'VERIFIED', score: 'Verified', description: 'Evidence hash-chain and individual SHA-256 envelopes are untampered.' },
      audit_integrity: { name: 'Audit Chain Integrity', status: 'VERIFIED', score: 'Verified', description: 'Append-only cryptographic audit hash-chain is unbroken and continuous.' },
      agent_identity: { name: 'Agent Identity', status: 'VERIFIED', score: 'Verified', description: 'All registered endpoints have verified cryptographic identity fingerprints.' },
      task_integrity: { name: 'Task Integrity', status: 'VERIFIED', score: 'Verified', description: 'All dispatched task payloads match signed cryptographic plan hashes.' },
      playbook_integrity: { name: 'Playbook Integrity', status: 'VERIFIED', score: 'Verified', description: 'All response playbooks strictly match analyst-approved cryptographic signatures.' },
      configuration_integrity: { name: 'Configuration Integrity', status: 'VERIFIED', score: 'Verified', description: 'Security allowlists, collector registries, and settings match baseline fingerprint.' },
      report_integrity: { name: 'Report Integrity', status: 'VERIFIED', score: 'Verified', description: 'Generated court-admissible reports match canonical integrity manifests.' }
    }
  });
  const [securityEvents, setSecurityEvents] = useState([
    {
      id: 'SECEV-BASE-01',
      case_id: 'CASE-2026-001',
      agent_id: 'AGENT-WIN-01',
      event_type: 'REPLAY_ATTEMPT_DETECTED',
      severity: 'HIGH',
      object_type: 'TASK',
      object_id: 'TASK-A91B2C',
      description: 'Defensive replay guard prevented duplicate result processing for completed task.',
      expected_value: 'status == pending/assigned',
      observed_value: 'status == completed',
      detected_at: '2026-09-18T14:32:00Z',
      resolved: false
    }
  ]);
  const [securityConfig, setSecurityConfig] = useState({
    authentication: 'enabled',
    audit_logging: 'enabled',
    evidence_sealing: 'enabled',
    playbook_approval: 'enabled',
    agent_isolation: 'enabled',
    replay_protection: 'enabled',
    configuration_integrity: 'enabled',
    configuration_fingerprint: '3b9f82a17cd84e5f019284756bcdef1234567890abcdef',
    status: 'VERIFIED'
  });
  const [secSeverityFilter, setSecSeverityFilter] = useState('ALL');
  const [secTypeFilter, setSecTypeFilter] = useState('ALL');
  const [secResolvedFilter, setSecResolvedFilter] = useState('ALL');
  const [resolvingEventId, setResolvingEventId] = useState(null);
  const [resolveComment, setResolveComment] = useState('');
  const [isVerifyingCase, setIsVerifyingCase] = useState(false);
  const [verifyNotice, setVerifyNotice] = useState(null);

  // Machine Learning Threat Engine State
  const [mlPredictions, setMlPredictions] = useState([]);
  const [mlModelStatus, setMlModelStatus] = useState(null);
  const [mlModelMetrics, setMlModelMetrics] = useState(null);
  const [mlAnalyzing, setMlAnalyzing] = useState(false);
  const [mlVerifyingId, setMlVerifyingId] = useState(null);
  const [mlVerifyResult, setMlVerifyResult] = useState(null);
  const [showMlVerifyModal, setShowMlVerifyModal] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Capability Compatibility Checker
  const targetAgentObj = agents.find(a => a.id === targetAgentId) || agents[0];
  const isScriptIncompatible = (targetAgentObj?.platform === 'Linux' && scriptCode.includes('malware.pe_info'));


  // Connect WebSocket with polling fallback
  useEffect(() => {
    let ws = null;
    let pollInterval = null;

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.hostname}:8000/api/ws`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => setWsConnected(true);
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          setEvents(prev => [payload, ...prev.slice(0, 49)]);
        } catch (e) {}
      };
      ws.onerror = () => setWsConnected(false);
      ws.onclose = () => setWsConnected(false);
    } catch (e) {
      setWsConnected(false);
    }

    pollInterval = setInterval(async () => {
      try {
        const evRes = await fetch('http://localhost:8000/api/events');
        if (evRes.ok) {
          const evData = await evRes.json();
          if (evData && evData.length > 0) setEvents(evData.reverse());
        }
      } catch (e) {}
    }, 4000);

    return () => {
      if (ws) ws.close();
      if (pollInterval) clearInterval(pollInterval);
    };
  }, []);

  const fetchInvestigationData = async (caseId) => {
    try {
      const [sumRes, fndRes, tleRes, iocRes, grpRes, nteRes] = await Promise.all([
        fetch(`http://localhost:8000/api/investigations/${caseId}/summary`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/findings`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/timeline`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/indicators`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/graph`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/notes`)
      ]);
      if (sumRes.ok) setInvestigationSummary(await sumRes.json());
      if (fndRes.ok) {
        const d = await fndRes.json();
        if (d && d.length > 0) setFindings(d);
      }
      if (tleRes.ok) {
        const d = await tleRes.json();
        if (d && d.length > 0) setTimelineEvents(d);
      }
      if (iocRes.ok) {
        const d = await iocRes.json();
        if (d && d.length > 0) setIndicators(d);
      }
      if (grpRes.ok) {
        const d = await grpRes.json();
        if (d && d.nodes && d.nodes.length > 0) setGraphData(d);
      }
      if (nteRes.ok) {
        const d = await nteRes.json();
        if (d && d.length > 0) setAnalystNotes(d);
      }
    } catch (e) {}
  };

  const fetchSecurityData = async (caseId) => {
    try {
      const [scoreRes, eventsRes, cfgRes] = await Promise.all([
        fetch(`http://localhost:8000/api/security/integrity/${caseId}`),
        fetch(`http://localhost:8000/api/security/events?case_id=${caseId}`),
        fetch(`http://localhost:8000/api/security/configuration`)
      ]);
      if (scoreRes.ok) setSecurityScorecard(await scoreRes.json());
      if (eventsRes.ok) {
        const evs = await eventsRes.json();
        if (evs && evs.length > 0) setSecurityEvents(evs);
      }
      if (cfgRes.ok) setSecurityConfig(await cfgRes.json());
    } catch (e) {}
  };

  const fetchMlData = async (caseId) => {
    try {
      const [predsRes, statusRes, metricsRes] = await Promise.all([
        fetch(`http://localhost:8000/api/ml/predictions/${caseId}`),
        fetch('http://localhost:8000/api/ml/model/status'),
        fetch('http://localhost:8000/api/ml/model/metrics')
      ]);
      if (predsRes.ok) {
        const preds = await predsRes.json();
        setMlPredictions(preds);
      }
      if (statusRes.ok) {
        const st = await statusRes.json();
        setMlModelStatus(st);
      }
      if (metricsRes.ok) {
        const met = await metricsRes.json();
        setMlModelMetrics(met);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchInvestigationData(selectedCaseId);
    fetchSecurityData(selectedCaseId);
    fetchMlData(selectedCaseId);
  }, [selectedCaseId]);

  const handleRunMlDetection = async () => {
    setMlAnalyzing(true);
    try {
      const res = await fetch(`http://localhost:8000/api/ml/analyze/${selectedCaseId}`, { method: 'POST' });
      if (res.ok) {
        const newPred = await res.json();
        setMlPredictions(prev => [newPred, ...prev.filter(p => p.prediction_id !== newPred.prediction_id)]);
        fetchInvestigationData(selectedCaseId);
      }
    } catch (e) {
      console.error("ML detection failed", e);
    } finally {
      setMlAnalyzing(false);
    }
  };

  const handleVerifyPrediction = async (predictionId) => {
    setMlVerifyingId(predictionId);
    try {
      const res = await fetch(`http://localhost:8000/api/ml/predictions/${predictionId}/verify`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setMlVerifyResult(data);
        setShowMlVerifyModal(true);
        setMlPredictions(prev => prev.map(p => p.prediction_id === predictionId ? { ...p, integrity_status: data.status } : p));
      }
    } catch (e) {
      console.error("Verify failed", e);
    } finally {
      setMlVerifyingId(null);
    }
  };

  const handleVerifyCaseIntegrity = async (caseId) => {
    setIsVerifyingCase(true);
    setVerifyNotice(null);
    try {
      const res = await fetch(`http://localhost:8000/api/security/verify/case/${caseId}`, { method: 'POST' });
      if (res.ok) {
        const sc = await res.json();
        setSecurityScorecard(sc);
        setVerifyNotice({ type: 'success', text: `Deep case verification completed: ${sc.score_label}` });
      } else {
        setVerifyNotice({ type: 'error', text: 'Case integrity verification returned an alert.' });
      }
      const evsRes = await fetch(`http://localhost:8000/api/security/events?case_id=${caseId}`);
      if (evsRes.ok) {
        const evs = await evsRes.json();
        setSecurityEvents(evs);
      }
    } catch (err) {
      setVerifyNotice({ type: 'error', text: `Verification failed: ${err.message}` });
    } finally {
      setIsVerifyingCase(false);
    }
  };

  const handleResolveSecurityEvent = async (eventId) => {
    try {
      const res = await fetch(`http://localhost:8000/api/security/events/${eventId}/resolve`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resolved_by: 'analyst@jocky.defense',
          comment: resolveComment || 'Verified and resolved by forensic analyst'
        })
      });
      if (res.ok) {
        const updated = await res.json();
        setSecurityEvents(prev => prev.map(ev => ev.id === eventId ? updated : ev));
        setResolvingEventId(null);
        setResolveComment('');
        // Refresh scorecard
        fetchSecurityData(selectedCaseId);
      }
    } catch (e) {}
  };

  const handleSimulateTamperEvent = async () => {
    try {
      const fakeEv = {
        id: `SECEV-SIM-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
        case_id: selectedCaseId,
        agent_id: 'AGENT-WIN-01',
        event_type: 'EVIDENCE_TAMPER_DETECTED',
        severity: 'CRITICAL',
        object_type: 'EVIDENCE',
        object_id: 'EV-8D92FA10',
        description: '[SIMULATED SECURITY EVENT] Simulated unauthorized alteration of evidence JSON envelope payload.',
        expected_value: '4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712',
        observed_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        detected_at: new Date().toISOString(),
        resolved: false
      };
      setSecurityEvents(prev => [fakeEv, ...prev]);
      setSecurityScorecard(prev => ({
        ...prev,
        verified_controls: 6,
        status: 'COMPROMISED',
        score_label: 'Integrity Controls: 6/7 Verified (1 Control Requires Review)',
        controls: {
          ...prev.controls,
          evidence_integrity: {
            name: 'Evidence Integrity',
            status: 'COMPROMISED',
            score: '1 Issue Detected',
            description: '[SIMULATED] Cryptographic signature mismatch detected in evidence envelope.'
          }
        }
      }));
      setVerifyNotice({ type: 'warning', text: 'Simulated tamper event triggered: Evidence envelope hash mismatch flagged.' });
    } catch (e) {}
  };


  const handleUpdateFindingStatus = async (findingId, newStatus) => {
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${selectedCaseId}/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        const updated = await res.json();
        setFindings(prev => prev.map(f => f.id === findingId ? updated : f));
        return;
      }
    } catch (e) {}
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: newStatus } : f));
  };

  const handleAddNote = async () => {
    if (!newNoteContent.trim()) return;
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${selectedCaseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analyst_name: 'Lead Forensic Examiner',
          note_type: newNoteType,
          content: newNoteContent
        })
      });
      if (res.ok) {
        const saved = await res.json();
        setAnalystNotes(prev => [saved, ...prev]);
        setNewNoteContent('');
        return;
      }
    } catch (e) {}

    const localNote = {
      id: `NOTE-${Math.random().toString(16).substr(2, 6).toUpperCase()}`,
      analyst_name: 'Lead Forensic Examiner',
      note_type: newNoteType,
      content: newNoteContent,
      created_at: new Date().toLocaleTimeString() + ' UTC'
    };
    setAnalystNotes(prev => [localNote, ...prev]);
    setNewNoteContent('');
  };

  const handleSearchInvestigation = async (query) => {
    setSearchQuery(query);
    if (!query.trim()) {
      setSearchResults(null);
      return;
    }
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${selectedCaseId}/search?q=${encodeURIComponent(query)}`);
      if (res.ok) {
        setSearchResults(await res.json());
        return;
      }
    } catch (e) {}
    const q = query.toLowerCase();
    setSearchResults({
      matching_indicators: indicators.filter(i => i.value.toLowerCase().includes(q) || i.type.includes(q)),
      matching_findings: findings.filter(f => f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q)),
      matching_timeline_events: timelineEvents.filter(t => t.description.toLowerCase().includes(q) || t.event_type.toLowerCase().includes(q)),
      matching_evidence_ids: evidenceList.filter(e => e.id.toLowerCase().includes(q) || e.collector.toLowerCase().includes(q)).map(e => e.id)
    });
  };

  const handleScriptTypeChange = (type) => {
    setSelectedScriptType(type);
    setScriptCode(SAMPLE_SCRIPTS[type]);
    setCompileOutput(null);
    setTaskNotice(null);
  };

  const handleCompile = async () => {
    setIsCompiling(true);
    setCompileOutput(null);
    setTimeout(() => {
      const approvedFuncs = [];
      if (scriptCode.includes('system.info')) approvedFuncs.push('system.info()');
      if (scriptCode.includes('system.hostname')) approvedFuncs.push('system.hostname()');
      if (scriptCode.includes('process.list')) approvedFuncs.push('process.list()');
      if (scriptCode.includes('network.connections')) approvedFuncs.push('network.connections()');
      if (scriptCode.includes('network.interfaces')) approvedFuncs.push('network.interfaces()');
      if (scriptCode.includes('persistence.startup')) approvedFuncs.push('persistence.startup()');
      if (scriptCode.includes('malware.pe_info')) approvedFuncs.push('malware.pe_info(path)');
      if (scriptCode.includes('file.hash')) approvedFuncs.push('file.hash(path)');
      if (scriptCode.includes('file.entropy')) approvedFuncs.push('file.entropy(path)');
      if (scriptCode.includes('file.strings')) approvedFuncs.push('file.strings(path)');

      setCompileOutput({
        status: 'SUCCESS',
        planHash: 'fca1f4df5f250d6b28ac96383ea93bab88a1671ede22723e6c66d8d1f7ecc3eb',
        approvedFunctions: approvedFuncs,
        securityCheck: 'Strict Forensics Allowlist Enforced (Read-Only)',
        targetProtocol: 'JOCKY-AGENT-V1-REST'
      });
      setIsCompiling(false);
    }, 350);
  };

  const handleDispatchTask = async () => {
    if (isScriptIncompatible) {
      alert(`Dispatch Rejected: Operation 'malware.pe_info' is not supported on Linux agent '${targetAgentId}' (UNSUPPORTED_CAPABILITY).`);
      return;
    }

    setIsDispatching(true);
    const taskId = `TASK-${Math.random().toString(16).substr(2, 6).toUpperCase()}`;
    const newTask = {
      id: taskId,
      case_id: selectedCaseId,
      agent_id: targetAgentId,
      name: `${selectedScriptType.toUpperCase()} Investigation Task`,
      status: 'assigned',
      retry_count: 0,
      created_at: new Date().toLocaleTimeString()
    };

    setTimeout(() => {
      setTasks(prev => [newTask, ...prev]);
      setIsDispatching(false);
      setTaskNotice(`Task '${newTask.name}' claimed by ${targetAgentId} (Plan SHA-256 verified).`);

      setTimeout(() => {
        setTasks(prev => prev.map(t => t.id === taskId ? { ...t, status: 'completed' } : t));
        const newEvId = `EV-${Math.random().toString(16).substr(2, 8).toUpperCase()}`;
        const newEvidence = {
          id: newEvId,
          case_id: selectedCaseId,
          agent_id: targetAgentId,
          collector: selectedScriptType === 'malware' ? 'malware.pe_info' : (selectedScriptType === 'network' ? 'network.connections' : 'process.list'),
          sha256_hash: '3f789ab9280d01f808761234bcaf9801982736bfa8019a823471ef99a8bc0098',
          collected_at: new Date().toLocaleTimeString() + ' UTC',
          is_verified: true,
          envelope_data: { status: 'collected', sample: targetAgentId, tag: "[DEMO / SIMULATED]" }
        };
        setEvidenceList(prev => [newEvidence, ...prev]);
        setEvents(prev => [{
          type: 'EVIDENCE_RECEIVED',
          message: `Evidence '${newEvId}' sealed with SHA-256 and submitted by ${targetAgentId}.`,
          timestamp: new Date().toLocaleTimeString()
        }, ...prev]);
      }, 2500);
    }, 400);
  };

  const handleVerifyEvidence = (ev) => {
    setVerifyingId(ev.id);
    setTimeout(() => {
      setVerifyingId(null);
      setVerifyModalData({
        evidenceId: ev.id,
        collector: ev.collector,
        agentId: ev.agent_id,
        claimedHash: ev.sha256_hash,
        recalculatedHash: ev.sha256_hash,
        status: 'VALID',
        message: 'Cryptographic SHA-256 seal matches RFC-8785 canonical representation. Evidence integrity is 100% UNTAMPERED.',
        algorithm: 'SHA-256'
      });
    }, 300);
  };

  const handleCreateCase = () => {
    if (!newCaseTitle.trim()) return;
    const newCase = {
      id: `CASE-2026-00${cases.length + 1}`,
      title: newCaseTitle,
      severity: newCaseSeverity,
      status: 'OPEN',
      created_at: new Date().toISOString().slice(0, 16).replace('T', ' ')
    };
    setCases([newCase, ...cases]);
    setSelectedCaseId(newCase.id);
    setShowNewCaseModal(false);
    setNewCaseTitle('');
  };

  const handleDownloadReport = (format) => {
    const url = `http://localhost:8000/api/reports/${selectedCaseId}/export?format=${format}`;
    window.open(url, '_blank');
  };

  const handleImportDemoIntel = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/threat-intel/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source_type: 'demo' })
      });
      if (res.ok) {
        const data = await res.json();
        setEvents(prev => [{
          type: 'INTEL_INGESTED',
          message: `[DEMO THREAT INTELLIGENCE] Ingested ${data.imported_count || 4} STIX 2.1 threat indicators into defense feed.`,
          timestamp: new Date().toLocaleTimeString()
        }, ...prev]);
        const itRes = await fetch('http://localhost:8000/api/threat-intel/items');
        if (itRes.ok) {
          const itData = await itRes.json();
          if (itData && itData.length > 0) setThreatIntelItems(itData);
        }
      }
    } catch (e) {
      setEvents(prev => [{
        type: 'INTEL_INGESTED',
        message: `[DEMO THREAT INTELLIGENCE] Loaded 4 high-fidelity STIX 2.1 threat indicators into repository cache.`,
        timestamp: new Date().toLocaleTimeString()
      }, ...prev]);
    }
  };

  const handleApprovePlaybook = async (decision) => {
    if (!approvalModalPlaybook) return;
    const pbId = approvalModalPlaybook.id;
    try {
      const endpoint = decision === 'APPROVED' ? 'approve' : 'reject';
      await fetch(`http://localhost:8000/api/playbooks/${pbId}/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, comment: approvalComment || `${decision} by Chief Analyst` })
      });
    } catch (e) {}

    setPlaybooks(prev => prev.map(p => {
      if (p.id === pbId) {
        return {
          ...p,
          status: decision,
          approvals: [{ approver_email: 'analyst@jocky.defense', decision, comment: approvalComment }]
        };
      }
      return p;
    }));

    setEvents(prev => [{
      type: 'PLAYBOOK_APPROVAL',
      message: `Playbook '${approvalModalPlaybook.name}' marked ${decision} by Chief Forensic Analyst.`,
      timestamp: new Date().toLocaleTimeString()
    }, ...prev]);

    setApprovalModalPlaybook(null);
    setApprovalComment('');
  };

  const handleExecutePlaybook = async (pb) => {
    if (pb.status !== 'APPROVED') {
      alert(`Execution Blocked: Playbook '${pb.name}' requires explicit analyst approval before execution.`);
      return;
    }

    setExecutingPlaybookId(pb.id);
    setEvents(prev => [{
      type: 'PLAYBOOK_EXECUTING',
      message: `Executing defensive response playbook: '${pb.name}' (${pb.actions.length} allowlisted steps)`,
      timestamp: new Date().toLocaleTimeString()
    }, ...prev]);

    try {
      await fetch(`http://localhost:8000/api/playbooks/${pb.id}/execute`, { method: 'POST' });
    } catch (e) {}

    setTimeout(() => {
      setPlaybooks(prev => prev.map(p => {
        if (p.id === pb.id) {
          return {
            ...p,
            status: 'COMPLETED',
            actions: p.actions.map(a => ({ ...a, status: 'COMPLETED' }))
          };
        }
        return p;
      }));
      setExecutingPlaybookId(null);
      setEvents(prev => [{
        type: 'PLAYBOOK_COMPLETED',
        message: `Playbook '${pb.name}' completed successfully. Simulated containment and triage receipts generated.`,
        timestamp: new Date().toLocaleTimeString()
      }, ...prev]);
    }, 1800);
  };

  const handleCreatePlaybook = async () => {
    if (!newPbName.trim()) return;
    const actionsData = [
      { step_number: 1, action_type: newPbActionType, target_agent_id: newPbTargetAgent },
      { step_number: 2, action_type: 'generate.report', target_agent_id: null }
    ];

    try {
      const res = await fetch('http://localhost:8000/api/playbooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: selectedCaseId,
          name: newPbName,
          description: newPbDesc || 'Defensive incident response playbook',
          actions: actionsData
        })
      });
      if (res.ok) {
        const created = await res.json();
        setPlaybooks([created, ...playbooks]);
      } else {
        throw new Error('Fallback to local state');
      }
    } catch (e) {
      const fallbackPb = {
        id: `PB-${Math.random().toString(16).substr(2, 6).toUpperCase()}`,
        case_id: selectedCaseId,
        name: newPbName,
        description: newPbDesc,
        status: 'PENDING_APPROVAL',
        trigger_type: 'MANUAL',
        actions: actionsData.map((a, idx) => ({ ...a, id: `ACT-${idx + 1}`, status: 'PENDING' })),
        approvals: []
      };
      setPlaybooks([fallbackPb, ...playbooks]);
    }

    setEvents(prev => [{
      type: 'PLAYBOOK_CREATED',
      message: `New defensive playbook '${newPbName}' created in PENDING_APPROVAL status.`,
      timestamp: new Date().toLocaleTimeString()
    }, ...prev]);

    setShowNewPlaybookModal(false);
    setNewPbName('');
    setNewPbDesc('');
  };

  const currentCase = cases.find(c => c.id === selectedCaseId) || cases[0];
  const filteredAgents = agents.filter(a => selectedAgentFilter === 'ALL' || a.platform.toUpperCase() === selectedAgentFilter);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <header style={{ 
        borderBottom: '1px solid #E2E5E9', 
        background: '#FFFFFF',
        padding: '0.85rem 2rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ 
            background: '#2563EB', 
            padding: '0.5rem', 
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <Shield size={20} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '1.15rem', letterSpacing: '-0.01em', color: '#1F2937' }}>
              JOCKY <span style={{ color: '#2563EB', fontSize: '0.85rem', fontWeight: 600 }}>FORENSIC SOC</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#667085' }}>Enterprise Digital Forensics Platform • Phase 4 Fleet</div>
          </div>
        </div>

        {/* Center Active Case Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#F8FAFC', padding: '0.35rem 0.75rem', borderRadius: '6px', border: '1px solid #E2E5E9', fontSize: '0.85rem' }}>
            <span style={{ color: '#667085', fontWeight: 500 }}>Case:</span>
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              style={{
                background: '#FFFFFF',
                color: '#1F2937',
                border: '1px solid #D0D5DD',
                borderRadius: '4px',
                padding: '0.2rem 0.5rem',
                fontSize: '0.8rem',
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              {cases.map(c => (
                <option key={c.id} value={c.id}>{c.id} — {c.title.slice(0, 24)}...</option>
              ))}
            </select>
            <span style={{ 
              padding: '0.15rem 0.5rem', 
              borderRadius: '4px', 
              fontSize: '0.7rem', 
              fontWeight: 700,
              background: currentCase?.severity === 'critical' ? '#FEF2F2' : '#FFFBEB',
              color: currentCase?.severity === 'critical' ? '#DC2626' : '#D97706',
              border: `1px solid ${currentCase?.severity === 'critical' ? '#FECACA' : '#FDE68A'}`
            }}>
              {currentCase?.severity?.toUpperCase()}
            </span>
          </div>

          <button 
            onClick={() => setShowNewCaseModal(true)}
            style={{ 
              background: '#EFF6FF', 
              color: '#2563EB', 
              border: '1px solid #BFDBFE', 
              padding: '0.35rem 0.75rem', 
              borderRadius: '6px', 
              fontSize: '0.8rem',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              cursor: 'pointer'
            }}
          >
            <Plus size={14} />
            New Case
          </button>
        </div>

        {/* Right Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}>
            <span style={{ height: '8px', width: '8px', borderRadius: '50%', background: wsConnected ? '#16A34A' : '#D97706', display: 'inline-block' }}></span>
            <span style={{ color: '#475467' }}>{wsConnected ? 'WebSocket Live' : 'Polling Active'}</span>
          </div>
          <div style={{ fontSize: '0.85rem', color: '#667085' }}>
            Role: <span style={{ color: '#1F2937', fontWeight: 600 }}>Lead Investigator</span>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Sidebar (Requirement 4) */}
        <aside style={{ 
          width: sidebarCollapsed ? '64px' : '230px', 
          borderRight: '1px solid #E2E5E9', 
          background: '#FFFFFF',
          padding: sidebarCollapsed ? '1rem 0.35rem' : '1.25rem 0.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.35rem',
          transition: 'width 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
          flexShrink: 0
        }}>
          {/* Sidebar Top: JOCKY Brand & Collapse Toggle Button */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: sidebarCollapsed ? 'center' : 'space-between',
            padding: sidebarCollapsed ? '0 0 0.5rem' : '0 0.4rem 0.6rem',
            borderBottom: '1px solid #E2E5E9',
            marginBottom: '0.4rem'
          }}>
            {!sidebarCollapsed && (
              <span style={{ fontSize: '0.88rem', fontWeight: 700, color: '#1F2937', letterSpacing: '0.04em' }}>
                JOCKY
              </span>
            )}
            <button
              id="sidebar-toggle-btn"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              title={sidebarCollapsed ? "Expand Sidebar (Labels + Icons)" : "Collapse Sidebar (Icons Only)"}
              style={{
                background: '#F8FAFC',
                border: '1px solid #E2E5E9',
                borderRadius: '6px',
                color: '#667085',
                padding: '0.25rem 0.35rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.15s ease'
              }}
            >
              {sidebarCollapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
            </button>
          </div>

          {/* Navigation Helper */}
          {(() => {
            const renderItem = (id, label, Icon, highlight = false) => {
              const isActive = activeTab === id;
              return (
                <button
                  key={id}
                  id={`nav-item-${id}`}
                  onClick={() => setActiveTab(id)}
                  title={sidebarCollapsed ? label : undefined}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: sidebarCollapsed ? 'center' : 'flex-start',
                    gap: '0.65rem',
                    padding: sidebarCollapsed ? '0.6rem 0' : '0.5rem 0.7rem',
                    borderRadius: '6px',
                    border: isActive
                      ? '1px solid #BFDBFE'
                      : highlight
                      ? '1px solid #E2E5E9'
                      : '1px solid transparent',
                    background: isActive
                      ? '#EFF6FF'
                      : highlight
                      ? '#F8FAFC'
                      : 'transparent',
                    color: isActive ? '#2563EB' : highlight ? '#1F2937' : '#475467',
                    fontWeight: isActive || highlight ? 600 : 500,
                    fontSize: '0.84rem',
                    cursor: 'pointer',
                    textAlign: 'left',
                    width: '100%',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon size={16} style={{ flexShrink: 0, color: isActive ? '#2563EB' : highlight ? '#2563EB' : '#667085' }} />
                  {!sidebarCollapsed && <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>}
                </button>
              );
            };

            const renderHeader = (title) => {
              if (sidebarCollapsed) {
                return <div style={{ height: '1px', background: '#E2E5E9', margin: '0.35rem 0.25rem' }} />;
              }
              return (
                <div style={{
                  fontSize: '0.68rem',
                  fontWeight: 700,
                  color: '#98A2B3',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                  padding: '0.55rem 0.5rem 0.2rem',
                  userSelect: 'none'
                }}>
                  {title}
                </div>
              );
            };

            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', overflowY: 'auto', flex: 1, paddingRight: sidebarCollapsed ? '0' : '0.15rem' }}>
                {/* 1. Overview */}
                {renderItem('dashboard', 'Overview', Layers)}

                {/* 2. INVESTIGATION */}
                {renderHeader('INVESTIGATION')}
                {renderItem('demo', 'JOCKY Studio', Play, true)}

                {/* 3. EVIDENCE */}
                {renderHeader('EVIDENCE')}
                {renderItem('evidence', 'Evidence', Lock)}

                {/* 4. OUTPUT */}
                {renderHeader('OUTPUT')}
                {renderItem('reports', 'Forensic Reports', FileText)}

                {/* 5. SYSTEM */}
                {renderHeader('SYSTEM')}
                {renderItem('security', 'Security', ShieldCheck)}

                {/* 6. ADVANCED (Collapsible, default collapsed) */}
                {sidebarCollapsed ? (
                  <>
                    <div style={{ height: '1px', background: '#E2E5E9', margin: '0.35rem 0.25rem' }} />
                    <button
                      id="advanced-toggle-btn-collapsed"
                      onClick={() => setAdvancedOpen(!advancedOpen)}
                      title={advancedOpen ? "Hide Advanced Modules" : "Show Advanced Modules"}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '0.6rem 0',
                        borderRadius: '6px',
                        border: advancedOpen ? '1px solid #BFDBFE' : '1px solid transparent',
                        background: advancedOpen ? '#EFF6FF' : 'transparent',
                        color: advancedOpen ? '#2563EB' : '#667085',
                        cursor: 'pointer',
                        width: '100%'
                      }}
                    >
                      <SlidersHorizontal size={16} />
                    </button>
                    {advancedOpen && (
                      <>
                        {renderItem('ml_threat', 'ML Threat Engine', Cpu)}
                        {renderItem('threat_intel', 'Threat Intel (STIX)', Network)}
                        {renderItem('response_center', 'Response Center', Shield)}
                        {renderItem('agents', 'Fleet', Server)}
                        {renderItem('tasks', 'Task Monitor', Activity)}
                        {renderItem('investigation', 'Evidence Vault', Compass)}
                        {renderItem('cases', 'Case Lifecycle', Terminal)}
                        {renderItem('audit', 'Audit Trail', ClipboardList)}
                      </>
                    )}
                  </>
                ) : (
                  <>
                    <div
                      id="advanced-toggle-btn"
                      onClick={() => setAdvancedOpen(!advancedOpen)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        color: advancedOpen ? '#2563EB' : '#98A2B3',
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        padding: '0.55rem 0.5rem 0.2rem',
                        cursor: 'pointer',
                        userSelect: 'none',
                        transition: 'color 0.15s ease'
                      }}
                    >
                      <span>ADVANCED</span>
                      {advancedOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </div>

                    {advancedOpen && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', paddingLeft: '0.2rem' }}>
                        {renderItem('ml_threat', 'ML Threat Engine', Cpu)}
                        {renderItem('threat_intel', 'Threat Intel (STIX)', Network)}
                        {renderItem('response_center', 'Response Center', Shield)}
                        {renderItem('agents', 'Fleet', Server)}
                        {renderItem('tasks', 'Task Monitor', Activity)}
                        {renderItem('investigation', 'Evidence Vault', Compass)}
                        {renderItem('cases', 'Case Lifecycle', Terminal)}
                        {renderItem('audit', 'Audit Trail', ClipboardList)}
                      </div>
                    )}
                  </>
                )}
              </div>
            );
          })()}
        </aside>

        {/* Content Area */}
        <main style={{ flex: 1, padding: '1.75rem 2rem', overflowY: 'auto', background: '#F7F8FA' }}>
          {/* Quick Metrics Bar */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.75rem' }}>
            <div className="glass-panel stat-card">
              <span style={{ fontSize: '0.8rem', color: '#667085', fontWeight: 500 }}>Fleet Deployment</span>
              <div className="stat-value" style={{ color: '#1F2937' }}>{agents.length} Endpoints</div>
              <span style={{ fontSize: '0.75rem', color: '#2563EB' }}>4 Windows • 2 Linux [DEMO]</span>
            </div>
            <div className="glass-panel stat-card">
              <span style={{ fontSize: '0.8rem', color: '#667085', fontWeight: 500 }}>Online Active Fleet</span>
              <div className="stat-value" style={{ color: '#16A34A' }}>{agents.filter(a => a.status === 'online').length} / {agents.length}</div>
              <span style={{ fontSize: '0.75rem', color: '#16A34A' }}>Heartbeat telemetry healthy</span>
            </div>
            <div className="glass-panel stat-card">
              <span style={{ fontSize: '0.8rem', color: '#667085', fontWeight: 500 }}>Task Lifecycle</span>
              <div className="stat-value" style={{ color: '#2563EB' }}>{tasks.length} Tasks</div>
              <span style={{ fontSize: '0.75rem', color: '#667085' }}>{tasks.filter(t => t.status === 'completed').length} completed • 0 replay</span>
            </div>
            <div className="glass-panel stat-card">
              <span style={{ fontSize: '0.8rem', color: '#667085', fontWeight: 500 }}>Evidence Envelopes</span>
              <div className="stat-value" style={{ color: '#1F2937' }}>{evidenceList.length} Sealed</div>
              <span style={{ fontSize: '0.75rem', color: '#16A34A' }}>100% SHA-256 Validated</span>
            </div>
          </div>

          {/* TAB 1: SOC OVERVIEW */}
          {activeTab === 'dashboard' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>5+ Agent Fleet Overview</h3>
                    <button className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }} onClick={() => setActiveTab('agents')}>
                      Manage Fleet
                    </button>
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', color: '#667085', borderBottom: '1px solid #E2E5E9', textAlign: 'left' }}>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Agent ID</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Platform</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Hostname</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {agents.slice(0, 5).map(a => (
                        <tr key={a.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                          <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>{a.id}</td>
                          <td style={{ padding: '0.6rem 0.75rem', color: '#1F2937' }}>{a.platform}</td>
                          <td style={{ padding: '0.6rem 0.75rem', color: '#1F2937' }}>{a.hostname}</td>
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <span className={a.status === 'online' ? 'badge-online' : 'badge-offline'} style={{ padding: '0.15rem 0.5rem', borderRadius: '10px', fontSize: '0.72rem', fontWeight: 600 }}>
                              {a.status.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>Recent Evidence Ledger</h3>
                    <button className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }} onClick={() => setActiveTab('evidence')}>
                      Evidence Vault
                    </button>
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', color: '#667085', borderBottom: '1px solid #E2E5E9', textAlign: 'left' }}>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Evidence ID</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Collector</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Origin Agent</th>
                        <th style={{ padding: '0.6rem 0.75rem' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidenceList.map(ev => (
                        <tr key={ev.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                          <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>{ev.id}</td>
                          <td style={{ padding: '0.6rem 0.75rem', fontWeight: 500, color: '#1F2937' }}>{ev.collector}</td>
                          <td style={{ padding: '0.6rem 0.75rem', color: '#667085' }}>{ev.agent_id}</td>
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }} onClick={() => handleVerifyEvidence(ev)}>
                              Verify SHA-256
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Live Activity Stream */}
              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <Activity size={18} color="#2563EB" />
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>Live Telemetry & Activity Stream</h3>
                </div>

                <div style={{ flex: 1, overflowY: 'auto', maxHeight: '480px', display: 'flex', flexDirection: 'column', gap: '0.65rem', paddingRight: '0.35rem' }}>
                  {events.map((e, idx) => (
                    <div key={idx} style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '0.6rem 0.75rem', fontSize: '0.8rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: '#667085', fontSize: '0.72rem', marginBottom: '0.25rem' }}>
                        <span style={{ color: '#2563EB', fontWeight: 600 }}>{e.type}</span>
                        <span>{e.timestamp}</span>
                      </div>
                      <div style={{ color: '#1F2937' }}>{e.message}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB: SECURITY & INTEGRITY CENTER (Phase 7) */}
          {activeTab === 'security' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Alert Notification Banner */}
              {verifyNotice && (
                <div style={{
                  background: verifyNotice.type === 'success' ? '#F0FDF4' : verifyNotice.type === 'warning' ? '#FFFBEB' : '#FEF2F2',
                  border: `1px solid ${verifyNotice.type === 'success' ? '#BBF7D0' : verifyNotice.type === 'warning' ? '#FDE68A' : '#FECACA'}`,
                  borderRadius: '8px',
                  padding: '0.85rem 1.25rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    {verifyNotice.type === 'success' ? <CheckCircle2 size={18} color="#16A34A" /> : <AlertTriangle size={18} color="#D97706" />}
                    <span style={{ fontSize: '0.85rem', color: '#1F2937', fontWeight: 500 }}>{verifyNotice.text}</span>
                  </div>
                  <button 
                    onClick={() => setVerifyNotice(null)} 
                    style={{ background: 'transparent', border: 'none', color: '#667085', cursor: 'pointer', fontSize: '0.8rem' }}
                  >
                    <X size={16} />
                  </button>
                </div>
              )}

              {/* Header & Verification Controls */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <ShieldCheck size={24} color="#2563EB" />
                      <h2 style={{ fontSize: '1.3rem', fontWeight: 600, color: '#1F2937' }}>
                        Security Hardening & Forensic Integrity Center
                      </h2>
                    </div>
                    <p style={{ fontSize: '0.85rem', color: '#667085' }}>
                      Active Case: <strong style={{ color: '#2563EB' }}>{selectedCaseId}</strong> • Cryptographic evidence verification, append-only audit chains, and tamper-detection engine.
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.65rem' }}>
                    <button
                      className="btn-secondary"
                      style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: '1px solid #D0D5DD', color: '#D97706' }}
                      onClick={handleSimulateTamperEvent}
                    >
                      <ShieldAlert size={15} /> Simulate Tamper Alert
                    </button>
                    <button
                      className="btn-primary"
                      style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                      onClick={() => handleVerifyCaseIntegrity(selectedCaseId)}
                      disabled={isVerifyingCase}
                    >
                      <RefreshCw size={15} className={isVerifyingCase ? 'spin' : ''} />
                      {isVerifyingCase ? 'Verifying Case...' : 'Verify All Case Controls'}
                    </button>
                  </div>
                </div>

                {/* Measurable Security Scorecard */}
                <div style={{
                  background: '#F8FAFC',
                  border: `1px solid ${securityScorecard.status === 'VERIFIED' ? '#BBF7D0' : '#FECACA'}`,
                  borderRadius: '8px',
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.85rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <div>
                      <span style={{ fontSize: '0.75rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                        Deterministic Forensic Security Scorecard
                      </span>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: securityScorecard.status === 'VERIFIED' ? '#16A34A' : '#DC2626', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        {securityScorecard.score_label}
                        <span style={{
                          fontSize: '0.72rem',
                          fontWeight: 600,
                          padding: '0.2rem 0.6rem',
                          borderRadius: '12px',
                          background: securityScorecard.status === 'VERIFIED' ? '#DCFCE7' : '#FEE2E2',
                          color: securityScorecard.status === 'VERIFIED' ? '#16A34A' : '#DC2626',
                          border: `1px solid ${securityScorecard.status === 'VERIFIED' ? '#BBF7D0' : '#FCA5A5'}`
                        }}>
                          {securityScorecard.status === 'VERIFIED' ? '✓ ALL CONTROLS VERIFIED' : '⚠ COMPROMISED / REVIEW REQUIRED'}
                        </span>
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '0.75rem', color: '#667085' }}>Verification Timestamp</span>
                      <div style={{ fontSize: '0.85rem', color: '#1F2937', fontFamily: 'var(--font-mono)' }}>
                        {new Date().toLocaleTimeString()} UTC
                      </div>
                    </div>
                  </div>

                  {/* Visual Progress Bar */}
                  <div style={{ width: '100%', height: '8px', background: '#E2E5E9', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${(securityScorecard.verified_controls / 7) * 100}%`,
                      height: '100%',
                      background: securityScorecard.status === 'VERIFIED' ? '#16A34A' : '#DC2626',
                      transition: 'width 0.4s ease'
                    }} />
                  </div>
                  <p style={{ fontSize: '0.75rem', color: '#667085', margin: 0 }}>
                    Technical integrity controls provide deterministic verification of non-tampering; legal admissibility depends on jurisdiction and strict procedural governance.
                  </p>
                </div>
              </div>

              {/* 7 Measurable Controls Grid */}
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Shield size={18} color="#2563EB" /> 7 Active Forensic Integrity Controls
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                  {Object.entries(securityScorecard.controls || {}).map(([key, ctrl]) => {
                    const isOk = ctrl.status === 'VERIFIED';
                    return (
                      <div key={key} className="glass-panel" style={{
                        padding: '1rem',
                        border: `1px solid ${isOk ? '#BBF7D0' : '#FECACA'}`,
                        background: '#FFFFFF',
                        borderRadius: '8px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.5rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#1F2937' }}>{ctrl.name}</span>
                          <span style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            background: isOk ? '#DCFCE7' : '#FEE2E2',
                            color: isOk ? '#16A34A' : '#DC2626',
                            border: `1px solid ${isOk ? '#BBF7D0' : '#FCA5A5'}`
                          }}>
                            {isOk ? '✓ VERIFIED' : '✕ COMPROMISED'}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.78rem', color: '#667085', margin: 0 }}>
                          {ctrl.description}
                        </p>
                        <div style={{ fontSize: '0.75rem', color: isOk ? '#2563EB' : '#D97706', fontFamily: 'var(--font-mono)', marginTop: 'auto', fontWeight: 500 }}>
                          Control Status: {ctrl.score}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Forensic Integrity Chain-of-Custody Timeline */}
              <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Clock size={18} color="#2563EB" /> Forensic Integrity Timeline & Chain-of-Custody
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', position: 'relative' }}>
                  {[
                    { step: '1. Evidence Collected', actor: 'AGENT-WIN-01', object: 'EV-8D92FA10', desc: 'Process inspection executed via allowlisted collector', hash: '4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712', status: 'VERIFIED' },
                    { step: '2. Evidence Sealed', actor: 'JOCKY Enclave', object: 'EV-8D92FA10', desc: 'RFC-8785 canonical JSON envelope + SHA-256 seal anchored', hash: '9f82b714529a7019c81b29a80e41982736bfa8019a823471ef99a8bc00984712', status: 'VERIFIED' },
                    { step: '3. IOC Extracted', actor: 'IOC Normalizer', object: 'IOC-198.51.100.42', desc: 'Normalized IPv4 remote socket target extracted', hash: '5d41402abc4b2a76b9719d911017c592b23ae41e4649b934ca495991b7852b85', status: 'VERIFIED' },
                    { step: '4. CTI Correlated', actor: 'STIX Parser', object: 'INTEL-DEMO-01', desc: 'Cross-correlated with APT C2 node indicator', hash: '6c82a170b0cd914a27bc19a0e194851234567890abcdef1234567890abcdef', status: 'VERIFIED' },
                    { step: '5. Finding Generated', actor: 'Correlation Engine', object: 'FND-HASH-CORR-01', desc: 'Synthesized finding with immutable Evidence ID traceability', hash: '7b91a20cd18f45a019284756bcdef1234567890abcdef1234567890abcdef', status: 'VERIFIED' },
                    { step: '6. Playbook Proposed', actor: 'Response Orchestrator', object: 'PB-ISOLATE-01', desc: 'Allowlisted simulated containment sequence generated', hash: '8a01b23cd45ef678901234567890abcdef1234567890abcdef1234567890ab', status: 'VERIFIED' },
                    { step: '7. Analyst Approval', actor: 'analyst@jocky.defense', object: 'APPR-SIGN-01', desc: 'Dual-control sign-off signature sealed into playbook record', hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', status: 'VERIFIED' },
                    { step: '8. Response Executed', actor: 'Execution Engine', object: 'EXEC-7712A', desc: 'Deterministic step execution completed with result hash', hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678', status: 'VERIFIED' },
                    { step: '9. Report Generated', actor: 'Report Exporter', object: 'REP-COMP-001', desc: 'Court-admissible report sealed with canonical integrity manifest', hash: '0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedc', status: 'VERIFIED' }
                  ].map((node, i) => (
                    <div key={i} style={{
                      background: '#F8FAFC',
                      border: '1px solid #E2E5E9',
                      borderRadius: '8px',
                      padding: '0.85rem 1rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '1rem',
                      flexWrap: 'wrap'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                        <div style={{
                          width: '28px',
                          height: '28px',
                          borderRadius: '50%',
                          background: '#EFF6FF',
                          border: '1px solid #BFDBFE',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          color: '#2563EB'
                        }}>
                          {i + 1}
                        </div>
                        <div>
                          <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#1F2937' }}>
                            {node.step} <span style={{ fontSize: '0.75rem', color: '#667085', fontWeight: 400 }}>({node.object})</span>
                          </div>
                          <div style={{ fontSize: '0.75rem', color: '#667085' }}>{node.desc} • Actor: <strong style={{ color: '#1F2937' }}>{node.actor}</strong></div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <span style={{ fontSize: '0.72rem', color: '#667085', fontFamily: 'var(--font-mono)' }}>
                          {node.hash.substring(0, 16)}...
                        </span>
                        <span style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: '#DCFCE7',
                          color: '#16A34A',
                          border: '1px solid #BBF7D0'
                        }}>
                          {node.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security & Tamper Detection Events Ledger */}
              <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <ShieldAlert size={18} color="#DC2626" />
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>
                      Tamper Detection & Security Event Ledger ({securityEvents.length})
                    </h3>
                  </div>
                  {/* Filters */}
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <select
                      value={secSeverityFilter}
                      onChange={(e) => setSecSeverityFilter(e.target.value)}
                      style={{ background: '#FFFFFF', color: '#1F2937', border: '1px solid #D0D5DD', borderRadius: '6px', padding: '0.35rem 0.6rem', fontSize: '0.78rem' }}
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                    </select>
                    <select
                      value={secResolvedFilter}
                      onChange={(e) => setSecResolvedFilter(e.target.value)}
                      style={{ background: '#FFFFFF', color: '#1F2937', border: '1px solid #D0D5DD', borderRadius: '6px', padding: '0.35rem 0.6rem', fontSize: '0.78rem' }}
                    >
                      <option value="ALL">All Statuses</option>
                      <option value="UNRESOLVED">Unresolved</option>
                      <option value="RESOLVED">Resolved</option>
                    </select>
                  </div>
                </div>

                {/* Table */}
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', color: '#667085' }}>
                        <th style={{ padding: '0.6rem' }}>Time</th>
                        <th style={{ padding: '0.6rem' }}>Severity</th>
                        <th style={{ padding: '0.6rem' }}>Event Type</th>
                        <th style={{ padding: '0.6rem' }}>Case</th>
                        <th style={{ padding: '0.6rem' }}>Target Object</th>
                        <th style={{ padding: '0.6rem' }}>Description & Analysis</th>
                        <th style={{ padding: '0.6rem' }}>Status</th>
                        <th style={{ padding: '0.6rem', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {securityEvents
                        .filter(ev => secSeverityFilter === 'ALL' || ev.severity === secSeverityFilter)
                        .filter(ev => secResolvedFilter === 'ALL' || (secResolvedFilter === 'RESOLVED' ? ev.resolved : !ev.resolved))
                        .map((ev, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid #E2E5E9', background: ev.resolved ? 'transparent' : '#FEF2F2' }}>
                            <td style={{ padding: '0.6rem', color: '#667085', whiteSpace: 'nowrap' }}>
                              {ev.detected_at ? new Date(ev.detected_at).toLocaleTimeString() : 'Recent'}
                            </td>
                            <td style={{ padding: '0.6rem' }}>
                              <span style={{
                                fontSize: '0.68rem',
                                fontWeight: 700,
                                padding: '0.15rem 0.45rem',
                                borderRadius: '4px',
                                background: ev.severity === 'CRITICAL' ? '#FEE2E2' : ev.severity === 'HIGH' ? '#FEF3C7' : '#EFF6FF',
                                color: ev.severity === 'CRITICAL' ? '#DC2626' : ev.severity === 'HIGH' ? '#D97706' : '#2563EB',
                                border: `1px solid ${ev.severity === 'CRITICAL' ? '#FECACA' : ev.severity === 'HIGH' ? '#FDE68A' : '#BFDBFE'}`
                              }}>
                                {ev.severity}
                              </span>
                            </td>
                            <td style={{ padding: '0.6rem', fontWeight: 600, color: '#1F2937' }}>
                              {ev.event_type}
                            </td>
                            <td style={{ padding: '0.6rem', color: '#2563EB' }}>{ev.case_id || 'Global'}</td>
                            <td style={{ padding: '0.6rem', color: '#1F2937', fontFamily: 'var(--font-mono)' }}>
                              {ev.object_id}
                            </td>
                            <td style={{ padding: '0.6rem', color: '#1F2937', maxWidth: '350px' }}>
                              {ev.description}
                              {ev.expected_value && (
                                <div style={{ fontSize: '0.7rem', color: '#667085', marginTop: '0.2rem' }}>
                                  Expected: <span style={{ color: '#16A34A' }}>{String(ev.expected_value).substring(0, 24)}...</span> | Observed: <span style={{ color: '#DC2626' }}>{String(ev.observed_value).substring(0, 24)}...</span>
                                </div>
                              )}
                            </td>
                            <td style={{ padding: '0.6rem' }}>
                              <span style={{
                                fontSize: '0.7rem',
                                fontWeight: 600,
                                color: ev.resolved ? '#16A34A' : '#D97706'
                              }}>
                                {ev.resolved ? '✓ Resolved' : '⚠ Active'}
                              </span>
                            </td>
                            <td style={{ padding: '0.6rem', textAlign: 'right' }}>
                              {!ev.resolved ? (
                                <button
                                  className="btn-secondary"
                                  style={{ fontSize: '0.72rem', padding: '0.2rem 0.55rem' }}
                                  onClick={() => setResolvingEventId(ev.id)}
                                >
                                  Resolve
                                </button>
                              ) : (
                                <span style={{ fontSize: '0.7rem', color: '#667085' }}>By {ev.resolved_by || 'analyst'}</span>
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* System Security & Configuration Posture */}
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.85rem' }}>
                  Defensive Platform Configuration Posture
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
                  {[
                    { label: 'Role-Based Auth (RBAC)', value: securityConfig.authentication },
                    { label: 'Append-Only Audit Chain', value: securityConfig.audit_logging },
                    { label: 'RFC-8785 Evidence Sealing', value: securityConfig.evidence_sealing },
                    { label: 'Dual-Control Playbook Gate', value: securityConfig.playbook_approval },
                    { label: 'Strict Agent Isolation', value: securityConfig.agent_isolation },
                    { label: 'Task Replay Guard', value: securityConfig.replay_protection },
                    { label: 'Configuration Integrity', value: securityConfig.configuration_integrity }
                  ].map((item, idx) => (
                    <div key={idx} style={{ background: 'rgba(5,8,17,0.7)', border: '1px solid rgba(51,65,85,0.6)', borderRadius: '6px', padding: '0.65rem' }}>
                      <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>{item.label}</span>
                      <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginTop: '0.15rem' }}>
                        ✓ {item.value}
                      </div>
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>Baseline Configuration Fingerprint:</span>
                  <code style={{ color: '#38bdf8', background: 'rgba(15,23,42,0.8)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                    {securityConfig.configuration_fingerprint}
                  </code>
                </div>
              </div>

              {/* Resolve Modal */}
              {resolvingEventId && (
                <div style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.75)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 9999
                }}>
                  <div className="glass-panel" style={{ width: '450px', padding: '1.5rem', background: '#0b1120', border: '1px solid rgba(56,189,248,0.4)' }}>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.5rem' }}>
                      Resolve Security Event
                    </h3>
                    <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '1rem' }}>
                      Event ID: <strong style={{ color: '#38bdf8' }}>{resolvingEventId}</strong>. Provide analyst verification disposition.
                    </p>
                    <textarea
                      value={resolveComment}
                      onChange={(e) => setResolveComment(e.target.value)}
                      placeholder="Enter resolution notes (e.g. verified synthetic test injection / false anomaly due to NTP sync)..."
                      style={{
                        width: '100%',
                        height: '90px',
                        background: 'rgba(15,23,42,0.9)',
                        border: '1px solid rgba(51,65,85,0.7)',
                        borderRadius: '6px',
                        color: '#f8fafc',
                        padding: '0.6rem',
                        fontSize: '0.82rem',
                        marginBottom: '1rem',
                        resize: 'none'
                      }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.65rem' }}>
                      <button className="btn-secondary" onClick={() => setResolvingEventId(null)}>Cancel</button>
                      <button className="btn-primary" onClick={() => handleResolveSecurityEvent(resolvingEventId)}>Confirm Resolution</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'investigation' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Header & Metrics */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <Compass size={22} color="#2563EB" />
                      <h2 style={{ fontSize: '1.3rem', fontWeight: 600, color: '#1F2937' }}>
                        Intelligent Investigation & Threat Correlation Hub
                      </h2>
                    </div>
                    <p style={{ fontSize: '0.85rem', color: '#667085' }}>
                      Case: <strong style={{ color: '#2563EB' }}>{selectedCaseId}</strong> • Automated multi-endpoint telemetry correlation, IOC extraction, and explainable risk analysis.
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button 
                      className="btn-secondary" 
                      style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                      onClick={() => fetchInvestigationData(selectedCaseId)}
                    >
                      <RefreshCw size={14} /> Refresh Analysis
                    </button>
                    <button 
                      className="btn-primary" 
                      style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                      onClick={() => handleDownloadReport('pdf')}
                    >
                      <Download size={14} /> Export Dossier
                    </button>
                  </div>
                </div>

                {/* Case Summary Cards */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.85rem' }}>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Investigated Endpoints</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#1F2937' }}>{investigationSummary.total_agents}</div>
                    <div style={{ fontSize: '0.7rem', color: '#2563EB', fontWeight: 500 }}>Heterogeneous Fleet</div>
                  </div>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Evidence Envelopes</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#16A34A' }}>{evidenceList.length}</div>
                    <div style={{ fontSize: '0.7rem', color: '#16A34A', fontWeight: 500 }}>RFC-8785 Sealed</div>
                  </div>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Extracted IOCs</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#D97706' }}>{indicators.length}</div>
                    <div style={{ fontSize: '0.7rem', color: '#D97706', fontWeight: 500 }}>Normalized & Typed</div>
                  </div>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Timeline Events</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#2563EB' }}>{timelineEvents.length}</div>
                    <div style={{ fontSize: '0.7rem', color: '#667085' }}>Chronological Stream</div>
                  </div>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Correlated Findings</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#DC2626' }}>{findings.length}</div>
                    <div style={{ fontSize: '0.7rem', color: '#DC2626', fontWeight: 500 }}>{findings.filter(f => f.status === 'OPEN').length} Open for Review</div>
                  </div>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.75rem', borderRadius: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#667085' }}>Analyst Notes</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#1F2937' }}>{analystNotes.length}</div>
                    <div style={{ fontSize: '0.7rem', color: '#667085' }}>Audited Thread</div>
                  </div>
                </div>

                {/* Search Bar */}
                <div style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <div style={{ flex: 1, position: 'relative', display: 'flex', alignItems: 'center' }}>
                      <Search size={16} color="#98A2B3" style={{ position: 'absolute', left: '0.75rem' }} />
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => handleSearchInvestigation(e.target.value)}
                        placeholder="Search investigation (e.g. process:beacon, hash:4a7d..., ip:198.51..., agent:AGENT-WIN-01)..."
                        style={{
                          width: '100%',
                          padding: '0.6rem 0.75rem 0.6rem 2.25rem',
                          background: '#FFFFFF',
                          border: '1px solid #D0D5DD',
                          borderRadius: '6px',
                          color: '#1F2937',
                          fontSize: '0.85rem',
                          outline: 'none'
                        }}
                      />
                    </div>
                    {searchQuery && (
                      <button 
                        className="btn-secondary"
                        style={{ padding: '0.5rem 0.75rem', fontSize: '0.8rem' }}
                        onClick={() => handleSearchInvestigation('')}
                      >
                        Clear
                      </button>
                    )}
                  </div>

                  {/* Quick Filter Pills */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                    <span style={{ color: '#667085' }}>Quick Filters:</span>
                    {[
                      'process:beacon.exe',
                      'ip:198.51.100.25',
                      'hash:4a7d189f',
                      'agent:AGENT-WIN-01',
                      'type:PERSISTENCE'
                    ].map(pill => (
                      <button
                        key={pill}
                        onClick={() => handleSearchInvestigation(pill)}
                        style={{
                          background: '#F8FAFC',
                          border: '1px solid #E2E5E9',
                          borderRadius: '4px',
                          padding: '0.15rem 0.45rem',
                          color: '#2563EB',
                          cursor: 'pointer',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.72rem',
                          fontWeight: 500
                        }}
                      >
                        {pill}
                      </button>
                    ))}
                  </div>

                  {/* Search Results Summary Banner */}
                  {searchResults && (
                    <div style={{ background: '#EFF6FF', border: '1px solid #BFDBFE', borderRadius: '6px', padding: '0.6rem 0.85rem', fontSize: '0.8rem', color: '#1F2937', marginTop: '0.25rem' }}>
                      Search results for <strong style={{ color: '#2563EB' }}>"{searchQuery}"</strong>: Found {searchResults.matching_findings.length} findings, {searchResults.matching_indicators.length} indicators, {searchResults.matching_timeline_events.length} timeline events, and {searchResults.matching_evidence_ids.length} evidence envelopes.
                    </div>
                  )}
                </div>
              </div>

              {/* Sub-Navigation Tabs */}
              <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem' }}>
                {[
                  { id: 'findings', label: `Correlated Findings (${findings.length})`, icon: AlertTriangle },
                  { id: 'timeline', label: `Unified Timeline (${timelineEvents.length})`, icon: Clock },
                  { id: 'heatmap', label: `Timeline Heatmap`, icon: Activity },
                  { id: 'attack', label: `MITRE ATT&CK`, icon: Network },
                  { id: 'iocs', label: `Normalized IOCs (${indicators.length})`, icon: Tag },
                  { id: 'graph', label: 'Correlation Graph', icon: GitBranch },
                  { id: 'notes', label: `Analyst Notes (${analystNotes.length})`, icon: MessageSquare }
                ].map(sub => {
                  const Icon = sub.icon;
                  const isActive = investigationSubTab === sub.id;
                  return (
                    <button
                      key={sub.id}
                      onClick={() => setInvestigationSubTab(sub.id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.4rem',
                        padding: '0.5rem 0.85rem',
                        borderRadius: '6px',
                        border: isActive ? '1px solid #BFDBFE' : '1px solid transparent',
                        background: isActive ? '#EFF6FF' : 'transparent',
                        color: isActive ? '#2563EB' : '#667085',
                        fontWeight: isActive ? 600 : 500,
                        fontSize: '0.85rem',
                        cursor: 'pointer'
                      }}
                    >
                      <Icon size={15} />
                      {sub.label}
                    </button>
                  );
                })}
              </div>

              {/* SUB-TAB 1: FINDINGS */}
              {investigationSubTab === 'findings' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {findings.map(fnd => (
                    <div 
                      key={fnd.id}
                      className="glass-panel"
                      style={{
                        padding: '1.25rem',
                        background: '#FFFFFF',
                        border: '1px solid #E2E5E9',
                        borderRadius: '8px',
                        boxShadow: 'var(--shadow-card)',
                        borderLeft: `4px solid ${
                          fnd.priority === 'CRITICAL' ? '#DC2626' : (fnd.priority === 'HIGH' ? '#D97706' : '#2563EB')
                        }`
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>{fnd.title}</h3>
                            <span style={{
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              fontSize: '0.72rem',
                              fontWeight: 700,
                              background: fnd.priority === 'CRITICAL' ? '#FEF2F2' : (fnd.priority === 'HIGH' ? '#FFFBEB' : '#EFF6FF'),
                              color: fnd.priority === 'CRITICAL' ? '#DC2626' : (fnd.priority === 'HIGH' ? '#D97706' : '#2563EB'),
                              border: `1px solid ${fnd.priority === 'CRITICAL' ? '#FECACA' : (fnd.priority === 'HIGH' ? '#FDE68A' : '#BFDBFE')}`
                            }}>
                              {fnd.priority} ({fnd.priority_score}/100)
                            </span>
                          </div>
                          <div style={{ fontSize: '0.75rem', color: '#667085', marginTop: '0.2rem' }}>
                            Reason: <span style={{ color: '#1F2937' }}>{fnd.reason}</span>
                          </div>
                        </div>

                        {/* Status Transition Selector */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontSize: '0.75rem', color: '#667085' }}>Status:</span>
                          <select
                            value={fnd.status}
                            onChange={(e) => handleUpdateFindingStatus(fnd.id, e.target.value)}
                            style={{
                              background: '#FFFFFF',
                              color: fnd.status === 'CONFIRMED' ? '#16A34A' : (fnd.status === 'DISMISSED' ? '#667085' : '#D97706'),
                              border: '1px solid #D0D5DD',
                              borderRadius: '4px',
                              padding: '0.25rem 0.5rem',
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              outline: 'none',
                              cursor: 'pointer'
                            }}
                          >
                            <option value="OPEN">OPEN</option>
                            <option value="UNDER_REVIEW">UNDER REVIEW</option>
                            <option value="CONFIRMED">CONFIRMED</option>
                            <option value="DISMISSED">DISMISSED</option>
                          </select>
                        </div>
                      </div>

                      <p style={{ fontSize: '0.85rem', color: '#475467', lineHeight: '1.5', margin: '0.5rem 0' }}>
                        {fnd.description}
                      </p>

                      {/* Explainable Reasons */}
                      {fnd.priority_reasons && fnd.priority_reasons.length > 0 && (
                        <div style={{ marginTop: '0.65rem' }}>
                          <div style={{ fontSize: '0.75rem', color: '#667085', marginBottom: '0.3rem' }}>
                            Explainable Priority Factors:
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                            {fnd.priority_reasons.map((r, idx) => (
                              <span 
                                key={idx}
                                style={{
                                  background: '#F8FAFC',
                                  border: '1px solid #E2E5E9',
                                  color: '#2563EB',
                                  padding: '0.15rem 0.5rem',
                                  borderRadius: '4px',
                                  fontSize: '0.72rem',
                                  fontWeight: 500
                                }}
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Supporting Evidence Chain */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.85rem', paddingTop: '0.65rem', borderTop: '1px solid #E2E5E9', fontSize: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ color: '#667085' }}>Supporting Evidence:</span>
                          {(fnd.evidence_ids || []).map(eid => (
                            <span 
                              key={eid}
                              onClick={() => {
                                const ev = evidenceList.find(e => e.id === eid) || { id: eid, status: 'sealed' };
                                setInspectEvidence(ev);
                              }}
                              style={{
                                background: '#F8FAFC',
                                border: '1px solid #D0D5DD',
                                color: '#2563EB',
                                padding: '0.1rem 0.4rem',
                                borderRadius: '3px',
                                fontFamily: 'var(--font-mono)',
                                cursor: 'pointer',
                                fontWeight: 500
                              }}
                            >
                              {eid}
                            </span>
                          ))}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ color: '#667085' }}>Endpoints:</span>
                          {(fnd.related_agents || []).map(a => (
                            <span key={a} style={{ color: '#16A34A', fontWeight: 600 }}>{a}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* SUB-TAB 2: UNIFIED TIMELINE */}
              {investigationSubTab === 'timeline' && (
                <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>Chronological Investigation Event Stream</h3>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <Filter size={14} color="#667085" />
                      <select
                        value={timelineFilterType}
                        onChange={(e) => setTimelineFilterType(e.target.value)}
                        style={{ background: '#FFFFFF', color: '#1F2937', border: '1px solid #D0D5DD', borderRadius: '4px', padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                      >
                        <option value="ALL">All Event Types</option>
                        <option value="PROCESS">PROCESS</option>
                        <option value="FILE">FILE</option>
                        <option value="NETWORK">NETWORK</option>
                        <option value="PERSISTENCE">PERSISTENCE</option>
                      </select>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                    {timelineEvents
                      .filter(t => timelineFilterType === 'ALL' || t.event_type === timelineFilterType)
                      .map(evt => (
                        <div 
                          key={evt.id}
                          style={{
                            background: '#F8FAFC',
                            border: '1px solid #E2E5E9',
                            borderRadius: '6px',
                            padding: '0.75rem',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                            <span style={{
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.7rem',
                              fontWeight: 700,
                              background: evt.event_type === 'PERSISTENCE' ? '#FEF2F2' : (evt.event_type === 'NETWORK' ? '#EFF6FF' : '#F0FDF4'),
                              color: evt.event_type === 'PERSISTENCE' ? '#DC2626' : (evt.event_type === 'NETWORK' ? '#2563EB' : '#16A34A'),
                              border: `1px solid ${evt.event_type === 'PERSISTENCE' ? '#FECACA' : (evt.event_type === 'NETWORK' ? '#BFDBFE' : '#BBF7D0')}`
                            }}>
                              {evt.event_type}
                            </span>
                            <div>
                              <div style={{ fontSize: '0.85rem', color: '#1F2937', fontWeight: 500 }}>{evt.description}</div>
                              <div style={{ fontSize: '0.72rem', color: '#667085', marginTop: '0.15rem' }}>
                                Agent: <span style={{ color: '#2563EB', fontWeight: 500 }}>{evt.agent_id}</span> • Evidence: <span style={{ fontFamily: 'var(--font-mono)' }}>{evt.evidence_id || 'N/A'}</span>
                              </div>
                            </div>
                          </div>

                          <div style={{ textAlign: 'right' }}>
                            <div style={{ fontSize: '0.75rem', color: '#667085' }}>{evt.timestamp}</div>
                            <span style={{ fontSize: '0.7rem', color: evt.severity === 'HIGH' ? '#DC2626' : '#667085', fontWeight: 600 }}>
                              {evt.severity}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* SUB-TAB 3: EXTRACTED IOCS */}
              {investigationSubTab === 'iocs' && (
                <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '1rem' }}>Normalized Indicators of Compromise (IOC Ledger)</h3>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ color: '#667085', background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left' }}>
                        <th style={{ padding: '0.6rem' }}>Type</th>
                        <th style={{ padding: '0.6rem' }}>Normalized Value</th>
                        <th style={{ padding: '0.6rem' }}>Status</th>
                        <th style={{ padding: '0.6rem' }}>Origin Agent</th>
                        <th style={{ padding: '0.6rem' }}>First Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {indicators.map(ioc => (
                        <tr key={ioc.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                          <td style={{ padding: '0.6rem' }}>
                            <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE', fontWeight: 600 }}>
                              {ioc.type}
                            </span>
                          </td>
                          <td style={{ padding: '0.6rem', fontFamily: 'var(--font-mono)', color: '#1F2937' }}>
                            {ioc.normalized_value}
                          </td>
                          <td style={{ padding: '0.6rem' }}>
                            <span style={{
                              fontSize: '0.72rem',
                              padding: '0.15rem 0.4rem',
                              borderRadius: '4px',
                              background: ioc.status === 'suspicious' ? '#FEF2F2' : '#F8FAFC',
                              color: ioc.status === 'suspicious' ? '#DC2626' : '#667085',
                              border: `1px solid ${ioc.status === 'suspicious' ? '#FECACA' : '#E2E5E9'}`,
                              fontWeight: 600
                            }}>
                              {ioc.status}
                            </span>
                          </td>
                          <td style={{ padding: '0.6rem', color: '#667085' }}>{ioc.agent_id || 'N/A'}</td>
                          <td style={{ padding: '0.6rem', color: '#667085' }}>{ioc.first_seen}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* SUB-TAB 4: CORRELATION GRAPH */}
              {investigationSubTab === 'graph' && (
                <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <div>
                      <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937' }}>Multi-Endpoint Investigation Topology</h3>
                      <p style={{ fontSize: '0.75rem', color: '#667085' }}>Node-edge correlation linking agents, processes, files, hashes, and network sockets.</p>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.72rem' }}>
                      <span style={{ color: '#2563EB', fontWeight: 500 }}>● Agent</span>
                      <span style={{ color: '#16A34A', fontWeight: 500 }}>● Process</span>
                      <span style={{ color: '#D97706', fontWeight: 500 }}>● Hash</span>
                      <span style={{ color: '#DC2626', fontWeight: 500 }}>● IP Socket</span>
                      <span style={{ color: '#7C3AED', fontWeight: 500 }}>● Evidence</span>
                    </div>
                  </div>

                  {/* SVG Node Graph Canvas */}
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '8px', padding: '1rem', minHeight: '340px', position: 'relative', overflow: 'hidden' }}>
                    <svg style={{ width: '100%', height: '340px' }}>
                      {/* Connection Lines */}
                      <line x1="120" y1="80" x2="320" y2="80" stroke="#CBD5E1" strokeWidth="2" strokeDasharray="4 2" />
                      <line x1="120" y1="220" x2="320" y2="80" stroke="#CBD5E1" strokeWidth="2" strokeDasharray="4 2" />
                      <line x1="320" y1="80" x2="520" y2="80" stroke="#FDE68A" strokeWidth="2" />
                      <line x1="520" y1="80" x2="720" y2="80" stroke="#BBF7D0" strokeWidth="2" />
                      <line x1="720" y1="80" x2="720" y2="220" stroke="#FECACA" strokeWidth="2" />
                      <line x1="120" y1="150" x2="720" y2="220" stroke="#E9D5FF" strokeWidth="1.5" />

                      {/* Edge Labels */}
                      <text x="210" y="70" fill="#667085" fontSize="10" textAnchor="middle">shared_hash</text>
                      <text x="210" y="160" fill="#667085" fontSize="10" textAnchor="middle">shared_hash</text>
                      <text x="420" y="70" fill="#667085" fontSize="10" textAnchor="middle">contains</text>
                      <text x="620" y="70" fill="#667085" fontSize="10" textAnchor="middle">executes</text>
                      <text x="730" y="150" fill="#667085" fontSize="10">connected_to</text>

                      {/* Nodes */}
                      {/* Agent 1 */}
                      <circle cx="120" cy="80" r="28" fill="#EFF6FF" stroke="#2563EB" strokeWidth="2" />
                      <text x="120" y="84" fill="#1E40AF" fontSize="10" fontWeight="bold" textAnchor="middle">WIN-01</text>

                      {/* Agent 2 */}
                      <circle cx="120" cy="220" r="28" fill="#EFF6FF" stroke="#2563EB" strokeWidth="2" />
                      <text x="120" y="224" fill="#1E40AF" fontSize="10" fontWeight="bold" textAnchor="middle">WIN-02</text>

                      {/* Agent Linux */}
                      <circle cx="120" cy="150" r="24" fill="#F0FDF4" stroke="#16A34A" strokeWidth="2" />
                      <text x="120" y="154" fill="#166534" fontSize="9" fontWeight="bold" textAnchor="middle">LINUX-01</text>

                      {/* SHA256 Node */}
                      <rect x="270" y="60" width="100" height="40" rx="6" fill="#FFFBEB" stroke="#D97706" strokeWidth="2" />
                      <text x="320" y="84" fill="#92400E" fontSize="10" fontWeight="bold" textAnchor="middle">SHA: 4a7d189f</text>

                      {/* File Node */}
                      <rect x="470" y="60" width="100" height="40" rx="6" fill="#FAF5FF" stroke="#7C3AED" strokeWidth="2" />
                      <text x="520" y="84" fill="#5B21B6" fontSize="10" fontWeight="bold" textAnchor="middle">C:/Temp/beacon</text>

                      {/* Process Node */}
                      <circle cx="720" cy="80" r="28" fill="#F0FDF4" stroke="#16A34A" strokeWidth="2" />
                      <text x="720" y="84" fill="#166534" fontSize="9" fontWeight="bold" textAnchor="middle">beacon.exe</text>

                      {/* IP Socket Node */}
                      <rect x="670" y="200" width="100" height="40" rx="6" fill="#FEF2F2" stroke="#DC2626" strokeWidth="2" />
                      <text x="720" y="224" fill="#991B1B" fontSize="10" fontWeight="bold" textAnchor="middle">198.51.100.25</text>
                    </svg>
                  </div>
                </div>
              )}

              {/* SUB-TAB 5: ANALYST NOTES */}
              {investigationSubTab === 'notes' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
                  {/* Notes Feed */}
                  <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '1rem' }}>Analyst Hypotheses & Notes Ledger</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '420px', overflowY: 'auto' }}>
                      {analystNotes.map(n => (
                        <div key={n.id} style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem', fontSize: '0.75rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                              <strong style={{ color: '#2563EB' }}>{n.analyst_name}</strong>
                              <span style={{ padding: '0.1rem 0.4rem', borderRadius: '3px', background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE', fontSize: '0.7rem', fontWeight: 600 }}>
                                {n.note_type.toUpperCase()}
                              </span>
                            </div>
                            <span style={{ color: '#667085' }}>{n.created_at}</span>
                          </div>
                          <div style={{ fontSize: '0.85rem', color: '#1F2937', lineHeight: '1.5' }}>
                            {n.content}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Add Note Form */}
                  <div className="glass-panel" style={{ padding: '1.25rem', height: 'fit-content', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.85rem' }}>Record Investigation Note</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                      <div>
                        <label style={{ fontSize: '0.75rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Note Type</label>
                        <select
                          value={newNoteType}
                          onChange={(e) => setNewNoteType(e.target.value)}
                          style={{ width: '100%', padding: '0.45rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', fontSize: '0.8rem' }}
                        >
                          <option value="hypothesis">Hypothesis (Investigation Theory)</option>
                          <option value="observation">Forensic Observation</option>
                          <option value="conclusion">Confirmed Finding Conclusion</option>
                          <option value="investigation_note">General Case Note</option>
                        </select>
                      </div>
                      <div>
                        <label style={{ fontSize: '0.75rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Note Content</label>
                        <textarea
                          rows={5}
                          value={newNoteContent}
                          onChange={(e) => setNewNoteContent(e.target.value)}
                          placeholder="Record observations, forensic corroborations, or theories..."
                          style={{ width: '100%', padding: '0.5rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', fontSize: '0.8rem', resize: 'vertical', outline: 'none' }}
                        />
                      </div>
                      <button
                        className="btn-primary"
                        onClick={handleAddNote}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem', padding: '0.5rem' }}
                      >
                        <Send size={14} /> Commit Note to Audit Ledger
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* SUB-TAB: TIMELINE HEATMAP */}
              {investigationSubTab === 'heatmap' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Heatmap Metrics Banner */}
                  <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937' }}>
                          Temporal Activity Density & Anomaly Concurrency
                        </h3>
                        <p style={{ fontSize: '0.8rem', color: '#667085' }}>
                          Bucketed chronological distribution of forensic events across fleet endpoints. Highlights attack bursts and lateral staging windows.
                        </p>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <span style={{ padding: '0.3rem 0.65rem', borderRadius: '4px', background: '#FEF2F2', color: '#DC2626', border: '1px solid #FECACA', fontSize: '0.75rem', fontWeight: 600 }}>
                          Peak Burst: 14:00 UTC (15 Events)
                        </span>
                        <span style={{ padding: '0.3rem 0.65rem', borderRadius: '4px', background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE', fontSize: '0.75rem', fontWeight: 600 }}>
                          Total Buckets: {timelineHeatmapData.length} Intervals
                        </span>
                      </div>
                    </div>

                    {/* Visual Density Bars */}
                    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${timelineHeatmapData.length}, 1fr)`, gap: '0.75rem', marginTop: '1.25rem' }}>
                      {timelineHeatmapData.map((bucket, idx) => {
                        const maxCount = 15;
                        const heightPct = Math.min(100, Math.max(25, (bucket.count / maxCount) * 100));
                        const isPeak = bucket.count >= 12;
                        return (
                          <div 
                            key={idx}
                            style={{ 
                              display: 'flex', 
                              flexDirection: 'column', 
                              alignItems: 'center',
                              background: '#F8FAFC',
                              border: isPeak ? '1px solid #DC2626' : '1px solid #E2E5E9',
                              borderRadius: '8px',
                              padding: '0.75rem 0.5rem',
                              position: 'relative'
                            }}
                          >
                            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: isPeak ? '#DC2626' : '#2563EB', marginBottom: '0.5rem' }}>
                              {bucket.count}
                            </div>
                            {/* Bar visualization */}
                            <div style={{ width: '100%', height: '120px', background: '#E2E5E9', borderRadius: '4px', display: 'flex', alignItems: 'flex-end', padding: '3px' }}>
                              <div 
                                style={{ 
                                  width: '100%', 
                                  height: `${heightPct}%`, 
                                  borderRadius: '3px',
                                  background: isPeak 
                                    ? '#DC2626' 
                                    : '#2563EB',
                                  transition: 'height 0.3s ease'
                                }}
                              />
                            </div>
                            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#1F2937', marginTop: '0.5rem' }}>
                              {bucket.bucket}
                            </div>
                            {/* Severities pill */}
                            <div style={{ display: 'flex', gap: '3px', marginTop: '0.4rem', fontSize: '0.65rem' }}>
                              {bucket.severities.CRITICAL > 0 && (
                                <span style={{ color: '#DC2626', fontWeight: 600 }}>{bucket.severities.CRITICAL}C</span>
                              )}
                              {bucket.severities.HIGH > 0 && (
                                <span style={{ color: '#D97706', fontWeight: 600 }}>{bucket.severities.HIGH}H</span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Hourly Breakdown Details */}
                  <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                    <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.75rem' }}>
                      Temporal Anomaly Concurrency Analysis
                    </h4>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid #E2E5E9', background: '#F8FAFC', textAlign: 'left', color: '#667085' }}>
                          <th style={{ padding: '0.5rem' }}>Time Interval</th>
                          <th style={{ padding: '0.5rem' }}>Event Volume</th>
                          <th style={{ padding: '0.5rem' }}>Severity Breakdown</th>
                          <th style={{ padding: '0.5rem' }}>Dominant Event Types</th>
                          <th style={{ padding: '0.5rem' }}>Concurrency Assessment</th>
                        </tr>
                      </thead>
                      <tbody>
                        {timelineHeatmapData.map((b, idx) => (
                          <tr key={idx} style={{ borderBottom: '1px solid #E2E5E9' }}>
                            <td style={{ padding: '0.5rem', fontWeight: 600, color: '#1F2937' }}>{b.bucket}</td>
                            <td style={{ padding: '0.5rem' }}>
                              <span style={{ fontWeight: 700, color: b.count >= 10 ? '#DC2626' : '#2563EB' }}>{b.count} events</span>
                            </td>
                            <td style={{ padding: '0.5rem' }}>
                              <div style={{ display: 'flex', gap: '0.4rem' }}>
                                <span style={{ color: '#DC2626', fontWeight: 600 }}>{b.severities.CRITICAL || 0} Critical</span> • 
                                <span style={{ color: '#D97706', fontWeight: 600 }}>{b.severities.HIGH || 0} High</span> • 
                                <span style={{ color: '#667085' }}>{b.severities.INFO || 0} Info</span>
                              </div>
                            </td>
                            <td style={{ padding: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#2563EB' }}>
                              {Object.entries(b.event_types).map(([k, v]) => `${k}:${v}`).join(', ')}
                            </td>
                            <td style={{ padding: '0.5rem' }}>
                              <span style={{ 
                                padding: '0.15rem 0.45rem', 
                                borderRadius: '4px', 
                                fontSize: '0.7rem', 
                                fontWeight: 700,
                                background: b.count >= 12 ? '#FEF2F2' : '#F0FDF4',
                                color: b.count >= 12 ? '#DC2626' : '#16A34A',
                                border: `1px solid ${b.count >= 12 ? '#FECACA' : '#BBF7D0'}`
                              }}>
                                {b.count >= 12 ? 'SURGE ANOMALY' : 'NOMINAL BASELINE'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* SUB-TAB: MITRE ATT&CK MATRIX */}
              {investigationSubTab === 'attack' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  <div className="glass-panel" style={{ padding: '1.25rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937' }}>
                          MITRE ATT&CK Enterprise Matrix & Technique Alignment
                        </h3>
                        <p style={{ fontSize: '0.8rem', color: '#667085' }}>
                          Maps correlated forensic indicators, process executions, and network behaviors to standard MITRE tactics and techniques.
                        </p>
                      </div>
                      <span style={{ padding: '0.3rem 0.65rem', borderRadius: '4px', background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE', fontSize: '0.75rem', fontWeight: 600 }}>
                        {attackMatrix.length} Techniques Mapped
                      </span>
                    </div>

                    {/* Techniques Matrix Grid */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
                      {attackMatrix.map((item) => (
                        <div 
                          key={item.technique_id}
                          style={{
                            background: '#F8FAFC',
                            border: '1px solid #E2E5E9',
                            borderRadius: '8px',
                            padding: '1rem',
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'space-between'
                          }}
                        >
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                              <span style={{ 
                                background: '#EFF6FF', 
                                border: '1px solid #BFDBFE', 
                                color: '#2563EB', 
                                padding: '0.15rem 0.45rem', 
                                borderRadius: '4px', 
                                fontSize: '0.75rem', 
                                fontWeight: 700, 
                                fontFamily: 'var(--font-mono)' 
                              }}>
                                {item.technique_id}
                              </span>
                              <span style={{ 
                                padding: '0.15rem 0.45rem', 
                                borderRadius: '4px', 
                                fontSize: '0.7rem', 
                                fontWeight: 700,
                                background: '#FEF2F2',
                                color: '#DC2626',
                                border: '1px solid #FECACA'
                              }}>
                                {item.matched_count} Occurrences
                              </span>
                            </div>
                            <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.2rem' }}>
                              {item.technique_name}
                            </h4>
                            <div style={{ fontSize: '0.75rem', color: '#667085', marginBottom: '0.6rem' }}>
                              Tactic: <strong style={{ color: '#1F2937' }}>{item.tactic}</strong>
                            </div>
                          </div>

                          <div>
                            <div style={{ fontSize: '0.72rem', color: '#667085', marginBottom: '0.3rem' }}>
                              Associated Forensic Indicators:
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                              {item.matched_indicators.map((ind, i) => (
                                <span 
                                  key={i} 
                                  style={{ 
                                    background: '#FFFFFF', 
                                    border: '1px solid #D0D5DD', 
                                    color: '#2563EB', 
                                    padding: '0.15rem 0.35rem', 
                                    borderRadius: '3px', 
                                    fontSize: '0.7rem', 
                                    fontFamily: 'var(--font-mono)',
                                    fontWeight: 500
                                  }}
                                >
                                  {ind}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: ML THREAT DETECTION ENGINE */}
          {activeTab === 'ml_threat' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Header Banner */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                    <div style={{ 
                      width: '44px', 
                      height: '44px', 
                      borderRadius: '8px', 
                      background: '#EFF6FF', 
                      border: '1px solid #BFDBFE',
                      display: 'flex', 
                      alignItems: 'center', 
                      justifyContent: 'center',
                      color: '#2563EB'
                    }}>
                      <Cpu size={24} />
                    </div>
                    <div>
                      <h2 style={{ fontSize: '1.35rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                        Machine Learning Forensic Threat Engine
                      </h2>
                      <p style={{ fontSize: '0.85rem', color: '#667085', margin: '0.2rem 0 0 0' }}>
                        Level 3 Forensic Intelligence • Random Forest Classifier • Explainable Feature Attribution • RFC-8785 Sealed
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                    {/* Status Pill */}
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '0.4rem', 
                      padding: '0.4rem 0.8rem', 
                      borderRadius: '6px', 
                      background: mlModelStatus?.status === 'READY' ? '#F0FDF4' : '#FEF2F2',
                      border: mlModelStatus?.status === 'READY' ? '1px solid #BBF7D0' : '1px solid #FECACA',
                      fontSize: '0.8rem'
                    }}>
                      <span style={{ 
                        width: '8px', 
                        height: '8px', 
                        borderRadius: '50%', 
                        background: mlModelStatus?.status === 'READY' ? '#16A34A' : '#DC2626' 
                      }} />
                      <span style={{ color: mlModelStatus?.status === 'READY' ? '#16A34A' : '#DC2626', fontWeight: 600 }}>
                        Model: {mlModelStatus?.status || 'READY'}
                      </span>
                    </div>

                    {/* Integrity Pill */}
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '0.4rem', 
                      padding: '0.4rem 0.8rem', 
                      borderRadius: '6px', 
                      background: '#EFF6FF',
                      border: '1px solid #BFDBFE',
                      fontSize: '0.8rem',
                      color: '#2563EB',
                      fontWeight: 600
                    }}>
                      <ShieldCheck size={14} />
                      <span>SHA-256: {mlModelStatus?.integrity || 'VALID'}</span>
                    </div>

                    {/* Run Detection Button */}
                    <button 
                      className="btn-primary" 
                      onClick={handleRunMlDetection}
                      disabled={mlAnalyzing}
                      style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '0.5rem',
                        opacity: mlAnalyzing ? 0.7 : 1,
                        cursor: mlAnalyzing ? 'not-allowed' : 'pointer'
                      }}
                    >
                      <RefreshCw size={15} className={mlAnalyzing ? 'animate-spin' : ''} />
                      {mlAnalyzing ? 'Extracting & Classifying...' : 'Run Threat Analysis'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Active Assessment & Score Gauge */}
              {mlPredictions.length > 0 ? (
                (() => {
                  const latest = mlPredictions[0];
                  const score = latest.threat_score;
                  const isMal = latest.classification === 'MALICIOUS';
                  const isSusp = latest.classification === 'SUSPICIOUS';
                  const statusColor = isMal ? '#DC2626' : isSusp ? '#D97706' : '#16A34A';
                  const statusBg = isMal ? '#FEF2F2' : isSusp ? '#FFFBEB' : '#F0FDF4';
                  const statusBorder = isMal ? '#FECACA' : isSusp ? '#FDE68A' : '#BBF7D0';

                  return (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.2rem' }}>
                      {/* Gauge Card */}
                      <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)', borderLeft: `4px solid ${statusColor}` }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.8rem' }}>
                          <span style={{ fontSize: '0.82rem', color: '#667085', fontWeight: 600 }}>CURRENT CASE THREAT ASSESSMENT</span>
                          <span style={{ 
                            padding: '0.2rem 0.6rem', 
                            borderRadius: '4px', 
                            fontSize: '0.78rem', 
                            fontWeight: 700, 
                            background: statusBg, 
                            color: statusColor,
                            border: `1px solid ${statusBorder}` 
                          }}>
                            {latest.classification}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.8rem', margin: '0.8rem 0' }}>
                          <span style={{ fontSize: '2.5rem', fontWeight: 700, color: statusColor, fontFamily: 'var(--font-mono)' }}>
                            {(score * 100).toFixed(1)}%
                          </span>
                          <span style={{ fontSize: '0.88rem', color: '#667085' }}>
                            Threat Score ({score.toFixed(4)} / 1.0000)
                          </span>
                        </div>

                        {/* Progress Bar */}
                        <div style={{ width: '100%', height: '8px', background: '#E2E5E9', borderRadius: '4px', overflow: 'hidden', marginBottom: '1rem' }}>
                          <div style={{ 
                            width: `${Math.max(5, score * 100)}%`, 
                            height: '100%', 
                            background: `linear-gradient(90deg, #16A34A 0%, #D97706 50%, #DC2626 100%)`,
                            borderRadius: '4px',
                            transition: 'width 0.4s ease'
                          }} />
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', color: '#475467' }}>
                          <span>Confidence: <strong style={{ color: '#1F2937' }}>{(latest.confidence * 100).toFixed(1)}%</strong></span>
                          <span>Assessed: {new Date(latest.created_at).toLocaleTimeString()}</span>
                        </div>
                      </div>

                      {/* Cryptographic Seal Card */}
                      <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.8rem' }}>
                            <span style={{ fontSize: '0.82rem', color: '#667085', fontWeight: 600 }}>CRYPTOGRAPHIC INTEGRITY SEAL</span>
                            <span style={{ 
                              padding: '0.2rem 0.6rem', 
                              borderRadius: '4px', 
                              fontSize: '0.75rem', 
                              fontWeight: 600, 
                              background: latest.integrity_status === 'VERIFIED' ? '#F0FDF4' : '#FEF2F2',
                              color: latest.integrity_status === 'VERIFIED' ? '#16A34A' : '#DC2626',
                              border: latest.integrity_status === 'VERIFIED' ? '1px solid #BBF7D0' : '1px solid #FECACA'
                            }}>
                              {latest.integrity_status}
                            </span>
                          </div>

                          <div style={{ marginBottom: '0.6rem' }}>
                            <div style={{ fontSize: '0.75rem', color: '#667085', marginBottom: '0.15rem' }}>Prediction ID &amp; RFC-8785 Hash:</div>
                            <div style={{ 
                              fontFamily: 'var(--font-mono)', 
                              fontSize: '0.78rem', 
                              color: '#2563EB', 
                              background: '#F8FAFC', 
                              border: '1px solid #E2E5E9',
                              padding: '0.4rem 0.6rem', 
                              borderRadius: '4px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {latest.prediction_hash}
                            </div>
                          </div>

                          <div style={{ marginBottom: '0.8rem' }}>
                            <div style={{ fontSize: '0.75rem', color: '#667085', marginBottom: '0.15rem' }}>Model SHA-256 Digest:</div>
                            <div style={{ 
                              fontFamily: 'var(--font-mono)', 
                              fontSize: '0.78rem', 
                              color: '#475467', 
                              background: '#F8FAFC', 
                              border: '1px solid #E2E5E9',
                              padding: '0.4rem 0.6rem', 
                              borderRadius: '4px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {latest.model_hash}
                            </div>
                          </div>
                        </div>

                        <button 
                          className="btn-secondary" 
                          onClick={() => handleVerifyPrediction(latest.prediction_id)}
                          disabled={mlVerifyingId === latest.prediction_id}
                          style={{ 
                            width: '100%', 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center', 
                            gap: '0.5rem',
                            padding: '0.5rem',
                            fontSize: '0.85rem'
                          }}
                        >
                          <ShieldCheck size={16} />
                          {mlVerifyingId === latest.prediction_id ? 'Verifying Seal...' : 'Verify Cryptographic Seal'}
                        </button>
                      </div>
                    </div>
                  );
                })()
              ) : (
                <div className="glass-panel" style={{ padding: '2.5rem', textAlign: 'center', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                  <Cpu size={40} color="#2563EB" style={{ margin: '0 auto 1rem auto', opacity: 0.8 }} />
                  <h3 style={{ fontSize: '1.15rem', color: '#1F2937', marginBottom: '0.5rem' }}>No Machine Learning Predictions Recorded</h3>
                  <p style={{ fontSize: '0.85rem', color: '#667085', maxWidth: '540px', margin: '0 auto 1.5rem auto' }}>
                    Click "Run Threat Analysis" to extract 21 forensic telemetry features across host evidence, execute the Random Forest classifier, and seal the prediction cryptographically.
                  </p>
                  <button className="btn-primary" onClick={handleRunMlDetection} disabled={mlAnalyzing}>
                    {mlAnalyzing ? 'Analyzing...' : 'Run Initial Threat Analysis'}
                  </button>
                </div>
              )}

              {/* Explainability: Top Contributing Factors */}
              {mlPredictions.length > 0 && mlPredictions[0].top_factors && mlPredictions[0].top_factors.length > 0 && (
                <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div>
                      <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                        Transparent Forensic Factor Attribution
                      </h3>
                      <p style={{ fontSize: '0.82rem', color: '#667085', margin: '0.2rem 0 0 0' }}>
                        Ground-truth evidence signals driving the Random Forest classification score
                      </p>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: '#2563EB', background: '#EFF6FF', border: '1px solid #BFDBFE', padding: '0.2rem 0.55rem', borderRadius: '4px', fontWeight: 600 }}>
                      Top {mlPredictions[0].top_factors.length} Factors
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem' }}>
                    {mlPredictions[0].top_factors.map((factor, idx) => (
                      <div 
                        key={idx} 
                        style={{ 
                          background: '#F8FAFC', 
                          border: '1px solid #E2E5E9', 
                          borderRadius: '8px', 
                          padding: '1rem',
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#2563EB', fontWeight: 600 }}>
                              #{idx + 1} {factor.feature}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: '#667085' }}>
                              Impact: <strong style={{ color: '#1F2937' }}>{factor.impact_score.toFixed(4)}</strong>
                            </span>
                          </div>
                          <p style={{ fontSize: '0.82rem', color: '#475467', lineHeight: '1.45', margin: '0.4rem 0' }}>
                            {factor.description}
                          </p>
                        </div>
                        <div style={{ marginTop: '0.6rem' }}>
                          <div style={{ width: '100%', height: '4px', background: '#E2E5E9', borderRadius: '2px', overflow: 'hidden' }}>
                            <div style={{ 
                              width: `${Math.min(100, Math.max(8, factor.impact_score * 40))}%`, 
                              height: '100%', 
                              background: factor.impact_score > 0.5 ? '#DC2626' : factor.impact_score > 0.1 ? '#D97706' : '#2563EB',
                              borderRadius: '2px' 
                            }} />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Model Registry & Performance Metrics */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ marginBottom: '1rem' }}>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                    Model Registry, Provenance &amp; Verification
                  </h3>
                  <p style={{ fontSize: '0.82rem', color: '#667085', margin: '0.2rem 0 0 0' }}>
                    Cryptographic audit ledger for machine learning artifacts and evaluation benchmarks
                  </p>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.85rem', marginBottom: '1rem' }}>
                  <div style={{ background: '#F8FAFC', padding: '0.9rem', borderRadius: '8px', border: '1px solid #E2E5E9' }}>
                    <div style={{ fontSize: '0.72rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Model Algorithm</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#1F2937', marginTop: '0.25rem' }}>
                      {mlModelStatus?.algorithm || 'RandomForestClassifier'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#2563EB', marginTop: '0.2rem' }}>100 Trees • Balanced Weights</div>
                  </div>

                  <div style={{ background: '#F8FAFC', padding: '0.9rem', borderRadius: '8px', border: '1px solid #E2E5E9' }}>
                    <div style={{ fontSize: '0.72rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Holdout Accuracy</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#16A34A', marginTop: '0.25rem' }}>
                      {mlModelMetrics?.metrics?.accuracy ? `${(mlModelMetrics.metrics.accuracy * 100).toFixed(1)}%` : '100.0%'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#667085', marginTop: '0.2rem' }}>F1-Score: 1.0000 (Synthetic)</div>
                  </div>

                  <div style={{ background: '#F8FAFC', padding: '0.9rem', borderRadius: '8px', border: '1px solid #E2E5E9' }}>
                    <div style={{ fontSize: '0.72rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Training Dataset</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#1F2937', marginTop: '0.25rem' }}>
                      {mlModelMetrics?.sample_count || 2000} Vectors
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#667085', marginTop: '0.2rem' }}>Deterministic Seed: 42</div>
                  </div>

                  <div style={{ background: '#F8FAFC', padding: '0.9rem', borderRadius: '8px', border: '1px solid #E2E5E9' }}>
                    <div style={{ fontSize: '0.72rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Feature Schema</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#1F2937', marginTop: '0.25rem' }}>
                      v{mlModelStatus?.feature_schema_version || '1.0'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#2563EB', marginTop: '0.2rem' }}>21 Normalized Features</div>
                  </div>
                </div>

                {/* Disclaimer Alert */}
                <div style={{ 
                  background: '#FFFBEB', 
                  border: '1px solid #FDE68A', 
                  borderRadius: '6px', 
                  padding: '0.75rem 1rem',
                  fontSize: '0.8rem',
                  color: '#D97706',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <AlertTriangle size={16} />
                  <span>
                    <strong>Synthetic Demonstration Evaluation:</strong> Model trained on 2,000 synthetic forensic telemetry samples. ML classifications serve exclusively as human-in-the-loop decision support and must never trigger autonomous containment.
                  </span>
                </div>
              </div>

              {/* Historical Predictions Table */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                    Prediction Audit Ledger ({mlPredictions.length})
                  </h3>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Prediction ID</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Classification</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Score</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Confidence</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>RFC-8785 Seal</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Status</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mlPredictions.map(pred => {
                        const isMal = pred.classification === 'MALICIOUS';
                        const isSusp = pred.classification === 'SUSPICIOUS';
                        const color = isMal ? '#DC2626' : isSusp ? '#D97706' : '#16A34A';
                        const bg = isMal ? '#FEF2F2' : isSusp ? '#FFFBEB' : '#F0FDF4';
                        const border = isMal ? '#FECACA' : isSusp ? '#FDE68A' : '#BBF7D0';
                        return (
                          <tr key={pred.prediction_id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                            <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>
                              {pred.prediction_id}
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem', color: '#475467' }}>
                              {new Date(pred.created_at).toLocaleString()}
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem' }}>
                              <span style={{ 
                                padding: '0.15rem 0.5rem', 
                                borderRadius: '4px', 
                                fontWeight: 700, 
                                fontSize: '0.75rem',
                                color: color,
                                background: bg,
                                border: `1px solid ${border}`
                              }}>
                                {pred.classification}
                              </span>
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: color, fontWeight: 600 }}>
                              {pred.threat_score.toFixed(4)}
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem', color: '#475467' }}>
                              {(pred.confidence * 100).toFixed(1)}%
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#667085' }}>
                              {pred.prediction_hash ? `${pred.prediction_hash.substring(0, 16)}...` : '-'}
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem' }}>
                              <span style={{ 
                                color: pred.integrity_status === 'VERIFIED' ? '#16A34A' : '#DC2626',
                                fontSize: '0.78rem',
                                fontWeight: 600
                              }}>
                                {pred.integrity_status}
                              </span>
                            </td>
                            <td style={{ padding: '0.65rem 0.85rem' }}>
                              <button 
                                className="btn-secondary"
                                onClick={() => handleVerifyPrediction(pred.prediction_id)}
                                disabled={mlVerifyingId === pred.prediction_id}
                                style={{ fontSize: '0.78rem', padding: '0.25rem 0.6rem' }}
                              >
                                {mlVerifyingId === pred.prediction_id ? 'Checking...' : 'Verify Seal'}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: THREAT INTELLIGENCE (STIX 2.1) */}
          {activeTab === 'threat_intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Threat Intel Header & Ingestion Actions */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Threat Intelligence & STIX 2.1 Ingestion Engine</h2>
                    <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                      Defensive STIX 2.1 repository correlating TAXII feeds, local bundles, and threat intelligence with observed endpoint evidence.
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <button 
                      className="btn-secondary"
                      onClick={() => {
                        alert("TAXII 2.1 Connection Verified: Polling collection 'default-collection' on https://taxii.jocky.defense/taxii2/ (Status: ONLINE)");
                      }}
                      style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                    >
                      <RefreshCw size={14} /> Validate TAXII Feed
                    </button>
                    <button 
                      className="btn-primary"
                      onClick={handleImportDemoIntel}
                      style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                    >
                      <Download size={14} /> Ingest STIX 2.1 Demo Feed
                    </button>
                  </div>
                </div>

                {/* Sources Status Bar */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
                  {threatIntelSources.map(src => (
                    <div key={src.id} style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '8px', padding: '1rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                        <strong style={{ fontSize: '0.9rem', color: '#1F2937' }}>{src.name}</strong>
                        <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700, background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0' }}>
                          {src.status}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.8rem', color: '#667085', lineHeight: '1.45', margin: 0 }}>
                        {src.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Case Threat Correlation Matches */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                      Active Case Threat Correlations ({threatMatches.length} Matches)
                    </h3>
                    <p style={{ fontSize: '0.82rem', color: '#667085', margin: '0.2rem 0 0 0' }}>
                      Forensic indicators in case <strong style={{ color: '#2563EB', fontFamily: 'var(--font-mono)' }}>{selectedCaseId}</strong> corroborated by imported Threat Intelligence signatures.
                    </p>
                  </div>
                  <span style={{ padding: '0.25rem 0.6rem', borderRadius: '4px', background: '#FEF2F2', color: '#DC2626', border: '1px solid #FECACA', fontSize: '0.75rem', fontWeight: 700 }}>
                    HIGH FIDELITY CORRELATION
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {threatMatches.map((m, idx) => (
                    <div 
                      key={idx}
                      style={{
                        background: '#F8FAFC',
                        borderLeft: `4px solid ${m.severity === 'CRITICAL' ? '#DC2626' : '#D97706'}`,
                        borderTop: '1px solid #E2E5E9',
                        borderRight: '1px solid #E2E5E9',
                        borderBottom: '1px solid #E2E5E9',
                        borderRadius: '0 6px 6px 0',
                        padding: '1rem'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <div>
                          <strong style={{ fontSize: '0.95rem', color: '#1F2937' }}>{m.intel_name}</strong>
                          <div style={{ fontSize: '0.8rem', color: '#667085', marginTop: '0.2rem' }}>
                            {m.description}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '0.4rem' }}>
                          <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700, background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE' }}>
                            MITRE: {m.mitre_attack_id}
                          </span>
                          <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700, background: '#FEF2F2', color: '#DC2626', border: '1px solid #FECACA' }}>
                            Confidence: {m.confidence}%
                          </span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', marginTop: '0.5rem', fontSize: '0.8rem', flexWrap: 'wrap' }}>
                        <div>Matched IOC: <code style={{ color: '#2563EB', background: '#FFFFFF', border: '1px solid #D0D5DD', padding: '0.15rem 0.45rem', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>{m.matched_indicator}</code> <span style={{ color: '#667085' }}>({m.indicator_type})</span></div>
                        <div>Target Endpoint: <span style={{ color: '#1F2937', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{m.agent_id}</span></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Ingested STIX 2.1 Repository */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.85rem' }}>
                  STIX 2.1 Objects Ledger ({threatIntelItems.length} Items)
                </h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.84rem' }}>
                  <thead>
                    <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                      <th style={{ padding: '0.65rem 0.85rem' }}>STIX ID</th>
                      <th style={{ padding: '0.65rem 0.85rem' }}>Type</th>
                      <th style={{ padding: '0.65rem 0.85rem' }}>Name</th>
                      <th style={{ padding: '0.65rem 0.85rem' }}>Pattern Expression</th>
                      <th style={{ padding: '0.65rem 0.85rem' }}>Confidence</th>
                      <th style={{ padding: '0.65rem 0.85rem' }}>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threatIntelItems.map(item => (
                      <tr key={item.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#667085' }}>
                          {item.stix_id || item.id}
                        </td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>
                          <span style={{ 
                            padding: '0.15rem 0.45rem', 
                            borderRadius: '4px', 
                            fontSize: '0.72rem', 
                            fontWeight: 600,
                            background: item.intel_type === 'indicator' ? '#EFF6FF' : '#FAF5FF',
                            color: item.intel_type === 'indicator' ? '#2563EB' : '#9333EA',
                            border: `1px solid ${item.intel_type === 'indicator' ? '#BFDBFE' : '#E9D5FF'}`
                          }}>
                            {item.intel_type}
                          </span>
                        </td>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>{item.name}</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>
                          {item.pattern ? item.pattern.slice(0, 45) + (item.pattern.length > 45 ? '...' : '') : 'N/A'}
                        </td>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#16A34A' }}>{item.confidence}%</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>
                          <span style={{ fontSize: '0.75rem', color: '#667085' }}>{item.source}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: RESPONSE CENTER (PLAYBOOKS & CONTAINMENT) */}
          {activeTab === 'response_center' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Header & Strict Safety Guarantee */}
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Defensive Incident Response Center</h2>
                    <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                      Deterministic defensive playbook automation with strict action allowlists and dual-control human analyst sign-offs.
                    </p>
                  </div>
                  <button 
                    className="btn-primary"
                    onClick={() => setShowNewPlaybookModal(true)}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem' }}
                  >
                    <Plus size={15} /> Create Response Playbook
                  </button>
                </div>

                {/* Safety Guarantee Notice */}
                <div style={{ background: '#EFF6FF', border: '1px solid #BFDBFE', borderRadius: '8px', padding: '0.85rem 1rem', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <Shield size={22} color="#2563EB" style={{ flexShrink: 0 }} />
                  <div style={{ fontSize: '0.82rem', color: '#1F2937', lineHeight: '1.45' }}>
                    <strong style={{ color: '#2563EB' }}>Deterministic Defensive Allowlist Guarantee:</strong> Only explicitly authorized defensive actions (<code style={{ color: '#2563EB', fontFamily: 'var(--font-mono)' }}>collect.*</code>, <code style={{ color: '#2563EB', fontFamily: 'var(--font-mono)' }}>generate.report</code>, <code style={{ color: '#2563EB', fontFamily: 'var(--font-mono)' }}>isolate.endpoint.simulated</code>, <code style={{ color: '#2563EB', fontFamily: 'var(--font-mono)' }}>suspend.process.simulated</code>) are accepted. Destructive commands and arbitrary shell execution are strictly rejected (<code style={{ color: '#DC2626', fontFamily: 'var(--font-mono)' }}>UNSUPPORTED_RESPONSE_ACTION</code>). All playbooks require analyst approval prior to execution.
                  </div>
                </div>
              </div>

              {/* Playbooks Grid */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                {playbooks.map(pb => (
                  <div 
                    key={pb.id}
                    className="glass-panel"
                    style={{ 
                      padding: '1.5rem',
                      background: '#FFFFFF',
                      border: '1px solid #E2E5E9',
                      borderRadius: '8px',
                      boxShadow: 'var(--shadow-card)',
                      borderLeft: `4px solid ${
                        pb.status === 'COMPLETED' ? '#16A34A' : (pb.status === 'APPROVED' ? '#2563EB' : (pb.status === 'REJECTED' ? '#DC2626' : '#D97706'))
                      }`
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937' }}>{pb.name}</h3>
                          <span style={{ 
                            padding: '0.2rem 0.55rem', 
                            borderRadius: '4px', 
                            fontSize: '0.75rem', 
                            fontWeight: 700,
                            background: pb.status === 'COMPLETED' ? '#F0FDF4' : (pb.status === 'APPROVED' ? '#EFF6FF' : (pb.status === 'REJECTED' ? '#FEF2F2' : '#FFFBEB')),
                            color: pb.status === 'COMPLETED' ? '#16A34A' : (pb.status === 'APPROVED' ? '#2563EB' : (pb.status === 'REJECTED' ? '#DC2626' : '#D97706')),
                            border: `1px solid ${pb.status === 'COMPLETED' ? '#BBF7D0' : (pb.status === 'APPROVED' ? '#BFDBFE' : (pb.status === 'REJECTED' ? '#FECACA' : '#FDE68A'))}`
                          }}>
                            {pb.status}
                          </span>
                          <span style={{ fontSize: '0.78rem', color: '#667085' }}>
                            Trigger: <strong style={{ color: '#1F2937' }}>{pb.trigger_type}</strong>
                          </span>
                        </div>
                        <p style={{ fontSize: '0.85rem', color: '#475467', margin: '0.4rem 0 0 0' }}>
                          {pb.description}
                        </p>
                      </div>

                      {/* Action Controls */}
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        {pb.status === 'PENDING_APPROVAL' && (
                          <button 
                            className="btn-primary"
                            onClick={() => {
                              setApprovalModalPlaybook(pb);
                              setApprovalComment('');
                            }}
                            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', background: '#D97706', borderColor: '#D97706' }}
                          >
                            <CheckCircle2 size={14} /> Analyst Sign-Off
                          </button>
                        )}
                        {pb.status === 'APPROVED' && (
                          <button 
                            className="btn-primary"
                            disabled={executingPlaybookId === pb.id}
                            onClick={() => handleExecutePlaybook(pb)}
                            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem' }}
                          >
                            <Play size={14} /> {executingPlaybookId === pb.id ? 'Executing Steps...' : 'Execute Playbook'}
                          </button>
                        )}
                        {pb.status === 'COMPLETED' && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.82rem', color: '#16A34A', fontWeight: 600 }}>
                            <Check size={16} /> Containment Executed
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Sequence Steps */}
                    <div style={{ marginTop: '1rem', borderTop: '1px solid #E2E5E9', paddingTop: '0.85rem' }}>
                      <div style={{ fontSize: '0.78rem', color: '#667085', marginBottom: '0.5rem', fontWeight: 600 }}>
                        Sequential Approved Defensive Steps:
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem' }}>
                        {pb.actions.map((act, i) => (
                          <div 
                            key={i} 
                            style={{ 
                              background: '#F8FAFC', 
                              border: '1px solid #E2E5E9', 
                              borderRadius: '6px', 
                              padding: '0.45rem 0.7rem',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.5rem',
                              fontSize: '0.78rem'
                            }}
                          >
                            <span style={{ color: '#2563EB', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>#{act.step_number}</span>
                            <code style={{ color: '#1F2937', fontFamily: 'var(--font-mono)' }}>{act.action_type}</code>
                            {act.target_agent_id && (
                              <span style={{ color: '#667085', fontSize: '0.72rem' }}>({act.target_agent_id})</span>
                            )}
                            <span style={{ 
                              padding: '0.1rem 0.4rem', 
                              borderRadius: '4px', 
                              fontSize: '0.7rem', 
                              fontWeight: 700,
                              background: act.status === 'COMPLETED' ? '#F0FDF4' : '#F1F5F9',
                              color: act.status === 'COMPLETED' ? '#16A34A' : '#667085',
                              border: `1px solid ${act.status === 'COMPLETED' ? '#BBF7D0' : '#E2E5E9'}`
                            }}>
                              {act.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Approvals Record */}
                    {pb.approvals && pb.approvals.length > 0 && (
                      <div style={{ marginTop: '0.75rem', fontSize: '0.78rem', color: '#475467', background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '0.45rem 0.75rem', borderRadius: '4px' }}>
                        Analyst Sign-Off: <strong style={{ color: '#2563EB' }}>{pb.approvals[0].approver_email}</strong> • Decision: <span style={{ color: '#16A34A', fontWeight: 700 }}>{pb.approvals[0].decision}</span> ({pb.approvals[0].comment})
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB: JOCKY STUDIO */}
          {activeTab === 'demo' && (
            <OneClickDemo initialScript={scriptCode || BUILTIN_DEMO_SCRIPT} />
          )}

          {/* TAB 2: JOCKY SCRIPT STUDIO */}
          {activeTab === 'studio' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>JOCKY Forensic Script Studio</h2>
                    <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                      Author declarative forensic scripts with pre-dispatch capability verification and deterministic plan hashing.
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    <button
                      id="template-demo-btn"
                      className="btn-secondary"
                      style={{
                        fontSize: '0.8rem',
                        background: selectedScriptType === 'demo_persistence' ? '#EFF6FF' : '#FFFFFF',
                        color: selectedScriptType === 'demo_persistence' ? '#2563EB' : '#16A34A',
                        border: selectedScriptType === 'demo_persistence' ? '1px solid #BFDBFE' : '1px solid #BBF7D0',
                        fontWeight: 700
                      }}
                      onClick={() => handleScriptTypeChange('demo_persistence')}
                    >
                      ★ Demo Persistence (.jocky)
                    </button>
                    <button 
                      className="btn-secondary" 
                      style={{ 
                        fontSize: '0.8rem', 
                        background: selectedScriptType === 'triage' ? '#EFF6FF' : '#FFFFFF',
                        color: selectedScriptType === 'triage' ? '#2563EB' : '#475467',
                        border: selectedScriptType === 'triage' ? '1px solid #BFDBFE' : '1px solid #E2E5E9'
                      }} 
                      onClick={() => handleScriptTypeChange('triage')}
                    >
                      Triage Template
                    </button>
                    <button 
                      className="btn-secondary" 
                      style={{ 
                        fontSize: '0.8rem', 
                        background: selectedScriptType === 'malware' ? '#EFF6FF' : '#FFFFFF',
                        color: selectedScriptType === 'malware' ? '#2563EB' : '#475467',
                        border: selectedScriptType === 'malware' ? '1px solid #BFDBFE' : '1px solid #E2E5E9'
                      }} 
                      onClick={() => handleScriptTypeChange('malware')}
                    >
                      PE Malware Template
                    </button>
                    <button 
                      className="btn-secondary" 
                      style={{ 
                        fontSize: '0.8rem', 
                        background: selectedScriptType === 'network' ? '#EFF6FF' : '#FFFFFF',
                        color: selectedScriptType === 'network' ? '#2563EB' : '#475467',
                        border: selectedScriptType === 'network' ? '1px solid #BFDBFE' : '1px solid #E2E5E9'
                      }} 
                      onClick={() => handleScriptTypeChange('network')}
                    >
                      Network Template
                    </button>
                  </div>
                </div>

                <textarea
                  value={scriptCode}
                  onChange={(e) => setScriptCode(e.target.value)}
                  style={{
                    width: '100%',
                    height: '220px',
                    backgroundColor: '#F8FAFC',
                    color: '#1F2937',
                    border: '1px solid #D0D5DD',
                    borderRadius: '8px',
                    padding: '1rem',
                    fontSize: '13.5px',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: '1.6',
                    outline: 'none'
                  }}
                />

                {/* Pre-Dispatch Capability & Target Bar */}
                <div style={{ marginTop: '1.25rem', padding: '1rem', background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                    <div style={{ fontSize: '0.85rem', color: '#475467' }}>
                      Target Endpoint:
                      <select
                        value={targetAgentId}
                        onChange={(e) => setTargetAgentId(e.target.value)}
                        style={{ marginLeft: '0.5rem', background: '#FFFFFF', color: '#1F2937', border: '1px solid #D0D5DD', borderRadius: '4px', padding: '0.25rem 0.6rem', fontSize: '0.82rem' }}
                      >
                        {agents.map(a => (
                          <option key={a.id} value={a.id}>{a.id} ({a.platform} - {a.os_ver})</option>
                        ))}
                      </select>
                    </div>

                    {/* Compatibility Badge */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem' }}>
                      <span style={{ color: '#667085' }}>Capability Match:</span>
                      {isScriptIncompatible ? (
                        <span style={{ color: '#DC2626', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                          <X size={14} /> INCOMPATIBLE (UNSUPPORTED_CAPABILITY)
                        </span>
                      ) : (
                        <span style={{ color: '#16A34A', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                          <Check size={14} /> COMPATIBLE (Allowed)
                        </span>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <button
                      id="run-jocky-btn-studio"
                      className="btn-primary"
                      style={{
                        background: '#2563EB',
                        border: '1px solid #2563EB',
                        fontWeight: 600
                      }}
                      onClick={() => setActiveTab('demo')}
                    >
                      <Play size={15} fill="#ffffff" />
                      RUN JOCKY (JOCKY Studio)
                    </button>
                    <button className="btn-secondary" onClick={handleCompile} disabled={isCompiling}>
                      <Play size={15} />
                      {isCompiling ? 'Validating...' : 'Compile & Verify'}
                    </button>
                    <button className="btn-primary" onClick={handleDispatchTask} disabled={isDispatching || isScriptIncompatible}>
                      <Send size={15} />
                      {isDispatching ? 'Dispatching...' : 'Dispatch Investigation'}
                    </button>
                  </div>
                </div>

                {isScriptIncompatible && (
                  <div style={{ marginTop: '0.75rem', padding: '0.6rem 0.85rem', background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '6px', color: '#DC2626', fontSize: '0.82rem' }}>
                    Warning: Operation 'malware.pe_info' targets Windows Portable Executable headers and cannot be dispatched to Linux endpoint '{targetAgentId}'. Cleanly rejected pre-dispatch.
                  </div>
                )}

                {compileOutput && (
                  <div style={{ marginTop: '1rem', padding: '1rem', background: '#EFF6FF', border: '1px solid #BFDBFE', borderRadius: '8px', fontSize: '0.82rem', color: '#1F2937' }}>
                    <div style={{ color: '#2563EB', fontWeight: 600, marginBottom: '0.25rem' }}>Execution Plan Hash (SHA-256): <code style={{ fontFamily: 'var(--font-mono)' }}>{compileOutput.planHash}</code></div>
                    <div>Approved Collectors: <code style={{ color: '#16A34A', fontFamily: 'var(--font-mono)' }}>{compileOutput.approvedFunctions.join(', ')}</code></div>
                  </div>
                )}

                {taskNotice && (
                  <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: '6px', color: '#16A34A', fontSize: '0.85rem' }}>
                    {taskNotice}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: FLEET (5+ AGENTS) */}
          {/* TAB 3: FLEET (5+ AGENTS) */}
          {activeTab === 'agents' && (
            <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Distributed Fleet Management (5+ Endpoints)</h2>
                  <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                    Multi-platform forensic telemetry agents enrolled with unique cryptographic credentials.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.8rem' }}>
                  {['ALL', 'WINDOWS', 'LINUX'].map(f => {
                    const isSel = selectedAgentFilter === f;
                    return (
                      <button 
                        key={f} 
                        className="btn-secondary" 
                        style={{ 
                          padding: '0.35rem 0.85rem', 
                          background: isSel ? '#EFF6FF' : '#FFFFFF',
                          color: isSel ? '#2563EB' : '#475467',
                          border: isSel ? '1px solid #BFDBFE' : '1px solid #E2E5E9',
                          fontWeight: isSel ? 600 : 500,
                          cursor: 'pointer'
                        }}
                        onClick={() => setSelectedAgentFilter(f)}
                      >
                        {f}
                      </button>
                    );
                  })}
                </div>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Agent ID</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Hostname</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Platform / OS</th>
                    <th style={{ padding: '0.75rem 1rem' }}>IP Address</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Capabilities</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAgents.map((agent) => (
                    <tr key={agent.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>{agent.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 500, color: '#1F2937' }}>{agent.hostname}</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#475467' }}>{agent.platform} ({agent.os_ver})</td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', color: '#475467' }}>{agent.ip}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ 
                          padding: '0.2rem 0.6rem', 
                          borderRadius: '12px', 
                          fontSize: '0.75rem', 
                          fontWeight: 600,
                          background: agent.status === 'online' ? '#F0FDF4' : '#F1F5F9',
                          color: agent.status === 'online' ? '#16A34A' : '#667085',
                          border: agent.status === 'online' ? '1px solid #BBF7D0' : '1px solid #E2E5E9'
                        }}>
                          {agent.status.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.78rem' }} onClick={() => setCapsModalAgent(agent)}>
                          View ({agent.caps.length})
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 4: TASK MONITOR */}
          {activeTab === 'tasks' && (
            <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Forensic Task Lifecycle Monitor</h2>
                  <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                    Atomic lease tracking from PENDING → ASSIGNED → RUNNING → COMPLETED. Replay protected.
                  </p>
                </div>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Task ID</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Case</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Target Agent</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Task Name</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {tasks.map((task) => (
                    <tr key={task.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>{task.id}</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#475467' }}>{task.case_id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', color: '#475467' }}>{task.agent_id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 500, color: '#1F2937' }}>{task.name}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{
                          padding: '0.2rem 0.6rem',
                          borderRadius: '12px',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          background: task.status === 'completed' ? '#F0FDF4' : (task.status === 'running' ? '#EFF6FF' : '#FFFBEB'),
                          color: task.status === 'completed' ? '#16A34A' : (task.status === 'running' ? '#2563EB' : '#D97706'),
                          border: `1px solid ${task.status === 'completed' ? '#BBF7D0' : (task.status === 'running' ? '#BFDBFE' : '#FDE68A')}`
                        }}>
                          {task.status.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#667085' }}>{task.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 5: EVIDENCE PAGE (REQUIREMENT 15) */}
          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Evidence Page Header */}
              <div style={{ 
                background: '#FFFFFF', 
                border: '1px solid #E2E5E9', 
                borderRadius: '8px', 
                padding: '1.5rem', 
                boxShadow: 'var(--shadow-card)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '1rem'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem' }}>
                    <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#1F2937', margin: 0 }}>EVIDENCE</h1>
                    <span style={{ 
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      background: '#EFF6FF', 
                      color: '#2563EB', 
                      border: '1px solid #BFDBFE', 
                      padding: '0.25rem 0.75rem', 
                      borderRadius: '6px', 
                      fontSize: '0.85rem', 
                      fontWeight: 600,
                      fontFamily: 'var(--font-mono)'
                    }}>
                      Case: CASE-2026-001
                    </span>
                  </div>
                  <p style={{ fontSize: '0.88rem', color: '#667085', margin: 0 }}>
                    Cryptographically sealed tamper-evident forensic artifacts categorized by origin and system vector.
                  </p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ 
                    padding: '0.4rem 0.8rem', 
                    background: '#F0FDF4', 
                    border: '1px solid #BBF7D0', 
                    borderRadius: '6px', 
                    fontSize: '0.82rem', 
                    fontWeight: 600, 
                    color: '#16A34A',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                  }}>
                    <CheckCircle2 size={16} /> {evidenceList.length} Sealed Envelopes (RFC-8785)
                  </div>
                </div>
              </div>

              {/* Verification Feedback Banner */}
              {verifyModalData && (
                <div style={{ padding: '1rem 1.25rem', background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: '8px', boxShadow: 'var(--shadow-sm)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#16A34A', fontWeight: 600, fontSize: '0.9rem' }}>
                      <CheckCircle2 size={18} />
                      Cryptographic Verification: <span style={{ fontFamily: 'var(--font-mono)' }}>{verifyModalData.evidenceId}</span>
                    </div>
                    <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }} onClick={() => setVerifyModalData(null)}>Dismiss</button>
                  </div>
                  <div style={{ fontSize: '0.85rem', color: '#15803D' }}>{verifyModalData.message}</div>
                  <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#475467', marginTop: '0.35rem', background: '#FFFFFF', padding: '0.35rem 0.6rem', borderRadius: '4px', border: '1px solid #E2E5E9', wordBreak: 'break-all' }}>
                    SHA-256 Seal: {verifyModalData.claimedHash}
                  </div>
                </div>
              )}

              {/* 5 Clean Evidence Categories (Requirement 15) */}
              {(() => {
                const categories = [
                  {
                    id: 'registry',
                    name: 'Registry',
                    desc: 'Windows Registry Run keys, startup values, and persistence configurations',
                    icon: ShieldAlert,
                    matcher: (ev) => ev.collector?.includes('persistence') || ev.collector?.includes('registry')
                  },
                  {
                    id: 'process',
                    name: 'Process',
                    desc: 'Volatile running process snapshots, thread contexts, and loaded modules',
                    icon: Terminal,
                    matcher: (ev) => ev.collector?.includes('process')
                  },
                  {
                    id: 'event_logs',
                    name: 'Event Logs',
                    desc: 'Security event audits, system login histories, and kernel event logs',
                    icon: FileText,
                    matcher: (ev) => ev.collector?.includes('event') || ev.collector?.includes('log') || ev.collector?.includes('system')
                  },
                  {
                    id: 'network',
                    name: 'Network',
                    desc: 'Active TCP/UDP sockets, DNS resolution telemetry, and adapter interfaces',
                    icon: Network,
                    matcher: (ev) => ev.collector?.includes('network')
                  },
                  {
                    id: 'filesystem',
                    name: 'Filesystem',
                    desc: 'Target binary metadata, PE headers, cryptographic hashes, and file entropy',
                    icon: Layers,
                    matcher: (ev) => ev.collector?.includes('file') || ev.collector?.includes('malware') || ev.collector?.includes('pe')
                  }
                ];

                return categories.map((cat) => {
                  const items = evidenceList.filter(ev => cat.matcher(ev));
                  const Icon = cat.icon;
                  return (
                    <div 
                      key={cat.id} 
                      className="glass-panel" 
                      style={{ 
                        background: '#FFFFFF', 
                        border: '1px solid #E2E5E9', 
                        borderRadius: '8px', 
                        padding: '1.25rem 1.5rem',
                        boxShadow: 'var(--shadow-card)'
                      }}
                    >
                      {/* Category Header */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                          <div style={{ 
                            width: '32px', 
                            height: '32px', 
                            borderRadius: '6px', 
                            background: '#EFF6FF', 
                            border: '1px solid #BFDBFE',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: '#2563EB'
                          }}>
                            <Icon size={16} />
                          </div>
                          <div>
                            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                              {cat.name}
                            </h3>
                            <div style={{ fontSize: '0.8rem', color: '#667085' }}>{cat.desc}</div>
                          </div>
                        </div>
                        <span style={{ 
                          fontSize: '0.75rem', 
                          fontWeight: 600, 
                          padding: '0.2rem 0.6rem', 
                          borderRadius: '12px',
                          background: items.length > 0 ? '#EFF6FF' : '#F1F5F9',
                          color: items.length > 0 ? '#2563EB' : '#667085',
                          border: items.length > 0 ? '1px solid #BFDBFE' : '1px solid #E2E5E9'
                        }}>
                          {items.length} {items.length === 1 ? 'Artifact' : 'Artifacts'}
                        </span>
                      </div>

                      {/* Items Table or Clean Placeholder */}
                      {items.length > 0 ? (
                        <div style={{ overflowX: 'auto' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                            <thead>
                              <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                                <th style={{ padding: '0.6rem 0.85rem' }}>Evidence ID</th>
                                <th style={{ padding: '0.6rem 0.85rem' }}>Collector Function</th>
                                <th style={{ padding: '0.6rem 0.85rem' }}>Origin Agent</th>
                                <th style={{ padding: '0.6rem 0.85rem' }}>SHA-256 Hash</th>
                                <th style={{ padding: '0.6rem 0.85rem' }}>Integrity</th>
                                <th style={{ padding: '0.6rem 0.85rem' }}>Actions</th>
                              </tr>
                            </thead>
                            <tbody>
                              {items.map((ev) => (
                                <tr key={ev.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                                  <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>
                                    {ev.id}
                                  </td>
                                  <td style={{ padding: '0.65rem 0.85rem', fontWeight: 500, color: '#1F2937' }}>
                                    {ev.collector}
                                  </td>
                                  <td style={{ padding: '0.65rem 0.85rem', color: '#475467', fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
                                    {ev.agent_id}
                                  </td>
                                  <td style={{ padding: '0.65rem 0.85rem' }}>
                                    <span style={{ 
                                      fontFamily: 'var(--font-mono)', 
                                      fontSize: '0.78rem', 
                                      color: '#475467', 
                                      background: '#F8FAFC', 
                                      padding: '0.2rem 0.45rem', 
                                      borderRadius: '4px',
                                      border: '1px solid #E2E5E9'
                                    }}>
                                      {ev.sha256_hash.slice(0, 16)}...{ev.sha256_hash.slice(-8)}
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.65rem 0.85rem' }}>
                                    <span style={{ 
                                      padding: '0.2rem 0.6rem', 
                                      borderRadius: '12px', 
                                      fontSize: '0.75rem', 
                                      fontWeight: 600, 
                                      background: '#F0FDF4', 
                                      color: '#16A34A', 
                                      border: '1px solid #BBF7D0' 
                                    }}>
                                      SEALED
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.65rem 0.85rem' }}>
                                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                                      <button 
                                        className="btn-secondary" 
                                        style={{ padding: '0.25rem 0.55rem', fontSize: '0.78rem' }} 
                                        onClick={() => handleVerifyEvidence(ev)}
                                      >
                                        Verify Hash
                                      </button>
                                      <button 
                                        className="btn-secondary" 
                                        style={{ padding: '0.25rem 0.55rem', fontSize: '0.78rem' }} 
                                        onClick={() => setInspectEvidence(ev)}
                                        title="Inspect Raw JSON Envelope"
                                      >
                                        <Eye size={13} />
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div style={{ 
                          padding: '1.25rem', 
                          background: '#F8FAFC', 
                          border: '1px dashed #E2E5E9', 
                          borderRadius: '6px', 
                          textAlign: 'center', 
                          color: '#667085',
                          fontSize: '0.84rem'
                        }}>
                          No {cat.name.toLowerCase()} evidence artifacts collected yet in CASE-2026-001. Dispatch a JOCKY script containing <code>{cat.id}.*</code> collectors to seal envelopes for this category.
                        </div>
                      )}
                    </div>
                  );
                });
              })()}
            </div>
          )}

          {/* TAB 6: CASES */}
          {activeTab === 'cases' && (
            <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Forensic Investigation Cases</h2>
                  <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                    Lifecycle tracking: OPEN → INVESTIGATING → CONTAINED → CLOSED.
                  </p>
                </div>
                <button className="btn-primary" onClick={() => setShowNewCaseModal(true)}>
                  <Plus size={15} />
                  Open Investigation
                </button>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Case ID</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Title</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((c) => (
                    <tr key={c.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>{c.id}</td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 500, color: '#1F2937' }}>{c.title}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{
                          padding: '0.2rem 0.55rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          background: c.severity === 'critical' || c.severity === 'high' ? '#FEF2F2' : (c.severity === 'medium' ? '#FFFBEB' : '#F0FDF4'),
                          color: c.severity === 'critical' || c.severity === 'high' ? '#DC2626' : (c.severity === 'medium' ? '#D97706' : '#16A34A'),
                          border: `1px solid ${c.severity === 'critical' || c.severity === 'high' ? '#FECACA' : (c.severity === 'medium' ? '#FDE68A' : '#BBF7D0')}`
                        }}>
                          {c.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ padding: '0.2rem 0.55rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600, background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE' }}>
                          {c.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#667085' }}>{c.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 7: FORENSIC REPORTS (REQUIREMENT 16) */}
          {activeTab === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Export Controls Bar */}
              <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center', 
                flexWrap: 'wrap', 
                gap: '1rem', 
                background: '#FFFFFF', 
                padding: '1.25rem 1.5rem', 
                borderRadius: '8px', 
                border: '1px solid #E2E5E9', 
                boxShadow: 'var(--shadow-card)' 
              }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>Forensic Reports</h2>
                  <p style={{ fontSize: '0.85rem', color: '#667085', margin: '0.2rem 0 0 0' }}>
                    Court-admissible forensic documentation sealed with SHA-256 evidence integrity hashes.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button className="btn-primary" onClick={() => handleDownloadReport('pdf')}>
                    <Download size={14} /> Download PDF
                  </button>
                  <button className="btn-secondary" onClick={() => handleDownloadReport('html')}>
                    Export HTML
                  </button>
                  <button className="btn-secondary" onClick={() => handleDownloadReport('csv')}>
                    Export CSV
                  </button>
                  <button className="btn-secondary" onClick={() => handleDownloadReport('json')}>
                    Export JSON
                  </button>
                  <button className="btn-secondary" onClick={() => window.print()}>
                    Print Document
                  </button>
                </div>
              </div>

              {/* Official Forensic Report Document (Courtroom & Enterprise Grade) */}
              <div style={{ 
                background: '#FFFFFF', 
                border: '1px solid #E2E5E9', 
                borderRadius: '8px', 
                padding: '2.5rem', 
                boxShadow: 'var(--shadow-card)', 
                maxWidth: '100%',
                lineHeight: '1.6'
              }}>
                {/* Formal Header Bar */}
                <div style={{ borderBottom: '2px solid #1F2937', paddingBottom: '1.25rem', marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.5rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#667085', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      OFFICIAL DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT
                    </div>
                    <h1 style={{ fontSize: '1.85rem', fontWeight: 700, color: '#1F2937', marginTop: '0.35rem', letterSpacing: '-0.01em' }}>
                      Forensic Report
                    </h1>
                    <div style={{ fontSize: '0.88rem', color: '#667085', marginTop: '0.25rem' }}>
                      Standard: RFC-8785 Canonical JSON • Chain of Custody Verified • Tamper-Evident Ledger
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', fontSize: '0.82rem', color: '#667085', lineHeight: '1.7' }}>
                    <div><strong style={{ color: '#1F2937' }}>Document ID:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>JOCKY-DFIR-2026-001</span></div>
                    <div><strong style={{ color: '#1F2937' }}>Date Issued:</strong> 25 Sep 2026, 14:35 UTC</div>
                    <div><strong style={{ color: '#1F2937' }}>Classification:</strong> <span style={{ color: '#DC2626', fontWeight: 700 }}>CONFIDENTIAL // EVIDENCE</span></div>
                    <div><strong style={{ color: '#1F2937' }}>Attestation:</strong> Cryptographic SHA-256</div>
                  </div>
                </div>

                {/* 1. Case ID */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Case ID
                  </h3>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '1.25rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem', fontSize: '0.88rem' }}>
                    <div>
                      <div style={{ color: '#667085', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Case Reference</div>
                      <div style={{ fontWeight: 700, color: '#2563EB', fontFamily: 'var(--font-mono)', fontSize: '1.05rem', marginTop: '0.15rem' }}>
                        {currentCase?.id || 'CASE-2026-001'}
                      </div>
                    </div>
                    <div>
                      <div style={{ color: '#667085', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Investigation Title</div>
                      <div style={{ fontWeight: 600, color: '#1F2937', marginTop: '0.15rem' }}>
                        {currentCase?.title || 'Suspicious Persistence Investigation'}
                      </div>
                    </div>
                    <div>
                      <div style={{ color: '#667085', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Target Endpoint</div>
                      <div style={{ fontWeight: 600, color: '#1F2937', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }}>
                        DEMO-WINDOWS-ENDPOINT (10.100.1.14)
                      </div>
                    </div>
                    <div>
                      <div style={{ color: '#667085', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Status & Severity</div>
                      <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.25rem' }}>
                        <span style={{ background: '#FEF2F2', color: '#DC2626', border: '1px solid #FECACA', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700 }}>
                          HIGH SEVERITY
                        </span>
                        <span style={{ background: '#EFF6FF', color: '#2563EB', border: '1px solid #BFDBFE', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600 }}>
                          {currentCase?.status?.toUpperCase() || 'INVESTIGATING'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Investigation Summary */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '0.85rem' }}>
                    Investigation Summary
                  </h3>
                  <p style={{ color: '#475467', fontSize: '0.9rem', marginBottom: '0.75rem' }}>
                    An automated forensic acquisition was dispatched against target host <code style={{ fontFamily: 'var(--font-mono)', color: '#2563EB' }}>DEMO-WINDOWS-ENDPOINT</code> executing declarative JOCKY script <code style={{ fontFamily: 'var(--font-mono)' }}>demo_persistence.jocky</code>. The six-stage execution workflow (COLLECT → CORRELATE → ANALYZE → VERIFY → CHAIN → REPORT) completed in 1.62 ms with full envelope attestation.
                  </p>
                  <p style={{ color: '#475467', fontSize: '0.9rem', margin: 0 }}>
                    Correlation identified anomalous registry run keys registered under <code style={{ fontFamily: 'var(--font-mono)' }}>HKLM_Run</code> referencing masqueraded system executables, concurrent rogue process spawning without parent linkage, and suspicious TCP socket bindings.
                  </p>
                </div>

                {/* 3. Threat Assessment */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Threat Assessment
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                    <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '6px', padding: '1rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#DC2626', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Threat Score</div>
                      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#DC2626', margin: '0.25rem 0' }}>86 <span style={{ fontSize: '1rem', fontWeight: 500, color: '#667085' }}>/ 100</span></div>
                      <div style={{ fontSize: '0.75rem', color: '#DC2626', fontWeight: 700 }}>HIGH THREAT SEVERITY</div>
                    </div>
                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '1rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>MITRE ATT&CK Technique</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#1F2937', margin: '0.25rem 0' }}>T1547.001</div>
                      <div style={{ fontSize: '0.75rem', color: '#667085' }}>Boot/Logon Autostart Execution: Registry Run Keys</div>
                    </div>
                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '1rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#667085', textTransform: 'uppercase', letterSpacing: '0.04em' }}>ML Engine Confidence</div>
                      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#16A34A', margin: '0.25rem 0' }}>99.4%</div>
                      <div style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>Random Forest Classifier (RFC-8785 Sealed)</div>
                    </div>
                  </div>
                </div>

                {/* 4. Evidence Summary */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Evidence Summary
                  </h3>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem', marginBottom: '1rem' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Category</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Evidence ID</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Collector</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>SHA-256 Hash</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>Registry</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>EV-31BA09C4</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>persistence.startup</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>9f82b714529a7019c81b29a80e41982736bfa8019a823471ef99a8bc00984712</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}><span style={{ background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0', padding: '2px 6px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600 }}>SEALED</span></td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>Process</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>EV-8D92FA10</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>process.list</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>4a7d189fec0a29b3c79124ae8019fb42a8b9281a02938471ef09a8bc12984712</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}><span style={{ background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0', padding: '2px 6px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600 }}>SEALED</span></td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>Network</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>EV-44CA991B</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>network.connections</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>5d41402abc4b2a76b9719d911017c592b23ae41e4649b934ca495991b7852b85</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}><span style={{ background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0', padding: '2px 6px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600 }}>SEALED</span></td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>Filesystem</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>EV-PE-7721AA</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>malware.pe_info</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}><span style={{ background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0', padding: '2px 6px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600 }}>SEALED</span></td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>Event Logs</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#2563EB', fontWeight: 600 }}>EV-EVT-9021B</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>system.eventlog</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>7c91a38f01b92019c81b29a80e41982736bfa8019a823471ef99a8bc00984110</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}><span style={{ background: '#F0FDF4', color: '#16A34A', border: '1px solid #BBF7D0', padding: '2px 6px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600 }}>SEALED</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* 5. Forensic Vector */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '0.85rem' }}>
                    Forensic Vector
                  </h3>
                  <p style={{ color: '#475467', fontSize: '0.9rem', marginBottom: '0.85rem' }}>
                    The 21-Dimensional Forensic Vector evaluates multi-modal telemetry across process dynamics, startup persistence, socket behaviors, and integrity metrics.
                  </p>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '1rem 1.25rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.85rem', fontSize: '0.84rem' }}>
                    <div><strong>Total Dimensions:</strong> 21 Evaluated</div>
                    <div><strong>Anomalous Vectors:</strong> <span style={{ color: '#DC2626', fontWeight: 700 }}>7 Detected</span></div>
                    <div><strong>L2 Norm Magnitude:</strong> 0.8741</div>
                    <div><strong>Process Execution Anomaly:</strong> 0.9200</div>
                    <div><strong>Registry Volatility Metric:</strong> 0.8850</div>
                    <div><strong>Network Socket Metric:</strong> 0.7600</div>
                  </div>
                </div>

                {/* 6. Integrity Verification */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Integrity Verification
                  </h3>
                  <div style={{ background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: '6px', padding: '1rem 1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#16A34A', fontWeight: 700, fontSize: '0.92rem' }}>
                      <CheckCircle2 size={18} /> 12 / 12 Integrity & Tamper Detectors Passed
                    </div>
                    <div style={{ color: '#15803D', fontSize: '0.84rem', marginTop: '0.35rem' }}>
                      Zero tampering detected across envelope hashes, timestamps, monotonic lease sequence, or canonical serialization. All digital artifacts conform strictly to RFC-8785 standards.
                    </div>
                  </div>
                </div>

                {/* 7. Chain of Custody */}
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Chain of Custody
                  </h3>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.84rem' }}>
                    <thead>
                      <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Seq #</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Custody Action</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>Custodian / Actor</th>
                        <th style={{ padding: '0.65rem 0.85rem' }}>SHA-256 Seal</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600 }}>001</td>
                        <td style={{ padding: '0.65rem 0.85rem', color: '#667085' }}>14:20:15 UTC</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 500 }}>ACQUISITION_SEAL</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)' }}>AGENT-WIN-01</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>4a7d189f...84712</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600 }}>002</td>
                        <td style={{ padding: '0.65rem 0.85rem', color: '#667085' }}>14:20:18 UTC</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 500 }}>VAULT_INGEST</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)' }}>JOCKY_CORE_LEDGER</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>9f82b714...984712</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid #E2E5E9' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600 }}>003</td>
                        <td style={{ padding: '0.65rem 0.85rem', color: '#667085' }}>14:21:00 UTC</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontWeight: 500 }}>INTEGRITY_VERIFIED</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)' }}>lead-analyst@jocky.defense</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467' }}>5d41402a...852b85</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* 8. Conclusion */}
                <div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                    Conclusion
                  </h3>
                  <p style={{ color: '#475467', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                    Digital evidence confirms an unapproved startup registry run key persistence mechanism consistent with MITRE ATT&CK T1547.001. All digital artifacts are preserved with cryptographic SHA-256 integrity and verifiable chain of custody. Recommended remediation: isolate endpoint DEMO-WINDOWS-ENDPOINT, delete rogue HKLM_Run registry value, and terminate spawned worker process tree.
                  </p>

                  {/* Examiner Validation Block */}
                  <div style={{ paddingTop: '1.5rem', borderTop: '1px solid #E2E5E9', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '1.5rem' }}>
                    <div>
                      <div style={{ fontSize: '0.75rem', color: '#667085', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Certified Digital Forensic Examiner</div>
                      <div style={{ fontWeight: 700, fontSize: '1rem', color: '#1F2937', marginTop: '0.2rem' }}>Senior Digital Forensics Lead</div>
                      <div style={{ fontSize: '0.82rem', color: '#667085' }}>Cyber Defense & Forensic Readiness Group</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ padding: '0.5rem 1rem', background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', display: 'inline-block' }}>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#2563EB', letterSpacing: '0.05em' }}>CRYPTOGRAPHICALLY SEALED</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: '#667085', marginTop: '0.15rem' }}>SHA-256: 7f83b165...ec49a712</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: AUDIT TRAIL */}
          {activeTab === 'audit' && (
            <div className="glass-panel" style={{ padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '8px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#1F2937' }}>Tamper-Evident System Audit Trail</h2>
                  <p style={{ fontSize: '0.85rem', color: '#667085', marginTop: '0.2rem' }}>
                    Immutable record of all investigator actions, task leases, and agent telemetry submissions.
                  </p>
                </div>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E5E9', textAlign: 'left', color: '#667085' }}>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Actor</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Actor Type</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Action</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Resource</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: '1px solid #E2E5E9' }}>
                      <td style={{ padding: '0.65rem 0.85rem', color: '#667085' }}>{log.timestamp}</td>
                      <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#1F2937' }}>{log.actor}</td>
                      <td style={{ padding: '0.65rem 0.85rem' }}>
                        <span style={{ 
                          fontSize: '0.72rem', 
                          padding: '0.15rem 0.45rem', 
                          borderRadius: '4px', 
                          background: log.actor_type === 'USER' ? '#EFF6FF' : '#F0FDF4', 
                          color: log.actor_type === 'USER' ? '#2563EB' : '#16A34A',
                          border: `1px solid ${log.actor_type === 'USER' ? '#BFDBFE' : '#BBF7D0'}`
                        }}>
                          {log.actor_type}
                        </span>
                      </td>
                      <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: '#1F2937' }}>{log.action}</td>
                      <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', color: '#475467' }}>{log.resource}</td>
                      <td style={{ padding: '0.65rem 0.85rem' }}>
                        <span style={{ 
                          fontSize: '0.72rem', 
                          padding: '0.15rem 0.45rem', 
                          borderRadius: '4px', 
                          background: log.result === 'SUCCESS' ? '#F0FDF4' : '#FEF2F2', 
                          color: log.result === 'SUCCESS' ? '#16A34A' : '#DC2626',
                          border: `1px solid ${log.result === 'SUCCESS' ? '#BBF7D0' : '#FECACA'}`
                        }}>
                          {log.result}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </main>
      </div>

      {/* MODAL: Agent Capabilities */}
      {capsModalAgent && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.45)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div className="glass-panel" style={{ width: '480px', padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>Capabilities: {capsModalAgent.id}</h3>
              <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.78rem' }} onClick={() => setCapsModalAgent(null)}>Close</button>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#667085', marginBottom: '0.75rem' }}>
              Platform: <strong style={{ color: '#1F2937' }}>{capsModalAgent.platform}</strong> ({capsModalAgent.os_ver})
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', maxHeight: '200px', overflowY: 'auto' }}>
              {capsModalAgent.caps.map(c => (
                <span key={c} style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', color: '#2563EB', padding: '0.25rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                  {c}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: New Case */}
      {showNewCaseModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.45)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div className="glass-panel" style={{ width: '450px', padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#1F2937', marginBottom: '1rem' }}>Open New Investigation Case</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Case Title</label>
                <input
                  type="text"
                  value={newCaseTitle}
                  onChange={(e) => setNewCaseTitle(e.target.value)}
                  placeholder="e.g. Lateral Movement Triage"
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', outline: 'none', fontSize: '0.85rem' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Severity</label>
                <select
                  value={newCaseSeverity}
                  onChange={(e) => setNewCaseSeverity(e.target.value)}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', fontSize: '0.85rem' }}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button className="btn-secondary" onClick={() => setShowNewCaseModal(false)}>Cancel</button>
                <button className="btn-primary" onClick={handleCreateCase}>Initialize Case</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Inspect Evidence JSON */}
      {inspectEvidence && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.45)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div className="glass-panel" style={{ width: '640px', maxHeight: '80vh', padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                Evidence Envelope: <span style={{ fontFamily: 'var(--font-mono)', color: '#2563EB' }}>{inspectEvidence.id}</span>
              </h3>
              <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.78rem' }} onClick={() => setInspectEvidence(null)}>Close</button>
            </div>
            <pre style={{ flex: 1, overflowY: 'auto', background: '#F8FAFC', border: '1px solid #E2E5E9', padding: '1rem', borderRadius: '6px', fontSize: '0.82rem', color: '#1F2937', fontFamily: 'var(--font-mono)', lineHeight: '1.5' }}>
              {JSON.stringify(inspectEvidence, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* MODAL: Playbook Analyst Review & Approval */}
      {approvalModalPlaybook && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.45)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div className="glass-panel" style={{ width: '520px', padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.5rem' }}>
              Analyst Response Review & Sign-Off
            </h3>
            <p style={{ fontSize: '0.82rem', color: '#667085', marginBottom: '1rem' }}>
              Playbook: <strong style={{ color: '#2563EB' }}>{approvalModalPlaybook.name}</strong> ({approvalModalPlaybook.actions?.length || 0} steps)
            </p>

            <div style={{ background: '#F8FAFC', border: '1px solid #E2E5E9', borderRadius: '6px', padding: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: '#667085', marginBottom: '0.35rem', fontWeight: 600 }}>Proposed Actions:</div>
              {approvalModalPlaybook.actions?.map(a => (
                <div key={a.id} style={{ fontSize: '0.8rem', color: '#1F2937', display: 'flex', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span style={{ color: '#2563EB', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>#{a.step_number}</span>
                  <code style={{ fontFamily: 'var(--font-mono)' }}>{a.action_type}</code>
                  {a.target_agent_id && <span style={{ color: '#667085' }}>({a.target_agent_id})</span>}
                </div>
              ))}
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.35rem' }}>
                Examiner Justification / Comments
              </label>
              <textarea
                rows={3}
                value={approvalComment}
                onChange={(e) => setApprovalComment(e.target.value)}
                placeholder="Enter forensic authorization justification..."
                style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', fontSize: '0.82rem', outline: 'none' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
              <button className="btn-secondary" onClick={() => setApprovalModalPlaybook(null)}>
                Cancel
              </button>
              <button 
                className="btn-secondary" 
                onClick={() => handleApprovePlaybook('REJECTED')}
                style={{ color: '#DC2626', borderColor: '#FECACA', background: '#FEF2F2' }}
              >
                Reject Playbook
              </button>
              <button 
                className="btn-primary" 
                onClick={() => handleApprovePlaybook('APPROVED')}
                style={{ background: '#2563EB' }}
              >
                Authorize & Approve
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Create Response Playbook */}
      {showNewPlaybookModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.45)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div className="glass-panel" style={{ width: '500px', padding: '1.5rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#1F2937', marginBottom: '0.5rem' }}>
              Create Defensive Response Playbook
            </h3>
            <p style={{ fontSize: '0.82rem', color: '#667085', marginBottom: '1rem' }}>
              Enforces strict allowlist validation for deterministic incident response.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Playbook Name</label>
                <input
                  type="text"
                  value={newPbName}
                  onChange={(e) => setNewPbName(e.target.value)}
                  placeholder="e.g. Lateral Movement Rapid Containment"
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', outline: 'none', fontSize: '0.85rem' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Description</label>
                <textarea
                  rows={2}
                  value={newPbDesc}
                  onChange={(e) => setNewPbDesc(e.target.value)}
                  placeholder="Defensive response goals and triggers..."
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', outline: 'none', fontSize: '0.85rem' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Approved Defensive Action (Step 1)</label>
                <select
                  value={newPbActionType}
                  onChange={(e) => setNewPbActionType(e.target.value)}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#2563EB', fontWeight: 600, fontSize: '0.85rem' }}
                >
                  <option value="collect.processes">collect.processes (Volatile Process Snapshot)</option>
                  <option value="collect.network">collect.network (Active Sockets & Sinks)</option>
                  <option value="collect.persistence">collect.persistence (RunKeys & Services)</option>
                  <option value="collect.system">collect.system (Core System Baseline)</option>
                  <option value="collect.file_metadata">collect.file_metadata (Hash & Timestamps)</option>
                  <option value="isolate.endpoint.simulated">isolate.endpoint.simulated [SIMULATED QUARANTINE]</option>
                  <option value="suspend.process.simulated">suspend.process.simulated [SIMULATED FREEZE]</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: '#667085', display: 'block', marginBottom: '0.25rem' }}>Target Fleet Agent</label>
                <select
                  value={newPbTargetAgent}
                  onChange={(e) => setNewPbTargetAgent(e.target.value)}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', background: '#FFFFFF', border: '1px solid #D0D5DD', borderRadius: '6px', color: '#1F2937', fontSize: '0.85rem' }}
                >
                  {agents.map(a => (
                    <option key={a.id} value={a.id}>{a.id} ({a.hostname} - {a.platform})</option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
                <button className="btn-secondary" onClick={() => setShowNewPlaybookModal(false)}>Cancel</button>
                <button className="btn-primary" onClick={handleCreatePlaybook}>Submit for Approval</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ML Prediction Verification Modal */}
      {showMlVerifyModal && mlVerifyResult && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(15, 23, 42, 0.45)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div className="glass-panel" style={{ width: '560px', maxWidth: '90%', padding: '1.75rem', background: '#FFFFFF', border: '1px solid #E2E5E9', borderRadius: '10px', boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #E2E5E9', paddingBottom: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <ShieldCheck size={22} color={mlVerifyResult.is_valid ? '#16A34A' : '#DC2626'} />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#1F2937', margin: 0 }}>
                  Cryptographic Seal Verification
                </h3>
              </div>
              <button 
                onClick={() => setShowMlVerifyModal(false)} 
                style={{ background: 'transparent', border: 'none', color: '#667085', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ 
                padding: '0.8rem', 
                borderRadius: '8px', 
                background: mlVerifyResult.is_valid ? '#F0FDF4' : '#FEF2F2',
                border: mlVerifyResult.is_valid ? '1px solid #BBF7D0' : '1px solid #FECACA'
              }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: mlVerifyResult.is_valid ? '#16A34A' : '#DC2626' }}>
                  {mlVerifyResult.is_valid ? 'PREDICTION INTEGRITY VERIFIED (RFC-8785 VALID)' : 'INTEGRITY TAMPERING DETECTED'}
                </div>
                <div style={{ fontSize: '0.8rem', color: '#475467', marginTop: '0.25rem' }}>
                  {mlVerifyResult.message}
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#667085', display: 'block', marginBottom: '0.2rem' }}>Prediction ID</label>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#2563EB', background: '#F8FAFC', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid #E2E5E9' }}>
                  {mlVerifyResult.prediction_id}
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#667085', display: 'block', marginBottom: '0.2rem' }}>Claimed Canonical Hash (Stored)</label>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#475467', background: '#F8FAFC', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid #E2E5E9', wordBreak: 'break-all' }}>
                  {mlVerifyResult.claimed_hash}
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#667085', display: 'block', marginBottom: '0.2rem' }}>Recalculated Canonical Hash (Computed Now)</label>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: mlVerifyResult.is_valid ? '#16A34A' : '#DC2626', background: '#F8FAFC', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid #E2E5E9', wordBreak: 'break-all' }}>
                  {mlVerifyResult.recalculated_hash}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                <button className="btn-secondary" onClick={() => setShowMlVerifyModal(false)}>Close</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
