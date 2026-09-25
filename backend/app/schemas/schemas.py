"""
Pydantic Schemas for JOCKY API
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, ConfigDict

# Auth Schemas
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    role: str = "analyst"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    email: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# Agent Schemas
class AgentRegister(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: str = "1.0.0"
    enrollment_token: str
    capabilities: Optional[List[str]] = None

class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    platform: str
    os_version: Optional[str]
    architecture: Optional[str]
    ip_address: Optional[str]
    agent_version: str
    status: str
    capabilities: Optional[List[str]] = None
    auth_token: Optional[str] = None
    last_seen: datetime
    created_at: datetime

class HeartbeatPayload(BaseModel):
    status: str = "online"

# Case Schemas
class CaseCreate(BaseModel):
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    status: str = "OPEN"      # OPEN, INVESTIGATING, CONTAINED, CLOSED

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None

class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    analyst_id: Optional[int]
    created_at: datetime
    updated_at: Optional[datetime] = None

# Task Schemas
class TaskCreate(BaseModel):
    case_id: str
    agent_id: str
    name: str
    jocky_script: Optional[str] = None
    plan_payload: Optional[Dict[str, Any]] = None

class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    agent_id: str
    name: str
    script_source: Optional[str]
    plan_payload: Optional[Dict[str, Any]] = None
    status: str
    error_message: Optional[str] = None
    retry_count: int = 0
    timeout_seconds: int = 300
    created_at: datetime
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class TaskFailPayload(BaseModel):
    error: str
    agent_id: Optional[str] = None

# Capability Check
class CapabilityCheckRequest(BaseModel):
    agent_id: str
    jocky_script: Optional[str] = None
    operations: Optional[List[str]] = None

class CapabilityCheckResponse(BaseModel):
    agent_id: str
    platform: str
    is_compatible: bool
    supported_operations: List[str]
    unsupported_operations: List[str]
    reason: Optional[str] = None

# Result & Evidence Schemas
class ResultSubmit(BaseModel):
    task_id: str
    agent_id: str
    evidence_envelopes: List[Dict[str, Any]]

class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    agent_id: str
    execution_id: Optional[str] = None
    script_hash: Optional[str] = None
    collector: str
    collector_version: Optional[str] = "1.0.0"
    collector_source: Optional[str] = None
    platform: str
    sha256_hash: str
    raw_data_hash: Optional[str] = None
    normalized_data_hash: Optional[str] = None
    raw_data: Optional[Any] = None
    normalized_data: Optional[Any] = None
    previous_hash: Optional[str] = None
    integrity_status: Optional[str] = "VERIFIED"
    is_verified: bool
    collected_at: datetime
    envelope_data: Dict[str, Any]

class EvidenceVerificationResponse(BaseModel):
    evidence_id: str
    is_valid: bool
    algorithm: str
    claimed_hash: str
    recalculated_hash: str
    message: str

# Report Schemas
class ReportCreate(BaseModel):
    case_id: str
    title: Optional[str] = "Forensic Investigation Report"
    report_type: str = "comprehensive"

class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    title: str
    report_type: str
    created_at: datetime
    content_json: Dict[str, Any]
    pdf_path: Optional[str] = None

# Audit Log Schema
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: Optional[str] = None
    case_id: Optional[str] = None
    actor: str
    actor_type: str
    action: str
    resource: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    result: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    timestamp: datetime
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

# Real-Time Event Schema
class EventItem(BaseModel):
    type: str
    message: str
    data: Dict[str, Any] = {}
    timestamp: str

# Phase 5 Investigation Schemas
class IndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    indicator_type: str
    value: str
    normalized_value: str
    source_evidence_id: Optional[str] = None
    agent_id: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    status: str
    context_data: Optional[Dict[str, Any]] = None

class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    agent_id: Optional[str] = None
    execution_id: Optional[str] = None
    finding_id: Optional[str] = None
    timestamp: datetime
    event_type: str
    description: str
    evidence_id: Optional[str] = None
    evidence_ids: Optional[List[str]] = None
    severity: str
    details: Optional[Dict[str, Any]] = None

class CorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    correlation_type: str
    title: str
    description: str
    primary_agent_id: Optional[str] = None
    related_agent_ids: Optional[List[str]] = None
    evidence_ids: Optional[List[str]] = None
    indicators: Optional[List[str]] = None
    score: int = 50
    detected_at: datetime

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: str
    case_id: str
    execution_id: Optional[str] = None
    script_hash: Optional[str] = None
    detection_type: Optional[str] = "rule"
    detection_rule_id: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    confidence_score: Optional[float] = None
    title: str
    description: str
    reason: Optional[str] = None
    status: str
    priority: str
    priority_score: int
    priority_reasons: Optional[List[str]] = None
    explainable_factors: Optional[List[Dict[str, Any]]] = None
    related_agents: Optional[List[str]] = None
    evidence_ids: Optional[List[str]] = None
    created_at: datetime
    updated_at: datetime

class FindingStatusUpdate(BaseModel):
    status: str  # OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED

class AnalystNoteCreate(BaseModel):
    analyst_name: Optional[str] = "Forensic Analyst"
    note_type: Optional[str] = "investigation_note"  # observation, hypothesis, conclusion, investigation_note
    content: str

class AnalystNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    analyst_name: str
    note_type: str
    content: str
    created_at: datetime

class InvestigationSummaryResponse(BaseModel):
    case_id: str
    case_title: str
    severity: str
    status: str
    total_agents: int
    total_evidence: int
    total_indicators: int
    total_timeline_events: int
    total_findings: int
    open_findings: int
    total_notes: int
    last_updated: str

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # agent, process, file, hash, ip, domain, persistence, evidence
    data: Optional[Dict[str, Any]] = None

class GraphEdge(BaseModel):
    source: str
    target: str
    label: str

class InvestigationGraphResponse(BaseModel):
    case_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class InvestigationSearchResponse(BaseModel):
    case_id: str
    query: str
    matching_indicators: List[IndicatorResponse]
    matching_findings: List[FindingResponse]
    matching_timeline_events: List[TimelineEventResponse]
    matching_evidence_ids: List[str]


# ============================================================================
# PHASE 6 SCHEMAS — Threat Intelligence, Response Playbooks & Visualizations
# ============================================================================

class ThreatIntelItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    stix_id: Optional[str] = None
    intel_type: str
    name: str
    description: Optional[str] = None
    pattern: Optional[str] = None
    pattern_type: str = "stix"
    confidence: int = 75
    source: str = "LOCAL"
    labels: Optional[List[str]] = None
    indicators: Optional[Dict[str, Any]] = None
    mitre_attack_id: Optional[str] = None
    created_at: datetime


class ThreatIntelImportRequest(BaseModel):
    source_type: str = "bundle"  # bundle, demo, taxii
    bundle_json: Optional[Dict[str, Any]] = None
    taxii_url: Optional[str] = None
    collection_id: Optional[str] = None


class ThreatIntelMatchResponse(BaseModel):
    intel_id: str
    intel_name: str
    intel_type: str
    matched_indicator: str
    indicator_type: str
    confidence: int
    severity: str
    evidence_id: Optional[str] = None
    agent_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    description: Optional[str] = None


class ThreatIntelCaseOverview(BaseModel):
    case_id: str
    total_intel_items: int
    matches: List[ThreatIntelMatchResponse]
    mitre_coverage: List[str]


class PlaybookActionCreate(BaseModel):
    step_number: int
    action_type: str
    target_agent_id: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class PlaybookActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    step_number: int
    action_type: str
    target_agent_id: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    status: str
    result_details: Optional[Dict[str, Any]] = None
    executed_at: Optional[datetime] = None


class PlaybookApprovalCreate(BaseModel):
    decision: str  # APPROVED, REJECTED
    comment: Optional[str] = None


class PlaybookApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    approver_id: Optional[int] = None
    approver_email: str
    decision: str
    comment: Optional[str] = None
    created_at: datetime


class PlaybookCreate(BaseModel):
    case_id: str
    name: str
    description: Optional[str] = None
    version: Optional[str] = "1.0.0"
    trigger_type: Optional[str] = "MANUAL"
    actions: List[PlaybookActionCreate]


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    name: str
    description: Optional[str] = None
    version: str
    status: str
    trigger_type: str
    created_by: str
    actions: List[PlaybookActionResponse] = []
    approvals: List[PlaybookApprovalResponse] = []
    created_at: datetime
    updated_at: Optional[datetime] = None


class PlaybookExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    case_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = None


class TimelineHeatmapResponse(BaseModel):
    case_id: str
    buckets: List[Dict[str, Any]]
    peak_bucket: Optional[str] = None
    total_events: int


class AttackPatternResponse(BaseModel):
    case_id: str
    patterns: List[Dict[str, Any]]


# ============================================================================
# PHASE 7 SCHEMAS — Security Hardening, Tamper Detection & Integrity
# ============================================================================

class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: Optional[str] = None
    agent_id: Optional[str] = None
    event_type: str
    severity: str
    object_type: str
    object_id: str
    description: str
    expected_value: Optional[str] = None
    observed_value: Optional[str] = None
    detected_at: datetime
    resolved: bool
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    integrity_hash: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None


class SecurityEventResolve(BaseModel):
    resolved_by: str = "analyst@jocky.defense"
    comment: Optional[str] = None


class VerificationResult(BaseModel):
    object_type: str
    object_id: str
    status: str  # VERIFIED, WARNING, COMPROMISED
    is_valid: bool
    expected_hash: Optional[str] = None
    calculated_hash: Optional[str] = None
    reason: str
    recommended_action: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ControlStatus(BaseModel):
    name: str
    status: str  # VERIFIED, WARNING, COMPROMISED
    score: str   # e.g. "Verified", "1 Issue Detected"
    description: str
    details: Optional[Dict[str, Any]] = None


class CaseIntegrityScorecard(BaseModel):
    case_id: str
    verified_controls: int
    total_controls: int = 7
    score_label: str  # e.g. "Integrity Controls: 7/7 Verified"
    status: str       # VERIFIED, WARNING, COMPROMISED
    controls: Dict[str, ControlStatus]
    timestamp: datetime


class ReportManifest(BaseModel):
    report_id: str
    case_id: str
    content_sha256: str
    evidence_manifest_hash: str
    audit_chain_hash: str
    investigation_hash: str
    cti_hash: str
    generated_at: str
    status: str = "VERIFIED"


class SecurityConfigurationResponse(BaseModel):
    authentication: str = "enabled"
    audit_logging: str = "enabled"
    evidence_sealing: str = "enabled"
    playbook_approval: str = "enabled"
    agent_isolation: str = "enabled"
    replay_protection: str = "enabled"
    configuration_integrity: str = "enabled"
    configuration_fingerprint: str
    algorithm: str = "SHA-256"
    status: str = "VERIFIED"


# ============================================================================
# PHASE 27 SCHEMAS — Provenance, Traceability, Merkle, Blockchain & Integrity
# ============================================================================

class MerkleTreeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    case_id: str
    execution_id: Optional[str] = None
    merkle_root: str
    evidence_count: int
    evidence_hashes: List[str]
    algorithm: str = "SHA-256"
    created_at: datetime


class BlockchainAnchorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    block_number: int
    case_id: str
    execution_id: Optional[str] = None
    merkle_root: str
    script_hash: Optional[str] = None
    evidence_count: int
    previous_block_hash: str
    block_hash: str
    network: str = "Local Evidence Blockchain"
    status: str = "ANCHORED"
    timestamp: datetime


class FindingProvenanceResponse(BaseModel):
    finding: FindingResponse
    supporting_evidence: List[EvidenceResponse]
    execution: Optional[Dict[str, Any]] = None
    script_hash: Optional[str] = None
    script_content: Optional[str] = None
    merkle_root: Optional[str] = None
    blockchain_anchor: Optional[BlockchainAnchorResponse] = None
    traceability_chain: List[Dict[str, Any]]


class InvestigationIntegrityVerifyResponse(BaseModel):
    valid: bool
    case_id: str
    execution_id: Optional[str] = None
    evidence: Dict[str, Any]
    hash_chain: Dict[str, Any]
    merkle: Dict[str, Any]
    blockchain: Dict[str, Any]
    script: Dict[str, Any]
    report: Dict[str, Any]
    failures: List[Dict[str, Any]] = []
    verified_at: str


class CorrelatedIncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    execution_id: Optional[str] = None
    title: str
    classification: str
    description: str
    evidence_ids: List[str]
    finding_ids: Optional[List[str]] = None
    timeline_sequence: Optional[List[str]] = None
    severity: str
    created_at: datetime



