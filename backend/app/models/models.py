"""
SQLAlchemy ORM Models for JOCKY Forensic Platform
Implements users, agents, cases, tasks, task_results, evidence, audit_logs, and reports.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    Float,
)
from sqlalchemy.orm import relationship
from backend.app.database.base import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="analyst", nullable=False)  # admin, analyst, agent
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)

    cases = relationship("Case", back_populates="analyst")
    audit_logs = relationship("AuditLog", back_populates="user")

class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(100), primary_key=True, index=True)  # AGENT-WIN-01
    hostname = Column(String(255), nullable=False)
    platform = Column(String(100), nullable=False)          # Windows, Linux, Darwin
    os_version = Column(String(255), nullable=True)
    architecture = Column(String(50), nullable=True)
    ip_address = Column(String(100), nullable=True)
    agent_version = Column(String(50), default="1.0.0")
    status = Column(String(50), default="online")          # online, offline, busy
    capabilities = Column(JSON, nullable=True)              # list of approved collector functions
    auth_token = Column(String(255), nullable=True)         # unique agent secret token
    identity_fingerprint = Column(String(64), nullable=True, index=True) # SHA-256 identity fingerprint
    capability_fingerprint = Column(String(64), nullable=True) # SHA-256 capability profile fingerprint
    last_seen = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)

    tasks = relationship("Task", back_populates="agent")
    evidence_items = relationship("Evidence", back_populates="agent")

class Case(Base):
    __tablename__ = "cases"

    id = Column(String(100), primary_key=True, index=True)  # CASE-2026-001
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="medium")        # low, medium, high, critical
    status = Column(String(50), default="OPEN")            # OPEN, INVESTIGATING, CONTAINED, CLOSED
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    analyst = relationship("User", back_populates="cases")
    tasks = relationship("Task", back_populates="case", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    indicators = relationship("InvestigationIndicator", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    correlations = relationship("EvidenceCorrelation", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("AnalystNote", back_populates="case", cascade="all, delete-orphan")
    playbooks = relationship("Playbook", back_populates="case", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="case", cascade="all, delete-orphan")
    ml_predictions = relationship("MLThreatPrediction", back_populates="case", cascade="all, delete-orphan")
    merkle_trees = relationship("MerkleTreeRecord", back_populates="case", cascade="all, delete-orphan")
    blockchain_anchors = relationship("BlockchainAnchorRecord", back_populates="case", cascade="all, delete-orphan")
    correlated_incidents = relationship("CorrelatedIncident", back_populates="case", cascade="all, delete-orphan")


class Task(Base):
    __tablename__ = "tasks"

    id = Column(String(100), primary_key=True, index=True)  # TASK-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=False)
    name = Column(String(255), nullable=False)
    script_source = Column(Text, nullable=True)
    plan_payload = Column(JSON, nullable=False)
    task_hash = Column(String(64), nullable=True, index=True)
    plan_hash = Column(String(64), nullable=True)
    status = Column(String(50), default="pending")          # pending, assigned, running, completed, failed, timeout
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    timeout_seconds = Column(Integer, default=300)
    created_at = Column(DateTime, default=utc_now)
    assigned_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="tasks")
    agent = relationship("Agent", back_populates="tasks")
    results = relationship("TaskResult", back_populates="task", cascade="all, delete-orphan")

class TaskResult(Base):
    __tablename__ = "task_results"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(100), ForeignKey("tasks.id"), nullable=False)
    status = Column(String(50), default="success")
    output_summary = Column(Text, nullable=True)
    received_at = Column(DateTime, default=utc_now)

    task = relationship("Task", back_populates="results")
    evidence_items = relationship("Evidence", back_populates="task_result")

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(100), primary_key=True, index=True)  # EV-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=False)
    task_result_id = Column(Integer, ForeignKey("task_results.id"), nullable=True)
    execution_id = Column(String(100), nullable=True, index=True)
    script_hash = Column(String(64), nullable=True, index=True)
    collector = Column(String(100), nullable=False)        # process.list, file.hash, malware.pe_info, etc.
    collector_version = Column(String(50), default="1.0.0")
    collector_source = Column(String(100), nullable=True)
    platform = Column(String(50), nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    raw_data_hash = Column(String(64), nullable=True)
    normalized_data_hash = Column(String(64), nullable=True)
    raw_data = Column(JSON, nullable=True)
    normalized_data = Column(JSON, nullable=True)
    host_metadata = Column(JSON, nullable=True)
    envelope_data = Column(JSON, nullable=False)
    is_verified = Column(Boolean, default=True)
    collected_at = Column(DateTime, default=utc_now)
    content_hash = Column(String(64), nullable=True)
    metadata_hash = Column(String(64), nullable=True)
    previous_hash = Column(String(64), nullable=True)
    integrity_status = Column(String(50), default="VERIFIED")  # VERIFIED, SEALED, TAMPERED
    sealed_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="evidence_items")
    agent = relationship("Agent", back_populates="evidence_items")
    task_result = relationship("TaskResult", back_populates="evidence_items")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), nullable=True, index=True) # AUDIT-UUID
    case_id = Column(String(100), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    actor = Column(String(100), default="SYSTEM")          # email, agent_id, or SYSTEM
    actor_type = Column(String(50), default="USER")        # USER, AGENT, SYSTEM
    action = Column(String(100), nullable=False)           # LOGIN, DISPATCH_TASK, VERIFY_EVIDENCE, etc.
    resource = Column(String(255), nullable=False)
    resource_type = Column(String(100), nullable=True)      # Task, Evidence, Playbook, Config, Case
    resource_id = Column(String(100), nullable=True)
    result = Column(String(50), default="SUCCESS")         # SUCCESS, DENIED, FAILURE
    details = Column(JSON, nullable=True)
    ip_address = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=utc_now)
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True, index=True)

    user = relationship("User", back_populates="audit_logs")

class Report(Base):
    __tablename__ = "reports"

    id = Column(String(100), primary_key=True, index=True)  # REP-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), default="comprehensive") # summary, comprehensive, technical
    content_json = Column(JSON, nullable=False)
    html_content = Column(Text, nullable=True)
    csv_content = Column(Text, nullable=True)
    pdf_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    report_version = Column(String(50), default="1.0.0")
    evidence_count = Column(Integer, default=0)
    evidence_hash = Column(String(64), nullable=True)
    investigation_hash = Column(String(64), nullable=True)
    cti_hash = Column(String(64), nullable=True)
    playbook_audit_hash = Column(String(64), nullable=True)
    report_content_hash = Column(String(64), nullable=True)
    manifest_json = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="reports")
 
class InvestigationIndicator(Base):
    __tablename__ = "investigation_indicators"

    id = Column(String(100), primary_key=True, index=True)  # IOC-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    indicator_type = Column(String(50), nullable=False)      # ipv4, ipv6, domain, url, filepath, sha256, md5, process_name, service_name, registry_path
    value = Column(String(500), nullable=False)
    normalized_value = Column(String(500), nullable=False, index=True)
    source_evidence_id = Column(String(100), ForeignKey("evidence.id"), nullable=True)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    status = Column(String(50), default="observed")          # observed, suspicious, matched, correlated
    context_data = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="indicators")
    source_evidence = relationship("Evidence")
    agent = relationship("Agent")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String(100), primary_key=True, index=True)  # TLE-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=True)
    execution_id = Column(String(100), nullable=True, index=True)
    finding_id = Column(String(100), nullable=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    event_type = Column(String(50), nullable=False)         # PROCESS, FILE, NETWORK, PERSISTENCE, SERVICE, REGISTRY, SYSTEM, ANALYSIS
    description = Column(Text, nullable=False)
    evidence_id = Column(String(100), ForeignKey("evidence.id"), nullable=True)
    evidence_ids = Column(JSON, nullable=True)
    severity = Column(String(50), default="INFO")           # INFO, LOW, MEDIUM, HIGH, CRITICAL
    details = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="timeline_events")
    agent = relationship("Agent")
    evidence = relationship("Evidence")

class EvidenceCorrelation(Base):
    __tablename__ = "evidence_correlations"

    id = Column(String(100), primary_key=True, index=True)  # CORR-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    correlation_type = Column(String(100), nullable=False)  # SAME_HASH_CROSS_AGENT, PROCESS_NETWORK_OUTBOUND, PERSISTENCE_EXECUTABLE_LINK, TEMPORAL_CONCURRENCY
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    primary_agent_id = Column(String(100), nullable=True)
    related_agent_ids = Column(JSON, nullable=True)         # list of agent ids
    evidence_ids = Column(JSON, nullable=True)              # list of evidence ids
    indicators = Column(JSON, nullable=True)                # list of indicator values
    score = Column(Integer, default=50)
    detected_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="correlations")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(100), primary_key=True, index=True)  # FINDING-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    execution_id = Column(String(100), nullable=True, index=True)
    script_hash = Column(String(64), nullable=True, index=True)
    detection_type = Column(String(50), default="rule")     # rule, ml, correlation
    detection_rule_id = Column(String(100), nullable=True)  # RULE-PROC-001
    model_name = Column(String(100), nullable=True)
    model_version = Column(String(50), nullable=True)
    confidence_score = Column(Float, nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    reason = Column(Text, nullable=True)
    status = Column(String(50), default="OPEN")             # OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED
    priority = Column(String(50), default="MEDIUM")         # LOW, MEDIUM, HIGH, CRITICAL
    priority_score = Column(Integer, default=50)
    priority_reasons = Column(JSON, nullable=True)          # list of string reasons
    explainable_factors = Column(JSON, nullable=True)       # list of {name, value, contribution, evidence_ids}
    related_agents = Column(JSON, nullable=True)            # list of agent ids
    evidence_ids = Column(JSON, nullable=True)              # list of evidence ids
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    case = relationship("Case", back_populates="findings")

class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(String(100), primary_key=True, index=True)  # NOTE-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    analyst_name = Column(String(255), default="Forensic Analyst")
    note_type = Column(String(50), default="investigation_note")  # observation, hypothesis, conclusion, investigation_note
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="notes")


# ============================================================================
# PHASE 6 MODELS — Threat Intelligence, Response Playbooks & Approvals
# ============================================================================

class ThreatIntelItem(Base):
    __tablename__ = "threat_intel_items"

    id = Column(String(100), primary_key=True, index=True)  # INTEL-UUID
    stix_id = Column(String(255), nullable=True, index=True) # STIX 2.1 ID e.g. indicator--...
    intel_type = Column(String(50), nullable=False)          # indicator, malware, threat-actor, attack-pattern, relationship
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    pattern = Column(Text, nullable=True)                    # STIX pattern or indicator value
    pattern_type = Column(String(50), default="stix")
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    confidence = Column(Integer, default=75)
    source = Column(String(100), default="LOCAL")            # LOCAL, TAXII, DEMO
    labels = Column(JSON, nullable=True)                     # list of tag strings
    indicators = Column(JSON, nullable=True)                 # parsed IOC dict: {sha256: [...], ip: [...], domain: [...], process: [...]}
    mitre_attack_id = Column(String(100), nullable=True, index=True) # e.g. T1059, T1053
    raw_stix = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(100), primary_key=True, index=True)  # PB-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(String(50), default="1.0.0")
    status = Column(String(50), default="DRAFT")            # DRAFT, PENDING_APPROVAL, APPROVED, EXECUTING, COMPLETED, REJECTED
    trigger_type = Column(String(100), default="MANUAL")    # MANUAL, THREAT_MATCH, CORRELATION
    definition_json = Column(JSON, nullable=False)
    content_hash = Column(String(64), nullable=True, index=True) # SHA-256 canonical hash of playbook actions
    approval_hash = Column(String(64), nullable=True)            # Cryptographic signature/hash of approved definition
    created_by = Column(String(100), default="analyst")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    case = relationship("Case", back_populates="playbooks")
    actions = relationship("PlaybookAction", back_populates="playbook", cascade="all, delete-orphan", order_by="PlaybookAction.step_number")
    approvals = relationship("PlaybookApproval", back_populates="playbook", cascade="all, delete-orphan")
    executions = relationship("PlaybookExecution", back_populates="playbook", cascade="all, delete-orphan")


class PlaybookAction(Base):
    __tablename__ = "playbook_actions"

    id = Column(String(100), primary_key=True, index=True)  # ACT-UUID
    playbook_id = Column(String(100), ForeignKey("playbooks.id"), nullable=False)
    step_number = Column(Integer, nullable=False)
    action_type = Column(String(100), nullable=False)        # collect.processes, isolate.endpoint.simulated, etc.
    target_agent_id = Column(String(100), nullable=True)
    parameters = Column(JSON, nullable=True)
    status = Column(String(50), default="PENDING")          # PENDING, RUNNING, COMPLETED, FAILED, SKIPPED
    result_details = Column(JSON, nullable=True)
    executed_at = Column(DateTime, nullable=True)

    playbook = relationship("Playbook", back_populates="actions")


class PlaybookApproval(Base):
    __tablename__ = "playbook_approvals"

    id = Column(String(100), primary_key=True, index=True)  # APPR-UUID
    playbook_id = Column(String(100), ForeignKey("playbooks.id"), nullable=False)
    approver_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approver_email = Column(String(255), nullable=False)
    decision = Column(String(50), nullable=False)           # APPROVED, REJECTED
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    playbook = relationship("Playbook", back_populates="approvals")


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(String(100), primary_key=True, index=True)  # EXEC-UUID
    playbook_id = Column(String(100), ForeignKey("playbooks.id"), nullable=False)
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False)
    executor_email = Column(String(255), nullable=True)
    status = Column(String(50), default="RUNNING")          # RUNNING, COMPLETED, FAILED
    result_hash = Column(String(64), nullable=True)
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    summary = Column(JSON, nullable=True)

    playbook = relationship("Playbook", back_populates="executions")


# ============================================================================
# PHASE 7 MODELS — Security Hardening, Tamper Detection & Integrity
# ============================================================================

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(100), primary_key=True, index=True)  # SECEV-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=True, index=True)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)  # EVIDENCE_TAMPER, AUDIT_CHAIN_CORRUPTION, etc.
    severity = Column(String(50), default="HIGH", index=True)     # LOW, MEDIUM, HIGH, CRITICAL
    object_type = Column(String(100), nullable=False)            # EVIDENCE, AUDIT, AGENT, TASK, PLAYBOOK, CONFIG, REPORT
    object_id = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    expected_value = Column(Text, nullable=True)
    observed_value = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=utc_now, index=True)
    resolved = Column(Boolean, default=False, index=True)
    resolved_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    integrity_hash = Column(String(64), nullable=True)
    metadata_json = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="security_events")
    agent = relationship("Agent")


# ============================================================================
# LEVEL 3 MODELS — ML Threat Detection & Prediction Integrity
# ============================================================================

class MLThreatPrediction(Base):
    __tablename__ = "ml_threat_predictions"

    id = Column(String(100), primary_key=True, index=True)  # MLPRED-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String(100), ForeignKey("evidence.id"), nullable=True, index=True)
    agent_id = Column(String(100), ForeignKey("agents.id"), nullable=True, index=True)

    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50), nullable=False)
    feature_schema_version = Column(String(50), nullable=False, default="1.0")

    classification = Column(String(50), nullable=False)  # NORMAL, SUSPICIOUS, MALICIOUS
    threat_score = Column(Float, nullable=False)         # 0.0 - 1.0
    confidence = Column(Float, nullable=False)           # 0.0 - 1.0

    feature_vector = Column(JSON, nullable=False)        # Dict of 21 features
    top_factors = Column(JSON, nullable=True)            # List of top contributing factors
    probabilities = Column(JSON, nullable=True)          # Dict of class probabilities

    model_hash = Column(String(64), nullable=False)
    prediction_hash = Column(String(64), nullable=False, index=True)
    integrity_status = Column(String(50), default="VERIFIED")  # VERIFIED, TAMPERED

    created_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="ml_predictions")
    evidence = relationship("Evidence")
    agent = relationship("Agent")


# ============================================================================
# JOCKY Studio Execution History Model
# ============================================================================

class ExecutionHistory(Base):
    __tablename__ = "execution_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_id = Column(String(50), unique=True, index=True, nullable=False)  # EXE-0001
    case_id = Column(String(100), default="CASE-2026-001", index=True)
    script_name = Column(String(255), default="demo_persistence.jocky")
    script_content = Column(Text, nullable=False)
    script_hash = Column(String(64), nullable=True, index=True)
    target = Column(String(255), default="DEMO-WINDOWS-ENDPOINT")
    status = Column(String(50), default="SUCCESS")  # SUCCESS, FAILED, RUNNING
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, default=0.0)
    threat_score = Column(Integer, nullable=True)
    risk_level = Column(String(50), nullable=True)
    evidence_categories = Column(JSON, nullable=True)
    forensic_vector_dimensions = Column(Integer, default=21)
    tamper_checks_passed = Column(Integer, default=12)
    tamper_checks_total = Column(Integer, default=12)
    chain_status = Column(String(50), default="VERIFIED")
    merkle_root = Column(String(64), nullable=True)
    blockchain_block_hash = Column(String(64), nullable=True)
    evidence_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    result_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)


# ============================================================================
# PHASE 27 MODELS — Merkle Tree, Blockchain Anchoring & Incidents
# ============================================================================

class MerkleTreeRecord(Base):
    __tablename__ = "merkle_trees"

    id = Column(String(100), primary_key=True, index=True)  # MRK-UUID
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False, index=True)
    execution_id = Column(String(100), nullable=True, index=True)
    merkle_root = Column(String(64), nullable=False, index=True)
    evidence_count = Column(Integer, nullable=False, default=0)
    evidence_hashes = Column(JSON, nullable=False)          # Ordered list of leaf hashes
    tree_structure = Column(JSON, nullable=True)            # All levels of the tree
    algorithm = Column(String(50), default="SHA-256")
    created_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="merkle_trees")


class BlockchainAnchorRecord(Base):
    __tablename__ = "blockchain_anchors"

    id = Column(String(100), primary_key=True, index=True)  # BLK-UUID
    block_number = Column(Integer, nullable=False, index=True)
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False, index=True)
    execution_id = Column(String(100), nullable=True, index=True)
    merkle_root = Column(String(64), nullable=False, index=True)
    script_hash = Column(String(64), nullable=True, index=True)
    evidence_count = Column(Integer, nullable=False, default=0)
    previous_block_hash = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False, index=True)
    network = Column(String(100), default="Local Evidence Blockchain")
    status = Column(String(50), default="ANCHORED")         # ANCHORED, VERIFIED, TAMPERED
    timestamp = Column(DateTime, default=utc_now)
    payload_json = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="blockchain_anchors")


class CorrelatedIncident(Base):
    __tablename__ = "correlated_incidents"

    id = Column(String(100), primary_key=True, index=True)  # INC-000003
    case_id = Column(String(100), ForeignKey("cases.id"), nullable=False, index=True)
    execution_id = Column(String(100), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    classification = Column(String(100), default="Suspicious Activity Cluster")
    description = Column(Text, nullable=False)
    evidence_ids = Column(JSON, nullable=False)             # ["EVD-21", "EVD-34", ...]
    finding_ids = Column(JSON, nullable=True)              # ["FND-004", ...]
    timeline_sequence = Column(JSON, nullable=True)        # ["process_created", ...]
    severity = Column(String(50), default="HIGH")
    created_at = Column(DateTime, default=utc_now)

    case = relationship("Case", back_populates="correlated_incidents")


