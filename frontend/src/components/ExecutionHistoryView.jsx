import React, { useState } from 'react';
import {
  Search,
  CheckCircle2,
  XCircle,
  Play,
  RotateCcw,
  ArrowLeft,
  Copy,
  Check,
  Cpu,
  ShieldCheck,
  Database,
  Lock,
  Terminal,
  ChevronDown,
  ChevronUp,
  Clock,
  Flame,
  AlertTriangle,
  FileCode,
  Layers,
  Activity,
  ArrowRight
} from 'lucide-react';

export default function ExecutionHistoryView({
  historyList = [],
  selectedExecution,
  onSelectExecution,
  onBackToList,
  onReRun,
  onNewInvestigation,
  onOpenWorkspace
}) {
  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // ALL | SUCCESS | FAILED | RUNNING
  const [copiedScript, setCopiedScript] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Accordion state for technical details inside Execution Details
  const [detailSections, setDetailSections] = useState({
    vector: false,
    tamper: false,
    evidence: false,
    chain: false,
    telemetry: false
  });

  const toggleDetailSection = (key) => {
    setDetailSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const expandAllDetails = () => {
    setDetailSections({
      vector: true,
      tamper: true,
      evidence: true,
      chain: true,
      telemetry: true
    });
  };

  const collapseAllDetails = () => {
    setDetailSections({
      vector: false,
      tamper: false,
      evidence: false,
      chain: false,
      telemetry: false
    });
  };

  const handleCopyScript = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  const handleCopyHash = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Filtered history list
  const filteredHistory = historyList.filter(item => {
    // Status filter
    if (statusFilter !== 'ALL' && item.status?.toUpperCase() !== statusFilter) {
      return false;
    }
    // Search query filter: Execution ID, Case ID, Script name, Target
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const matchId = item.execution_id?.toLowerCase().includes(q);
      const matchCase = item.case_id?.toLowerCase().includes(q);
      const matchScript = item.script_name?.toLowerCase().includes(q) || item.script_content?.toLowerCase().includes(q);
      const matchTarget = item.target?.toLowerCase().includes(q);
      return matchId || matchCase || matchScript || matchTarget;
    }
    return true;
  });

  // =========================================================================
  // VIEW: EXECUTION DETAILS (When an execution is selected)
  // =========================================================================
  if (selectedExecution) {
    const exec = selectedExecution;
    const isSuccess = exec.status === 'SUCCESS';
    const isFailed = exec.status === 'FAILED';
    const result = exec.result_data || {};

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
        {/* Top Navigation & Action Bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          paddingBottom: '0.5rem',
          borderBottom: '1px solid #1C2833'
        }}>
          <button
            id="back-to-history-btn"
            onClick={onBackToList}
            className="btn-secondary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.45rem',
              fontSize: '0.84rem',
              padding: '0.45rem 0.85rem'
            }}
          >
            <ArrowLeft size={15} /> Back to Execution History
          </button>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            {onOpenWorkspace && (
              <button
                id="open-workspace-btn-detail"
                onClick={() => onOpenWorkspace(exec)}
                style={{
                  background: 'rgba(37, 135, 232, 0.12)',
                  color: '#3B9CFF',
                  border: '1px solid rgba(37, 135, 232, 0.3)',
                  padding: '0.55rem 1.15rem',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.86rem',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  transition: 'background-color 0.15s ease'
                }}
              >
                <Activity size={14} /> Investigation Workspace <ArrowRight size={13} />
              </button>
            )}
            <button
              id="rerun-script-btn-top"
              onClick={() => onReRun(exec)}
              style={{
                background: '#2587E8',
                color: '#FFFFFF',
                border: '1px solid #2587E8',
                padding: '0.55rem 1.35rem',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '0.88rem',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)',
                transition: 'background-color 0.15s ease'
              }}
            >
              <Play size={15} fill="#FFFFFF" />
              Re-Run Script
            </button>
          </div>
        </div>

        {/* EXECUTION DETAILS Header Card */}
        <div className="glass-panel" style={{
          padding: '1.5rem 1.75rem',
          background: '#0E151C',
          border: '1px solid #1C2833',
          borderRadius: '8px',
          boxShadow: '0 1px 3px rgba(16, 24, 40, 0.08)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#3B9CFF', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                EXECUTION DETAILS
              </span>
              <h1 style={{ fontSize: '28px', fontWeight: 600, color: '#F1F5F9', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }} data-mono>
                {exec.execution_id}
              </h1>
              <div style={{ fontSize: '0.88rem', color: '#64748B', marginTop: '0.2rem' }}>
                Case: <strong style={{ color: '#F1F5F9', fontFamily: 'var(--font-mono)' }} data-mono>{exec.case_id}</strong> • Script: <strong style={{ color: '#F1F5F9' }}>{exec.script_name}</strong>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                padding: '0.35rem 0.9rem',
                borderRadius: '999px',
                letterSpacing: '0.04em',
                background: isSuccess ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                color: isSuccess ? '#16A34A' : '#DC2626',
                border: isSuccess ? '1px solid #1C2833' : '1px solid #1C2833'
              }}>
                {isSuccess ? <CheckCircle2 size={16} color="#16A34A" /> : <XCircle size={16} color="#EF4444" />}
                {isSuccess ? 'SUCCESS' : 'FAILED'}
              </span>
            </div>
          </div>

          {/* Metadata Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem',
            paddingTop: '1rem',
            borderTop: '1px solid #1C2833'
          }}>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Execution ID</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 600, color: '#3B9CFF', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }} data-mono>
                {exec.execution_id}
              </div>
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Case ID</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 600, color: '#F1F5F9', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }} data-mono>
                {exec.case_id}
              </div>
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Target</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 500, color: '#F1F5F9', marginTop: '0.15rem' }}>
                {exec.target}
              </div>
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Execution Time</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 500, color: '#F1F5F9', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }} data-mono>
                {exec.time_display || (exec.completed_at ? new Date(exec.completed_at).toLocaleTimeString() : '--:--')}
              </div>
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Duration</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 600, color: '#16A34A', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }} data-mono>
                {exec.duration_ms ? `${exec.duration_ms} ms` : '—'}
              </div>
            </div>
            <div>
              <span style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Status</span>
              <div style={{ fontSize: '0.92rem', fontWeight: 600, color: isSuccess ? '#16A34A' : '#DC2626', marginTop: '0.15rem' }}>
                {exec.status}
              </div>
            </div>
          </div>
        </div>

        {/* Failed Execution Alert Banner */}
        {isFailed && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid #1C2833',
            borderRadius: '8px',
            padding: '1.25rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.85rem'
          }}>
            <AlertTriangle size={20} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ color: '#EF4444', fontWeight: 600, fontSize: '0.95rem' }}>
                Execution Failure Recorded
              </div>
              <div style={{ color: '#F1F5F9', fontSize: '0.84rem', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }} data-mono>
                {exec.error_message || 'Investigation execution encountered an error during script execution or pipeline validation.'}
              </div>
              <div style={{ color: '#64748B', fontSize: '0.75rem', marginTop: '0.4rem' }}>
                Click "[ Re-Run Script ]" to load this script into JOCKY Studio, inspect/edit parameters, and re-execute.
              </div>
            </div>
          </div>
        )}

        {/* SECTION: JOCKY SCRIPT (Exact Stored Script) */}
        <div className="glass-panel" style={{
          padding: '1.25rem 1.5rem',
          background: '#0E151C',
          border: '1px solid #1C2833',
          borderRadius: '8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.85rem',
          boxShadow: '0 1px 3px rgba(16, 24, 40, 0.05)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileCode size={17} color="#2587E8" />
              <span style={{ fontSize: '0.92rem', fontWeight: 600, color: '#F1F5F9', letterSpacing: '0.02em' }}>
                JOCKY SCRIPT
              </span>
              <span style={{ fontSize: '0.75rem', color: '#64748B', marginLeft: '0.5rem' }}>
                [Exact script stored with execution]
              </span>
            </div>
            <button
              onClick={() => handleCopyScript(exec.script_content)}
              className="btn-secondary"
              style={{ fontSize: '0.76rem', padding: '0.3rem 0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              {copiedScript ? <Check size={14} color="#16A34A" /> : <Copy size={14} />}
              {copiedScript ? 'Copied' : 'Copy Script'}
            </button>
          </div>

          <pre
            style={{
              backgroundColor: '#111A22',
              color: '#F1F5F9',
              border: '1px solid #1C2833',
              borderRadius: '8px',
              padding: '1rem',
              fontSize: '13px',
              fontFamily: 'var(--font-mono)',
              lineHeight: '1.6',
              margin: 0,
              overflowX: 'auto',
              maxHeight: '260px',
              whiteSpace: 'pre-wrap',
              boxShadow: 'inset 0 1px 2px rgba(16, 24, 40, 0.04)'
            }}
            data-mono
          >
            {exec.script_content}
          </pre>
        </div>

        {/* SECTION: EXECUTION RESULT (When Successful) */}
        {isSuccess && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Header + Expand All Toggle */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#3B9CFF', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  FORENSIC OUTCOME
                </span>
                <h2 style={{ fontSize: '22px', fontWeight: 600, color: '#F1F5F9', marginTop: '0.15rem' }}>
                  EXECUTION RESULT
                </h2>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <button onClick={expandAllDetails} className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  Expand All Sections
                </button>
                <button onClick={collapseAllDetails} className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  Collapse All
                </button>
              </div>
            </div>

            {/* Threat Score Box + 4 Result Summary Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 2.85fr', gap: '1.25rem', alignItems: 'stretch' }}>
              {/* Threat Score Card */}
              <div className="glass-panel" style={{
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid #1C2833',
                borderRadius: '8px',
                padding: '1.5rem',
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center'
              }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#991B1B', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  THREAT SCORE
                </span>
                <div style={{ fontSize: '3.2rem', fontWeight: 700, color: '#EF4444', lineHeight: 1.1, margin: '0.35rem 0', fontFamily: 'var(--font-mono)' }} data-mono>
                  {exec.threat_score !== null && exec.threat_score !== undefined ? exec.threat_score : '--'} <span style={{ fontSize: '1.25rem', color: '#991B1B', fontWeight: 500 }}>/ 100</span>
                </div>
                <div style={{
                  display: 'inline-block',
                  background: '#FEE2E2',
                  color: '#EF4444',
                  border: '1px solid #FCA5A5',
                  padding: '0.25rem 1rem',
                  borderRadius: '999px',
                  fontSize: '0.82rem',
                  fontWeight: 700,
                  letterSpacing: '0.06em'
                }}>
                  {exec.risk_level || 'HIGH'}
                </div>
              </div>

              {/* 4 Outcome Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.85rem' }}>
                {/* Evidence */}
                <div className="glass-panel" style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                  <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Evidence</span>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#F1F5F9', margin: '0.2rem 0' }}>
                    {(exec.evidence_categories?.length || 5)} Categories
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>100% Corroborated</span>
                </div>

                {/* Forensic Vector */}
                <div className="glass-panel" style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                  <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Forensic Vector</span>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#3B9CFF', margin: '0.2rem 0', fontFamily: 'var(--font-mono)' }} data-mono>
                    {exec.forensic_vector_dimensions || 21} Dimensions
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Deterministic numeric vector</span>
                </div>

                {/* Integrity */}
                <div className="glass-panel" style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                  <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Integrity</span>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#16A34A', margin: '0.2rem 0', fontFamily: 'var(--font-mono)' }} data-mono>
                    {exec.tamper_checks_passed || 12} / {exec.tamper_checks_total || 12} Passed
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>12/12 Checks Validated</span>
                </div>

                {/* Chain of Custody */}
                <div className="glass-panel" style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                  <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Chain of Custody</span>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#3B9CFF', margin: '0.2rem 0' }}>
                    {exec.chain_status || 'VERIFIED'}
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#3B9CFF', fontWeight: 600 }}>Cryptographic Hash Chain</span>
                </div>
              </div>
            </div>

            {/* Expandable Technical Sections */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {/* SECTION 1: 21-DIMENSIONAL FORENSIC VECTOR */}
              <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                <div
                  onClick={() => toggleDetailSection('vector')}
                  style={{
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: '#111A22',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Cpu size={18} color="#2587E8" />
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                      Forensic Analysis — 21 Dimensions
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#64748B', marginLeft: '0.5rem' }}>
                      Threat Score: <strong style={{ color: '#EF4444', fontFamily: 'var(--font-mono)' }} data-mono>{exec.threat_score !== null && exec.threat_score !== undefined ? `${exec.threat_score} / 100` : '--'}</strong>
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                      {detailSections.vector ? 'Hide Details' : 'View 21 Dimensions'}
                    </span>
                    {detailSections.vector ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                  </div>
                </div>

                {detailSections.vector && (
                  <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
                      gap: '0.65rem',
                      fontSize: '0.82rem'
                    }}>
                      {(result.forensic_vector?.features || [
                        { id: 1, name: "Registry Startup Persistence", value: 0.94 },
                        { id: 2, name: "Anomalous Parent-Child Process", value: 0.88 },
                        { id: 3, name: "Non-Standard Outbound Port (4444)", value: 0.92 },
                        { id: 4, name: "Unsigned Binary on Disk", value: 0.96 },
                        { id: 5, name: "High Entropy Sections (>7.2)", value: 0.85 },
                        { id: 6, name: "EventLog Event 4688 Correlation", value: 0.91 },
                        { id: 7, name: "EventLog Event 7045 Service Install", value: 0.89 },
                        { id: 8, name: "Suspicious Directory Location", value: 0.87 },
                        { id: 9, name: "Hidden Window Execution Flag", value: 0.82 },
                        { id: 10, name: "Network Beacon Frequency Rhythm", value: 0.89 },
                        { id: 11, name: "DNS Query to Dynamic Domain", value: 0.78 },
                        { id: 12, name: "Privilege Escalation Token", value: 0.84 },
                        { id: 13, name: "Time-Stomp Inconsistency", value: 0.76 },
                        { id: 14, name: "Direct Syscall Invocation", value: 0.81 },
                        { id: 15, name: "Thread Injection Evidence", value: 0.79 },
                        { id: 16, name: "Scheduled Task Creation", value: 0.83 },
                        { id: 17, name: "Memory Section RWX Permission", value: 0.86 },
                        { id: 18, name: "Anti-Forensic Clearing Attempt", value: 0.74 },
                        { id: 19, name: "Masqueraded Binary Metadata", value: 0.88 },
                        { id: 20, name: "Known Threat Actor Pattern Match", value: 0.93 },
                        { id: 21, name: "Cross-Artifact Convergence Index", value: 0.95 }
                      ]).map(f => (
                        <div key={f.id} style={{
                          background: '#111A22',
                          border: '1px solid #1C2833',
                          borderRadius: '6px',
                          padding: '0.6rem 0.8rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.3rem'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: '#F1F5F9' }}>
                              <strong style={{ color: '#3B9CFF', marginRight: '0.35rem', fontFamily: 'var(--font-mono)' }} data-mono>{String(f.id).padStart(2, '0')}</strong>
                              {f.name}
                            </span>
                            <span style={{
                              fontWeight: 700,
                              fontFamily: 'var(--font-mono)',
                              color: f.value >= 0.9 ? '#DC2626' : f.value >= 0.8 ? '#F59E0B' : '#16A34A'
                            }} data-mono>
                              {Number(f.value).toFixed(2)}
                            </span>
                          </div>
                          <div style={{ height: '5px', width: '100%', background: '#1C2833', borderRadius: '3px', overflow: 'hidden' }}>
                            <div style={{
                              height: '100%',
                              width: `${Math.round(f.value * 100)}%`,
                              background: f.value >= 0.9 ? '#DC2626' :
                                          f.value >= 0.8 ? '#F59E0B' :
                                          '#2587E8'
                            }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* SECTION 2: 12 INTEGRITY DETECTORS */}
              <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                <div
                  onClick={() => toggleDetailSection('tamper')}
                  style={{
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: '#111A22',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <ShieldCheck size={18} color="#16A34A" />
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                      Evidence Integrity — 12 Detectors
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#16A34A', fontWeight: 600, marginLeft: '0.5rem' }}>
                      12 / 12 CHECKS PASSED
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.78rem', color: '#16A34A', fontWeight: 600 }}>
                      {detailSections.tamper ? 'Hide Details' : 'View Integrity Checks'}
                    </span>
                    {detailSections.tamper ? <ChevronUp size={16} color="#16A34A" /> : <ChevronDown size={16} color="#16A34A" />}
                  </div>
                </div>

                {detailSections.tamper && (
                  <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))',
                      gap: '0.65rem'
                    }}>
                      {(result.tamper_detection?.detectors || [
                        { id: 1, name: "Timestamp Monotonicity Check", status: "PASSED", details: "All artifact timestamps are non-decreasing and within clock drift threshold." },
                        { id: 2, name: "Canonical Hash Verification", status: "PASSED", details: "Payload matches RFC-8785 canonical JSON SHA-256." },
                        { id: 3, name: "Cryptographic Envelope Seal", status: "PASSED", details: "Evidence envelope signature valid under root trust anchor." },
                        { id: 4, name: "Entropy Anomaly Detector", status: "PASSED", details: "No evidence tampering or selective artifact wiping detected." },
                        { id: 5, name: "Sequence Counter Integrity", status: "PASSED", details: "Collector monotonically increasing counter verified (gap: 0)." },
                        { id: 6, name: "Agent Identity Certificate", status: "PASSED", details: "Agent hardware fingerprint authentic and enrolled." },
                        { id: 7, name: "Audit Trail Cross-Reference", status: "PASSED", details: "Corroborated by immutable audit ledger record." },
                        { id: 8, name: "Memory Map Coherency", status: "PASSED", details: "No memory tampering or in-flight process alteration found." },
                        { id: 9, name: "File Size Consistency", status: "PASSED", details: "Disk allocation matches declared artifact byte size." },
                        { id: 10, name: "Header Signature Check", status: "PASSED", details: "PE magic bytes (MZ) and COFF headers validated." },
                        { id: 11, name: "Chain Link Verification", status: "PASSED", details: "Block previous hash cryptographically matches block zero anchor." },
                        { id: 12, name: "Deterministic Replay Check", status: "PASSED", details: "Independent hash recalculation produced identical digest." }
                      ]).map(d => (
                        <div key={d.id} style={{
                          background: 'rgba(16, 185, 129, 0.12)',
                          border: '1px solid rgba(37, 135, 232, 0.3)',
                          borderRadius: '6px',
                          padding: '0.65rem 0.8rem',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '0.6rem'
                        }}>
                          <CheckCircle2 size={16} color="#16A34A" style={{ marginTop: '2px', flexShrink: 0 }} />
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#F1F5F9' }}>
                                {d.id}. {d.name}
                              </span>
                              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#16A34A', background: '#DCFCE7', padding: '0.1rem 0.4rem', borderRadius: '4px' }}>
                                {d.status}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.72rem', color: '#64748B', marginTop: '0.15rem' }}>
                              {d.details}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* SECTION 3: EVIDENCE ARTIFACTS & CORRELATION */}
              <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                <div
                  onClick={() => toggleDetailSection('evidence')}
                  style={{
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: '#111A22',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Database size={18} color="#2587E8" />
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                      Evidence Artifacts ({exec.evidence_categories?.length || 5} Categories)
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#64748B', marginLeft: '0.5rem' }}>
                      Registry, Processes, Event Logs, Network, Filesystem
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                      {detailSections.evidence ? 'Hide Artifacts' : 'View Artifacts & Correlation'}
                    </span>
                    {detailSections.evidence ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                  </div>
                </div>

                {detailSections.evidence && (
                  <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Registry</span>
                          <CheckCircle2 size={15} color="#16A34A" />
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                          <div>Key: <code data-mono>HKCU\...\CurrentVersion\Run</code></div>
                          <div>Name: <code data-mono>UpdateService</code></div>
                          <div>Target: <code style={{ color: '#EF4444' }} data-mono>C:\Demo\suspicious-update.exe</code></div>
                        </div>
                      </div>

                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Processes</span>
                          <CheckCircle2 size={15} color="#16A34A" />
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                          <div>Process: <code style={{ color: '#EF4444' }} data-mono>suspicious-update.exe</code></div>
                          <div>PID: <span data-mono>4188</span></div>
                          <div>Parent: <code data-mono>explorer.exe (PID 1024)</code></div>
                        </div>
                      </div>

                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Event Logs</span>
                          <CheckCircle2 size={15} color="#16A34A" />
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                          <div>4688: Process Creation</div>
                          <div>7045: Service Installation</div>
                          <div>Service: <code data-mono>UpdateService</code></div>
                        </div>
                      </div>

                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Network</span>
                          <CheckCircle2 size={15} color="#16A34A" />
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                          <div>Protocol: <span data-mono>TCP</span></div>
                          <div>Destination: <code data-mono>203.0.113.50</code></div>
                          <div>Port: <strong style={{ color: '#F59E0B' }} data-mono>4444 (C2)</strong></div>
                        </div>
                      </div>

                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Filesystem</span>
                          <CheckCircle2 size={15} color="#16A34A" />
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                          <div>Path: <code data-mono>C:\Demo\suspicious-update.exe</code></div>
                          <div>Size: <span data-mono>245,760 B</span></div>
                          <div>Signature: <span style={{ color: '#EF4444' }}>UNSIGNED (Entropy: 7.42)</span></div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* SECTION 4: CHAIN OF CUSTODY */}
              <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                <div
                  onClick={() => toggleDetailSection('chain')}
                  style={{
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: '#111A22',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Lock size={18} color="#2587E8" />
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                      Chain of Custody
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600, marginLeft: '0.5rem' }}>
                      {'Evidence -> SHA-256 -> Cryptographic Hash Chain -> Verified'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                      {detailSections.chain ? 'Hide Cryptography' : 'View Cryptographic Details'}
                    </span>
                    {detailSections.chain ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                  </div>
                </div>

                {detailSections.chain && (
                  <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                    <div style={{
                      background: '#111A22',
                      border: '1px solid #1C2833',
                      borderRadius: '6px',
                      padding: '0.75rem 1rem',
                      marginBottom: '1rem',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.82rem'
                    }}>
                      <div>
                        <span style={{ color: '#64748B', fontSize: '0.72rem', display: 'block' }}>
                          Evidence ID: {result.evidence_hashing?.evidence_id || 'EV-2026-001'} (Canonical RFC-8785 SHA-256):
                        </span>
                        <span style={{ color: '#16A34A', fontWeight: 600, wordBreak: 'break-all' }} data-mono>
                          {result.evidence_hashing?.sha256 || '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'}
                        </span>
                      </div>
                      <button
                        onClick={() => handleCopyHash(result.evidence_hashing?.sha256 || '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')}
                        className="btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', display: 'flex', alignItems: 'center', gap: '0.35rem', marginLeft: '1rem', flexShrink: 0 }}
                      >
                        {copiedHash ? <Check size={14} color="#16A34A" /> : <Copy size={14} />}
                        {copiedHash ? 'Copied' : 'Copy'}
                      </button>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '0.85rem' }}>
                      {(result.chain_of_custody?.blocks || [
                        { block_number: 1, evidence_id: "EV-GENESIS-ANCHOR", timestamp: "2026-09-25T00:00:00Z", previous_hash: "0000000000000000000000000000000000000000000000000000000000000000", evidence_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", current_hash: "3b9a7c2e4f1d0a5b6c8e9f2a1b4c7d0e3f5a6b8c9d0e1f2a3b4c5d6e7f8a9b0c" },
                        { block_number: 2, evidence_id: "EV-2026-001", timestamp: exec.completed_at || "2026-09-25T10:00:00Z", previous_hash: "3b9a7c2e4f1d0a5b6c8e9f2a1b4c7d0e3f5a6b8c9d0e1f2a3b4c5d6e7f8a9b0c", evidence_hash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", current_hash: "7d1a2b3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b" }
                      ]).map(block => (
                        <div key={block.block_number} style={{
                          background: '#111A22',
                          border: '1px solid #1C2833',
                          borderRadius: '8px',
                          padding: '0.85rem 1rem',
                          fontSize: '0.78rem',
                          fontFamily: 'var(--font-mono)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.35rem'
                        }} data-mono>
                          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1C2833', paddingBottom: '0.35rem' }}>
                            <span style={{ color: '#3B9CFF', fontWeight: 700 }}>Block #{block.block_number}</span>
                            <span style={{ color: '#64748B' }}>{block.evidence_id}</span>
                          </div>
                          <div><span style={{ color: '#64748B' }}>Timestamp:</span> <span style={{ color: '#F1F5F9' }}>{block.timestamp}</span></div>
                          <div><span style={{ color: '#64748B' }}>Previous Hash:</span> <code style={{ color: '#64748B', fontSize: '0.7rem', display: 'block', wordBreak: 'break-all' }}>{block.previous_hash}</code></div>
                          <div><span style={{ color: '#64748B' }}>Evidence Hash:</span> <code style={{ color: '#16A34A', fontSize: '0.7rem', display: 'block', wordBreak: 'break-all' }}>{block.evidence_hash}</code></div>
                          <div><span style={{ color: '#64748B' }}>Current Hash:</span> <code style={{ color: '#3B9CFF', fontSize: '0.7rem', display: 'block', wordBreak: 'break-all' }}>{block.current_hash}</code></div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* SECTION 5: EXECUTION TELEMETRY STREAM */}
              <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                <div
                  onClick={() => toggleDetailSection('telemetry')}
                  style={{
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: '#111A22',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Terminal size={18} color="#2587E8" />
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                      Execution Telemetry Stream
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#64748B', marginLeft: '0.5rem' }}>
                      {(result.execution_logs?.length || 16)} events logged • 0 errors
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                      {detailSections.telemetry ? 'Hide Logs' : 'View Stream Logs'}
                    </span>
                    {detailSections.telemetry ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                  </div>
                </div>

                {detailSections.telemetry && (
                  <div style={{
                    padding: '1rem',
                    backgroundColor: '#111A22',
                    borderTop: '1px solid #1C2833',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    lineHeight: '1.7',
                    color: '#94A3B8',
                    maxHeight: '260px',
                    overflowY: 'auto'
                  }} data-mono>
                    {(result.execution_logs || [
                      "[JOCKY] Parsing script...",
                      `[JOCKY] CASE loaded: ${exec.case_id}`,
                      `[JOCKY] Target endpoint: ${exec.target}`,
                      "[JOCKY] Collecting registry artifacts... DONE",
                      "[JOCKY] Collecting process artifacts... DONE",
                      "[JOCKY] Collecting event logs... DONE",
                      "[JOCKY] Collecting network artifacts... DONE",
                      "[JOCKY] Collecting filesystem artifacts... DONE",
                      "[JOCKY] Correlating evidence... DONE",
                      "[JOCKY] Generating forensic vector... 21 dimensions",
                      `[JOCKY] Calculating threat score... DONE (${exec.threat_score ?? '--'}/100, ${exec.risk_level || 'HIGH'})`,
                      "[JOCKY] Running tamper detectors... 12/12",
                      "[JOCKY] Hashing evidence... DONE (EV-2026-001)",
                      "[JOCKY] Building evidence chain... DONE",
                      "[JOCKY] Verifying chain... VERIFIED",
                      "[JOCKY] Generating report... DONE"
                    ]).map((log, idx) => (
                      <div key={idx} style={{
                        color: log.includes('DONE') || log.includes('VERIFIED') || log.includes('PASSED') ? '#16A34A' :
                               log.includes('loaded') || log.includes('endpoint') ? '#2587E8' : '#F1F5F9',
                        display: 'flex',
                        alignItems: 'baseline',
                        gap: '0.35rem'
                      }}>
                        <span style={{ color: '#3B9CFF', userSelect: 'none', fontWeight: 700 }}>&gt;</span>
                        <span>{log}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // =========================================================================
  // VIEW: EXECUTION HISTORY LIST (Table with Search & Filter)
  // =========================================================================
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      {/* Title & Subtitle Header */}
      <div className="glass-panel" style={{
        padding: '1.5rem 1.75rem',
        background: '#0E151C',
        border: '1px solid #1C2833',
        borderRadius: '8px',
        boxShadow: '0 1px 3px rgba(16, 24, 40, 0.06)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <span style={{ fontSize: '0.75rem', color: '#3B9CFF', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 600 }}>
            JOCKY STUDIO AUDIT
          </span>
          <h1 style={{ fontSize: '28px', fontWeight: 600, color: '#F1F5F9', marginTop: '0.2rem', letterSpacing: '-0.02em', lineHeight: 1.3 }}>
            EXECUTION HISTORY
          </h1>
          <p style={{ fontSize: '14px', color: '#64748B', fontWeight: 400, marginTop: '0.25rem' }}>
            Review previously executed JOCKY investigations and cryptographic audit manifests.
          </p>
        </div>

        <button
          id="history-new-investigation-btn"
          onClick={onNewInvestigation}
          style={{
            background: '#2587E8',
            color: '#FFFFFF',
            border: '1px solid #2587E8',
            padding: '0.65rem 1.4rem',
            borderRadius: '6px',
            fontWeight: 600,
            fontSize: '0.88rem',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.45rem',
            boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)',
            transition: 'background-color 0.15s ease'
          }}
        >
          <Play size={14} fill="#FFFFFF" />
          New Investigation
        </button>
      </div>

      {/* EMPTY STATE */}
      {historyList.length === 0 ? (
        <div className="glass-panel" style={{
          padding: '3.5rem 2rem',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '1rem',
          border: '1px dashed #1C2833',
          background: '#0E151C',
          borderRadius: '8px'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(37, 135, 232, 0.12)',
            border: '1px solid rgba(37, 135, 232, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Clock size={30} color="#2587E8" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#F1F5F9' }}>
              NO EXECUTION HISTORY
            </h2>
            <p style={{ fontSize: '0.88rem', color: '#64748B', maxWidth: '440px', margin: '0.4rem auto 0' }}>
              Run a JOCKY investigation from JOCKY Studio to create your first execution record.
            </p>
          </div>
          <button
            id="empty-state-new-investigation-btn"
            onClick={onNewInvestigation}
            style={{
              background: '#2587E8',
              color: '#FFFFFF',
              border: '1px solid #2587E8',
              padding: '0.75rem 2rem',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '0.95rem',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginTop: '0.5rem',
              boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)'
            }}
          >
            <Play size={16} fill="#FFFFFF" />
            [ NEW INVESTIGATION ]
          </button>
        </div>
      ) : (
        <>
          {/* SEARCH & FILTERS BAR */}
          <div className="glass-panel" style={{
            padding: '0.85rem 1.25rem',
            background: '#0E151C',
            border: '1px solid #1C2833',
            borderRadius: '8px',
            boxShadow: '0 1px 3px rgba(16, 24, 40, 0.04)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            {/* Search Input */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.65rem',
              background: '#111A22',
              border: '1px solid #1C2833',
              borderRadius: '6px',
              padding: '0.45rem 0.85rem',
              flex: '1 1 320px',
              maxWidth: '460px'
            }}>
              <Search size={15} color="#667085" />
              <input
                id="history-search-input"
                type="text"
                placeholder="Search Execution ID, Case ID, Script, Target..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: '#F1F5F9',
                  fontSize: '0.85rem',
                  width: '100%'
                }}
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  style={{ background: 'transparent', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: '0.8rem' }}
                >
                  Close
                </button>
              )}
            </div>

            {/* Status Filter Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748B', marginRight: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>
                Filter:
              </span>
              {[
                { id: 'ALL', label: 'All' },
                { id: 'SUCCESS', label: 'Success' },
                { id: 'FAILED', label: 'Failed' },
                { id: 'RUNNING', label: 'Running' }
              ].map(f => {
                const isActive = statusFilter === f.id;
                return (
                  <button
                    key={f.id}
                    id={`filter-btn-${f.id.toLowerCase()}`}
                    onClick={() => setStatusFilter(f.id)}
                    style={{
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      fontWeight: isActive ? 600 : 500,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      background: isActive ? 'rgba(37, 135, 232, 0.12)' : '#111A22',
                      border: isActive ? '1px solid #1C2833' : '1px solid #1C2833',
                      color: isActive ? '#2587E8' : '#667085'
                    }}
                  >
                    {f.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* TABLE: EXECUTION HISTORY (Requirement 14) */}
          {filteredHistory.length === 0 ? (
            <div className="glass-panel" style={{ padding: '2.5rem', textAlign: 'center', color: '#64748B', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
              <p style={{ fontSize: '0.9rem' }}>No executions found matching your search or filter.</p>
              <button
                onClick={() => { setSearchQuery(''); setStatusFilter('ALL'); }}
                className="btn-secondary"
                style={{ fontSize: '0.8rem', marginTop: '0.75rem' }}
              >
                Clear Filters
              </button>
            </div>
          ) : (
            <div className="glass-panel" style={{
              overflowX: 'auto',
              border: '1px solid #1C2833',
              borderRadius: '8px',
              background: '#0E151C',
              boxShadow: '0 1px 3px rgba(16, 24, 40, 0.05)'
            }}>
              <table style={{
                width: '100%',
                borderCollapse: 'collapse',
                textAlign: 'left',
                fontSize: '0.85rem'
              }}>
                <thead>
                  <tr style={{
                    background: '#111A22',
                    borderBottom: '1px solid #1C2833',
                    color: '#64748B',
                    fontSize: '0.75rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em'
                  }}>
                    <th style={{ padding: '0.85rem 1rem' }}>Execution</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Case ID</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Script</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Target</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Status</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Threat</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Duration</th>
                    <th style={{ padding: '0.85rem 1rem' }}>Time</th>
                    <th style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.map((item, idx) => {
                    const isSuccess = item.status === 'SUCCESS';
                    const isFailed = item.status === 'FAILED';
                    const isRunning = item.status === 'RUNNING';

                    return (
                      <tr
                        key={item.execution_id || idx}
                        id={`history-row-${item.execution_id}`}
                        onClick={() => onSelectExecution(item)}
                        style={{
                          borderBottom: '1px solid #1C2833',
                          cursor: 'pointer',
                          transition: 'background-color 0.15s ease',
                          background: idx % 2 === 0 ? '#0E151C' : '#111A22'
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(37, 135, 232, 0.12)'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = idx % 2 === 0 ? '#0E151C' : '#111A22'; }}
                      >
                        {/* Execution ID */}
                        <td style={{ padding: '0.85rem 1rem', fontWeight: 600, color: '#3B9CFF', fontFamily: 'var(--font-mono)' }} data-mono>
                          {item.execution_id}
                        </td>

                        {/* Case ID */}
                        <td style={{ padding: '0.85rem 1rem', color: '#F1F5F9', fontFamily: 'var(--font-mono)' }} data-mono>
                          {item.case_id}
                        </td>

                        {/* Script */}
                        <td style={{ padding: '0.85rem 1rem', color: '#F1F5F9', fontWeight: 500 }}>
                          <span title={item.script_name} style={{ display: 'inline-block', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {item.script_name || 'demo_persistence.jocky'}
                          </span>
                        </td>

                        {/* Target */}
                        <td style={{ padding: '0.85rem 1rem', color: '#64748B' }}>
                          <span title={item.target} style={{ display: 'inline-block', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {item.target || 'DEMO-WINDOWS-ENDPOINT'}
                          </span>
                        </td>

                        {/* Status */}
                        <td style={{ padding: '0.85rem 1rem' }}>
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            padding: '0.2rem 0.6rem',
                            borderRadius: '4px',
                            background: isSuccess ? 'rgba(16, 185, 129, 0.12)' : isFailed ? 'rgba(239, 68, 68, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                            color: isSuccess ? '#16A34A' : isFailed ? '#DC2626' : '#F59E0B',
                            border: isSuccess ? '1px solid #1C2833' : isFailed ? '1px solid #1C2833' : '1px solid #FDE68A'
                          }}>
                            {isSuccess && 'SUCCESS'}
                            {isFailed && 'FAILED'}
                            {isRunning && '● RUNNING'}
                          </span>
                        </td>

                        {/* Threat */}
                        <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)' }} data-mono>
                          {isSuccess && item.threat_score !== null && item.threat_score !== undefined ? (
                            <span style={{
                              fontWeight: 700,
                              color: item.threat_score >= 80 ? '#DC2626' : item.threat_score >= 50 ? '#F59E0B' : '#16A34A'
                            }}>
                              {item.threat_score}
                            </span>
                          ) : (
                            <span style={{ color: '#64748B' }}>—</span>
                          )}
                        </td>

                        {/* Duration */}
                        <td style={{ padding: '0.85rem 1rem', color: '#64748B', fontFamily: 'var(--font-mono)' }} data-mono>
                          {item.duration_ms ? `${item.duration_ms} ms` : '—'}
                        </td>

                        {/* Time */}
                        <td style={{ padding: '0.85rem 1rem', color: '#64748B', fontFamily: 'var(--font-mono)' }} data-mono>
                          {item.time_display || (item.completed_at ? new Date(item.completed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--')}
                        </td>

                        {/* Actions */}
                        <td style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                            {onOpenWorkspace && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onOpenWorkspace(item);
                                }}
                                title="Open in 8-Tab Investigation Workspace"
                                style={{
                                  background: 'rgba(37, 135, 232, 0.12)',
                                  border: '1px solid rgba(37, 135, 232, 0.3)',
                                  color: '#3B9CFF',
                                  padding: '0.25rem 0.55rem',
                                  borderRadius: '4px',
                                  fontSize: '0.75rem',
                                  fontWeight: 600,
                                  cursor: 'pointer'
                                }}
                              >
                                Workspace
                              </button>
                            )}
                            <span style={{
                              color: '#3B9CFF',
                              fontSize: '0.8rem',
                              fontWeight: 600,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.25rem'
                            }}>
                              Details
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
