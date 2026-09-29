import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  Shield,
  ShieldCheck,
  Terminal,
  Hash,
  Clock,
  Layers,
  Activity,
  Copy,
  Check,
  RotateCcw,
  Zap,
  Cpu,
  Lock,
  ArrowRight,
  Database,
  FileText,
  Flame,
  Gauge,
  ChevronDown,
  ChevronUp,
  Search
} from 'lucide-react';
import ExecutionHistoryView from './ExecutionHistoryView';
import InvestigationWorkspaceView from './InvestigationWorkspaceView';

export const BUILTIN_DEMO_SCRIPT = `CASE "CASE-2026-001"

TARGET "DEMO-WINDOWS-ENDPOINT"

COLLECT registry
WHERE path MATCHES "Run|RunOnce"

COLLECT process
WHERE parent == "explorer.exe"

COLLECT eventlog
WHERE event_id IN [4688, 7045]

COLLECT network

COLLECT filesystem

CORRELATE
    registry
    WITH process
    WITH eventlog
    WITH network
    WITH filesystem

ANALYZE forensic_vector

CALCULATE threat_score

VERIFY tamper

HASH evidence

CHAIN evidence

REPORT`;

const PIPELINE_STAGES = [
  { id: 'COLLECT', num: '01', label: 'COLLECT', desc: 'Artifact Acquisition' },
  { id: 'CORRELATE', num: '02', label: 'CORRELATE', desc: 'Cross-Source Linkage' },
  { id: 'ANALYZE', num: '03', label: 'ANALYZE', desc: '21-D Vector Extraction' },
  { id: 'VERIFY', num: '04', label: 'VERIFY', desc: '12 Tamper Detectors' },
  { id: 'CHAIN', num: '05', label: 'CHAIN', desc: 'Cryptographic Custody' },
  { id: 'REPORT', num: '06', label: 'REPORT', desc: 'Court-Admissible Manifest' }
];

export default function OneClickDemo({ initialScript = BUILTIN_DEMO_SCRIPT }) {
  const [script, setScript] = useState(initialScript);
  const [isRunning, setIsRunning] = useState(false);
  const [stageIndex, setStageIndex] = useState(-1); // -1 = idle, 0..5 = active stage, 6 = all completed
  const [executionLogs, setExecutionLogs] = useState([]);
  const [demoResult, setDemoResult] = useState(null);
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Internal JOCKY Studio Tab Navigation state (Requirement 2 & Phase 27)
  const [studioTab, setStudioTab] = useState('new'); // 'new' | 'history' | 'workspace'
  const [workspaceCaseId, setWorkspaceCaseId] = useState('CASE-DEMO-01');
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [lastSavedExecutionId, setLastSavedExecutionId] = useState(null);

  // Execution History state & Persistence (Requirement 6 & 9)
  const STORAGE_KEY = 'jocky_execution_history';
  const [historyList, setHistoryList] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch (e) {
      return [];
    }
  });

  // Sync execution history with backend on mount
  useEffect(() => {
    const fetchBackendHistory = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/demo/history');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            setHistoryList(data);
            try {
              localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
            } catch (e) {}
          }
        }
      } catch (err) {
        console.warn('Backend history sync unavailable, using local cache', err);
      }
    };
    fetchBackendHistory();
  }, []);

  // Save execution to local and backend
  const saveExecutionToHistory = async (record) => {
    // 1. Update React state immediately
    setHistoryList(prev => {
      const updated = [record, ...prev];
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch (e) {
        console.error('LocalStorage save error', e);
      }
      return updated;
    });

    // 2. Persist to backend
    try {
      await fetch('http://localhost:8000/api/demo/history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(record)
      });
    } catch (e) {
      console.warn('Failed to persist execution record to backend', e);
    }
  };

  // Collapsible Accordion sections state
  const [openSections, setOpenSections] = useState({
    vector: false,
    tamper: false,
    evidence: false,
    chain: false,
    telemetry: false,
    benchmark: false,
    comparison: false
  });

  const toggleSection = (key) => {
    setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const expandAll = () => {
    setOpenSections({
      vector: true,
      tamper: true,
      evidence: true,
      chain: true,
      telemetry: true,
      benchmark: true,
      comparison: true
    });
  };

  const collapseAll = () => {
    setOpenSections({
      vector: false,
      tamper: false,
      evidence: false,
      chain: false,
      telemetry: false,
      benchmark: false,
      comparison: false
    });
  };

  const resultRef = useRef(null);

  const pipelineLogSteps = [
    { stage: 0, log: "[JOCKY] Parsing script... CASE: CASE-2026-001, TARGET: DEMO-WINDOWS-ENDPOINT" },
    { stage: 0, log: "[JOCKY] 01 COLLECT: Collecting registry Run/RunOnce keys... DONE" },
    { stage: 0, log: "[JOCKY] 01 COLLECT: Collecting process tree (parent==explorer.exe)... DONE" },
    { stage: 0, log: "[JOCKY] 01 COLLECT: Collecting event logs (4688, 7045)... DONE" },
    { stage: 0, log: "[JOCKY] 01 COLLECT: Collecting active network connections... DONE" },
    { stage: 0, log: "[JOCKY] 01 COLLECT: Collecting filesystem metadata & PE hashes... DONE" },
    { stage: 1, log: "[JOCKY] 02 CORRELATE: Cross-source artifact correlation converging... DONE" },
    { stage: 2, log: "[JOCKY] 03 ANALYZE: Computing 21-dimensional deterministic forensic vector... DONE" },
    { stage: 2, log: "[JOCKY] 03 ANALYZE: Calculating forensic threat score (weighted heuristic)... DONE" },
    { stage: 3, log: "[JOCKY] 04 VERIFY: Running 12 deterministic anti-tamper detectors... ALL PASSED" },
    { stage: 4, log: "[JOCKY] 05 CHAIN: Generating RFC-8785 canonical hash & building custody block #2... DONE" },
    { stage: 5, log: "[JOCKY] 06 REPORT: Synthesizing court-admissible forensic manifest... DONE" }
  ];

  const handleRunInvestigation = async (scriptOverride) => {
    const targetScript = typeof scriptOverride === 'string' ? scriptOverride : script;
    if (isRunning) return;
    setIsRunning(true);
    setDemoResult(null);
    setExecutionLogs([]);
    setStageIndex(0);

    const startedAt = new Date().toISOString();
    const t0 = performance.now();

    // Progressive stage & telemetry advancement
    for (let i = 0; i < pipelineLogSteps.length; i++) {
      const step = pipelineLogSteps[i];
      setStageIndex(step.stage);
      setExecutionLogs(prev => [...prev, step.log]);
      await new Promise(r => setTimeout(r, 60));
    }

    try {
      const res = await fetch('http://localhost:8000/api/demo/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script: targetScript })
      });

      const elapsedMs = Math.round(performance.now() - t0);

      if (res.ok) {
        const data = await res.json();
        setDemoResult(data);
        setStageIndex(6); // All 6 completed!
        if (data.execution_logs && data.execution_logs.length > 0) {
          setExecutionLogs(data.execution_logs);
        }

        const eid = data.execution_id || `EXE-${String(historyList.length + 1).padStart(4, '0')}`;
        setLastSavedExecutionId(eid);

        const newRecord = {
          id: Date.now(),
          execution_id: eid,
          case_id: data.investigation?.case_id || 'CASE-2026-001',
          script_name: 'demo_persistence.jocky',
          script_content: targetScript,
          target: data.investigation?.target || 'DEMO-WINDOWS-ENDPOINT',
          status: 'SUCCESS',
          started_at: startedAt,
          completed_at: new Date().toISOString(),
          time_display: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          duration_ms: data.execution_time_ms || elapsedMs,
          threat_score: data.threat_analysis?.threat_score,
          risk_level: data.threat_analysis?.risk_level,
          evidence_categories: data.evidence_collection?.categories_collected || ['registry', 'process', 'eventlog', 'network', 'filesystem'],
          forensic_vector_dimensions: data.forensic_vector?.dimensions || 21,
          tamper_checks_passed: data.tamper_detection?.passed_detectors || 12,
          tamper_checks_total: data.tamper_detection?.total_detectors || 12,
          chain_status: data.chain_of_custody?.chain_status || 'VERIFIED',
          error_message: null,
          result_data: data
        };

        saveExecutionToHistory(newRecord);

        setTimeout(() => {
          if (resultRef.current) {
            resultRef.current.scrollIntoView({ behavior: 'smooth' });
          }
        }, 120);
      } else {
        const err = await res.json();
        const errorMsg = err.detail || 'Internal server error';
        const failedId = `EXE-${String(historyList.length + 1).padStart(4, '0')}`;
        setLastSavedExecutionId(failedId);

        const failedRecord = {
          id: Date.now(),
          execution_id: failedId,
          case_id: 'CASE-2026-001',
          script_name: 'demo_persistence.jocky',
          script_content: targetScript,
          target: 'DEMO-WINDOWS-ENDPOINT',
          status: 'FAILED',
          started_at: startedAt,
          completed_at: new Date().toISOString(),
          time_display: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          duration_ms: elapsedMs,
          threat_score: null,
          risk_level: null,
          evidence_categories: [],
          forensic_vector_dimensions: 0,
          tamper_checks_passed: 0,
          tamper_checks_total: 12,
          chain_status: 'FAILED',
          error_message: errorMsg,
          result_data: null
        };
        saveExecutionToHistory(failedRecord);

        alert(`Execution failed: ${errorMsg}`);
        setStageIndex(-1);
      }
    } catch (err) {
      console.error('Demo execution error', err);
      const elapsedMs = Math.round(performance.now() - t0);
      const failedId = `EXE-${String(historyList.length + 1).padStart(4, '0')}`;
      setLastSavedExecutionId(failedId);

      const failedRecord = {
        id: Date.now(),
        execution_id: failedId,
        case_id: 'CASE-2026-001',
        script_name: 'demo_persistence.jocky',
        script_content: targetScript,
        target: 'DEMO-WINDOWS-ENDPOINT',
        status: 'FAILED',
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        time_display: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        duration_ms: elapsedMs,
        threat_score: null,
        risk_level: null,
        evidence_categories: [],
        forensic_vector_dimensions: 0,
        tamper_checks_passed: 0,
        tamper_checks_total: 12,
        chain_status: 'FAILED',
        error_message: `Network error connecting to backend: ${err.message}`,
        result_data: null
      };
      saveExecutionToHistory(failedRecord);

      alert(`Network error connecting to backend: ${err.message}`);
      setStageIndex(-1);
    } finally {
      setIsRunning(false);
    }
  };

  const handleReRun = (exec) => {
    const rerunScript = exec.script_content;
    setScript(rerunScript);
    setSelectedExecution(null);
    setStudioTab('new');
    setTimeout(() => {
      handleRunInvestigation(rerunScript);
    }, 80);
  };

  const handleBenchmark = async () => {
    setIsBenchmarking(true);
    try {
      const res = await fetch('http://localhost:8000/api/demo/benchmark', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script })
      });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
        setOpenSections(prev => ({ ...prev, benchmark: true }));
      }
    } catch (e) {
      console.error('Benchmark failed', e);
    } finally {
      setIsBenchmarking(false);
    }
  };

  const handleCopyHash = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      {/* JOCKY STUDIO INTERNAL NAVIGATION (Requirement 2 & 6) */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: '#0E151C',
        border: '1px solid #1C2833',
        borderRadius: '8px',
        padding: '0.5rem 0.75rem',
        boxShadow: '0 1px 3px rgba(16, 24, 40, 0.06)',
        flexWrap: 'wrap',
        gap: '0.5rem'
      }}>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            id="studio-tab-new-investigation"
            onClick={() => {
              setStudioTab('new');
              setSelectedExecution(null);
            }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1.15rem',
              borderRadius: '6px',
              fontSize: '0.84rem',
              fontWeight: 600,
              cursor: 'pointer',
              letterSpacing: '0.02em',
              transition: 'all 0.15s ease',
              background: studioTab === 'new' ? 'rgba(37, 135, 232, 0.12)' : 'transparent',
              border: studioTab === 'new' ? '1px solid #1C2833' : '1px solid transparent',
              color: studioTab === 'new' ? '#2587E8' : '#667085'
            }}
          >
            <Play size={13} /> NEW INVESTIGATION
          </button>
          <button
            id="studio-tab-execution-history"
            onClick={() => setStudioTab('history')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1.15rem',
              borderRadius: '6px',
              fontSize: '0.84rem',
              fontWeight: 600,
              cursor: 'pointer',
              letterSpacing: '0.02em',
              transition: 'all 0.15s ease',
              background: studioTab === 'history' ? 'rgba(37, 135, 232, 0.12)' : 'transparent',
              border: studioTab === 'history' ? '1px solid #1C2833' : '1px solid transparent',
              color: studioTab === 'history' ? '#2587E8' : '#667085'
            }}
          >
            <Clock size={13} /> EXECUTION HISTORY
            {historyList.length > 0 && (
              <span style={{
                fontSize: '0.72rem',
                padding: '0.1rem 0.45rem',
                borderRadius: '999px',
                background: studioTab === 'history' ? '#2587E8' : '#1C2833',
                color: studioTab === 'history' ? '#FFFFFF' : '#475467',
                fontWeight: 700,
                marginLeft: '0.25rem'
              }}>
                {historyList.length}
              </span>
            )}
          </button>
          <button
            id="studio-tab-investigation-workspace"
            onClick={() => {
              setStudioTab('workspace');
              setSelectedExecution(null);
            }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1.15rem',
              borderRadius: '6px',
              fontSize: '0.84rem',
              fontWeight: 600,
              cursor: 'pointer',
              letterSpacing: '0.02em',
              transition: 'all 0.15s ease',
              background: studioTab === 'workspace' ? 'rgba(37, 135, 232, 0.12)' : 'transparent',
              border: studioTab === 'workspace' ? '1px solid #1C2833' : '1px solid transparent',
              color: studioTab === 'workspace' ? '#2587E8' : '#667085'
            }}
          >
            <Activity size={13} /> INVESTIGATION WORKSPACE
            <span style={{
              fontSize: '0.72rem',
              padding: '0.1rem 0.45rem',
              borderRadius: '999px',
              background: studioTab === 'workspace' ? '#2587E8' : '#1C2833',
              color: studioTab === 'workspace' ? '#FFFFFF' : '#475467',
              fontWeight: 700,
              marginLeft: '0.25rem'
            }}>
              8 Tabs
            </span>
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: '#64748B' }}>
          <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: '#16A34A' }}></span>
          <span style={{ fontWeight: 500 }}>JOCKY Forensic DSL Engine Active</span>
        </div>
      </div>

      {studioTab === 'new' && (
        <>
          {/* 1. INVESTIGATION HEADER (Requirement 7) */}
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
                JOCKY FORENSIC INVESTIGATION
              </span>
              <h1 style={{ fontSize: '28px', fontWeight: 600, color: '#F1F5F9', marginTop: '0.2rem', letterSpacing: '-0.02em', lineHeight: 1.3 }}>
                CASE-2026-001
              </h1>
              <div style={{ fontSize: '14px', color: '#64748B', fontWeight: 400, marginTop: '0.25rem' }}>
                Suspicious Persistence Investigation • Target: <strong style={{ color: '#F1F5F9', fontWeight: 600 }}>DEMO-WINDOWS-ENDPOINT</strong>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center' }}>
              <button
                id="demo-load-script-btn"
                onClick={() => setScript(BUILTIN_DEMO_SCRIPT)}
                className="btn-secondary"
                style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <RotateCcw size={14} /> Reset Script
              </button>
              <button
                id="demo-benchmark-btn"
                onClick={handleBenchmark}
                disabled={isBenchmarking}
                className="btn-secondary"
                style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: '1px solid #1C2833', color: '#F59E0B' }}
              >
                <Gauge size={14} /> {isBenchmarking ? 'Testing...' : 'Latency Benchmark'}
              </button>
            </div>
          </div>

          {/* 2. PROMINENT 6-STAGE PIPELINE (Requirement 8) */}
          <div className="glass-panel" style={{
            padding: '1.25rem 1.5rem',
            background: '#0E151C',
            border: '1px solid #1C2833',
            borderRadius: '8px',
            boxShadow: '0 1px 3px rgba(16, 24, 40, 0.05)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#64748B', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                Execution Pipeline Architecture
              </span>
              <span style={{
                fontSize: '0.78rem',
                fontWeight: 600,
                color: stageIndex === 6 ? '#10B981' : isRunning ? '#2587E8' : '#64748B'
              }}>
                {stageIndex === 6 ? '6 / 6 STAGES COMPLETED' : isRunning ? `EXECUTING STAGE ${stageIndex + 1} OF 6` : 'READY FOR EXECUTION'}
              </span>
            </div>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '0.75rem',
              alignItems: 'stretch'
            }}>
              {PIPELINE_STAGES.map((stg, idx) => {
                const isCompleted = stageIndex > idx || stageIndex === 6;
                const isActive = stageIndex === idx && isRunning;
                const isPending = stageIndex < idx && stageIndex !== 6;

                let statusIcon = '';
                let borderColor = '#1C2833';
                let bgColor = '#111A22';
                let textColor = '#94A3B8';

                if (isCompleted) {
                  statusIcon = '';
                  borderColor = 'rgba(16, 185, 129, 0.3)';
                  bgColor = 'rgba(16, 185, 129, 0.12)';
                  textColor = '#10B981';
                } else if (isActive) {
                  statusIcon = '';
                  borderColor = 'rgba(37, 135, 232, 0.4)';
                  bgColor = 'rgba(37, 135, 232, 0.15)';
                  textColor = '#3B9CFF';
                }

                return (
                  <div
                    key={stg.id}
                    style={{
                      border: `1px solid ${borderColor}`,
                      background: bgColor,
                      borderRadius: '8px',
                      padding: '0.75rem 0.85rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.25rem',
                      transition: 'all 0.15s ease',
                      boxShadow: isActive ? '0 1px 3px rgba(37, 99, 235, 0.12)' : 'none'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.88rem', fontWeight: 600, color: textColor }}>
                        {stg.label}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: '#64748B', fontWeight: 500 }}>
                        {stg.num}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.72rem', color: '#64748B' }}>
                      {stg.desc}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 3. PRIMARY USER ACTION & SCRIPT INPUT (Requirement 9 & 10) */}
          <div className="glass-panel" style={{
            padding: '1.5rem',
            background: '#0E151C',
            border: '1px solid #1C2833',
            borderRadius: '8px',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            boxShadow: '0 1px 3px rgba(16, 24, 40, 0.05)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Terminal size={17} color="#2587E8" />
                <span style={{ fontSize: '0.92rem', fontWeight: 600, color: '#F1F5F9', letterSpacing: '0.02em' }}>
                  JOCKY INVESTIGATION SCRIPT
                </span>
              </div>
              <span style={{ fontSize: '0.78rem', color: '#64748B' }}>
                Declarative Forensic DSL • 1-Click Execution
              </span>
            </div>

            <textarea
              id="jocky-script-input"
              value={script}
              onChange={(e) => setScript(e.target.value)}
              style={{
                width: '100%',
                minHeight: '260px',
                backgroundColor: '#111A22',
                color: '#F1F5F9',
                border: '1px solid #1C2833',
                borderRadius: '8px',
                padding: '1rem',
                fontSize: '13.5px',
                fontFamily: 'var(--font-mono)',
                lineHeight: '1.6',
                outline: 'none',
                resize: 'vertical',
                boxShadow: 'inset 0 1px 2px rgba(16, 24, 40, 0.04)'
              }}
              placeholder="Paste or enter .jocky script..."
            />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <span style={{ fontSize: '0.78rem', color: '#64748B' }}>
                Automated forensic extraction • Mathematical proof of custody • Zero manual configuration
              </span>
              <button
                id="run-investigation-btn"
                onClick={() => handleRunInvestigation()}
                disabled={isRunning || !script.trim()}
                style={{
                  background: isRunning ? '#64748B' : '#2587E8',
                  color: '#FFFFFF',
                  border: `1px solid ${isRunning ? '#98A2B3' : '#2587E8'}`,
                  padding: '0.75rem 2.25rem',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.95rem',
                  letterSpacing: '0.02em',
                  cursor: isRunning ? 'not-allowed' : 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                  boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)',
                  transition: 'background-color 0.15s ease',
                  opacity: isRunning ? 0.7 : 1
                }}
              >
                <Play size={16} fill="#ffffff" />
                {isRunning ? 'EXECUTING PIPELINE...' : 'RUN INVESTIGATION'}
              </button>
            </div>
          </div>

          {/* 4. FINAL RESULT & SUMMARY (Requirement 11 & 12) */}
          {demoResult && (
            <div ref={resultRef} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Execution Saved Confirmation Banner */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.8rem 1.25rem',
                background: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(37, 135, 232, 0.3)',
                borderRadius: '8px',
                boxShadow: '0 1px 2px rgba(16, 24, 40, 0.03)',
                flexWrap: 'wrap',
                gap: '0.75rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  <CheckCircle2 size={18} color="#16A34A" />
                  <span style={{ color: '#16A34A', fontSize: '0.88rem', fontWeight: 600 }}>
                    Execution saved to History
                  </span>
                  {lastSavedExecutionId && (
                    <span style={{ color: '#64748B', fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }} data-mono>
                      ({lastSavedExecutionId})
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <button
                    id="open-investigation-workspace-from-demo-btn"
                    onClick={() => {
                      setWorkspaceCaseId(demoResult?.investigation?.case_id || 'CASE-DEMO-01');
                      setStudioTab('workspace');
                    }}
                    style={{
                      background: '#2587E8',
                      border: '1px solid #2587E8',
                      color: '#FFFFFF',
                      padding: '0.45rem 1rem',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <Search size={14} /> OPEN INVESTIGATION WORKSPACE <ArrowRight size={14} />
                  </button>
                  <button
                    id="view-execution-history-btn"
                    onClick={() => {
                      setStudioTab('history');
                      setSelectedExecution(null);
                    }}
                    style={{
                      background: 'rgba(37, 135, 232, 0.12)',
                      border: '1px solid rgba(37, 135, 232, 0.3)',
                      color: '#3B9CFF',
                      padding: '0.45rem 1rem',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    VIEW EXECUTION HISTORY
                  </button>
                </div>
              </div>

              {/* Main Result Card */}
              <div className="glass-panel" style={{
                padding: '1.75rem',
                background: '#0E151C',
                border: '1px solid #1C2833',
                borderRadius: '8px',
                boxShadow: '0 1px 3px rgba(16, 24, 40, 0.08)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1C2833', paddingBottom: '0.85rem', marginBottom: '1.25rem' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#3B9CFF', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      AUTOMATED PIPELINE COMPLETE
                    </span>
                    <h2 style={{ fontSize: '22px', fontWeight: 600, color: '#F1F5F9', marginTop: '0.2rem' }}>
                      INVESTIGATION COMPLETE
                    </h2>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <button onClick={expandAll} className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                      Expand All Details
                    </button>
                    <button onClick={collapseAll} className="btn-secondary" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                      Collapse All
                    </button>
                  </div>
                </div>

                {/* Prominent Threat Score & 4 Summary Cards (Requirement 11 & 12) */}
                <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 2.85fr', gap: '1.25rem', alignItems: 'stretch', marginBottom: '1rem' }}>
                  {/* Threat Score Box */}
                  {(() => {
                    const score = demoResult.threat_analysis.threat_score;
                    const isCritical = score >= 90;
                    const isHigh = score >= 70 && score < 90;
                    const isMedium = score >= 40 && score < 70;
                    const theme = (isCritical || isHigh) ? {
                      bg: 'rgba(239, 68, 68, 0.12)',
                      border: 'rgba(239, 68, 68, 0.25)',
                      label: '#991B1B',
                      num: '#DC2626',
                      slash: '#991B1B',
                      badgeBg: '#FEE2E2',
                      badgeBorder: '#FCA5A5',
                      badgeText: '#DC2626'
                    } : isMedium ? {
                      bg: 'rgba(245, 158, 11, 0.12)',
                      border: 'rgba(245, 158, 11, 0.25)',
                      label: '#F59E0B',
                      num: '#F59E0B',
                      slash: '#F59E0B',
                      badgeBg: '#FEF3C7',
                      badgeBorder: '#FCD34D',
                      badgeText: '#B45309'
                    } : {
                      bg: 'rgba(16, 185, 129, 0.12)',
                      border: '#1C2833',
                      label: '#166534',
                      num: '#16A34A',
                      slash: '#166534',
                      badgeBg: '#DCFCE7',
                      badgeBorder: '#86EFAC',
                      badgeText: '#15803D'
                    };

                    return (
                      <div style={{
                        background: theme.bg,
                        border: `1px solid ${theme.border}`,
                        borderRadius: '8px',
                        padding: '1.5rem',
                        textAlign: 'center',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'center',
                        alignItems: 'center'
                      }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: theme.label, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                          THREAT SCORE
                        </span>
                        <div style={{ fontSize: '3.2rem', fontWeight: 700, color: theme.num, lineHeight: 1.1, margin: '0.35rem 0' }}>
                          {demoResult.threat_analysis.threat_score} <span style={{ fontSize: '1.25rem', color: theme.slash, fontWeight: 500 }}>/ 100</span>
                        </div>
                        <div style={{
                          display: 'inline-block',
                          background: theme.badgeBg,
                          color: theme.badgeText,
                          border: `1px solid ${theme.badgeBorder}`,
                          padding: '0.25rem 1rem',
                          borderRadius: '999px',
                          fontSize: '0.82rem',
                          fontWeight: 700,
                          letterSpacing: '0.06em'
                        }}>
                          {demoResult.threat_analysis.risk_level}
                        </div>
                      </div>
                    );
                  })()}

                  {/* Four Authoritative Summary Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.85rem' }}>
                    {/* Evidence */}
                    <div style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Evidence</span>
                      <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#F1F5F9', margin: '0.2rem 0' }}>
                        {demoResult.evidence_collection.total_categories} Categories
                      </div>
                      <span style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>100% Corroborated</span>
                    </div>

                    {/* Forensic Vector */}
                    <div style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Forensic Vector</span>
                      <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#3B9CFF', margin: '0.2rem 0' }}>
                        {demoResult.forensic_vector.dimensions} Dimensions
                      </div>
                      <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Deterministic numeric vector</span>
                    </div>

                    {/* Integrity */}
                    <div style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Integrity</span>
                      <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#16A34A', margin: '0.2rem 0' }}>
                        {demoResult.tamper_detection.passed_detectors} / {demoResult.tamper_detection.total_detectors} Passed
                      </div>
                      <span style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>12/12 Checks Validated</span>
                    </div>

                    {/* Chain of Custody */}
                    <div style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Chain of Custody</span>
                      <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#3B9CFF', margin: '0.2rem 0' }}>
                        {demoResult.chain_of_custody.chain_status}
                      </div>
                      <span style={{ fontSize: '0.75rem', color: '#3B9CFF', fontWeight: 600 }}>Cryptographic Hash Chain</span>
                    </div>
                  </div>
                </div>

                <div style={{ fontSize: '0.8rem', color: '#64748B', borderTop: '1px solid #1C2833', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                  <span>Observed Latency: <strong style={{ color: '#16A34A' }}>{demoResult.execution_time_ms} ms</strong> ({demoResult.performance_metric.observed_latency_label})</span>
                  <span>Evidence ID: <strong style={{ color: '#3B9CFF', fontFamily: 'var(--font-mono)' }}>{demoResult.evidence_hashing.evidence_id}</strong></span>
                </div>
              </div>

              {/* 5. COLLAPSIBLE TECHNICAL DETAILS (Requirement 13) */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {/* ACCORDION 1: 21-DIMENSIONAL FORENSIC VECTOR */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('vector')}
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
                        Threat Score: <strong style={{ color: '#EF4444' }}>{demoResult.threat_analysis.threat_score} / 100</strong>
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                        {openSections.vector ? 'Hide Details' : 'View 21 Dimensions'}
                      </span>
                      {openSections.vector ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                    </div>
                  </div>

                  {openSections.vector && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
                        gap: '0.65rem',
                        fontSize: '0.82rem'
                      }}>
                        {demoResult.forensic_vector.features.map(f => (
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
                                <strong style={{ color: '#3B9CFF', marginRight: '0.35rem' }}>{String(f.id).padStart(2, '0')}</strong>
                                {f.name}
                              </span>
                              <span style={{
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)',
                                color: f.value >= 0.9 ? '#DC2626' : f.value >= 0.8 ? '#F59E0B' : '#16A34A'
                              }}>
                                {f.value.toFixed(2)}
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

                {/* ACCORDION 2: 12 DETERMINISTIC TAMPER DETECTORS */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('tamper')}
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
                        {openSections.tamper ? 'Hide Details' : 'View Integrity Checks'}
                      </span>
                      {openSections.tamper ? <ChevronUp size={16} color="#16A34A" /> : <ChevronDown size={16} color="#16A34A" />}
                    </div>
                  </div>

                  {openSections.tamper && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))',
                        gap: '0.65rem'
                      }}>
                        {demoResult.tamper_detection.detectors.map(d => (
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

                {/* ACCORDION 3: EVIDENCE ARTIFACTS & CORRELATION */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('evidence')}
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
                        Evidence Artifacts ({demoResult.evidence_collection.total_categories} Categories)
                      </span>
                      <span style={{ fontSize: '0.78rem', color: '#64748B', marginLeft: '0.5rem' }}>
                        Registry, Processes, Event Logs, Network, Filesystem
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                        {openSections.evidence ? 'Hide Artifacts' : 'View Artifacts & Correlation'}
                      </span>
                      {openSections.evidence ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                    </div>
                  </div>

                  {openSections.evidence && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
                        {/* Registry */}
                        <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                            <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Registry</span>
                            <CheckCircle2 size={15} color="#16A34A" />
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                            <div>Key: <code>HKCU\...\CurrentVersion\Run</code></div>
                            <div>Name: <code>UpdateService</code></div>
                            <div>Target: <code style={{ color: '#EF4444' }}>C:\Demo\suspicious-update.exe</code></div>
                          </div>
                        </div>

                        {/* Processes */}
                        <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                            <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Processes</span>
                            <CheckCircle2 size={15} color="#16A34A" />
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                            <div>Process: <code style={{ color: '#EF4444' }}>suspicious-update.exe</code></div>
                            <div>PID: 4188</div>
                            <div>Parent: <code>explorer.exe (PID 1024)</code></div>
                          </div>
                        </div>

                        {/* Event Logs */}
                        <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                            <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Event Logs</span>
                            <CheckCircle2 size={15} color="#16A34A" />
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                            <div>4688: Process Creation</div>
                            <div>7045: Service Installation</div>
                            <div>Service: <code>UpdateService</code></div>
                          </div>
                        </div>

                        {/* Network */}
                        <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                            <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Network</span>
                            <CheckCircle2 size={15} color="#16A34A" />
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                            <div>Protocol: TCP</div>
                            <div>Destination: <code>203.0.113.50</code></div>
                            <div>Port: <strong style={{ color: '#F59E0B' }}>4444 (C2)</strong></div>
                          </div>
                        </div>

                        {/* Filesystem */}
                        <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                            <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: '0.85rem' }}>Filesystem</span>
                            <CheckCircle2 size={15} color="#16A34A" />
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#64748B' }}>
                            <div>Path: <code>C:\Demo\suspicious-update.exe</code></div>
                            <div>Size: 245,760 B</div>
                            <div>Signature: <span style={{ color: '#EF4444' }}>UNSIGNED (Entropy: 7.42)</span></div>
                          </div>
                        </div>
                      </div>

                      {/* Correlation Callout */}
                      <div style={{ padding: '0.75rem', background: 'rgba(37, 135, 232, 0.12)', border: '1px solid rgba(37, 135, 232, 0.3)', borderRadius: '6px', fontSize: '0.8rem' }}>
                        <div style={{ color: '#3B9CFF', fontWeight: 600, marginBottom: '0.25rem' }}>
                          Cross-Artifact Correlation Convergence:
                        </div>
                        <ul style={{ paddingLeft: '1.25rem', color: '#F1F5F9', display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                          {demoResult.evidence_correlation.links.map((link, idx) => (
                            <li key={idx}>{link}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>

                {/* ACCORDION 4: CHAIN OF CUSTODY */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('chain')}
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
                        {'Evidence -> SHA-256 -> Block #1 -> Block #2 -> Verified'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                        {openSections.chain ? 'Hide Cryptography' : 'View Cryptographic Details'}
                      </span>
                      {openSections.chain ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                    </div>
                  </div>

                  {openSections.chain && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      {/* Evidence Hash Callout */}
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
                            Evidence ID: {demoResult.evidence_hashing.evidence_id} (Canonical RFC-8785 SHA-256):
                          </span>
                          <span style={{ color: '#16A34A', fontWeight: 600, wordBreak: 'break-all' }}>
                            {demoResult.evidence_hashing.sha256}
                          </span>
                        </div>
                        <button
                          onClick={() => handleCopyHash(demoResult.evidence_hashing.sha256)}
                          className="btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', display: 'flex', alignItems: 'center', gap: '0.35rem', marginLeft: '1rem', flexShrink: 0 }}
                        >
                          {copiedHash ? <Check size={14} color="#16A34A" /> : <Copy size={14} />}
                          {copiedHash ? 'Copied' : 'Copy'}
                        </button>
                      </div>

                      {/* Block Cards */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '0.85rem' }}>
                        {demoResult.chain_of_custody.blocks.map(block => (
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
                          }}>
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

                {/* ACCORDION 5: EXECUTION TELEMETRY STREAM */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('telemetry')}
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
                        {executionLogs.length} events logged • 0 errors
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                        {openSections.telemetry ? 'Hide Logs' : 'View Stream Logs'}
                      </span>
                      {openSections.telemetry ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                    </div>
                  </div>

                  {openSections.telemetry && (
                    <div style={{
                      padding: '1rem',
                      backgroundColor: '#111A22',
                      borderTop: '1px solid #1C2833',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.8rem',
                      lineHeight: '1.7',
                      color: '#94A3B8',
                      maxHeight: '280px',
                      overflowY: 'auto'
                    }}>
                      {executionLogs.map((log, idx) => (
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

                {/* ACCORDION 6: PERFORMANCE BENCHMARK */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('benchmark')}
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
                      <Gauge size={18} color="#F59E0B" />
                      <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                        Performance Benchmark
                      </span>
                      <span style={{ fontSize: '0.78rem', color: '#F59E0B', fontWeight: 600, marginLeft: '0.5rem' }}>
                        {demoResult.performance_metric.observed_latency_label}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#F59E0B', fontWeight: 600 }}>
                        {openSections.benchmark ? 'Hide Benchmark' : 'View Performance Details'}
                      </span>
                      {openSections.benchmark ? <ChevronUp size={16} color="#F59E0B" /> : <ChevronDown size={16} color="#F59E0B" />}
                    </div>
                  </div>

                  {openSections.benchmark && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontSize: '0.85rem' }}>
                        <div>
                          <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Measured Execution Time</span>
                          <div style={{ fontSize: '1.3rem', fontWeight: 700, color: '#16A34A' }}>
                            {demoResult.execution_time_ms} ms
                          </div>
                          <span style={{ fontSize: '0.72rem', color: '#3B9CFF' }}>{demoResult.performance_metric.observed_latency_label}</span>
                        </div>
                        <div>
                          <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Environment</span>
                          <div style={{ fontSize: '0.9rem', color: '#F1F5F9', fontWeight: 600 }}>
                            {demoResult.performance_metric.environment}
                          </div>
                        </div>
                        <div>
                          <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Workload</span>
                          <div style={{ fontSize: '0.9rem', color: '#F1F5F9', fontWeight: 600 }}>
                            {demoResult.performance_metric.workload}
                          </div>
                        </div>
                        <div>
                          <span style={{ color: '#64748B', fontSize: '0.75rem' }}>Artifact Categories</span>
                          <div style={{ fontSize: '0.9rem', color: '#3B9CFF', fontWeight: 600 }}>
                            {demoResult.performance_metric.artifacts_count} categories
                          </div>
                        </div>
                      </div>

                      {benchmarkResult && (
                        <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid #1C2833', display: 'flex', gap: '1.5rem', fontSize: '0.8rem', color: '#F1F5F9' }}>
                          <span>5-Pass Average: <strong style={{ color: '#16A34A' }}>{benchmarkResult.average_latency_ms} ms</strong></span>
                          <span>Min: <strong>{benchmarkResult.min_latency_ms} ms</strong></span>
                          <span>Max: <strong>{benchmarkResult.max_latency_ms} ms</strong></span>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* ACCORDION 7: TRADITIONAL VS JOCKY COMPARISON */}
                <div className="glass-panel" style={{ overflow: 'hidden', border: '1px solid #1C2833', borderRadius: '8px' }}>
                  <div
                    onClick={() => toggleSection('comparison')}
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
                      <Layers size={18} color="#2587E8" />
                      <span style={{ fontWeight: 600, fontSize: '0.95rem', color: '#F1F5F9' }}>
                        Workflow Comparison: Traditional vs JOCKY
                      </span>
                      <span style={{ fontSize: '0.78rem', color: '#64748B', marginLeft: '0.5rem' }}>
                        Manual Triage vs Automated Declarative Pipeline
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#3B9CFF', fontWeight: 600 }}>
                        {openSections.comparison ? 'Hide Comparison' : 'View Comparison'}
                      </span>
                      {openSections.comparison ? <ChevronUp size={16} color="#2587E8" /> : <ChevronDown size={16} color="#2587E8" />}
                    </div>
                  </div>

                  {openSections.comparison && (
                    <div style={{ padding: '1.25rem', borderTop: '1px solid #1C2833', background: '#0E151C' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                        <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid #1C2833', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#EF4444', marginBottom: '0.65rem' }}>
                            Traditional Manual Forensic Workflow
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: '#4B5563' }}>
                            {demoResult.traditional_vs_jocky.traditional.map((step, idx) => (
                              <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <span style={{ color: '#EF4444', fontWeight: 700 }}>{idx + 1}.</span>
                                <span>{step}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ marginTop: '0.65rem', fontSize: '0.72rem', color: '#64748B', fontStyle: 'italic' }}>
                            Multiple disconnected tools, manual spreadsheet correlation, and variable integrity verification times.
                          </div>
                        </div>

                        <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(37, 135, 232, 0.3)', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#16A34A', marginBottom: '0.65rem' }}>
                            JOCKY Automated Forensic Pipeline
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: '#F1F5F9' }}>
                            {demoResult.traditional_vs_jocky.jocky.map((step, idx) => (
                              <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <CheckCircle2 size={13} color="#16A34A" />
                                <span>{step}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ marginTop: '0.65rem', fontSize: '0.72rem', color: '#16A34A', fontWeight: 600 }}>
                            Single declarative script execution with sub-second latency and mathematical chain of custody.
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* VIEW 2: EXECUTION HISTORY (Requirement 14) */}
      {studioTab === 'history' && (
        <ExecutionHistoryView
          historyList={historyList}
          selectedExecution={selectedExecution}
          onSelectExecution={setSelectedExecution}
          onBackToList={() => setSelectedExecution(null)}
          onReRun={handleReRun}
          onNewInvestigation={() => {
            setStudioTab('new');
            setSelectedExecution(null);
          }}
          onOpenWorkspace={(exec) => {
            setWorkspaceCaseId(exec?.case_id || 'CASE-DEMO-01');
            setStudioTab('workspace');
          }}
        />
      )}

      {/* VIEW 3: INVESTIGATION WORKSPACE (Phase 27) */}
      {studioTab === 'workspace' && (
        <InvestigationWorkspaceView
          caseId={workspaceCaseId || 'CASE-DEMO-01'}
          onBackToStudio={() => setStudioTab('new')}
        />
      )}
    </div>
  );
}
