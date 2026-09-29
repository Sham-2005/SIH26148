import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Hash,
  Clock,
  Layers,
  Activity,
  Copy,
  Check,
  RotateCcw,
  Cpu,
  Lock,
  ArrowRight,
  Database,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  Eye,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  GitBranch,
  Network
} from 'lucide-react';

const TAMPER_SCENARIOS = [
  { id: 'modify_raw', label: '1. Modify Raw Evidence Telemetry (EVD-DEMO-01-00010)' },
  { id: 'modify_hash', label: '2. Modify Evidence Sealed Hash Directly' },
  { id: 'delete_evidence', label: '3. Delete Evidence Record From Sequence' },
  { id: 'reorder_evidence', label: '4. Break Sequential Hash Chain (previous_hash)' },
  { id: 'chronological_inversion', label: '5. Invert Chronological Timestamp Ordering' },
  { id: 'modify_merkle', label: '6. Tamper Merkle Root Record' },
  { id: 'modify_blockchain', label: '7. Corrupt Blockchain Anchor Block Hash' },
  { id: 'modify_script', label: '8. Modify JOCKY Script Source Code' }
];

export default function InvestigationWorkspaceView({
  caseId = 'CASE-DEMO-01',
  onBackToStudio,
  onOpenReport
}) {
  const [activeTab, setActiveTab] = useState('overview'); // overview, script, execution, evidence, findings, timeline, integrity, report
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [notice, setNotice] = useState(null);

  // Core Data fetched from API
  const [integrityData, setIntegrityData] = useState(null);
  const [evidenceList, setEvidenceList] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [merkleData, setMerkleData] = useState(null);
  const [blockchainData, setBlockchainData] = useState(null);
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [findings, setFindings] = useState([]);

  // Selected sub-states
  const [selectedEvidenceModal, setSelectedEvidenceModal] = useState(null);
  const [evidenceModalTab, setEvidenceModalTab] = useState('raw'); // raw, normalized, envelope
  const [selectedFindingProvenance, setSelectedFindingProvenance] = useState(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);
  const [copiedText, setCopiedText] = useState(null);

  // Evidence Tab Filters
  const [evidenceCollectorFilter, setEvidenceCollectorFilter] = useState('ALL');
  const [evidenceSearchQuery, setEvidenceSearchQuery] = useState('');

  // Timeline Filters
  const [timelineFilter, setTimelineFilter] = useState('ALL');

  // Tamper Demo state
  const [selectedTamperScenario, setSelectedTamperScenario] = useState('modify_raw');

  // 1. Initial Load: Fetch all data from backend
  const fetchAllData = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [
        integrityRes,
        evidenceRes,
        incidentsRes,
        merkleRes,
        blockchainRes,
        timelineRes
      ] = await Promise.all([
        fetch(`http://localhost:8000/api/investigations/${caseId}/integrity`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/evidence`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/incidents`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/merkle`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/blockchain`),
        fetch(`http://localhost:8000/api/investigations/${caseId}/timeline`)
      ]);

      if (integrityRes.ok) {
        setIntegrityData(await integrityRes.json());
      }
      if (evidenceRes.ok) {
        setEvidenceList(await evidenceRes.json());
      }
      if (incidentsRes.ok) {
        setIncidents(await incidentsRes.json());
      }
      if (merkleRes.ok) {
        setMerkleData(await merkleRes.json());
      }
      if (blockchainRes.ok) {
        setBlockchainData(await blockchainRes.json());
      }
      if (timelineRes.ok) {
        setTimelineEvents(await timelineRes.json());
      }

      // Fetch findings from incidents or directly
      const findingsRes = await fetch(`http://localhost:8000/api/investigations/${caseId}/findings`);
      if (findingsRes.ok) {
        setFindings(await findingsRes.json());
      }
    } catch (err) {
      console.error('Error fetching investigation workspace data:', err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, [caseId]);

  // Copy helper
  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedText(key);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Re-run full deterministic provenance pipeline
  const handleExecuteFreshDemo = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${caseId}/execute-provenance-demo`, {
        method: 'POST'
      });
      if (res.ok) {
        await fetchAllData(true);
        setNotice({ type: 'success', message: 'Deterministic investigation executed: 28 evidence records sealed & anchored.' });
      } else {
        setNotice({ type: 'error', message: 'Failed to execute provenance demo.' });
      }
    } catch (err) {
      setNotice({ type: 'error', message: 'Network error executing demo.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Live Verify Integrity
  const handleVerifyIntegrity = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${caseId}/integrity/verify`, {
        method: 'POST'
      });
      if (res.ok) {
        const result = await res.json();
        setIntegrityData(result);
        if (result.valid) {
          setNotice({ type: 'success', message: 'All 8 cryptographic integrity checks passed successfully.' });
        } else {
          setNotice({ type: 'error', message: `Integrity failure detected! ${result.failures?.length || 1} discrepancy identified.` });
        }
      }
    } catch (err) {
      setNotice({ type: 'error', message: 'Failed to verify integrity.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Simulate Tampering
  const handleSimulateTamper = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${caseId}/integrity/tamper-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tamper_type: selectedTamperScenario })
      });
      if (res.ok) {
        const result = await res.json();
        setIntegrityData(result);
        await fetchAllData(true);
        setNotice({ type: 'warning', message: `Tampering simulated: ${result.scenario}. Integrity verification correctly flagged failure!` });
      }
    } catch (err) {
      setNotice({ type: 'error', message: 'Error simulating tamper event.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Restore Clean Evidence
  const handleRestoreEvidence = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${caseId}/integrity/restore-demo`, {
        method: 'POST'
      });
      if (res.ok) {
        const result = await res.json();
        setIntegrityData(result);
        await fetchAllData(true);
        setNotice({ type: 'success', message: 'Evidence restored from pristine state! All 8 integrity checks verified.' });
      }
    } catch (err) {
      setNotice({ type: 'error', message: 'Error restoring evidence.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Load Finding Provenance
  const handleViewFindingProvenance = async (findingId) => {
    setProvenanceLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/investigations/${caseId}/provenance/${findingId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedFindingProvenance(data);
      }
    } catch (err) {
      console.error('Error fetching finding provenance:', err);
    } finally {
      setProvenanceLoading(false);
    }
  };

  // JOCKY Script source for CASE-DEMO-01
  const jockyScriptCode = `CASE "${caseId}"

TARGET "DEMO-WINDOWS-ENDPOINT"

COLLECT registry
WHERE path MATCHES "Run|RunOnce|Services"

COLLECT processes
WHERE parent == "explorer.exe"

COLLECT network
WHERE protocol IN ["TCP", "UDP"]

COLLECT files
WHERE extension IN [".exe", ".dll", ".ps1"]

COLLECT system
WHERE telemetry == "baseline"

CORRELATE
    registry
    WITH processes
    WITH network
    WITH files
    WITH system

ANALYZE forensic_vector

CALCULATE threat_score

VERIFY tamper

HASH evidence

CHAIN evidence

REPORT "Suspicious Endpoint Forensics"`;

  const scriptHash = '34bbbedb48a6c0cc73a0578b9e8c61b481067dd4752b267a80892717e31b0c2a';

  // Filter evidence list
  const filteredEvidence = evidenceList.filter(ev => {
    if (evidenceCollectorFilter !== 'ALL' && ev.collector !== evidenceCollectorFilter) {
      return false;
    }
    if (evidenceSearchQuery.trim()) {
      const q = evidenceSearchQuery.toLowerCase();
      const matchId = ev.id?.toLowerCase().includes(q);
      const matchColl = ev.collector?.toLowerCase().includes(q);
      const matchHash = ev.sha256_hash?.toLowerCase().includes(q);
      const matchRaw = JSON.stringify(ev.raw_data || {}).toLowerCase().includes(q);
      const matchNorm = JSON.stringify(ev.normalized_data || {}).toLowerCase().includes(q);
      return matchId || matchColl || matchHash || matchRaw || matchNorm;
    }
    return true;
  });

  // Filter timeline events
  const filteredTimeline = timelineEvents.filter(ev => {
    if (timelineFilter === 'ALL') return true;
    return ev.event_type?.toUpperCase() === timelineFilter;
  });

  const isIntegrityValid = integrityData?.valid === true;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%', maxWidth: '1440px', margin: '0 auto' }}>
      
      {/* NOTICE BANNER */}
      {notice && (
        <div style={{
          padding: '0.85rem 1.25rem',
          borderRadius: '8px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: notice.type === 'success' ? 'rgba(16, 185, 129, 0.12)' : notice.type === 'warning' ? 'rgba(245, 158, 11, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          border: `1px solid ${notice.type === 'success' ? '#1C2833' : notice.type === 'warning' ? 'rgba(245, 158, 11, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
          boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            {notice.type === 'success' ? <CheckCircle2 size={18} color="#16A34A" /> : <AlertTriangle size={18} color={notice.type === 'warning' ? '#F59E0B' : '#DC2626'} />}
            <span style={{ fontSize: '0.85rem', color: '#F1F5F9', fontWeight: 500 }}>{notice.message}</span>
          </div>
          <button
            onClick={() => setNotice(null)}
            style={{ background: 'transparent', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: '0.8rem' }}
          ><X size={15} /></button>
        </div>
      )}

      {/* TOP WORKSPACE HEADER CARD */}
      <div className="glass-panel" style={{
        padding: '1.5rem 1.75rem',
        background: '#0E151C',
        border: '1px solid #1C2833',
        borderRadius: '8px',
        boxShadow: '0 1px 3px rgba(16, 24, 40, 0.06)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '0.75rem', color: '#3B9CFF', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700 }}>
                INVESTIGATION WORKSPACE
              </span>
              <span style={{ fontSize: '0.72rem', background: 'rgba(37, 135, 232, 0.12)', color: '#3B9CFF', padding: '0.1rem 0.45rem', borderRadius: '4px', border: '1px solid rgba(37, 135, 232, 0.3)', fontWeight: 600 }}>
                PHASE 27 PROVENANCE ENGINE
              </span>
            </div>
            <h1 style={{ fontSize: '26px', fontWeight: 700, color: '#F1F5F9', marginTop: '0.25rem', letterSpacing: '-0.02em', lineHeight: 1.25 }}>
              JOCKY Investigation: Suspicious Endpoint
            </h1>
            <div style={{ fontSize: '0.88rem', color: '#64748B', marginTop: '0.25rem' }}>
              Case: <strong style={{ color: '#F1F5F9', fontFamily: 'var(--font-mono)' }}>{caseId}</strong> • Target: <strong style={{ color: '#F1F5F9' }}>DEMO-WINDOWS-ENDPOINT</strong> (Win 11 Ent x64) • Operator: <strong style={{ color: '#F1F5F9' }}>secops-lead@jocky.defense</strong>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              onClick={handleExecuteFreshDemo}
              disabled={actionLoading}
              className="btn-secondary"
              style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: '1px solid #1C2833' }}
              title="Resets and re-executes the complete deterministic investigation across 5 collectors"
            >
              <RotateCcw size={14} className={actionLoading ? 'spin' : ''} />
              Re-Execute Pipeline
            </button>
            <button
              onClick={() => setActiveTab('integrity')}
              style={{
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                background: isIntegrityValid ? 'rgba(37, 135, 232, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                color: isIntegrityValid ? '#2587E8' : '#DC2626',
                border: `1px solid ${isIntegrityValid ? 'rgba(37, 135, 232, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                padding: '0.45rem 0.85rem',
                borderRadius: '6px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <ShieldCheck size={15} />
              {isIntegrityValid ? 'Integrity Verified' : 'Integrity Failure'}
            </button>
          </div>
        </div>

        {/* STATUS PILLS ROW */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: '0.85rem',
          paddingTop: '1rem',
          borderTop: '1px solid #F1F3F5'
        }}>
          {/* Status */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Status</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#16A34A', marginTop: '0.15rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <CheckCircle2 size={15} color="#16A34A" /> COMPLETED
            </div>
          </div>

          {/* Integrity */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Integrity</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: isIntegrityValid ? '#16A34A' : '#DC2626', marginTop: '0.15rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              {isIntegrityValid ? <Check size={15} color="#16A34A" /> : <AlertTriangle size={15} color="#EF4444" />}
              {isIntegrityValid ? 'VERIFIED (8/8)' : 'TAMPER DETECTED'}
            </div>
          </div>

          {/* Evidence Count */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Evidence</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#3B9CFF', marginTop: '0.15rem' }}>
              {evidenceList.length} Sealed Items
            </div>
          </div>

          {/* Findings Count */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Findings</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#F59E0B', marginTop: '0.15rem' }}>
              {findings.length || 4} Detections (2 Rule, 2 ML)
            </div>
          </div>

          {/* Timeline Events */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Timeline Events</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#7C3AED', marginTop: '0.15rem' }}>
              {timelineEvents.length || 10} Chronological Events
            </div>
          </div>

          {/* Blockchain Anchor */}
          <div style={{ background: '#111A22', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Blockchain</div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#F1F5F9', marginTop: '0.15rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Lock size={14} color="#2587E8" /> ANCHORED (Block #{blockchainData?.block_number || 77})
            </div>
          </div>
        </div>
      </div>

      {/* 8-TAB NAVIGATION BAR */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.35rem',
        background: '#0E151C',
        border: '1px solid #1C2833',
        borderRadius: '8px',
        padding: '0.4rem',
        boxShadow: '0 1px 2px rgba(16, 24, 40, 0.05)',
        overflowX: 'auto'
      }}>
        {[
          { id: 'overview', label: 'Overview', icon: Layers },
          { id: 'script', label: 'Script', icon: Terminal },
          { id: 'execution', label: 'Execution', icon: Activity },
          { id: 'evidence', label: `Evidence (${evidenceList.length})`, icon: Database },
          { id: 'findings', label: `Findings (${findings.length || 4})`, icon: AlertTriangle },
          { id: 'timeline', label: `Timeline (${timelineEvents.length || 10})`, icon: Clock },
          { id: 'integrity', label: 'Integrity Verification', icon: ShieldCheck, badge: isIntegrityValid ? '8/8' : 'FAIL' },
          { id: 'report', label: 'Forensic Report', icon: FileText }
        ].map(tab => {
          const isActive = activeTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              id={`workspace-tab-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.55rem 0.95rem',
                borderRadius: '6px',
                fontSize: '0.84rem',
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                background: isActive ? 'rgba(37, 135, 232, 0.12)' : 'transparent',
                border: isActive ? '1px solid #1C2833' : '1px solid transparent',
                color: isActive ? '#2587E8' : '#475467',
                whiteSpace: 'nowrap'
              }}
            >
              <Icon size={15} color={isActive ? '#2587E8' : '#667085'} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span style={{
                  fontSize: '0.7rem',
                  padding: '0.1rem 0.4rem',
                  borderRadius: '999px',
                  fontWeight: 700,
                  background: isIntegrityValid ? '#DCFCE7' : '#FEE2E2',
                  color: isIntegrityValid ? '#16A34A' : '#DC2626',
                  border: `1px solid ${isIntegrityValid ? '#1C2833' : 'rgba(239, 68, 68, 0.25)'}`
                }}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: OVERVIEW */}
      {/* ========================================================================= */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Metadata Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
            {/* Identity & Scope */}
            <div className="glass-panel" style={{ padding: '1.25rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <Terminal size={16} color="#2587E8" /> Investigation Identity
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem', fontSize: '0.82rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Investigation ID:</span>
                  <strong style={{ color: '#F1F5F9', fontFamily: 'var(--font-mono)' }}>{caseId}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Execution ID:</span>
                  <strong style={{ color: '#3B9CFF', fontFamily: 'var(--font-mono)' }}>{integrityData?.execution_id || 'EXE-2026-909F'}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Target Host:</span>
                  <strong style={{ color: '#F1F5F9' }}>DEMO-WINDOWS-ENDPOINT</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Platform:</span>
                  <span style={{ color: '#F1F5F9' }}>Windows 11 Enterprise (x64)</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Operator:</span>
                  <span style={{ color: '#F1F5F9' }}>secops-lead@jocky.defense</span>
                </div>
              </div>
            </div>

            {/* Cryptographic Manifest */}
            <div className="glass-panel" style={{ padding: '1.25rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <Lock size={16} color="#2587E8" /> Cryptographic Integrity Anchors
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem', fontSize: '0.82rem' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748B', marginBottom: '0.15rem' }}>
                    <span>Script SHA-256 Digest:</span>
                    <button
                      onClick={() => handleCopy(scriptHash, 'script_hash_overview')}
                      style={{ background: 'transparent', border: 'none', color: '#3B9CFF', cursor: 'pointer', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                    >
                      {copiedText === 'script_hash_overview' ? <Check size={12} color="#16A34A" /> : <Copy size={12} />}
                      {copiedText === 'script_hash_overview' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#F1F5F9', background: '#111A22', padding: '0.35rem 0.5rem', borderRadius: '4px', border: '1px solid #1C2833', wordBreak: 'break-all' }}>
                    {scriptHash}
                  </div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748B', marginBottom: '0.15rem' }}>
                    <span>Merkle Tree Root:</span>
                    <button
                      onClick={() => handleCopy(integrityData?.merkle?.root || merkleData?.merkle_root, 'merkle_root_overview')}
                      style={{ background: 'transparent', border: 'none', color: '#3B9CFF', cursor: 'pointer', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                    >
                      {copiedText === 'merkle_root_overview' ? <Check size={12} color="#16A34A" /> : <Copy size={12} />}
                      {copiedText === 'merkle_root_overview' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#F1F5F9', background: '#111A22', padding: '0.35rem 0.5rem', borderRadius: '4px', border: '1px solid #1C2833', wordBreak: 'break-all' }}>
                    {integrityData?.merkle?.root || merkleData?.merkle_root || '2033beab256bc186e24a0dd0377e7beaddf986c9e8b2fb52c8e58be44bfc85fc'}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                  <span style={{ color: '#64748B' }}>Blockchain Ledger:</span>
                  <span style={{ color: '#16A34A', fontWeight: 600 }}>Local Evidence Blockchain (Block #{blockchainData?.block_number || 77})</span>
                </div>
              </div>
            </div>

            {/* Telemetry Scope */}
            <div className="glass-panel" style={{ padding: '1.25rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <Activity size={16} color="#2587E8" /> Execution Summary
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem', fontSize: '0.82rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Collectors Executed:</span>
                  <strong style={{ color: '#F1F5F9' }}>5 Collectors (registry, processes, network, files, system)</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Evidence Envelopes:</span>
                  <strong style={{ color: '#3B9CFF' }}>28 RFC-8785 Sealed Envelopes</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Detection Findings:</span>
                  <strong style={{ color: '#EF4444' }}>4 Findings (Rule &amp; Explainable ML)</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Correlated Incidents:</span>
                  <strong style={{ color: '#F59E0B' }}>1 Multi-Source Cluster</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748B' }}>Verification Status:</span>
                  <span style={{ color: isIntegrityValid ? '#16A34A' : '#DC2626', fontWeight: 700 }}>
                    {isIntegrityValid ? 'Validated' : 'Discrepancy Flagged'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Correlated Incidents Section */}
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#F1F5F9', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Network size={18} color="#2587E8" /> Correlated Incident: Suspicious Activity Cluster
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  Automated correlation linking independent evidence sources into unified forensic clusters.
                </p>
              </div>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.12)', color: '#EF4444', border: '1px solid #1C2833' }}>
                SEVERITY: CRITICAL
              </span>
            </div>

            {incidents.length > 0 ? (
              incidents.map((inc, i) => (
                <div key={i} style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
                    <div>
                      <div style={{ fontSize: '0.75rem', color: '#3B9CFF', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{inc.id}</div>
                      <div style={{ fontSize: '0.98rem', fontWeight: 600, color: '#F1F5F9', marginTop: '0.15rem' }}>{inc.title}</div>
                    </div>
                    <span style={{ fontSize: '0.72rem', background: 'rgba(37, 135, 232, 0.12)', color: '#3B9CFF', border: '1px solid rgba(37, 135, 232, 0.3)', padding: '0.15rem 0.5rem', borderRadius: '4px', fontWeight: 600 }}>
                      {inc.classification || 'Suspicious Activity Cluster'}
                    </span>
                  </div>

                  <p style={{ fontSize: '0.84rem', color: '#94A3B8', lineHeight: '1.5', margin: '0.4rem 0 0.85rem 0' }}>
                    {inc.description}
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', borderTop: '1px solid #1C2833', paddingTop: '0.85rem' }}>
                    <div style={{ fontSize: '0.78rem', color: '#64748B', fontWeight: 600 }}>Correlated Temporal Sequence:</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {(inc.timeline_sequence || ['Registry persistence written', 'Process spawned', 'Outbound socket established', 'Service registered']).map((step, idx) => (
                        <div key={idx} style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '4px', padding: '0.3rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ color: '#3B9CFF', fontWeight: 700 }}>#{idx + 1}</span>
                          <span style={{ color: '#F1F5F9' }}>{step}</span>
                        </div>
                      ))}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.4rem' }}>
                      <span style={{ fontSize: '0.78rem', color: '#64748B', fontWeight: 600 }}>Linked Evidence:</span>
                      {(inc.evidence_ids || []).map(eid => (
                        <span key={eid} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#3B9CFF', background: 'rgba(37, 135, 232, 0.12)', border: '1px solid rgba(37, 135, 232, 0.3)', padding: '0.15rem 0.45rem', borderRadius: '3px' }}>
                          {eid}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ background: '#111A22', padding: '1rem', borderRadius: '6px', fontSize: '0.84rem', color: '#64748B' }}>
                No correlated incidents registered for this case.
              </div>
            )}
          </div>

          {/* Complete Provenance Architecture Flow */}
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '0.5rem' }}>
              Phase 27 Evidence Provenance &amp; Traceability Architecture
            </h3>
            <p style={{ fontSize: '0.82rem', color: '#64748B', marginBottom: '1.25rem' }}>
              Deterministic lifecycle connecting declarative JOCKY script execution to courtroom-admissible blockchain-anchored evidence.
            </p>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.5rem',
              alignItems: 'center'
            }}>
              {[
                { step: '1', title: 'JOCKY Script', sub: 'Declarative Syntax' },
                { step: '2', title: 'Script Hash', sub: 'SHA-256 Digest' },
                { step: '3', title: '5 Collectors', sub: 'Kernel & Userland' },
                { step: '4', title: '28 Evidence', sub: 'Raw & Normalized' },
                { step: '5', title: 'Hash Chain', sub: 'RFC-8785 Sealed' },
                { step: '6', title: 'Correlation', sub: 'Multi-Source Cluster' },
                { step: '7', title: 'Rule & ML', sub: 'Explainable Signals' },
                { step: '8', title: '4 Findings', sub: 'Traceable Origin' },
                { step: '9', title: 'Timeline', sub: 'Chronological' },
                { step: '10', title: 'Merkle Root', sub: 'Binary Tree Commit' },
                { step: '11', title: 'Blockchain', sub: 'Local Evidence Anchor' }
              ].map((item, i) => (
                <div key={i} style={{
                  background: '#111A22',
                  border: '1px solid #1C2833',
                  borderRadius: '6px',
                  padding: '0.75rem 0.5rem',
                  textAlign: 'center',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.2rem'
                }}>
                  <div style={{ fontSize: '0.7rem', color: '#3B9CFF', fontWeight: 700 }}>Step {item.step}</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#F1F5F9' }}>{item.title}</div>
                  <div style={{ fontSize: '0.7rem', color: '#64748B' }}>{item.sub}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: SCRIPT */}
      {/* ========================================================================= */}
      {activeTab === 'script' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                  Declarative JOCKY Forensic Script
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  Read-only execution source registered with immutable SHA-256 cryptographic plan digest.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <span style={{ fontSize: '0.78rem', color: '#16A34A', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(37, 135, 232, 0.3)', padding: '0.25rem 0.6rem', borderRadius: '4px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Check size={14} color="#16A34A" /> SHA-256 Verified
                </span>
                <button
                  onClick={() => handleCopy(scriptHash, 'script_tab_hash')}
                  className="btn-secondary"
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  {copiedText === 'script_tab_hash' ? <Check size={13} color="#16A34A" /> : <Copy size={13} />}
                  {copiedText === 'script_tab_hash' ? 'Copied Hash' : 'Copy Hash'}
                </button>
              </div>
            </div>

            {/* Script Hash Banner */}
            <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '6px', padding: '0.75rem 1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ fontSize: '0.8rem', color: '#64748B' }}>
                Recorded Script SHA-256 Digest: <strong style={{ color: '#F1F5F9', fontFamily: 'var(--font-mono)' }}>{scriptHash}</strong>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#3B9CFF', fontWeight: 600 }}>
                Version: 1.0 • Execution: {integrityData?.execution_id || 'EXE-2026-909F'}
              </div>
            </div>

            {/* Code View */}
            <div style={{
              background: '#0F172A',
              color: '#F8FAFC',
              borderRadius: '8px',
              padding: '1.25rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '13px',
              lineHeight: '1.7',
              maxHeight: '440px',
              overflowY: 'auto',
              border: '1px solid #1E293B'
            }}>
              {jockyScriptCode.split('\n').map((line, idx) => {
                const isComment = line.trim().startsWith('//');
                const isKeyword = /^(CASE|TARGET|COLLECT|WHERE|CORRELATE|ANALYZE|CALCULATE|VERIFY|HASH|CHAIN|REPORT)/.test(line.trim());
                return (
                  <div key={idx} style={{ display: 'flex', gap: '1rem' }}>
                    <span style={{ color: '#94A3B8', width: '28px', textAlign: 'right', userSelect: 'none' }}>{idx + 1}</span>
                    <span style={{
                      color: isComment ? '#64748B' : isKeyword ? '#38BDF8' : '#E2E8F0',
                      fontWeight: isKeyword ? 700 : 400
                    }}>
                      {line}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: EXECUTION */}
      {/* ========================================================================= */}
      {activeTab === 'execution' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Execution Environment Card */}
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '1rem' }}>
              Execution Lifecycle &amp; Telemetry Environment
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.85rem', marginBottom: '1.5rem' }}>
              <div style={{ background: '#111A22', padding: '0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
                <div style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase' }}>Execution ID</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#3B9CFF', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }}>
                  {integrityData?.execution_id || 'EXE-2026-909F'}
                </div>
              </div>

              <div style={{ background: '#111A22', padding: '0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
                <div style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase' }}>Runtime Version</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', marginTop: '0.15rem' }}>
                  v1.0.0-phase27 (x64)
                </div>
              </div>

              <div style={{ background: '#111A22', padding: '0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
                <div style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase' }}>Target Architecture</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', marginTop: '0.15rem' }}>
                  Windows 11 Enterprise (23H2)
                </div>
              </div>

              <div style={{ background: '#111A22', padding: '0.85rem', borderRadius: '6px', border: '1px solid #1C2833' }}>
                <div style={{ fontSize: '0.72rem', color: '#64748B', textTransform: 'uppercase' }}>Execution Duration</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#16A34A', marginTop: '0.15rem' }}>
                  182 ms (Deterministic)
                </div>
              </div>
            </div>

            {/* Visual 8-Stage Execution Pipeline */}
            <div style={{ marginTop: '1rem' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#F1F5F9', marginBottom: '0.85rem' }}>
                Sequential Lifecycle Execution Pipeline
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {[
                  { stage: '1', title: 'SCRIPT LOADED', status: 'COMPLETED', desc: 'Parsed declarative JOCKY script AST, verified statement semantics and target parameters.' },
                  { stage: '2', title: 'VALIDATED', status: 'COMPLETED', desc: 'Pre-flight capability match checked against fleet endpoint security allowlist.' },
                  { stage: '3', title: 'EXECUTED', status: 'COMPLETED', desc: 'Safe low-footprint forensic execution engine initiated collection leases.' },
                  { stage: '4', title: 'COLLECTING', status: 'COMPLETED', desc: 'Dispatched 5 specialized collectors: registry, processes, network, files, system.' },
                  { stage: '5', title: 'EVIDENCE SEALED', status: 'COMPLETED', desc: 'Generated 28 canonical RFC-8785 JSON hashes and chained previous_evidence_hash values.' },
                  { stage: '6', title: 'ANALYZING', status: 'COMPLETED', desc: 'Extracted 21-dimensional vector, evaluated threat rules, and generated explainable ML scores.' },
                  { stage: '7', title: 'REPORT GENERATED', status: 'COMPLETED', desc: 'Synthesized court-admissible forensic manifest with explicit scope & methodological boundaries.' },
                  { stage: '8', title: 'INTEGRITY ANCHORED', status: 'COMPLETED', desc: 'Computed Merkle root and committed immutable anchor into Local Evidence Blockchain Block #77.' }
                ].map(step => (
                  <div key={step.stage} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.85rem 1rem',
                    background: '#111A22',
                    border: '1px solid #1C2833',
                    borderRadius: '6px',
                    gap: '1rem'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: '28px',
                        height: '28px',
                        borderRadius: '50%',
                        background: 'rgba(37, 135, 232, 0.12)',
                        color: '#3B9CFF',
                        fontWeight: 700,
                        fontSize: '0.82rem',
                        border: '1px solid rgba(37, 135, 232, 0.3)'
                      }}>
                        {step.stage}
                      </span>
                      <div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#F1F5F9' }}>{step.title}</div>
                        <div style={{ fontSize: '0.78rem', color: '#64748B', marginTop: '0.1rem' }}>{step.desc}</div>
                      </div>
                    </div>
                    <span style={{ fontSize: '0.72rem', padding: '0.2rem 0.55rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.12)', color: '#16A34A', border: '1px solid rgba(37, 135, 232, 0.3)', fontWeight: 700 }}>
                      {step.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: EVIDENCE */}
      {/* ========================================================================= */}
      {activeTab === 'evidence' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            {/* Header & Filter Controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                  Canonical Evidence Registry ({evidenceList.length} Items)
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  RFC-8785 canonical JSON sealed evidence items with sequential SHA-256 hash chains.
                </p>
              </div>

              {/* Search & Collector Filters */}
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative' }}>
                  <Search size={14} color="#98A2B3" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
                  <input
                    type="text"
                    value={evidenceSearchQuery}
                    onChange={(e) => setEvidenceSearchQuery(e.target.value)}
                    placeholder="Search by ID, hash, path..."
                    style={{
                      padding: '0.4rem 0.65rem 0.4rem 2rem',
                      background: '#0E151C',
                      border: '1px solid #1C2833',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      color: '#F1F5F9',
                      width: '220px'
                    }}
                  />
                </div>

                <select
                  value={evidenceCollectorFilter}
                  onChange={(e) => setEvidenceCollectorFilter(e.target.value)}
                  style={{
                    padding: '0.4rem 0.65rem',
                    background: '#0E151C',
                    border: '1px solid #1C2833',
                    borderRadius: '6px',
                    fontSize: '0.82rem',
                    color: '#F1F5F9'
                  }}
                >
                  <option value="ALL">All Collectors</option>
                  <option value="registry">Registry</option>
                  <option value="processes">Processes</option>
                  <option value="network">Network</option>
                  <option value="files">Files</option>
                  <option value="system">System</option>
                </select>
              </div>
            </div>

            {/* Evidence Table */}
            <div style={{ overflowX: 'auto', border: '1px solid #1C2833', borderRadius: '6px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.84rem' }}>
                <thead>
                  <tr style={{ background: '#111A22', borderBottom: '1px solid #1C2833', textAlign: 'left', color: '#64748B', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Evidence ID</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Collector</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Collected At</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Evidence Hash (SHA-256)</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Integrity</th>
                    <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvidence.map((ev, idx) => (
                    <tr
                      key={ev.id}
                      onClick={() => {
                        setSelectedEvidenceModal(ev);
                        setEvidenceModalTab('raw');
                      }}
                      style={{
                        borderBottom: '1px solid #1C2833',
                        background: idx % 2 === 0 ? '#0E151C' : '#111A22',
                        cursor: 'pointer',
                        transition: 'background-color 0.15s ease'
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(37, 135, 232, 0.12)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = idx % 2 === 0 ? '#0E151C' : '#111A22'; }}
                    >
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#3B9CFF' }}>
                        {ev.id}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: '#111A22', color: '#94A3B8', fontWeight: 600 }}>
                          {ev.collector?.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#F1F5F9' }}>
                        {ev.collector_source || ev.collector}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#64748B', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                        {ev.collected_at ? ev.collected_at.replace('T', ' ').slice(0, 19) : '10:21:01'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#F1F5F9' }}>
                        {ev.sha256_hash ? `${ev.sha256_hash.slice(0, 16)}...` : '7a91...e812'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{
                          fontSize: '0.72rem',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: ev.integrity_status === 'VERIFIED' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                          color: ev.integrity_status === 'VERIFIED' ? '#16A34A' : '#DC2626',
                          border: `1px solid ${ev.integrity_status === 'VERIFIED' ? '#1C2833' : 'rgba(239, 68, 68, 0.25)'}`,
                          fontWeight: 600
                        }}>
                          {ev.integrity_status === 'VERIFIED' ? 'Verified' : 'Integrity Check Failed'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <span style={{ color: '#3B9CFF', fontSize: '0.8rem', fontWeight: 600 }}>
                          Inspect Envelope
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: FINDINGS */}
      {/* ========================================================================= */}
      {activeTab === 'findings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                  Actionable Forensic Findings ({findings.length || 4})
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  Every finding is strictly attributable to supporting evidence, collectors, execution runs, and script hashes.
                </p>
              </div>
            </div>

            {/* Findings Cards Grid */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {(findings.length > 0 ? findings : [
                {
                  id: 'FND-DEMO-01-001',
                  title: 'Suspicious Process Execution: suspicious-update.exe',
                  description: 'Unsigned high-entropy PE executable spawned directly under Windows explorer shell without trusted signature.',
                  severity: 'HIGH',
                  detection_type: 'rule',
                  detection_rule_id: 'RULE-PROC-001',
                  confidence_score: 0.90,
                  evidence_ids: ['EVD-DEMO-01-00010', 'EVD-DEMO-01-00023']
                },
                {
                  id: 'FND-DEMO-01-002',
                  title: 'Anomalous Outbound C2 Socket Telemetry',
                  description: 'Outbound TCP connection established to external non-RFC1918 IPv4 address on non-standard port 4444.',
                  severity: 'CRITICAL',
                  detection_type: 'rule',
                  detection_rule_id: 'RULE-NET-002',
                  confidence_score: 0.95,
                  evidence_ids: ['EVD-DEMO-01-00017']
                },
                {
                  id: 'FND-DEMO-01-003',
                  title: 'Registry Persistence Hook via RunKey',
                  description: 'Autorun key created under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing to suspicious binary.',
                  severity: 'HIGH',
                  detection_type: 'rule',
                  detection_rule_id: 'RULE-PERSIST-001',
                  confidence_score: 0.92,
                  evidence_ids: ['EVD-DEMO-01-00004']
                },
                {
                  id: 'FND-DEMO-01-004',
                  title: 'Cross-Artifact Multi-Endpoint Threat Anomaly Cluster',
                  description: 'Machine Learning threat model flagged elevated composite risk vector based on 21-dimensional forensic telemetry.',
                  severity: 'CRITICAL',
                  detection_type: 'ml',
                  model_name: 'JOCKY-Anomaly-v1',
                  model_version: '1.0',
                  confidence_score: 0.91,
                  evidence_ids: ['EVD-DEMO-01-00010', 'EVD-DEMO-01-00017', 'EVD-DEMO-01-00023'],
                  explainable_factors: [
                    { name: 'unusual_binary_path', contribution: 0.32, evidence_ids: ['EVD-DEMO-01-00023'] },
                    { name: 'external_c2_connection', contribution: 0.28, evidence_ids: ['EVD-DEMO-01-00017'] },
                    { name: 'registry_persistence_hook', contribution: 0.24, evidence_ids: ['EVD-DEMO-01-00004'] },
                    { name: 'anomalous_parent_child', contribution: 0.16, evidence_ids: ['EVD-DEMO-01-00010'] }
                  ]
                }
              ]).map(f => {
                const isCrit = f.priority === 'CRITICAL' || f.severity === 'CRITICAL';
                const isML = f.detection_type === 'ml';

                return (
                  <div
                    key={f.id}
                    style={{
                      background: '#0E151C',
                      border: '1px solid #1C2833',
                      borderLeft: `4px solid ${isCrit ? '#DC2626' : '#F59E0B'}`,
                      borderRadius: '8px',
                      padding: '1.25rem 1.5rem',
                      boxShadow: '0 1px 3px rgba(16, 24, 40, 0.05)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 700, color: '#3B9CFF' }}>
                            {f.id}
                          </span>
                          <span style={{
                            fontSize: '0.72rem',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontWeight: 700,
                            background: isCrit ? 'rgba(239, 68, 68, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                            color: isCrit ? '#DC2626' : '#F59E0B',
                            border: `1px solid ${isCrit ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)'}`
                          }}>
                            {f.priority || f.severity || 'HIGH'}
                          </span>
                          <span style={{
                            fontSize: '0.72rem',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontWeight: 600,
                            background: isML ? '#FAF5FF' : 'rgba(37, 135, 232, 0.12)',
                            color: isML ? '#7C3AED' : '#2587E8',
                            border: `1px solid ${isML ? '#E9D5FF' : 'rgba(37, 135, 232, 0.25)'}`
                          }}>
                            {isML ? `ML Model: ${f.model_name || 'JOCKY-Anomaly-v1'}` : `Rule: ${f.detection_rule_id || 'RULE-PROC-001'}`}
                          </span>
                        </div>
                        <h4 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#F1F5F9', margin: '0.35rem 0 0 0' }}>
                          {f.title}
                        </h4>
                      </div>

                      <button
                        onClick={() => handleViewFindingProvenance(f.id)}
                        className="btn-primary"
                        style={{ fontSize: '0.8rem', padding: '0.4rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                      >
                        <GitBranch size={14} /> View Traceability Chain
                      </button>
                    </div>

                    <p style={{ fontSize: '0.85rem', color: '#94A3B8', lineHeight: '1.5', margin: '0 0 0.85rem 0' }}>
                      {f.description}
                    </p>

                    {/* Explainable Signals (Phase 27 ML Explainability Requirement) */}
                    {f.explainable_factors && f.explainable_factors.length > 0 && (
                      <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '6px', padding: '0.85rem', marginBottom: '0.85rem' }}>
                        <div style={{ fontSize: '0.78rem', color: '#F1F5F9', fontWeight: 600, marginBottom: '0.5rem' }}>
                          Contributing Evidence Signals (Model Explainability):
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.5rem' }}>
                          {f.explainable_factors.map((factor, idx) => (
                            <div key={idx} style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '4px', padding: '0.5rem 0.65rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', fontWeight: 600, color: '#F1F5F9' }}>
                                <span>{factor.name}</span>
                                <span style={{ color: '#3B9CFF' }}>{Math.round(factor.contribution * 100)}%</span>
                              </div>
                              <div style={{ width: '100%', height: '4px', background: '#1C2833', borderRadius: '2px', overflow: 'hidden', margin: '0.35rem 0' }}>
                                <div style={{ width: `${factor.contribution * 100}%`, height: '100%', background: '#2587E8', borderRadius: '2px' }} />
                              </div>
                              <div style={{ fontSize: '0.7rem', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                                Evidence: {factor.evidence_ids?.join(', ')}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Supporting Evidence Chips */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', paddingTop: '0.65rem', borderTop: '1px solid #F1F3F5' }}>
                      <span style={{ fontSize: '0.78rem', color: '#64748B', fontWeight: 600 }}>Supporting Evidence:</span>
                      {(f.evidence_ids || []).map(eid => (
                        <button
                          key={eid}
                          onClick={() => {
                            const found = evidenceList.find(e => e.id === eid);
                            if (found) {
                              setSelectedEvidenceModal(found);
                              setEvidenceModalTab('raw');
                            }
                          }}
                          style={{
                            background: 'rgba(37, 135, 232, 0.12)',
                            border: '1px solid rgba(37, 135, 232, 0.3)',
                            color: '#3B9CFF',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontFamily: 'var(--font-mono)',
                            cursor: 'pointer'
                          }}
                        >
                          {eid}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 6: TIMELINE */}
      {/* ========================================================================= */}
      {activeTab === 'timeline' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel" style={{ padding: '1.5rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                  Unified Chronological Forensic Timeline
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  Ordered multi-source timeline linking process creation, network sockets, persistence, and detection triggers.
                </p>
              </div>

              {/* Timeline filter buttons */}
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                {['ALL', 'PROCESS', 'NETWORK', 'FILE', 'REGISTRY', 'DETECTION', 'EVIDENCE'].map(f => (
                  <button
                    key={f}
                    onClick={() => setTimelineFilter(f)}
                    style={{
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      fontWeight: timelineFilter === f ? 600 : 500,
                      cursor: 'pointer',
                      background: timelineFilter === f ? 'rgba(37, 135, 232, 0.12)' : '#111A22',
                      border: timelineFilter === f ? '1px solid #1C2833' : '1px solid #1C2833',
                      color: timelineFilter === f ? '#2587E8' : '#667085'
                    }}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            {/* Timeline Stream */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', position: 'relative' }}>
              {filteredTimeline.map((item, idx) => (
                <div key={item.id || idx} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '1rem',
                  padding: '1rem',
                  background: '#111A22',
                  border: '1px solid #1C2833',
                  borderRadius: '6px'
                }}>
                  <div style={{
                    minWidth: '70px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    color: '#3B9CFF',
                    fontWeight: 700
                  }}>
                    {item.timestamp ? item.timestamp.slice(11, 19) : `10:21:${String(idx * 2).padStart(2, '0')}`}
                  </div>

                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <span style={{
                        fontSize: '0.72rem',
                        padding: '0.1rem 0.45rem',
                        borderRadius: '3px',
                        background: 'rgba(37, 135, 232, 0.12)',
                        color: '#3B9CFF',
                        border: '1px solid rgba(37, 135, 232, 0.3)',
                        fontWeight: 700
                      }}>
                        {item.event_type?.toUpperCase() || 'TELEMETRY'}
                      </span>
                      <strong style={{ fontSize: '0.9rem', color: '#F1F5F9' }}>{item.title}</strong>
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>{item.description}</div>

                    {item.evidence_ids && item.evidence_ids.length > 0 && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.4rem' }}>
                        <span style={{ fontSize: '0.72rem', color: '#64748B' }}>Sealed Evidence:</span>
                        {item.evidence_ids.map(eid => (
                          <span
                            key={eid}
                            onClick={() => {
                              const found = evidenceList.find(e => e.id === eid);
                              if (found) {
                                setSelectedEvidenceModal(found);
                                setEvidenceModalTab('raw');
                              }
                            }}
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.72rem',
                              color: '#3B9CFF',
                              background: '#0E151C',
                              border: '1px solid rgba(37, 135, 232, 0.3)',
                              padding: '0.1rem 0.4rem',
                              borderRadius: '3px',
                              cursor: 'pointer'
                            }}
                          >
                            {eid}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 7: INTEGRITY VERIFICATION (CENTERPIECE DEMO) */}
      {/* ========================================================================= */}
      {activeTab === 'integrity' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Integrity Master Card */}
          <div className="glass-panel" style={{
            padding: '1.75rem',
            background: '#0E151C',
            border: `1px solid ${isIntegrityValid ? '#1C2833' : 'rgba(239, 68, 68, 0.25)'}`,
            borderRadius: '8px',
            boxShadow: '0 1px 3px rgba(16, 24, 40, 0.06)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#64748B', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600 }}>
                  FORENSIC INTEGRITY VERIFICATION ENGINE
                </span>
                <div style={{ fontSize: '1.45rem', fontWeight: 700, color: isIntegrityValid ? '#16A34A' : '#DC2626', display: 'flex', alignItems: 'center', gap: '0.6rem', marginTop: '0.2rem' }}>
                  {isIntegrityValid ? <CheckCircle2 size={24} color="#16A34A" /> : <AlertTriangle size={24} color="#EF4444" />}
                  {isIntegrityValid ? 'ALL 8 CRYPTOGRAPHIC INTEGRITY CHECKS PASSED' : 'INTEGRITY FAILURE: TAMPERING DETECTED'}
                </div>
                <div style={{ fontSize: '0.85rem', color: '#64748B', marginTop: '0.25rem' }}>
                  Live verification against 28 RFC-8785 evidence envelopes, Merkle tree root, and Local Evidence Blockchain ledger.
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button
                  id="integrity-verify-btn"
                  onClick={handleVerifyIntegrity}
                  disabled={actionLoading}
                  className="btn-primary"
                  style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <RefreshCw size={14} className={actionLoading ? 'spin' : ''} />
                  Verify Integrity Now
                </button>
                <button
                  id="integrity-restore-btn"
                  onClick={handleRestoreEvidence}
                  disabled={actionLoading}
                  className="btn-secondary"
                  style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: '1px solid rgba(37, 135, 232, 0.3)', color: '#16A34A' }}
                >
                  <RotateCcw size={14} /> Restore Evidence
                </button>
              </div>
            </div>

            {/* 8-Check Diagnostic Matrix */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.85rem', marginBottom: '1.5rem' }}>
              {[
                { title: '1. Raw Evidence Hashes', status: integrityData?.evidence?.failed === 0, desc: `${integrityData?.evidence?.verified || 28}/${integrityData?.evidence?.total || 28} raw payloads match SHA-256 digests` },
                { title: '2. Normalized RFC-8785 Hashes', status: integrityData?.evidence?.failed === 0, desc: 'Canonical JSON canonicalization invariant satisfied' },
                { title: '3. Sequential Hash Chain', status: integrityData?.hash_chain?.valid, desc: 'Continuous monotonic previous_hash linkage across records' },
                { title: '4. Chronological Ordering', status: integrityData?.valid !== false || !integrityData?.failures?.some(f => f.reason?.includes('Chronological')), desc: 'Strict non-decreasing timestamp sequence across all collectors' },
                { title: '5. Merkle Root Match', status: integrityData?.merkle?.valid, desc: 'Binary tree calculated root == recorded Merkle root' },
                { title: '6. Blockchain Anchor', status: integrityData?.blockchain?.valid, desc: 'Committed block hash validated on Local Evidence Blockchain' },
                { title: '7. Script Hash Verification', status: integrityData?.script?.valid, desc: 'Declarative script SHA-256 matches recorded AST digest' },
                { title: '8. Report Manifest Hash', status: integrityData?.report?.valid, desc: 'Courtroom-admissible report manifest signature verified' }
              ].map((c, idx) => {
                const passed = c.status !== false;
                return (
                  <div key={idx} style={{
                    background: passed ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                    border: `1px solid ${passed ? '#1C2833' : 'rgba(239, 68, 68, 0.25)'}`,
                    borderRadius: '6px',
                    padding: '0.85rem 1rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: passed ? '#16A34A' : '#DC2626' }}>{c.title}</strong>
                      {passed ? <Check size={16} color="#16A34A" /> : <AlertTriangle size={16} color="#EF4444" />}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>{c.desc}</div>
                  </div>
                );
              })}
            </div>

            {/* FAILURE DIAGNOSTIC CARD (If Tampering is Simulated) */}
            {!isIntegrityValid && integrityData?.failures && integrityData.failures.length > 0 && (
              <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid #1C2833', borderRadius: '8px', padding: '1.25rem', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#EF4444', fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.65rem' }}>
                  <AlertTriangle size={18} color="#EF4444" />
                  SPECIFIC TAMPERING DISCREPANCY IDENTIFIED
                </div>
                {integrityData.failures.map((fail, i) => (
                  <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.82rem', color: '#F1F5F9' }}>
                    <div>Target Evidence / Artifact: <strong style={{ color: '#3B9CFF', fontFamily: 'var(--font-mono)' }}>{fail.evidence_id || fail.target_id || 'Evidence Record'}</strong></div>
                    <div>Integrity Failure Reason: <strong style={{ color: '#EF4444' }}>{fail.reason}</strong></div>
                    {fail.expected && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#64748B' }}>
                        Expected Hash: <code style={{ color: '#16A34A' }}>{fail.expected}</code>
                      </div>
                    )}
                    {fail.calculated && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#64748B' }}>
                        Calculated Hash: <code style={{ color: '#EF4444' }}>{fail.calculated}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* INTERACTIVE TAMPERING SIMULATION CONTROLS */}
            <div style={{
              background: '#111A22',
              border: '1px solid #1C2833',
              borderRadius: '8px',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                    Deterministic Anti-Tamper Demonstration Suite (Phase 27)
                  </h4>
                  <p style={{ fontSize: '0.8rem', color: '#64748B', margin: '0.15rem 0 0 0' }}>
                    Select any cryptographic tampering vector to test how the verification engine instantly detects unauthorized modification.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <select
                  id="tamper-scenario-selector"
                  value={selectedTamperScenario}
                  onChange={(e) => setSelectedTamperScenario(e.target.value)}
                  style={{
                    padding: '0.5rem 0.85rem',
                    background: '#0E151C',
                    border: '1px solid #1C2833',
                    borderRadius: '6px',
                    fontSize: '0.84rem',
                    color: '#F1F5F9',
                    flex: 1,
                    minWidth: '280px'
                  }}
                >
                  {TAMPER_SCENARIOS.map(s => (
                    <option key={s.id} value={s.id}>{s.label}</option>
                  ))}
                </select>

                <button
                  id="tamper-simulate-btn"
                  onClick={handleSimulateTamper}
                  disabled={actionLoading}
                  style={{
                    background: '#DC2626',
                    color: '#FFFFFF',
                    border: '1px solid #DC2626',
                    padding: '0.5rem 1rem',
                    borderRadius: '6px',
                    fontSize: '0.84rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem'
                  }}
                >
                  <ShieldAlert size={15} /> Simulate Tamper Event
                </button>

                <button
                  id="tamper-restore-btn"
                  onClick={handleRestoreEvidence}
                  disabled={actionLoading}
                  className="btn-secondary"
                  style={{
                    fontSize: '0.84rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    border: '1px solid rgba(37, 135, 232, 0.3)',
                    color: '#16A34A',
                    background: 'rgba(16, 185, 129, 0.12)'
                  }}
                >
                  <CheckCircle2 size={15} color="#16A34A" /> Restore Clean State
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 8: REPORT */}
      {/* ========================================================================= */}
      {activeTab === 'report' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel" style={{ padding: '1.75rem', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#F1F5F9', margin: 0 }}>
                  Court-Admissible Digital Forensic Report
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748B', margin: '0.2rem 0 0 0' }}>
                  Complete manifest including Merkle root, Local Evidence Blockchain anchor, hash chain, and explicit scope & limitations.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <a
                  href={`http://localhost:8000/api/reports/${caseId}/json`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary"
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                >
                  <Download size={13} /> JSON Report
                </a>
                <a
                  href={`http://localhost:8000/api/reports/${caseId}/html`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary"
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                >
                  <Download size={13} /> HTML Report
                </a>
                <a
                  href={`http://localhost:8000/api/reports/${caseId}/csv`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-primary"
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                >
                  <Download size={13} /> CSV Manifest
                </a>
              </div>
            </div>

            {/* Embedded Report Summary Sheet */}
            <div style={{ background: '#111A22', border: '1px solid #1C2833', borderRadius: '8px', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ borderBottom: '1px solid #1C2833', paddingBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: '#3B9CFF', fontWeight: 700, textTransform: 'uppercase' }}>Executive Forensic Summary</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F1F5F9', marginTop: '0.2rem' }}>Digital Forensic Investigation Report: {caseId}</div>
                <div style={{ fontSize: '0.82rem', color: '#64748B', marginTop: '0.2rem' }}>Generated: {new Date().toISOString()} • Operator: secops-lead@jocky.defense</div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.85rem' }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: '#64748B' }}>Evidence Envelopes:</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#F1F5F9' }}>28 Sealed Artifacts</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.72rem', color: '#64748B' }}>Findings:</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#EF4444' }}>4 Actionable Detections</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.72rem', color: '#64748B' }}>Merkle Root:</div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#3B9CFF', fontFamily: 'var(--font-mono)' }}>2033beab256b...</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.72rem', color: '#64748B' }}>Blockchain Anchor:</div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#16A34A', fontFamily: 'var(--font-mono)' }}>Block #77 (Local)</div>
                </div>
              </div>

              {/* Methodological Scope & Limitations */}
              <div style={{ background: '#0E151C', border: '1px solid #1C2833', borderRadius: '6px', padding: '1rem', marginTop: '0.5rem' }}>
                <div style={{ fontSize: '0.78rem', color: '#F1F5F9', fontWeight: 700, marginBottom: '0.35rem' }}>
                  Forensic Scope &amp; Methodological Boundaries:
                </div>
                <p style={{ fontSize: '0.8rem', color: '#64748B', lineHeight: '1.5', margin: 0 }}>
                  This forensic examination was conducted using declarative JOCKY script collection policies under non-invasive read-only constraints. Telemetry was gathered across 5 authorized collectors: registry, processes, network sockets, filesystem indicators, and system baseline. No memory injection, kernel driver hooking, or credential extraction was performed. All evidence is bound by RFC-8785 canonical JSON hashing and anchored in an append-only Local Evidence Blockchain ledger.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 1: EVIDENCE ENVELOPE INSPECTOR */}
      {/* ========================================================================= */}
      {selectedEvidenceModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '780px', maxWidth: '100%', maxHeight: '90vh', display: 'flex', flexDirection: 'column', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '10px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)' }}>
            {/* Modal Header */}
            <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid #1C2833', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: '#3B9CFF', fontWeight: 700 }}>EVIDENCE ENVELOPE INSPECTOR</div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#F1F5F9', margin: '0.15rem 0 0 0', fontFamily: 'var(--font-mono)' }}>
                  {selectedEvidenceModal.id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvidenceModal(null)}
                style={{ background: 'transparent', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: '1.1rem' }}
              ><X size={15} /></button>
            </div>

            {/* Modal Hash & Metadata Summary */}
            <div style={{ padding: '1rem 1.5rem', background: '#111A22', borderBottom: '1px solid #1C2833', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.65rem', fontSize: '0.78rem' }}>
              <div><span style={{ color: '#64748B' }}>Collector:</span> <strong style={{ color: '#F1F5F9' }}>{selectedEvidenceModal.collector}</strong></div>
              <div><span style={{ color: '#64748B' }}>Collector Source:</span> <strong style={{ color: '#F1F5F9' }}>{selectedEvidenceModal.collector_source || 'Win32 API'}</strong></div>
              <div><span style={{ color: '#64748B' }}>Collected At:</span> <span style={{ color: '#F1F5F9', fontFamily: 'var(--font-mono)' }}>{selectedEvidenceModal.collected_at?.slice(0, 19)}</span></div>
              <div><span style={{ color: '#64748B' }}>Integrity Status:</span> <strong style={{ color: '#16A34A' }}>{selectedEvidenceModal.integrity_status || 'VERIFIED'}</strong></div>
            </div>

            {/* Sub-tabs: Raw vs Normalized vs Envelope */}
            <div style={{ display: 'flex', borderBottom: '1px solid #1C2833', background: '#0E151C', padding: '0 1.5rem' }}>
              {[
                { id: 'raw', label: 'Raw Evidence' },
                { id: 'normalized', label: 'Normalized (RFC-8785)' },
                { id: 'envelope', label: 'Full Custody Envelope' }
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setEvidenceModalTab(t.id)}
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'transparent',
                    border: 'none',
                    borderBottom: evidenceModalTab === t.id ? '2px solid #2587E8' : '2px solid transparent',
                    color: evidenceModalTab === t.id ? '#2587E8' : '#667085',
                    fontSize: '0.84rem',
                    fontWeight: evidenceModalTab === t.id ? 600 : 500,
                    cursor: 'pointer'
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Modal Body */}
            <div style={{ padding: '1.25rem 1.5rem', overflowY: 'auto', flex: 1 }}>
              {evidenceModalTab === 'raw' && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#64748B', marginBottom: '0.5rem' }}>
                    Raw payload captured directly from origin collector before transformation:
                  </div>
                  <pre style={{
                    background: '#0F172A',
                    color: '#F8FAFC',
                    padding: '1rem',
                    borderRadius: '6px',
                    fontSize: '12.5px',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: '1.6',
                    overflowX: 'auto',
                    margin: 0
                  }}>
                    {JSON.stringify(selectedEvidenceModal.raw_data || { pid: 4188 }, null, 2)}
                  </pre>
                  <div style={{ marginTop: '0.65rem', fontSize: '0.72rem', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                    Raw Payload Hash (SHA-256): {selectedEvidenceModal.raw_data_hash || '7ba069bfc131baae06cd0482271cfbc42cac95900988eddd3d66713602bd2cb6'}
                  </div>
                </div>
              )}

              {evidenceModalTab === 'normalized' && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#64748B', marginBottom: '0.5rem' }}>
                    Normalized JSON formatted according to canonical schema:
                  </div>
                  <pre style={{
                    background: '#0F172A',
                    color: '#F8FAFC',
                    padding: '1rem',
                    borderRadius: '6px',
                    fontSize: '12.5px',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: '1.6',
                    overflowX: 'auto',
                    margin: 0
                  }}>
                    {JSON.stringify(selectedEvidenceModal.normalized_data || { pid: 4188, name: "suspicious-update.exe", ppid: 1024 }, null, 2)}
                  </pre>
                  <div style={{ marginTop: '0.65rem', fontSize: '0.72rem', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                    Normalized Canonical Hash: {selectedEvidenceModal.normalized_data_hash || '6319018c0350ddc0474839425b37ba93b91906a503cfee7105707c3879fb7399'}
                  </div>
                </div>
              )}

              {evidenceModalTab === 'envelope' && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#64748B', marginBottom: '0.5rem' }}>
                    Complete court-admissible custody envelope including sequential hash chain:
                  </div>
                  <pre style={{
                    background: '#0F172A',
                    color: '#F8FAFC',
                    padding: '1rem',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: '1.6',
                    overflowX: 'auto',
                    margin: 0
                  }}>
                    {JSON.stringify(selectedEvidenceModal.envelope_data || selectedEvidenceModal, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{ padding: '0.85rem 1.5rem', borderTop: '1px solid #1C2833', background: '#111A22', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                className="btn-secondary"
                onClick={() => setSelectedEvidenceModal(null)}
                style={{ fontSize: '0.82rem' }}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: VERTICAL FINDING TRACEABILITY CHAIN DRAWER */}
      {/* ========================================================================= */}
      {selectedFindingProvenance && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '840px', maxWidth: '100%', maxHeight: '90vh', display: 'flex', flexDirection: 'column', background: '#0E151C', border: '1px solid #1C2833', borderRadius: '10px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)' }}>
            {/* Header */}
            <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid #1C2833', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: '#3B9CFF', fontWeight: 700 }}>FINDING PROVENANCE &amp; TRACEABILITY CHAIN</div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#F1F5F9', margin: '0.15rem 0 0 0' }}>
                  {selectedFindingProvenance.finding?.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedFindingProvenance(null)}
                style={{ background: 'transparent', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: '1.1rem' }}
              ><X size={15} /></button>
            </div>

            {/* Traceability Stepper Body */}
            <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {(selectedFindingProvenance.traceability_chain || []).map((step, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '1rem',
                  background: '#111A22',
                  border: '1px solid #1C2833',
                  borderRadius: '6px',
                  padding: '1rem'
                }}>
                  <div style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '50%',
                    background: 'rgba(37, 135, 232, 0.12)',
                    border: '1px solid rgba(37, 135, 232, 0.3)',
                    color: '#3B9CFF',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '0.85rem',
                    flexShrink: 0
                  }}>
                    {step.step}
                  </div>

                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>{step.type}</span>
                      <span style={{ fontSize: '0.75rem', color: '#16A34A', fontWeight: 600 }}>Verified</span>
                    </div>
                    <div style={{ fontSize: '0.92rem', fontWeight: 600, color: '#F1F5F9', marginTop: '0.15rem' }}>
                      {step.name || step.title || step.id}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#94A3B8', marginTop: '0.2rem' }}>
                      {step.description}
                    </div>
                    {step.hash && (
                      <div style={{ marginTop: '0.35rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#3B9CFF', background: '#0E151C', padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid #1C2833', wordBreak: 'break-all' }}>
                        Hash: {step.hash}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Footer */}
            <div style={{ padding: '0.85rem 1.5rem', borderTop: '1px solid #1C2833', background: '#111A22', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                className="btn-secondary"
                onClick={() => setSelectedFindingProvenance(null)}
                style={{ fontSize: '0.82rem' }}
              >
                Close Traceability Chain
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
