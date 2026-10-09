import { useEffect, useMemo, useState } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  FileCheck, 
  Download,
  Search,
  Database
} from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import { fetchAuditSessions, fetchAuditSummary } from '../../utils/apiClient';

const isPresent = (value) => value !== null && value !== undefined && value !== '';

function countMatching(records, field, isValid, predicate) {
  const values = records.map((record) => record[field]).filter(isValid);
  return {
    matching: values.filter(predicate).length,
    total: values.length,
  };
}

function displayValue(value) {
  return isPresent(value) ? String(value) : '—';
}

function hasAssessmentData(session) {
  return Boolean(session)
    && typeof session.encryption === 'string'
    && Boolean(session.encryption)
    && typeof session.auth === 'string'
    && Boolean(session.auth)
    && isPresent(session.dhGroup)
    && Number.isFinite(Number(session.dhGroup))
    && typeof session.pfs === 'boolean'
    && typeof session.antiReplay === 'boolean'
    && isPresent(session.lifetime)
    && Number.isFinite(Number(session.lifetime))
    && isPresent(session.ikeVersion)
    && Number.isFinite(Number(session.ikeVersion))
    && isPresent(session.riskScore)
    && Number.isFinite(Number(session.riskScore))
    && typeof session.compliance === 'string'
    && Boolean(session.compliance)
    && session.compliance !== 'Insufficient Data';
}

function complianceBadgeClass(compliance) {
  const normalized = String(compliance || '').trim().toLowerCase();
  if (['high risk', 'critical', 'non-compliant'].includes(normalized)) return 'critical';
  if (normalized === 'medium risk' || normalized === 'medium') return 'medium';
  if (['low risk', 'compliant', 'secure compliant'].includes(normalized)) return 'success';
  return 'low';
}

function escapeCsv(value) {
  return `"${String(value ?? '').replaceAll('"', '""')}"`;
}

export default function SecurityAssessmentView() {
  const { file, analysisResult, status: analysisStatus, error: analysisError, analysisId } = usePcapAnalysis();
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 12;
  const [audits, setAudits] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([fetchAuditSessions(2000), fetchAuditSummary()])
      .then(([recordsResult, summaryResult]) => {
        if (cancelled) return;
        if (recordsResult.status === 'fulfilled') {
          const records = Array.isArray(recordsResult.value) ? recordsResult.value : [];
          setAudits(records);
          setSelectedSession(records[0] || null);
        } else {
          setLoadError(recordsResult.reason instanceof Error ? recordsResult.reason.message : String(recordsResult.reason));
        }
        if (summaryResult.status === 'fulfilled') {
          setSummary(summaryResult.value);
        } else {
          setLoadError((previous) => [
            previous,
            summaryResult.reason instanceof Error ? summaryResult.reason.message : String(summaryResult.reason),
          ].filter(Boolean).join(' '));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const observedCounts = useMemo(() => ({
    strongCipher: countMatching(
      audits,
      'encryption',
      (value) => typeof value === 'string' && value.length > 0,
      (value) => value.toUpperCase().includes('GCM') || value.includes('256'),
    ),
    strongAuth: countMatching(
      audits,
      'auth',
      (value) => typeof value === 'string' && value.length > 0,
      (value) => value.toUpperCase().includes('AEAD')
        || (value.toUpperCase().includes('SHA')
          && !value.toUpperCase().includes('SHA1')
          && !value.toUpperCase().includes('MD5')),
    ),
    strongDh: countMatching(
      audits,
      'dhGroup',
      (value) => isPresent(value) && Number.isFinite(Number(value)),
      (value) => Number(value) >= 14,
    ),
    pfs: countMatching(audits, 'pfs', (value) => typeof value === 'boolean', (value) => value),
    antiReplay: countMatching(
      audits,
      'antiReplay',
      (value) => typeof value === 'boolean',
      (value) => value,
    ),
    lifetime: countMatching(
      audits,
      'lifetime',
      (value) => isPresent(value) && Number.isFinite(Number(value)),
      (value) => Number(value) <= 28800,
    ),
    compliant: countMatching(
      audits,
      'compliance',
      (value) => typeof value === 'string' && value.length > 0 && value !== 'Insufficient Data',
      (value) => ['secure compliant', 'compliant', 'low risk'].includes(value.trim().toLowerCase()),
    ),
  }), [audits]);

  const captureFlows = Array.isArray(analysisResult?.flows) ? analysisResult.flows : [];
  const captureSummary = analysisResult?.summary;
  const observedProtocols = [...new Set(captureFlows.map((flow) => flow.proto).filter(Boolean))];
  const ikeNegotiations = Array.isArray(analysisResult?.ikeNegotiations)
    ? analysisResult.ikeNegotiations
    : [];
  const predictions = analysisResult?.predictions || {};
  const assessment = analysisResult?.assessment || {};

  const renderProvenanceField = (label, fieldObj) => {
    if (!fieldObj || fieldObj.source === "Unavailable" || fieldObj.source === "Insufficient Data" || fieldObj.source === "Not supported by the current model") {
      return (
        <div key={label}>
          <dt>{label}</dt>
          <dd>
            {fieldObj?.source === "Not supported by the current model" ? "Not supported by the current model" : "Insufficient Data"}
            <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '2px' }}>
              Reason: {fieldObj?.source || "No operational audit data or supported ML prediction available."}
            </div>
          </dd>
        </div>
      );
    }
    return (
      <div key={label}>
        <dt>{label}</dt>
        <dd>
          <div>{fieldObj.value}</div>
          <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '2px' }}>
            Source: {fieldObj.source}
            {fieldObj.confidence && ` | Confidence: ${fieldObj.confidence}%`}
          </div>
        </dd>
      </div>
    );
  };

  const categories = [
    { name: 'Cryptography', score: summary?.strongCipherRate, count: `${observedCounts.strongCipher.matching} of ${observedCounts.strongCipher.total} observed`, color: 'var(--green)' },
    { name: 'Authentication', score: summary?.strongAuthRate, count: `${observedCounts.strongAuth.matching} of ${observedCounts.strongAuth.total} observed`, color: 'var(--green)' },
    { name: 'Key Exchange (DH)', score: summary?.strongDhRate, count: `${observedCounts.strongDh.matching} of ${observedCounts.strongDh.total} observed`, color: 'var(--amber)' },
    { name: 'PFS Secrecy', score: summary?.pfsAdoptionRate, count: `${observedCounts.pfs.matching} of ${observedCounts.pfs.total} observed`, color: 'var(--green)' },
    { name: 'Replay Protection', score: summary?.antiReplayEnforcedRate, count: `${observedCounts.antiReplay.matching} of ${observedCounts.antiReplay.total} observed`, color: 'var(--green)' },
    { name: 'Key Lifetime', score: summary?.lifetimeCompliantRate, count: `${observedCounts.lifetime.matching} of ${observedCounts.lifetime.total} observed`, color: 'var(--green)' },
    { name: 'NIST Compliance', score: summary?.compliancePercentage, count: `${observedCounts.compliant.matching} of ${observedCounts.compliant.total} observed`, color: 'var(--cyan)' },
  ];

  // Filtered audit sessions
  const filteredAudits = useMemo(() => {
    return audits.filter(a => {
      if (selectedStatus !== 'ALL') {
        if (!String(a.compliance ?? '').toLowerCase().includes(selectedStatus.toLowerCase())) return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = String(a.sessionId ?? '').toLowerCase().includes(q);
        const matchSpi = String(a.spi ?? '').toLowerCase().includes(q);
        const matchEnc = String(a.encryption ?? '').toLowerCase().includes(q);
        const matchVuln = (Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [])
          .some(v => String(v).toLowerCase().includes(q));
        if (!matchId && !matchSpi && !matchEnc && !matchVuln) return false;
      }
      return true;
    });
  }, [audits, selectedStatus, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredAudits.length / pageSize));
  const paginatedAudits = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAudits.slice(start, start + pageSize);
  }, [filteredAudits, currentPage, pageSize]);

  const selectedVulnerabilities = Array.isArray(selectedSession?.vulnerabilities)
    ? selectedSession.vulnerabilities
    : [];
  const selectedHasRequiredData = hasAssessmentData(selectedSession);

  // Export audit CSV
  const handleExportAuditCsv = () => {
    const headers = [
      "session_id", "spi", "ip_version", "ike_version", "ipsec_mode",
      "encryption_algo", "auth_algo", "dh_group", "pfs_enabled",
      "anti_replay", "key_lifetime_sec", "risk_score", "compliance_status", "vulnerabilities"
    ];
    const rows = filteredAudits.map((a) => [
      a.sessionId, a.spi, a.ipVersion, a.ikeVersion, a.mode,
      a.encryption, a.auth, a.dhGroup,
      typeof a.pfs === 'boolean' ? Number(a.pfs) : '',
      typeof a.antiReplay === 'boolean' ? Number(a.antiReplay) : '',
      a.lifetime, a.riskScore, a.compliance,
      Array.isArray(a.vulnerabilities) ? a.vulnerabilities.join(' | ') : '',
    ].map(escapeCsv).join(','));

    const csvContent = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `vista_security_audit_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{
      padding: '24px 32px 48px 32px',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px',
      maxWidth: '1680px',
      margin: '0 auto',
      width: '100%'
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: '800', color: '#fff', letterSpacing: '-0.3px' }}>
              Security Posture & Compliance Assessment
            </h1>
            <span className="soc-badge success" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Database size={11} />
              <span>{loading ? 'LOADING AUDIT DATA' : summary?.assessedSessions
                ? `${summary.assessedSessions.toLocaleString()} ASSESSED SESSIONS`
                : 'NO OPERATIONAL AUDIT DATA'}</span>
            </span>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Source: {summary?.source || '/api/audit/sessions and /api/audit/summary'} · NIST SP 800-77 Rev. 1
          </p>
        </div>

      </div>

      {loadError && <div className="dashboard-empty" role="alert">Unable to load audit data: {loadError}</div>}
      {!loading && !loadError && audits.length === 0 && (
        <div className="dashboard-empty" role="status">
          No operational audit records are available. Generated scenario audit data is excluded from current security posture.
        </div>
      )}

      {file && (
        <section className="soc-card" style={{ padding: '20px' }}>
          <div style={{ marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck size={18} className="text-sage" />
              <h2 style={{ margin: 0, fontSize: '16px', color: 'var(--text-primary)' }}>Uploaded Capture Assessment</h2>
            </div>
            <p style={{ margin: '6px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              Source: {file.name} {analysisId ? `(Session: ${analysisId})` : ''} · backend PCAP analysis
            </p>
          </div>
          {analysisStatus === 'analyzing' ? (
            <div className="dashboard-empty" role="status">Analyzing {file.name}…</div>
          ) : analysisStatus === 'error' ? (
            <div className="dashboard-empty" role="alert">Unable to assess {file.name}: {analysisError || 'PCAP analysis failed.'}</div>
          ) : analysisResult ? (
            <>
              <dl className="connection-details">
                <div><dt>Packets observed</dt><dd>{analysisResult.totalPackets ?? captureSummary?.totalPackets ?? '—'}</dd></div>
                <div><dt>Flows extracted</dt><dd>{captureSummary?.totalFlows ?? captureFlows.length}</dd></div>
                <div><dt>Bytes observed</dt><dd>{analysisResult.totalBytes ?? captureSummary?.totalBytes ?? '—'}</dd></div>
                <div><dt>Observed protocols</dt><dd>{observedProtocols.length ? observedProtocols.join(', ') : '—'}</dd></div>
                <div><dt>IKE negotiations detected</dt><dd>{captureSummary?.detectedIkeNegotiations ?? ikeNegotiations.length}</dd></div>
                <div><dt>IKE versions observed</dt><dd>
                  {[...new Set(ikeNegotiations.map((negotiation) => negotiation.ikeVersion).filter(Boolean))].join(', ') || '—'}
                </dd></div>
              </dl>
              <div style={{ marginTop: '14px' }}>
                <p style={{ margin: '0 0 8px', fontSize: '12px', fontWeight: 650, color: 'var(--text-primary)' }}>
                  Cryptographic posture fields
                </p>
                <dl className="connection-details">
                  {renderProvenanceField("Encryption", predictions.encryption)}
                  {renderProvenanceField("Integrity / authentication", predictions.auth)}
                  {renderProvenanceField("DH group", predictions.dhGroup)}
                  {renderProvenanceField("PFS", predictions.pfs)}
                  {renderProvenanceField("Anti-replay", predictions.antiReplay)}
                  {renderProvenanceField("Key / SA lifetime", predictions.lifetime)}
                  <div>
                    <dt>Risk score / compliance</dt>
                    <dd>{assessment.compliance || "Insufficient Data"}</dd>
                  </div>
                </dl>
                <p style={{ margin: '8px 0 0', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  The uploaded PCAP exposes packet/flow metadata and IKE headers, not negotiated cipher, PFS, anti-replay, or SA lifetime values. No security score or compliance result is inferred from traffic classification.
                </p>
              </div>
            </>
          ) : (
            <div className="dashboard-empty" role="status">No completed PCAP analysis is available for this capture.</div>
          )}
        </section>
      )}

      {/* Assessment categories are calculated only from operational audit records. */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
        {categories.map((cat, idx) => (
          <div key={idx} className="soc-card" style={{ padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '12px', fontWeight: '700', color: '#fff' }}>{cat.name}</span>
              <span className={`soc-badge ${cat.score == null ? 'low' : cat.score < 80 ? 'critical' : cat.score < 90 ? 'medium' : 'success'}`} style={{ fontSize: '10px' }}>
                {cat.score == null ? 'Unavailable' : 'Evaluated'}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
              <span style={{ fontSize: '22px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: cat.color }}>
                {cat.score == null ? '—' : `${cat.score}%`}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                {audits.length ? cat.count : 'Insufficient Data'}
              </span>
            </div>
            <div style={{ height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ width: `${cat.score ?? 0}%`, height: '100%', background: cat.color, borderRadius: '2px' }} />
            </div>
          </div>
        ))}
      </div>

      {/* Selected Session Deep-Dive Inspector */}
      {selectedSession && (
        <div className="soc-card" style={{ padding: '20px', border: '1px solid var(--cyan)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck size={18} color="var(--cyan)" />
              <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                AUDIT DETAIL: {displayValue(selectedSession.sessionId)} (SPI {displayValue(selectedSession.spi)})
              </span>
              <span className={`soc-badge ${selectedHasRequiredData ? complianceBadgeClass(selectedSession.compliance) : 'low'}`}>
                {selectedHasRequiredData ? selectedSession.compliance : 'Insufficient Data'} (Risk: {selectedHasRequiredData ? selectedSession.riskScore : '—'}/100)
              </span>
            </div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              Mode: {displayValue(selectedSession.mode)} | IKE version: {displayValue(selectedSession.ikeVersion)}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '16px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
            <div style={{ background: 'rgba(6,9,15,0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>CIPHER ALGORITHM</div>
              <div style={{ color: '#fff', fontWeight: '600', marginTop: '2px' }}>{displayValue(selectedSession.encryption)}</div>
            </div>
            <div style={{ background: 'rgba(6,9,15,0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>INTEGRITY / AUTH</div>
              <div style={{ color: '#fff', fontWeight: '600', marginTop: '2px' }}>{displayValue(selectedSession.auth)}</div>
            </div>
            <div style={{ background: 'rgba(6,9,15,0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>DIFFIE-HELLMAN GROUP</div>
              <div style={{ color: '#fff', fontWeight: '600', marginTop: '2px' }}>Group {displayValue(selectedSession.dhGroup)}</div>
            </div>
            <div style={{ background: 'rgba(6,9,15,0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>KEY LIFETIME / PFS</div>
              <div style={{ color: '#fff', fontWeight: '600', marginTop: '2px' }}>
                {isPresent(selectedSession.lifetime) ? `${selectedSession.lifetime}s` : 'Lifetime —'}
                {' / PFS: '}
                {typeof selectedSession.pfs === 'boolean' ? (selectedSession.pfs ? 'ENABLED' : 'DISABLED') : '—'}
              </div>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>
              DETECTED CRYPTOGRAPHIC VULNERABILITIES:
            </div>
            {!selectedHasRequiredData ? (
              <span className="soc-badge low" style={{ fontSize: '11px' }}>
                Insufficient Data to assess vulnerability status.
              </span>
            ) : selectedVulnerabilities.length === 0 ? (
              <span className="soc-badge success" style={{ fontSize: '11px' }}>
                <CheckCircle2 size={12} />
                <span>No vulnerabilities are recorded for this audit session.</span>
              </span>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {selectedVulnerabilities.map((v, i) => (
                  <span key={i} className="soc-badge" style={{ fontSize: '11px' }}>
                    <AlertTriangle size={12} />
                    <span>{v.replace(/_/g, ' ')}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Filter & Session Table */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div className="soc-card-title">
              <FileCheck size={16} color="var(--cyan)" />
              <span>Audited IPsec Sessions ({audits.length.toLocaleString()} records)</span>
            </div>
            <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
              Click a backend audit record to inspect cryptographic details and compliance findings · Overall score {summary?.overallScore ?? '—'}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Search size={14} color="var(--text-dim)" />
              <input 
                type="text"
                placeholder="Search Session, SPI, Cipher..." 
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
                style={{ 
                  background: 'var(--bg-input)', 
                  border: '1px solid var(--border-subtle)', 
                  borderRadius: '4px', 
                  color: '#fff', 
                  padding: '4px 8px', 
                  fontSize: '11px', 
                  fontFamily: 'var(--font-mono)',
                  width: '180px'
                }}
              />
            </div>

            <select 
              value={selectedStatus} 
              onChange={(e) => { setSelectedStatus(e.target.value); setCurrentPage(1); }}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: '#fff', padding: '4px 8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
            >
              <option value="ALL">ALL COMPLIANCE LEVELS</option>
              <option value="Compliant">Secure Compliant Only</option>
              <option value="Medium">Medium Risk Only</option>
              <option value="High">High Risk Only</option>
              <option value="Critical">Critical Risk Only</option>
            </select>

            <button className="soc-btn" style={{ fontSize: '11px' }} onClick={handleExportAuditCsv}>
              <Download size={13} />
              <span>EXPORT AUDIT (CSV)</span>
            </button>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>SPI</th>
                <th>Mode</th>
                <th>Encryption</th>
                <th>HMAC Auth</th>
                <th>DH Group</th>
                <th>PFS</th>
                <th>Replay</th>
                <th>Lifetime</th>
                <th>Risk Score</th>
                <th>Compliance Status</th>
                <th>Vulnerabilities Detected</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAudits.map((a, index) => {
                const isSelected = selectedSession?.sessionId === a.sessionId;
                const vulnerabilities = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
                const hasAssessment = hasAssessmentData(a);
                return (
                  <tr 
                    key={a.sessionId ?? index}
                    onClick={() => setSelectedSession(a)}
                    style={{ 
                      cursor: 'pointer', 
                      background: isSelected ? 'rgba(0, 240, 255, 0.08)' : 'transparent' 
                    }}
                  >
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: '600' }}>
                      {displayValue(a.sessionId)}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)', fontSize: '11px' }}>
                      {displayValue(a.spi)}
                    </td>
                    <td style={{ fontSize: '11px' }}>{displayValue(a.mode)}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{displayValue(a.encryption)}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{displayValue(a.auth)}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {isPresent(a.dhGroup) ? `Grp ${a.dhGroup}` : '—'}
                    </td>
                    <td>
                      <span className="soc-badge" style={{ fontSize: '9px' }}>
                        {typeof a.pfs === 'boolean' ? (a.pfs ? 'YES' : 'NO') : '—'}
                      </span>
                    </td>
                    <td>
                      <span className="soc-badge" style={{ fontSize: '9px' }}>
                        {typeof a.antiReplay === 'boolean' ? (a.antiReplay ? 'YES' : 'NO') : '—'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {isPresent(a.lifetime) ? `${a.lifetime}s` : '—'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: !hasAssessment ? 'var(--text-dim)' : 'var(--text-primary)' }}>
                      {hasAssessment ? a.riskScore : '—'}
                    </td>
                    <td>
                      <span className={`soc-badge ${hasAssessment ? complianceBadgeClass(a.compliance) : 'low'}`} style={{ fontSize: '10px' }}>
                        {hasAssessment ? a.compliance : 'Insufficient Data'}
                      </span>
                    </td>
                    <td style={{ fontSize: '11px', color: 'var(--text-secondary)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {!hasAssessment ? 'Insufficient Data' : vulnerabilities.length > 0 ? vulnerabilities.join(', ') : 'None recorded'}
                    </td>
                  </tr>
                );
              })}
              {!loading && paginatedAudits.length === 0 && (
                <tr>
                  <td colSpan={12} style={{ textAlign: 'center', padding: '24px' }}>
                    {loadError ? 'Audit records are unavailable.' : 'No operational audit records are available.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)'
        }}>
          <span style={{ color: 'var(--text-dim)' }}>
            Page {currentPage} of {totalPages} ({filteredAudits.length} sessions)
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button 
              className="soc-btn" 
              style={{ padding: '4px 10px', fontSize: '11px' }}
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            >
              Previous
            </button>
            <button 
              className="soc-btn" 
              style={{ padding: '4px 10px', fontSize: '11px' }}
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            >
              Next
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
