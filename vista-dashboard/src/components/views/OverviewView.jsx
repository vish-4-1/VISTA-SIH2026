import { useCallback, useEffect, useState } from 'react';
import {
  Shield,
  Activity,
  BrainCircuit,
  Lock,
  Radio,
  Network,
  Server,
} from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import {
  fetchAuditSummary,
  fetchEbpfEvents,
  fetchEbpfStatus,
  fetchSocStatus,
} from '../../utils/apiClient';

const EMPTY_VALUE = '—';
const EVENT_POLL_INTERVAL_MS = 2500;

function displayValue(value) {
  return value === null || value === undefined || value === '' ? EMPTY_VALUE : String(value);
}

function formatTimestamp(value) {
  if (!value) return EMPTY_VALUE;
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? String(value) : timestamp.toLocaleTimeString();
}

function EventTable({ events, loading, error }) {
  if (events.length === 0) {
    return (
      <div className="dashboard-empty" role="status">
        {error
          ? `Unable to load collector events: ${error}`
          : loading
            ? 'Loading kernel ring buffer telemetry…'
            : 'No IPsec transform events observed in current window. Generate traffic between PC1 and PC2.'}
      </div>
    );
  }

  const getEventBadgeClass = (type) => {
    switch (type) {
      case 'XFRM_IN':
        return 'badge-xfrm-in';
      case 'XFRM_OUT':
        return 'badge-xfrm-out';
      case 'SOCK_SEND':
        return 'badge-sock-send';
      default:
        return 'badge-default';
    }
  };

  return (
    <div className="dashboard-table-wrap">
      <table className="dashboard-table">
        <thead>
          <tr>
            <th scope="col">Event Type</th>
            <th scope="col">Observed Time</th>
            <th scope="col">Process</th>
            <th scope="col">PID</th>
            <th scope="col">Bytes</th>
            <th scope="col">Packets</th>
          </tr>
        </thead>
        <tbody>
          {events.slice(0, 8).map((event, index) => (
            <tr key={`${event.timestamp || 'event'}-${event.pid ?? 'pid'}-${index}`}>
              <td>
                <span className={`event-badge ${getEventBadgeClass(event.eventType)}`}>
                  {displayValue(event.eventType)}
                </span>
              </td>
              <td className="monospace">{formatTimestamp(event.timestamp)}</td>
              <td>
                <span className="process-pill">{displayValue(event.process_name)}</span>
              </td>
              <td className="monospace text-muted">{displayValue(event.pid)}</td>
              <td className="monospace font-semibold">{displayValue(event.bytes)}</td>
              <td className="monospace font-semibold">{displayValue(event.packets)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function OverviewView({ refreshKey = 0 }) {
  const { analysisResult, file, analysisId, clearAnalysis } = usePcapAnalysis();
  const [events, setEvents] = useState([]);
  const [collectorStatus, setCollectorStatus] = useState(null);
  const [socStatus, setSocStatus] = useState(null);
  const [auditSummary, setAuditSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusError, setStatusError] = useState('');
  const [summaryError, setSummaryError] = useState('');

  const loadEvents = useCallback(async () => {
    const [eventsResult, statusResult] = await Promise.allSettled([
      fetchEbpfEvents(50),
      fetchEbpfStatus(),
    ]);
    if (eventsResult.status === 'fulfilled') {
      setEvents(Array.isArray(eventsResult.value?.events) ? eventsResult.value.events : []);
      setError('');
    } else {
      setError(eventsResult.reason instanceof Error ? eventsResult.reason.message : String(eventsResult.reason));
    }
    if (statusResult.status === 'fulfilled') {
      setCollectorStatus(statusResult.value);
      setStatusError('');
    } else {
      setStatusError(statusResult.reason instanceof Error ? statusResult.reason.message : String(statusResult.reason));
    }
    setLoading(false);
  }, []);

  const loadSummaries = useCallback(async () => {
    const [socResult, auditResult] = await Promise.allSettled([
      fetchSocStatus(),
      fetchAuditSummary(),
    ]);
    const failures = [];
    if (socResult.status === 'fulfilled') {
      setSocStatus(socResult.value);
    } else {
      failures.push(socResult.reason instanceof Error ? socResult.reason.message : String(socResult.reason));
    }
    if (auditResult.status === 'fulfilled') {
      setAuditSummary(auditResult.value);
    } else {
      failures.push(auditResult.reason instanceof Error ? auditResult.reason.message : String(auditResult.reason));
    }
    setSummaryError(failures.join(' '));
  }, []);

  useEffect(() => {
    const initialPoll = window.setTimeout(() => {
      void loadEvents();
    }, 0);
    const interval = window.setInterval(loadEvents, EVENT_POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initialPoll);
      window.clearInterval(interval);
    };
  }, [loadEvents, refreshKey]);

  useEffect(() => {
    const initialSummaryLoad = window.setTimeout(() => {
      void loadSummaries();
    }, 0);
    return () => window.clearTimeout(initialSummaryLoad);
  }, [loadSummaries, refreshKey]);

  const observedXfrm = events.some(
    (event) => event.eventType === 'XFRM_IN' || event.eventType === 'XFRM_OUT',
  );
  const isCollectorConnected = collectorStatus?.status === 'RUNNING' && collectorStatus?.mode === 'NATIVE_KERNEL_EBPF';

  // Strict separation of Live Telemetry vs PCAP metrics
  const totalFlows = analysisResult?.flows?.length ?? (events.length > 0 ? events.length : socStatus?.totalFlows ?? 0);
  const totalPackets = analysisResult?.totalPackets ?? analysisResult?.summary?.totalPackets ?? (events.reduce((acc, e) => acc + (Number(e.packets) || 0), 0) || socStatus?.rawPacketsCount || 0);
  const attackCount = analysisResult?.summary?.attackFlows ?? (analysisResult?.flows?.filter((f) => f.isAttack === 1).length) ?? (socStatus?.attackFlows ?? 0);
  const benignCount = analysisResult?.summary?.benignFlows ?? (analysisResult?.flows?.filter((f) => f.isAttack === 0).length) ?? (socStatus?.benignFlows ?? 0);
  const primaryFlow = analysisResult?.flows?.[0];
  const observedProposal = analysisResult?.ikeNegotiations?.[0]?.proposals
    || analysisResult?.predictions?.encryption?.value;

  const currentAnalysisId = analysisId || analysisResult?.analysisId;

  return (
    <div className="dashboard-content">
      {/* Active Analysis Mode Provenance Banner */}
      <section className="dashboard-section session-provenance-banner">
        <div className="provenance-banner-content">
          <div className="provenance-info">
            <span className={`provenance-mode-badge ${analysisResult ? 'is-pcap' : 'is-live'}`}>
              {analysisResult ? 'Mode B · Uploaded PCAP Analysis' : 'Mode A · Live Testbed Monitor'}
            </span>
            <div className="provenance-title-wrap">
              <h3 className="provenance-title">
                {analysisResult
                  ? `Active Analysis Session: ${file?.name || 'Uploaded Capture'}`
                  : 'Active Environment: PC1 ⇄ IPsec ESP Tunnel ⇄ PC2'}
              </h3>
              <span className="provenance-meta">
                {analysisResult
                  ? `Session ID: ${currentAnalysisId || 'ANL-ACTIVE'} · Flows: ${analysisResult.flows?.length || 0} extracted`
                  : 'Subnet: 172.20.0.0/24 · strongSwan 5.9.x · Linux XFRM'}
              </span>
            </div>
          </div>
          {analysisResult && (
            <button
              type="button"
              className="soc-btn"
              onClick={clearAnalysis}
              title="Return to live testbed telemetry"
            >
              Clear PCAP Session
            </button>
          )}
        </div>
      </section>

      {summaryError && <div className="dashboard-empty" role="alert">{summaryError}</div>}

      {/* Top Technical Telemetry KPI Cards Banner */}
      <section className="overview-kpi-grid" aria-label="System status metrics">
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Traffic Telemetry</span>
            <div className="kpi-icon-wrap sage">
              <Activity size={16} />
            </div>
          </div>
          <div className="kpi-body">
            <div className="kpi-value">{totalPackets ? Number(totalPackets).toLocaleString() : '—'}</div>
            <div className="kpi-sub">
              {analysisResult
                ? `${totalFlows} flows extracted from ${file?.name || 'PCAP'}`
                : `${events.length} kernel XFRM events in buffer`}
            </div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Linux eBPF Engine</span>
            <div className="kpi-icon-wrap sage">
              <Shield size={16} />
            </div>
          </div>
          <div className="kpi-body">
            <div className="kpi-value">
              {statusError ? 'Unavailable' : isCollectorConnected ? 'Active' : collectorStatus?.mode || 'Offline'}
            </div>
            <div className="kpi-sub">
              {observedXfrm ? 'XFRM transform events observed' : 'Monitoring Linux kernel ring buffer'}
            </div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">AI Dual-ML State</span>
            <div className="kpi-icon-wrap lilac">
              <BrainCircuit size={16} />
            </div>
          </div>
          <div className="kpi-body">
            <div className="kpi-value">
              {attackCount > 0 ? `${attackCount} Attacked` : benignCount > 0 ? 'Benign' : 'Ready'}
            </div>
            <div className="kpi-sub">
              {analysisResult
                ? `${benignCount} benign, ${attackCount} attack flows classified`
                : 'XGBoost Threat + Encrypted App Profiler'}
            </div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">NIST Security Posture</span>
            <div className="kpi-icon-wrap amber">
              <Lock size={16} />
            </div>
          </div>
          <div className="kpi-body">
            <div className="kpi-value">
              {auditSummary?.overallScore != null ? `${auditSummary.overallScore} / 100` : '—'}
            </div>
            <div className="kpi-sub">
              {auditSummary?.compliancePercentage != null
                ? `${auditSummary.compliancePercentage}% NIST SP 800-77 compliant`
                : (auditSummary?.source || 'No operational audit source configured')}
            </div>
          </div>
        </div>
      </section>

      {/* End-to-End Tunnel Architecture Diagram */}
      <section className="dashboard-section topology-visual-card" aria-labelledby="connection-title">
        <div className="section-heading">
          <div>
            <h2 id="connection-title" className="section-title-with-icon">
              <Network size={16} className="section-heading-icon text-sage" />
              IPsec End-to-End Tunnel Architecture
            </h2>
            <p>Authoritative PC1 ⇄ PC2 tunnel endpoint state and observed cryptographic transform headers.</p>
          </div>
          <span className={`tunnel-status-pill ${observedXfrm ? 'is-active' : ''}`}>
            <span className="pill-dot-core" />
            {observedXfrm ? 'XFRM SA Active' : 'Idle / Listening'}
          </span>
        </div>

        <div className="tunnel-interactive-diagram" aria-label="PC1 to PC2 IPsec topology diagram">
          {/* Peer 1: PC1 */}
          <div className="diagram-node left-node">
            <div className="diagram-node-icon-box">
              <Server size={20} />
            </div>
            <div className="diagram-node-name">PC1 Initiator</div>
            <div className="diagram-node-ip">{primaryFlow?.src || '172.20.0.2'}</div>
            <div className="diagram-node-badge">{primaryFlow ? 'Observed Peer' : 'Docker Host 1'}</div>
          </div>

          {/* Central Encrypted IPsec Tunnel Channel */}
          <div className="diagram-tunnel-channel">
            <div className="tunnel-crypto-chip">
              <Lock size={13} className="crypto-lock-icon" />
              <span>
                {primaryFlow?.spi
                  ? `ESP Tunnel (SPI: ${primaryFlow.spi})`
                  : observedXfrm
                    ? 'Kernel XFRM Tunnel Active'
                    : 'Tunnel unobserved in window'}
              </span>
            </div>
            <div className="tunnel-telemetry-badge">
              {observedProposal || (observedXfrm ? 'Linux XFRM IPsec Transform' : 'Proposals unobserved in capture')}
            </div>
          </div>

          {/* Peer 2: PC2 */}
          <div className="diagram-node right-node">
            <div className="diagram-node-icon-box">
              <Server size={20} />
            </div>
            <div className="diagram-node-name">PC2 Responder</div>
            <div className="diagram-node-ip">{primaryFlow?.dst || '172.20.0.3'}</div>
            <div className="diagram-node-badge">{primaryFlow ? 'Observed Peer' : 'Docker Host 2'}</div>
          </div>
        </div>

        <div className="connection-details-grid">
          <div className="detail-box">
            <span className="detail-label">Observed Protocol</span>
            <span className="detail-val">{analysisResult?.predictions?.protocol?.value || (observedXfrm ? 'ESP / XFRM' : '—')}</span>
          </div>
          <div className="detail-box">
            <span className="detail-label">Detected IKE Negotiations</span>
            <span className="detail-val">{analysisResult?.summary?.detectedIkeNegotiations != null ? String(analysisResult.summary.detectedIkeNegotiations) : '—'}</span>
          </div>
          <div className="detail-box">
            <span className="detail-label">eBPF Monitoring Hook</span>
            <span className="detail-val">xfrm_input / xfrm_output</span>
          </div>
          <div className="detail-box">
            <span className="detail-label">Security Association</span>
            <span className="detail-val text-sage">{primaryFlow?.spi ? `SPI ${primaryFlow.spi}` : observedXfrm ? 'Active in window' : '—'}</span>
          </div>
        </div>
      </section>

      {/* Live Telemetry Stream Section */}
      <section className="dashboard-section" aria-labelledby="telemetry-title">
        <div className="section-heading">
          <div>
            <h2 id="telemetry-title" className="section-title-with-icon">
              <Radio size={16} className="section-heading-icon text-sage" />
              Live Kernel Telemetry Stream
            </h2>
            <p>Authoritative Linux eBPF ring buffer event stream capturing live IPsec transforms.</p>
          </div>
          <span className="section-meta-pill">
            {events.length} events in buffer
          </span>
        </div>
        <EventTable events={events} loading={loading} error={error} />
      </section>
    </div>
  );
}
