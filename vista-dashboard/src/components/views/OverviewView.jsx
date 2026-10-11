import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Shield,
  Activity,
  BrainCircuit,
  Lock,
  Radio,
  Network,
} from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import ThreeCanvas from '../ThreeCanvas';
import {
  checkBackendStatus,
  fetchAuditSummary,
  fetchEbpfEvents,
  fetchEbpfStatus,
  fetchTestbedLiveStatus,
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

function getEventId(event) {
  if (!event) return '';
  if (event.id) return String(event.id);
  if (event.timestamp_ns) return `EBPF-${event.timestamp_ns}-${event.pid || 0}`;
  return `${event.timestamp || ''}:${event.eventType || ''}:${event.pid || ''}:${event.bytes || ''}`;
}

function getFreshnessState(lastUpdated, now, error) {
  if (error) {
    return {
      label: 'Telemetry Disconnected',
      indicatorClass: 'is-offline',
      isStale: true,
      description: 'Testbed collector API is unreachable or returned an error.',
    };
  }
  if (!lastUpdated) {
    return {
      label: 'Connecting to testbed…',
      indicatorClass: 'is-offline',
      isStale: false,
      description: 'Querying live runtime status from backend.',
    };
  }
  const seconds = Math.max(0, Math.floor((now - lastUpdated) / 1000));
  if (seconds < 5) {
    return {
      label: 'Live · Verified',
      indicatorClass: 'is-online',
      isStale: false,
      description: 'Operational status confirmed via live daemon & kernel telemetry.',
    };
  }
  if (seconds < 12) {
    return {
      label: `Live · Updated ${seconds}s ago`,
      indicatorClass: 'is-online',
      isStale: false,
      description: 'Telemetry freshly verified.',
    };
  }
  return {
    label: `Stale · Last update ${seconds}s ago`,
    indicatorClass: 'is-warning',
    isStale: true,
    description: 'Telemetry update delayed. Rendering last-known confirmed state.',
  };
}

function EventTable({ events, loading, error, onSelectEvent, selectedEventId }) {
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
            <th scope="col">Direction / Target</th>
            <th scope="col">Observed Time</th>
            <th scope="col">Process</th>
            <th scope="col">PID</th>
            <th scope="col">Bytes</th>
            <th scope="col">Packets</th>
          </tr>
        </thead>
        <tbody>
          {events.slice(0, 10).map((event) => {
            const id = getEventId(event);
            const isSelected = selectedEventId === id;
            return (
              <tr
                key={id}
                className={isSelected ? 'is-selected-row' : ''}
                onClick={() => onSelectEvent?.(event)}
                style={{ cursor: 'pointer' }}
                title="Click to inspect event details in drawer"
              >
                <td>
                  <span className={`event-badge ${getEventBadgeClass(event.eventType)}`}>
                    {displayValue(event.eventType)}
                  </span>
                </td>
                <td className="monospace text-muted">
                  {event.eventType === 'XFRM_OUT'
                    ? 'Outbound ESP (host-wide; endpoint not correlated)'
                    : event.eventType === 'XFRM_IN'
                      ? 'Inbound ESP (host-wide; endpoint not correlated)'
                      : displayValue(event.fn || event.target)}
                </td>
                <td className="monospace">{formatTimestamp(event.timestamp)}</td>
                <td>
                  <span className="process-pill">{displayValue(event.process_name)}</span>
                </td>
                <td className="monospace text-muted">{displayValue(event.pid)}</td>
                <td className="monospace font-semibold">{displayValue(event.bytes)}</td>
                <td className="monospace font-semibold">{displayValue(event.packets)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function OverviewView({ refreshKey = 0 }) {
  const { analysisResult, file, analysisId, clearAnalysis } = usePcapAnalysis();
  const [events, setEvents] = useState([]);
  const [collectorStatus, setCollectorStatus] = useState(null);
  const [auditSummary, setAuditSummary] = useState(null);
  const [liveStatus, setLiveStatus] = useState(null);
  const [modelReadiness, setModelReadiness] = useState('checking');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusError, setStatusError] = useState('');
  const [summaryError, setSummaryError] = useState('');
  const [liveStatusError, setLiveStatusError] = useState('');

  const [selectedNodeId, setSelectedNodeId] = useState('tunnel');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [activity, setActivity] = useState(null);

  const [lastUpdated, setLastUpdated] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  const seenEventIdsRef = useRef(new Set());
  const isInitialLoadRef = useRef(true);
  const activitySequence = useRef(0);
  const refreshInFlight = useRef(false);
  const abortControllerRef = useRef(null);

  // Time ticker for data freshness calculations
  useEffect(() => {
    const ticker = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(ticker);
  }, []);

  const refreshTelemetry = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    const [eventsResult, statusResult, liveStatusResult] = await Promise.allSettled([
      fetchEbpfEvents(50),
      fetchEbpfStatus(),
      fetchTestbedLiveStatus(controller.signal),
    ]);

    if (eventsResult.status === 'fulfilled') {
      const nextEvents = Array.isArray(eventsResult.value?.events)
        ? [...eventsResult.value.events].sort((left, right) => {
            const leftTime = Date.parse(left.timestamp);
            const rightTime = Date.parse(right.timestamp);
            if (Number.isNaN(leftTime) || Number.isNaN(rightTime)) return 0;
            return rightTime - leftTime;
          })
        : [];
      setEvents(nextEvents);
      setError('');

      if (isInitialLoadRef.current) {
        // Seed initial events so existing buffered events do not falsely animate on initial load
        for (const ev of nextEvents) {
          seenEventIdsRef.current.add(getEventId(ev));
        }
        isInitialLoadRef.current = false;
      } else {
        // Genuine evidence-driven activity marker: only animate when a genuinely new event arrives
        const newEvents = nextEvents.filter((ev) => {
          const id = getEventId(ev);
          const isNew = !seenEventIdsRef.current.has(id);
          if (isNew) {
            seenEventIdsRef.current.add(id);
          }
          // Kernel hook events are host-wide unless the collector verifies testbed correlation.
          return isNew && ev.correlation?.scope === 'testbed' && ev.correlation?.verified === true;
        });

        if (newEvents.length > 0) {
          const newest = newEvents[0];
          activitySequence.current += 1;
          setActivity({ event: newest, sequence: activitySequence.current });
        }
      }
    } else {
      setError(eventsResult.reason instanceof Error ? eventsResult.reason.message : String(eventsResult.reason));
    }

    if (statusResult.status === 'fulfilled') {
      setCollectorStatus(statusResult.value);
      setStatusError('');
    } else {
      setStatusError(statusResult.reason instanceof Error ? statusResult.reason.message : String(statusResult.reason));
    }

    if (liveStatusResult.status === 'fulfilled') {
      setLiveStatus(liveStatusResult.value);
      setLiveStatusError('');
      setLastUpdated(Date.now());
    } else {
      const isAbort = liveStatusResult.reason?.name === 'AbortError';
      if (!isAbort) {
        setLiveStatusError(liveStatusResult.reason instanceof Error ? liveStatusResult.reason.message : String(liveStatusResult.reason));
      }
    }

    setLoading(false);
    refreshInFlight.current = false;
  }, []);

  const loadSummaries = useCallback(async () => {
    try {
      const summary = await fetchAuditSummary();
      setAuditSummary(summary);
      setSummaryError('');
    } catch (err) {
      setSummaryError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    isInitialLoadRef.current = true;
    seenEventIdsRef.current.clear();

    const initialPoll = window.setTimeout(() => {
      void refreshTelemetry();
    }, 0);
    const interval = window.setInterval(refreshTelemetry, EVENT_POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initialPoll);
      window.clearInterval(interval);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [refreshTelemetry, refreshKey]);

  useEffect(() => {
    const initialSummaryLoad = window.setTimeout(() => {
      void loadSummaries();
    }, 0);
    return () => window.clearTimeout(initialSummaryLoad);
  }, [loadSummaries, refreshKey]);

  useEffect(() => {
    let active = true;
    checkBackendStatus().then((status) => {
      if (!active) return;
      if (!status.online) {
        setModelReadiness('unavailable');
        return;
      }
      const models = Object.values(status.models || {});
      const hasEligibleModel = models.some((model) => model?.inferenceEnabled === true);
      const hasLoadedModel = models.some((model) => model?.loaded === true);
      setModelReadiness(hasEligibleModel ? 'ready' : hasLoadedModel ? 'gated' : 'unavailable');
    });
    return () => {
      active = false;
    };
  }, [refreshKey]);

  const observedXfrm = events.some(
    (event) => event.eventType === 'XFRM_IN' || event.eventType === 'XFRM_OUT',
  );
  const isCollectorConnected = collectorStatus?.status === 'RUNNING' && collectorStatus?.mode === 'NATIVE_KERNEL_EBPF';
  const freshness = getFreshnessState(lastUpdated, now, liveStatusError);

  // Authoritative operational tunnel state: comes strictly from StrongSwan / XFRM SA status
  const tunnelState = liveStatus?.tunnel?.state || (liveStatusError ? 'UNAVAILABLE' : 'CONNECTING');

  // Operational traffic metrics:
  // In PCAP mode: from parsed PCAP analysis
  // In Live mode use CHILD_SA counters only. Kernel events are host-wide and are not a tunnel counter.
  const isPcapMode = Boolean(analysisResult);
  const totalFlows = isPcapMode ? (analysisResult.flows?.length ?? 0) : null;

  const totalPackets = isPcapMode
    ? (analysisResult.totalPackets ?? analysisResult.summary?.totalPackets ?? null)
    : (liveStatus?.tunnel?.child?.packetsIn != null && liveStatus?.tunnel?.child?.packetsOut != null)
      ? (liveStatus.tunnel.child.packetsIn + liveStatus.tunnel.child.packetsOut)
      : null;

  const attackCount = isPcapMode
    ? (analysisResult.summary?.attackFlows ?? analysisResult.flows?.filter((f) => f.isAttack === 1).length ?? 0)
    : null;
  const benignCount = isPcapMode
    ? (analysisResult.summary?.benignFlows ?? analysisResult.flows?.filter((f) => f.isAttack === 0).length ?? 0)
    : null;

  const primaryFlow = analysisResult?.flows?.[0];
  const observedProposal = analysisResult?.ikeNegotiations?.[0]?.proposals
    || analysisResult?.predictions?.encryption?.value;

  const currentAnalysisId = analysisId || analysisResult?.analysisId;

  const handleSelectNode = (nodeId, eventData) => {
    setSelectedNodeId(nodeId);
    if (nodeId === 'event' && eventData) {
      setSelectedEvent(eventData);
    }
  };

  const handleSelectEvent = (event) => {
    setSelectedEvent(event);
    setSelectedNodeId('event');
    if (event?.correlation?.scope === 'testbed' && event.correlation.verified === true) {
      activitySequence.current += 1;
      setActivity({ event, sequence: activitySequence.current });
    }
  };

  return (
    <div className="dashboard-content">
      {/* Active Analysis Mode Provenance Banner */}
      <section className="dashboard-section session-provenance-banner">
        <div className="provenance-banner-content">
          <div className="provenance-info">
            <span className={`provenance-mode-badge ${isPcapMode ? 'is-pcap' : 'is-live'}`}>
              {isPcapMode ? 'Mode B · Uploaded PCAP Analysis' : 'Mode A · Live Testbed Monitor'}
            </span>
            <div className="provenance-title-wrap">
              <h3 className="provenance-title">
                {isPcapMode
                  ? `Active Analysis Session: ${file?.name || 'Uploaded Capture'}`
                  : 'Active Environment: PC1 ⇄ IPsec ESP Tunnel ⇄ PC2'}
              </h3>
              <span className="provenance-meta">
                {isPcapMode
                  ? `Session ID: ${currentAnalysisId || '—'} · Flows: ${analysisResult.flows?.length ?? '—'} extracted`
                  : (liveStatus?.endpoints?.pc1?.subnet
                      ? `Subnet: ${liveStatus.endpoints.pc1.subnet} · strongSwan 5.9.x · Linux XFRM`
                      : 'Subnet: Querying runtime configuration… · strongSwan 5.9.x · Linux XFRM')}
              </span>
            </div>
          </div>
          {isPcapMode && (
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
      {liveStatusError && (
        <div className="dashboard-empty is-warning" role="alert">
          Testbed status notice: {liveStatusError} (Showing last-known or offline state)
        </div>
      )}

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
            <div className="kpi-value">
              {liveStatusError && !isPcapMode
                ? 'Unavailable'
                : totalPackets != null
                  ? Number(totalPackets).toLocaleString()
                  : '—'}
            </div>
            <div className="kpi-sub">
              {isPcapMode
                ? `${totalFlows} flows extracted from ${file?.name || 'PCAP'}`
                : liveStatus?.tunnel?.child?.packetsIn != null
                  ? `${liveStatus.tunnel.child.packetsIn} in / ${liveStatus.tunnel.child.packetsOut} out (Linux XFRM SA)`
                  : liveStatusError
                    ? 'XFRM SA counters unavailable'
                    : 'XFRM events are host-wide and not tunnel-correlated'}
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
              {statusError
                ? 'Unavailable'
                : isCollectorConnected
                  ? 'Active (Native CO-RE)'
                  : collectorStatus?.mode || (statusError ? 'Unavailable' : 'Loading')}
            </div>
            <div className="kpi-sub">
              {isCollectorConnected
                ? `${collectorStatus.probes?.length ?? '—'} kprobes · ${collectorStatus.ringEventsSeen == null ? '—' : Number(collectorStatus.ringEventsSeen).toLocaleString()} ring events`
                  : observedXfrm
                  ? 'Host-wide transform events recorded; not attributed to this tunnel'
                  : 'Linux kernel ring buffer observer'}
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
              {isPcapMode
                ? (attackCount > 0 ? `${attackCount} Attack` : benignCount > 0 ? 'Benign' : 'Analyzed')
                : modelReadiness === 'ready'
                  ? 'Ready'
                  : modelReadiness === 'checking'
                    ? 'Checking'
                    : modelReadiness === 'gated'
                      ? 'Gated'
                      : 'Unavailable'}
            </div>
            <div className="kpi-sub">
              {isPcapMode
                ? `${benignCount ?? 0} benign, ${attackCount ?? 0} attack flows classified`
                : modelReadiness === 'ready'
                  ? 'At least one validated model is enabled for inference'
                  : modelReadiness === 'checking'
                    ? 'Checking backend model eligibility'
                    : modelReadiness === 'gated'
                      ? 'Loaded models are gated until validation requirements pass'
                      : 'Backend model eligibility is unavailable'}
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

      {/* Dynamic 3D IPsec Testbed Topology & Refined Glass Inspector */}
      <section className="dashboard-section topology-visual-card" aria-labelledby="connection-title">
        <div className="section-heading">
          <div>
            <h2 id="connection-title" className="section-title-with-icon">
              <Network size={16} className="section-heading-icon text-sage" />
              IPsec End-to-End Testbed Topology
            </h2>
            <p>Authoritative PC1 ⇄ IPsec ESP Tunnel ⇄ PC2 runtime state, negotiated SAs, and Linux kernel telemetry.</p>
          </div>
          <div className="overview-status-group">
            <span
              className={`tunnel-status-pill ${
                freshness.isStale
                  ? 'is-warning'
                  : tunnelState === 'ESTABLISHED'
                    ? 'is-active'
                    : tunnelState === 'DOWN'
                      ? 'is-danger'
                      : tunnelState === 'NEGOTIATING'
                        ? 'is-warning'
                        : ''
              }`}
            >
              <span className="pill-dot-core" />
              {freshness.isStale
                ? `Last Known: ${tunnelState}`
                : tunnelState === 'ESTABLISHED'
                  ? 'Tunnel Established'
                  : tunnelState === 'DOWN'
                    ? 'Tunnel Down'
                    : tunnelState === 'NEGOTIATING'
                      ? 'Negotiating'
                      : 'State Unavailable'}
            </span>
            <span className="glass-pill" title={freshness.description}>
              <span className={`status-indicator ${freshness.indicatorClass}`} />
              {freshness.label}
            </span>
          </div>
        </div>

        <div className="overview-testbed-workspace">
          {/* 3D Scene Container */}
          <div className="testbed-scene overview-scene" aria-label="Interactive 3D PC1 to PC2 IPsec testbed">
            <div className="scene-identities scene-identities-glass" aria-hidden="true">
              <span>PC1 · {displayValue(liveStatus?.endpoints?.pc1?.ip)}</span>
              <span>IPsec ESP · {displayValue(tunnelState)}</span>
              <span>PC2 · {displayValue(liveStatus?.endpoints?.pc2?.ip)}</span>
            </div>

            <ThreeCanvas
              selectedNode={selectedNodeId}
              onSelectNode={handleSelectNode}
              activity={activity}
              tunnelState={tunnelState}
              isStale={freshness.isStale}
              telemetryError={Boolean(liveStatusError)}
              endpoints={liveStatus?.endpoints}
              captureActive={Boolean(liveStatus?.capture?.active)}
            />

            <div className="scene-state scene-state-glass">
              <span className={`status-indicator${isCollectorConnected ? ' is-online' : ''}`} />
              eBPF Ring Buffer · {isCollectorConnected ? 'Live Kernel Observer' : collectorStatus ? 'Unavailable' : 'Connecting…'}
            </div>

            {liveStatus?.capture?.active && (
              <div className="scene-capture-badge glass-panel" role="status">
                <Activity size={12} className="text-sage" />
                <span>Capture: {displayValue(liveStatus.capture.workload)} ({displayValue(liveStatus.capture.stage)})</span>
              </div>
            )}
          </div>

          {/* Frosted Glass Inspector Drawer */}
          <aside className="overview-inspector glass-panel" aria-label="Selected testbed entity details">
            <nav className="overview-inspector-tabs" aria-label="Inspection target tabs">
              <button
                type="button"
                className={`inspector-tab-btn ${selectedNodeId === 'pc1' ? 'is-active' : ''}`}
                onClick={() => setSelectedNodeId('pc1')}
              >
                PC1
              </button>
              <button
                type="button"
                className={`inspector-tab-btn ${selectedNodeId === 'tunnel' ? 'is-active' : ''}`}
                onClick={() => setSelectedNodeId('tunnel')}
              >
                Tunnel
              </button>
              <button
                type="button"
                className={`inspector-tab-btn ${selectedNodeId === 'pc2' ? 'is-active' : ''}`}
                onClick={() => setSelectedNodeId('pc2')}
              >
                PC2
              </button>
              <button
                type="button"
                className={`inspector-tab-btn ${selectedNodeId === 'ebpf' ? 'is-active' : ''}`}
                onClick={() => setSelectedNodeId('ebpf')}
              >
                eBPF
              </button>
              <button
                type="button"
                className={`inspector-tab-btn ${selectedNodeId === 'pcap' ? 'is-active' : ''}`}
                onClick={() => setSelectedNodeId('pcap')}
              >
                PCAP
              </button>
              {selectedEvent && (
                <button
                  type="button"
                  className={`inspector-tab-btn ${selectedNodeId === 'event' ? 'is-active' : ''}`}
                  onClick={() => setSelectedNodeId('event')}
                >
                  Event
                </button>
              )}
            </nav>

            <div className="overview-inspector-body">
              {/* PC1 Inspector */}
              {selectedNodeId === 'pc1' && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">PC1 (Initiator)</span>
                    <span className={`inspector-tag ${liveStatus?.endpoints?.pc1?.status === 'running' ? 'is-online' : 'is-offline'}`}>
                      {displayValue(liveStatus?.endpoints?.pc1?.status)}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Container IP</dt>
                      <dd className="inspector-kv-value font-semibold">{displayValue(liveStatus?.endpoints?.pc1?.ip)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Subnet</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc1?.subnet)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Gateway</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc1?.gateway)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">MAC Address</dt>
                      <dd className="inspector-kv-value monospace text-muted">{displayValue(liveStatus?.endpoints?.pc1?.mac)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">IKE Daemon</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc1?.daemon)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Role</dt>
                      <dd className="inspector-kv-value">IKEv2 Initiator / Client</dd>
                    </div>
                  </dl>
                </>
              )}

              {/* PC2 Inspector */}
              {selectedNodeId === 'pc2' && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">PC2 (Responder)</span>
                    <span className={`inspector-tag ${liveStatus?.endpoints?.pc2?.status === 'running' ? 'is-online' : 'is-offline'}`}>
                      {displayValue(liveStatus?.endpoints?.pc2?.status)}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Container IP</dt>
                      <dd className="inspector-kv-value font-semibold">{displayValue(liveStatus?.endpoints?.pc2?.ip)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Subnet</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc2?.subnet)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Gateway</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc2?.gateway)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">MAC Address</dt>
                      <dd className="inspector-kv-value monospace text-muted">{displayValue(liveStatus?.endpoints?.pc2?.mac)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">IKE Daemon</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.endpoints?.pc2?.daemon)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Role</dt>
                      <dd className="inspector-kv-value">IKEv2 Responder / Server</dd>
                    </div>
                  </dl>
                </>
              )}

              {/* Tunnel Inspector */}
              {selectedNodeId === 'tunnel' && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">IPsec ESP Tunnel</span>
                    <span className={`inspector-tag ${tunnelState === 'ESTABLISHED' ? 'is-online' : 'is-offline'}`}>
                      {displayValue(tunnelState)}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Connection</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.tunnel?.connectionName)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">CHILD SA Protocol</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.tunnel?.child?.protocol)} ({displayValue(liveStatus?.tunnel?.child?.mode)})</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">CHILD Cipher</dt>
                      <dd className="inspector-kv-value font-semibold">{displayValue(liveStatus?.tunnel?.child?.encryption)} {liveStatus?.tunnel?.child?.encryptionKeySize ? `(${liveStatus.tunnel.child.encryptionKeySize}-bit)` : ''}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">PFS / DH Group</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.tunnel?.child?.pfsGroupName)} {liveStatus?.tunnel?.child?.pfsGroup ? `(Group ${liveStatus.tunnel.child.pfsGroup})` : ''}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Inbound SPI</dt>
                      <dd className="inspector-kv-value monospace font-semibold text-sage">
                        {liveStatus?.tunnel?.child?.spiIn ? `0x${liveStatus.tunnel.child.spiIn}` : EMPTY_VALUE}
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Outbound SPI</dt>
                      <dd className="inspector-kv-value monospace font-semibold text-sage">
                        {liveStatus?.tunnel?.child?.spiOut ? `0x${liveStatus.tunnel.child.spiOut}` : EMPTY_VALUE}
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Packets (In / Out)</dt>
                      <dd className="inspector-kv-value monospace">
                        {displayValue(liveStatus?.tunnel?.child?.packetsIn)} in / {displayValue(liveStatus?.tunnel?.child?.packetsOut)} out
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Bytes (In / Out)</dt>
                      <dd className="inspector-kv-value monospace">
                        {displayValue(liveStatus?.tunnel?.child?.bytesIn)} B / {displayValue(liveStatus?.tunnel?.child?.bytesOut)} B
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Traffic Selectors</dt>
                      <dd className="inspector-kv-value monospace text-muted">
                        {displayValue(liveStatus?.tunnel?.child?.localTs)} ⇄ {displayValue(liveStatus?.tunnel?.child?.remoteTs)}
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">IKEv2 Initiator SPI</dt>
                      <dd className="inspector-kv-value monospace text-muted">{displayValue(liveStatus?.tunnel?.ike?.initiatorSpi)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Established Duration</dt>
                      <dd className="inspector-kv-value monospace text-muted">
                        {liveStatus?.tunnel?.ike?.establishedSeconds != null ? `${liveStatus.tunnel.ike.establishedSeconds}s` : EMPTY_VALUE}
                      </dd>
                    </div>
                  </dl>
                </>
              )}

              {/* eBPF Inspector */}
              {selectedNodeId === 'ebpf' && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">eBPF Kernel Monitor</span>
                    <span className={`inspector-tag ${isCollectorConnected ? 'is-online' : 'is-offline'}`}>
                      {isCollectorConnected ? 'Active' : displayValue(liveStatus?.ebpf?.status)}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Collector Mode</dt>
                      <dd className="inspector-kv-value font-semibold">{displayValue(liveStatus?.ebpf?.mode || collectorStatus?.mode)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Attached Probes</dt>
                      <dd className="inspector-kv-value">{liveStatus?.ebpf?.probes?.length ?? collectorStatus?.probes?.length ?? '—'} kernel kprobes</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Ring Events Seen</dt>
                      <dd className="inspector-kv-value font-semibold monospace">
                        {liveStatus?.ebpf?.ringEventsSeen != null ? Number(liveStatus.ebpf.ringEventsSeen).toLocaleString() : EMPTY_VALUE}
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">XFRM Inbound Hits</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(liveStatus?.ebpf?.hookHits?.XFRM_IN ?? collectorStatus?.hookHits?.XFRM_IN)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">XFRM Outbound Hits</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(liveStatus?.ebpf?.hookHits?.XFRM_OUT ?? collectorStatus?.hookHits?.XFRM_OUT)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Socket Sends</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(liveStatus?.ebpf?.hookHits?.SOCK_SEND ?? collectorStatus?.hookHits?.SOCK_SEND)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Last Kernel Event</dt>
                      <dd className="inspector-kv-value monospace">{formatTimestamp(liveStatus?.ebpf?.lastEventTimestamp)}</dd>
                    </div>
                  </dl>
                </>
              )}

              {/* PCAP Inspector */}
              {selectedNodeId === 'pcap' && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">PCAP Observer</span>
                    <span className={`inspector-tag ${liveStatus?.capture?.active === true ? 'is-online' : 'is-offline'}`}>
                      {!liveStatus?.capture ? 'Unavailable' : liveStatus.capture.active === true ? 'Active' : liveStatus.capture.active === false ? 'Standby' : 'Unknown'}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Active Capture Job</dt>
                      <dd className="inspector-kv-value font-semibold monospace">{displayValue(liveStatus?.capture?.jobId)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Target Workload</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.capture?.workload)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Generation Stage</dt>
                      <dd className="inspector-kv-value">{displayValue(liveStatus?.capture?.stage)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Analysis Mode</dt>
                      <dd className="inspector-kv-value">{isPcapMode ? `Mode B (File: ${file?.name})` : 'Mode A (Live Testbed Monitor)'}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Observed Flows</dt>
                      <dd className="inspector-kv-value monospace">{totalFlows ?? '—'}</dd>
                    </div>
                  </dl>
                </>
              )}

              {/* Event Inspector */}
              {selectedNodeId === 'event' && selectedEvent && (
                <>
                  <div className="inspector-entity-header">
                    <span className="inspector-entity-title">Kernel Event Detail</span>
                    <span className="inspector-tag is-online">
                      {displayValue(selectedEvent.eventType)}
                    </span>
                  </div>
                  <dl className="inspector-kv-table">
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Event ID</dt>
                      <dd className="inspector-kv-value monospace text-muted">{displayValue(selectedEvent.id)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Direction</dt>
                      <dd className="inspector-kv-value font-semibold">
                        {selectedEvent.eventType === 'XFRM_OUT'
                          ? 'Outbound ESP (host-wide; endpoint not correlated)'
                          : selectedEvent.eventType === 'XFRM_IN'
                            ? 'Inbound ESP (host-wide; endpoint not correlated)'
                            : displayValue(selectedEvent.fn)}
                      </dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Kernel Hook</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(selectedEvent.fn)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Process Name</dt>
                      <dd className="inspector-kv-value font-semibold">{displayValue(selectedEvent.process_name)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">PID</dt>
                      <dd className="inspector-kv-value monospace text-muted">{displayValue(selectedEvent.pid)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Payload Size</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(selectedEvent.bytes)} Bytes</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Observed Packets</dt>
                      <dd className="inspector-kv-value monospace">{displayValue(selectedEvent.packets)}</dd>
                    </div>
                    <div className="inspector-kv-row">
                      <dt className="inspector-kv-label">Observed Timestamp</dt>
                      <dd className="inspector-kv-value monospace">{formatTimestamp(selectedEvent.timestamp)}</dd>
                    </div>
                  </dl>
                </>
              )}
            </div>
          </aside>
        </div>

        {/* Technical Parameter Chips / Connection Details */}
        <div className="connection-details-grid">
          <div className="detail-box">
            <span className="detail-label">Observed Protocol</span>
            <span className="detail-val">
              {analysisResult?.predictions?.protocol?.value || (liveStatus?.tunnel?.child?.protocol ? `${liveStatus.tunnel.child.protocol} (${liveStatus.tunnel.child.mode || 'TUNNEL'})` : '—')}
            </span>
          </div>
          <div className="detail-box">
            <span className="detail-label">Negotiated IKE/CHILD SA</span>
            <span className="detail-val text-sage monospace">
              {liveStatus?.tunnel?.child?.spiIn
                ? `SPI In: 0x${liveStatus.tunnel.child.spiIn} · Out: 0x${liveStatus.tunnel.child.spiOut}`
                : primaryFlow?.spi
                  ? `SPI 0x${primaryFlow.spi}`
                  : '—'}
            </span>
          </div>
          <div className="detail-box">
            <span className="detail-label">eBPF Monitoring Hook</span>
            <span className="detail-val">
              {isCollectorConnected ? 'xfrm_input / xfrm_output (Attached)' : 'Collector Unattached'}
            </span>
          </div>
          <div className="detail-box">
            <span className="detail-label">Active Cryptographic Suite</span>
            <span className="detail-val">
              {liveStatus?.tunnel?.child?.encryption
                ? `${liveStatus.tunnel.child.encryption} (${liveStatus.tunnel.child.pfsGroupName || 'PFS'})`
                : observedProposal || '—'}
            </span>
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
            <p>Authoritative Linux eBPF ring buffer event stream capturing live IPsec transforms. Click any event to inspect.</p>
          </div>
          <span className="section-meta-pill">
            {events.length} events in buffer
          </span>
        </div>
        <EventTable
          events={events}
          loading={loading}
          error={error}
          onSelectEvent={handleSelectEvent}
          selectedEventId={selectedEvent ? getEventId(selectedEvent) : null}
        />
      </section>
    </div>
  );
}
