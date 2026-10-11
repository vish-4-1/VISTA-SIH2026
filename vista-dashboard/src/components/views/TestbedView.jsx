import { useCallback, useEffect, useRef, useState } from 'react';
import ThreeCanvas from '../ThreeCanvas';
import {
  fetchEbpfEvents,
  fetchEbpfStatus,
  fetchTestbedProfiles,
  fetchTestbedLiveStatus,
  validateTestbedConfig,
} from '../../utils/apiClient';

const POLL_INTERVAL_MS = 2500;
const EMPTY_VALUE = '—';

function formatTimestamp(value) {
  if (!value) return EMPTY_VALUE;
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? String(value) : timestamp.toLocaleString();
}

function eventIdentity(event) {
  return [
    event.timestamp ?? '',
    event.eventType ?? '',
    event.pid ?? '',
    event.process_name ?? '',
  ].join(':');
}

function fieldValue(value) {
  return value === null || value === undefined || value === '' ? EMPTY_VALUE : String(value);
}

function probeStatus(status, name) {
  const probe = status?.probes?.find((item) => item.name === name);
  return probe?.status || EMPTY_VALUE;
}

function ProbeLine({ status, name, label }) {
  const value = probeStatus(status, name);
  const attached = value === 'ATTACHED';
  return (
    <div className="testbed-probe-row">
      <span>{label}</span>
      <span className={`probe-state${attached ? ' is-attached' : ''}`}>
        <span className="status-indicator" />
        {value}
      </span>
    </div>
  );
}

export default function TestbedView({ refreshKey = 0 }) {
  const [collectorStatus, setCollectorStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [liveStatus, setLiveStatus] = useState(null);
  const [liveStatusError, setLiveStatusError] = useState('');
  const [lastStatusUpdated, setLastStatusUpdated] = useState(null);
  const [statusError, setStatusError] = useState('');
  const [eventError, setEventError] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState('pc1');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [activity, setActivity] = useState(null);
  const latestEventKey = useRef(null);
  const activitySequence = useRef(0);
  const refreshInFlight = useRef(false);

  // Testbed profiles & validator state
  const [profilesData, setProfilesData] = useState(null);
  const [profilesLoading, setProfilesLoading] = useState(true);
  const [profilesError, setProfilesError] = useState('');
  const [candidateConfig, setCandidateConfig] = useState({
    mode: 'tunnel',
    cipher: 'aes256gcm16',
    integrity: 'none',
    dhGroup: 14,
    pfs: true,
    ipVersion: 'IPv4',
    trafficType: 'ICMP Echo',
  });
  const [validationResult, setValidationResult] = useState(null);
  const [validating, setValidating] = useState(false);
  const [validationError, setValidationError] = useState('');

  const refreshTelemetry = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    const [statusResult, eventsResult, liveStatusResult] = await Promise.allSettled([
      fetchEbpfStatus(),
      fetchEbpfEvents(50),
      fetchTestbedLiveStatus(),
    ]);

    if (statusResult.status === 'fulfilled') {
      setCollectorStatus(statusResult.value);
      setStatusError('');
    } else {
      setStatusError(statusResult.reason instanceof Error
        ? statusResult.reason.message
        : String(statusResult.reason));
    }

    if (liveStatusResult.status === 'fulfilled') {
      const result = liveStatusResult.value;
      if (result?.tunnel && typeof result.tunnel.state === 'string' && result?.endpoints) {
        setLiveStatus(result);
        setLiveStatusError('');
        setLastStatusUpdated(Date.now());
      } else {
        setLiveStatusError('The live-status response did not match the expected testbed schema.');
      }
    } else {
      setLiveStatusError(liveStatusResult.reason instanceof Error
        ? liveStatusResult.reason.message
        : String(liveStatusResult.reason));
    }

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
      setEventError('');

      const newest = nextEvents[0];
      if (newest?.correlation?.scope === 'testbed' && newest.correlation.verified === true) {
        const identity = eventIdentity(newest);
        if (latestEventKey.current !== null && identity !== latestEventKey.current) {
          activitySequence.current += 1;
          setActivity({ event: newest, sequence: activitySequence.current });
        }
        latestEventKey.current = identity;
      }
    } else {
      setEventError(eventsResult.reason instanceof Error
        ? eventsResult.reason.message
        : String(eventsResult.reason));
    }
    refreshInFlight.current = false;
  }, []);

  useEffect(() => {
    const initialRefresh = window.setTimeout(() => {
      void refreshTelemetry();
    }, 0);
    const interval = window.setInterval(() => {
      void refreshTelemetry();
    }, POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(interval);
    };
  }, [refreshTelemetry, refreshKey]);

  useEffect(() => {
    let cancelled = false;
    fetchTestbedProfiles()
      .then((data) => {
        if (!cancelled) {
          setProfilesData(data);
          setProfilesLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setProfilesError(err instanceof Error ? err.message : String(err));
          setProfilesLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleValidateConfig = async () => {
    setValidating(true);
    setValidationError('');
    try {
      const result = await validateTestbedConfig(candidateConfig);
      setValidationResult(result);
    } catch (err) {
      setValidationError(err instanceof Error ? err.message : String(err));
      setValidationResult(null);
    } finally {
      setValidating(false);
    }
  };

  const collectorConnected = collectorStatus?.status === 'RUNNING'
    && collectorStatus?.mode === 'NATIVE_KERNEL_EBPF';
  const tunnelState = liveStatus?.tunnel?.state
    || (liveStatusError ? (liveStatus ? 'STALE' : 'UNAVAILABLE') : 'UNKNOWN');

  const inspectEvent = (event) => {
    setSelectedEvent(event);
    setSelectedNodeId('event');
    if (event?.correlation?.scope === 'testbed' && event.correlation.verified === true) {
      activitySequence.current += 1;
      setActivity({ event, sequence: activitySequence.current });
    }
  };

  const handleSelectNode = (nodeId, eventData) => {
    setSelectedNodeId(nodeId);
    if (nodeId === 'event' && eventData) {
      setSelectedEvent(eventData);
    }
  };

  return (
    <div className="testbed-page">
      <div className="testbed-heading">
        <div>
          <h2>3D IPsec Testbed Monitor</h2>
          <p>
            Authoritative topology: <strong>PC1 ⇄ IPsec ESP Tunnel ⇄ PC2</strong> · Linux XFRM &amp; strongSwan.
          </p>
        </div>
        <div className={`testbed-collector-status${collectorConnected ? ' is-online' : ''}`}>
          <span className="status-indicator" />
          <span>eBPF Collector</span>
          <strong>{statusError ? 'Disconnected' : collectorConnected ? 'Connected (Native)' : collectorStatus ? 'Unavailable' : 'Loading'}</strong>
        </div>
      </div>

      {liveStatusError && (
        <div className="dashboard-empty is-warning" role="alert">
          Live testbed status unavailable: {liveStatusError}.
          {liveStatus ? ` Showing last observation from ${formatTimestamp(liveStatus.timestamp || liveStatus.tunnel?.lastObserved || lastStatusUpdated)}.` : ' Endpoint and tunnel state are unavailable.'}
        </div>
      )}

      <div className="testbed-main">
        <section className="testbed-scene" aria-label="Interactive 3D PC1 to PC2 IPsec testbed">
          <div className="scene-identities" aria-hidden="true">
            <span>PC1 · {fieldValue(liveStatus?.endpoints?.pc1?.ip)}</span>
            <span>IPsec ESP · {liveStatusError && liveStatus ? `Last known ${tunnelState}` : tunnelState}</span>
            <span>PC2 · {fieldValue(liveStatus?.endpoints?.pc2?.ip)}</span>
          </div>
          <ThreeCanvas
            selectedNode={selectedNodeId}
            onSelectNode={handleSelectNode}
            activity={activity}
            tunnelState={tunnelState}
            isStale={Boolean(liveStatusError && liveStatus)}
            telemetryError={Boolean(liveStatusError && !liveStatus)}
            endpoints={liveStatus?.endpoints}
            captureActive={Boolean(liveStatus?.capture?.active)}
          />
          <div className="scene-state">
            <span className={`status-indicator${collectorConnected ? ' is-online' : ''}`} />
            eBPF Monitor · {collectorConnected ? 'Live Ring Buffer' : statusError ? 'Disconnected' : 'Unavailable'}
          </div>
        </section>

        <aside className="testbed-inspector" aria-label="Selected entity and telemetry details">
          <nav className="testbed-inspector-tabs" aria-label="Testbed entities">
            <button
              type="button"
              className={`testbed-inspector-tab-btn${selectedNodeId === 'pc1' ? ' is-active' : ''}`}
              onClick={() => setSelectedNodeId('pc1')}
            >
              PC1
            </button>
            <button
              type="button"
              className={`testbed-inspector-tab-btn${selectedNodeId === 'tunnel' ? ' is-active' : ''}`}
              onClick={() => setSelectedNodeId('tunnel')}
            >
              Tunnel
            </button>
            <button
              type="button"
              className={`testbed-inspector-tab-btn${selectedNodeId === 'pc2' ? ' is-active' : ''}`}
              onClick={() => setSelectedNodeId('pc2')}
            >
              PC2
            </button>
            <button
              type="button"
              className={`testbed-inspector-tab-btn${selectedNodeId === 'ebpf' ? ' is-active' : ''}`}
              onClick={() => setSelectedNodeId('ebpf')}
            >
              eBPF
            </button>
            <button
              type="button"
              className={`testbed-inspector-tab-btn${selectedNodeId === 'pcap' ? ' is-active' : ''}`}
              onClick={() => setSelectedNodeId('pcap')}
            >
              PCAP
            </button>
            {selectedEvent && (
              <button
                type="button"
                className={`testbed-inspector-tab-btn${selectedNodeId === 'event' ? ' is-active' : ''}`}
                onClick={() => setSelectedNodeId('event')}
              >
                Event
              </button>
            )}
          </nav>

          {(selectedNodeId === 'pc1' || selectedNodeId === 'pc2') && (
            <section className="inspector-section">
              <h3>Selected Endpoint</h3>
              <p className="inspector-endpoint">
                {selectedNodeId.toUpperCase()} {selectedNodeId === 'pc1' ? '(Initiator / Client)' : '(Responder / Gateway)'}
              </p>
              <dl className="inspector-fields">
                <div>
                  <dt>Observed IP</dt>
                  <dd>{selectedNodeId === 'pc1' ? fieldValue(liveStatus?.endpoints?.pc1?.ip) : fieldValue(liveStatus?.endpoints?.pc2?.ip)}</dd>
                </div>
                <div>
                  <dt>Subnet</dt>
                  <dd>{fieldValue(selectedNodeId === 'pc1' ? liveStatus?.endpoints?.pc1?.subnet : liveStatus?.endpoints?.pc2?.subnet)}</dd>
                </div>
                <div>
                  <dt>Subsystem</dt>
                  <dd>Linux XFRM / netlink</dd>
                </div>
                <div>
                  <dt>IKE Daemon</dt>
                  <dd>{fieldValue(selectedNodeId === 'pc1' ? liveStatus?.endpoints?.pc1?.daemon : liveStatus?.endpoints?.pc2?.daemon)}</dd>
                </div>
                <div>
                  <dt>Tunnel State</dt>
                  <dd className={tunnelState === 'ESTABLISHED' && !liveStatusError ? 'text-sage' : undefined}>{liveStatusError && liveStatus ? `STALE · ${tunnelState}` : tunnelState}</dd>
                </div>
              </dl>
            </section>
          )}

          {selectedNodeId === 'tunnel' && (
            <section className="inspector-section">
              <h3>IPsec ESP Tunnel</h3>
              <p className="inspector-endpoint">
                PC1 ⇄ ESP Tunnel ⇄ PC2
              </p>
              <dl className="inspector-fields">
                <div>
                  <dt>Protocol</dt>
                  <dd>ESP (IP Proto 50) / IKEv2</dd>
                </div>
                <div>
                  <dt>Tunnel State</dt>
                  <dd className={tunnelState === 'ESTABLISHED' && !liveStatusError ? 'text-sage' : undefined}>{liveStatusError && liveStatus ? `STALE · ${tunnelState}` : tunnelState}</dd>
                </div>
                <div>
                  <dt>Initiator (PC1)</dt>
                  <dd>{fieldValue(liveStatus?.endpoints?.pc1?.ip)}</dd>
                </div>
                <div>
                  <dt>Responder (PC2)</dt>
                  <dd>{fieldValue(liveStatus?.endpoints?.pc2?.ip)}</dd>
                </div>
                <div>
                  <dt>Security Assoc</dt>
                  <dd>XFRM State (SA) &amp; Policy (SP)</dd>
                </div>
                <div>
                  <dt>Encapsulation</dt>
                  <dd>Tunnel Mode (RFC 4301 / 4303)</dd>
                </div>
              </dl>
            </section>
          )}

          {selectedNodeId === 'ebpf' && (
            <section className="inspector-section">
              <h3>eBPF Telemetry Core</h3>
              <p className="inspector-endpoint">
                Kernel Ring Buffer Probes
              </p>
              <dl className="inspector-fields">
                <div>
                  <dt>Mode</dt>
                  <dd>{fieldValue(collectorStatus?.mode || (collectorConnected ? 'NATIVE_KERNEL_EBPF' : 'UNKNOWN'))}</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd className={collectorConnected ? 'text-sage' : undefined}>
                    {statusError ? 'OFFLINE' : collectorConnected ? 'RUNNING' : 'UNAVAILABLE'}
                  </dd>
                </div>
                <div>
                  <dt>Ring Buffer</dt>
                  <dd>{collectorConnected ? 'Lossless RingBuf' : 'Standby'}</dd>
                </div>
                <div>
                  <dt>Target Subsystem</dt>
                  <dd>net/xfrm &amp; net/ipv4</dd>
                </div>
              </dl>
            </section>
          )}

          {selectedNodeId === 'pcap' && (
            <section className="inspector-section">
              <h3>PCAP Packet Capture</h3>
              <p className="inspector-endpoint">
                Wire &amp; Synthetic Traffic Tap
              </p>
              <dl className="inspector-fields">
                <div>
                  <dt>Capture State</dt>
                  <dd className={liveStatus?.capture?.active ? 'text-sage' : undefined}>
                    {liveStatus?.capture?.active ? 'ACTIVE' : 'READY / IDLE'}
                  </dd>
                </div>
                <div>
                  <dt>Interface</dt>
                  <dd>{fieldValue(liveStatus?.capture?.interface || 'eth0 / docker0')}</dd>
                </div>
                <div>
                  <dt>Packets</dt>
                  <dd>{fieldValue(liveStatus?.capture?.packets ?? '0')}</dd>
                </div>
                <div>
                  <dt>Format</dt>
                  <dd>pcapng / libpcap</dd>
                </div>
              </dl>
            </section>
          )}

          {selectedNodeId === 'event' && selectedEvent && (
            <section className="inspector-section">
              <h3>Active 3D Telemetry Event</h3>
              <p className="inspector-endpoint">
                {selectedEvent.eventType || 'Kernel Event'}
              </p>
              <dl className="inspector-fields">
                <div><dt>Type</dt><dd>{fieldValue(selectedEvent.eventType)}</dd></div>
                <div><dt>Process</dt><dd>{fieldValue(selectedEvent.process_name)}</dd></div>
                <div><dt>PID</dt><dd>{fieldValue(selectedEvent.pid)}</dd></div>
                <div><dt>Bytes</dt><dd>{fieldValue(selectedEvent.bytes)}</dd></div>
                <div><dt>Packets</dt><dd>{fieldValue(selectedEvent.packets)}</dd></div>
                <div><dt>Timestamp</dt><dd>{formatTimestamp(selectedEvent.timestamp)}</dd></div>
              </dl>
            </section>
          )}

          <section className="inspector-section">
            <h3>eBPF Kernel Probes</h3>
            {statusError ? (
              <p className="inspector-message">Collector offline: {statusError}</p>
            ) : !collectorStatus ? (
              <p className="inspector-message">Querying Linux kernel probes…</p>
            ) : (
              <div className="testbed-probe-list">
                <ProbeLine status={collectorStatus} name="kprobe:xfrm_output" label="XFRM_OUT" />
                <ProbeLine status={collectorStatus} name="kprobe:xfrm_input" label="XFRM_IN" />
                <ProbeLine status={collectorStatus} name="kprobe:sock_sendmsg" label="SOCK_SEND" />
              </div>
            )}
          </section>

          {selectedNodeId !== 'event' && (
            <section className="inspector-section selected-event">
              <h3>Selected Event</h3>
              {selectedEvent ? (
                <dl className="inspector-fields">
                  <div><dt>Type</dt><dd>{fieldValue(selectedEvent.eventType)}</dd></div>
                  <div><dt>Process</dt><dd>{fieldValue(selectedEvent.process_name)}</dd></div>
                  <div><dt>PID</dt><dd>{fieldValue(selectedEvent.pid)}</dd></div>
                  <div><dt>Bytes</dt><dd>{fieldValue(selectedEvent.bytes)}</dd></div>
                  <div><dt>Packets</dt><dd>{fieldValue(selectedEvent.packets)}</dd></div>
                  <div><dt>Timestamp</dt><dd>{formatTimestamp(selectedEvent.timestamp)}</dd></div>
                </dl>
              ) : (
                <p className="inspector-message">Select any event below to inspect and project in 3D.</p>
              )}
            </section>
          )}
        </aside>
      </div>

      {/* Profile Evidence & Configuration Validation Section */}
      <section className="dashboard-section testbed-config-matrix" aria-labelledby="testbed-config-title">
        <div className="section-heading">
          <div>
            <h2 id="testbed-config-title">StrongSwan Profile Evidence &amp; Configuration Validator</h2>
            <p>
              Profile status reflects recorded experiment evidence. Parameter validation checks configuration compatibility; it does not prove negotiation or data-plane operation.
            </p>
          </div>
          <span className="section-meta">
            {profilesLoading
              ? 'Loading profile evidence…'
              : profilesError
                ? 'Profile evidence unavailable'
                : `${profilesData?.profiles?.filter((profile) => ['EXECUTED_WITH_EVIDENCE', 'VERIFIED_OPERATIONAL'].includes(profile.status)).length ?? '—'} of ${profilesData?.profiles?.length ?? '—'} profiles have runtime evidence`}
          </span>
        </div>

        <div className="config-matrix-layout">
          {/* Left: Repository Profile Evidence */}
          <div className="config-profiles-list">
            <h4 className="config-subsection-title">Repository Profile Inventory</h4>
            {profilesLoading ? (
              <p className="inspector-message">Loading profile inventory…</p>
            ) : profilesError ? (
              <p className="inspector-message">Unable to load profiles: {profilesError}</p>
            ) : (
              <div className="profile-cards-grid">
                {profilesData?.profiles?.map((profile) => {
                  const hasRuntimeEvidence = ['EXECUTED_WITH_EVIDENCE', 'VERIFIED_OPERATIONAL'].includes(profile.status);
                  const statusLabel = hasRuntimeEvidence
                    ? 'Executed with evidence'
                    : ['IMPLEMENTED_UNVERIFIED', 'SUPPORTED_KERNEL'].includes(profile.status)
                      ? 'Implemented · unverified'
                      : 'Configuration only';
                  const configLabel = profile.mode === 'transport' && !hasRuntimeEvidence
                    ? 'No verified profile'
                    : profile.configFile
                      || (['IMPLEMENTED_UNVERIFIED', 'SUPPORTED_KERNEL'].includes(profile.status) ? 'No verified profile' : '—');
                  return (
                    <div key={profile.id} className="profile-card">
                      <div className="profile-card-header">
                        <strong>{profile.name}</strong>
                        <span className={`profile-badge ${hasRuntimeEvidence ? 'verified' : 'unverified'}`}>{statusLabel}</span>
                      </div>
                      <div className="profile-card-specs">
                        <div><span>Mode:</span> <strong>{profile.mode}</strong></div>
                        <div><span>IKE:</span> <strong>v{profile.ikeVersion}</strong></div>
                        <div><span>Cipher:</span> <strong>{profile.encryption}</strong></div>
                        <div><span>ESP:</span> <code className="monospace">{profile.espProposals}</code></div>
                        <div><span>DH Group:</span> <strong>{profile.dhGroupName} (Group {profile.dhGroup})</strong></div>
                        <div><span>PFS:</span> <strong>{profile.pfs ? 'Enabled' : 'Disabled'}</strong></div>
                        <div><span>Config:</span> <code>{configLabel}</code></div>
                      </div>
                      <div className="profile-compliance-tag">{profile.nistCompliance}</div>
                      {profile.evidenceReference && (
                        <div className="profile-evidence-ref">Evidence: <code>{profile.evidenceReference}</code></div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right: Interactive Configuration Validator */}
          <div className="config-validator-panel">
            <h4 className="config-subsection-title">Testbed Parameter Validator (NIST SP 800-77 r1)</h4>
            <div className="validator-form-grid">
              <label>
                <span>Tunnel Mode</span>
                <select
                  value={candidateConfig.mode}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, mode: e.target.value }))}
                >
                  <option value="tunnel">Tunnel Mode (Site-to-Site)</option>
                  <option value="transport">Transport Mode (Host-to-Host)</option>
                </select>
              </label>

              <label>
                <span>Encryption Algorithm</span>
                <select
                  value={candidateConfig.cipher}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, cipher: e.target.value }))}
                >
                  <option value="aes256gcm16">AES-256-GCM (AEAD 128-bit ICV)</option>
                  <option value="aes128gcm16">AES-128-GCM (AEAD 128-bit ICV)</option>
                  <option value="aes256">AES-256-CBC (Requires HMAC)</option>
                  <option value="aes128">AES-128-CBC (Requires HMAC)</option>
                  <option value="3des">3DES-CBC (Deprecated)</option>
                </select>
              </label>

              <label>
                <span>Integrity / HMAC</span>
                <select
                  value={candidateConfig.integrity}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, integrity: e.target.value }))}
                >
                  <option value="none">None (Included in AEAD GCM)</option>
                  <option value="sha256">HMAC-SHA256 (SHA2-256-128)</option>
                  <option value="sha384">HMAC-SHA384</option>
                  <option value="sha512">HMAC-SHA512</option>
                  <option value="md5">HMAC-MD5 (Insecure / Non-compliant)</option>
                </select>
              </label>

              <label>
                <span>Diffie–Hellman Group</span>
                <select
                  value={candidateConfig.dhGroup}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, dhGroup: Number(e.target.value) }))}
                >
                  <option value={14}>Group 14: MODP-2048 (NIST Compliant)</option>
                  <option value={19}>Group 19: ECP-256 (NIST Compliant)</option>
                  <option value={20}>Group 20: ECP-384 (NIST Compliant)</option>
                  <option value={2}>Group 2: MODP-1024 (Deprecated / Insecure)</option>
                </select>
              </label>

              <label>
                <span>Perfect Forward Secrecy</span>
                <select
                  value={candidateConfig.pfs ? 'true' : 'false'}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, pfs: e.target.value === 'true' }))}
                >
                  <option value="true">Enabled (Dedicated Child SA DH)</option>
                  <option value="false">Disabled (Reuse IKE SA Keys)</option>
                </select>
              </label>

              <label>
                <span>IP Protocol Version</span>
                <select
                  value={candidateConfig.ipVersion}
                  onChange={(e) => setCandidateConfig((c) => ({ ...c, ipVersion: e.target.value }))}
                >
                  <option value="IPv4">IPv4 (Subnet 172.20.0.0/24)</option>
                  <option value="IPv6">IPv6 (Dual-Stack Bridge Required)</option>
                </select>
              </label>
            </div>

            <button
              className="soc-btn soc-btn-primary validator-submit-btn"
              type="button"
              disabled={validating}
              onClick={handleValidateConfig}
            >
              {validating ? 'Verifying Configuration…' : 'Validate Configuration with StrongSwan Rules'}
            </button>

            {validationError && (
              <div className="validator-feedback error" role="alert">
                <strong>Validation Request Failed:</strong> {validationError}
              </div>
            )}

            {validationResult && (
              <div className={`validator-feedback ${validationResult.isSupported ? 'success' : 'warning'}`}>
                <div className="validation-header">
                  <strong>
                    {validationResult.isSupported ? 'Configuration Verified Supported' : 'Configuration Unsupported or Deprecated'}
                  </strong>
                  <span className={`soc-badge ${validationResult.isSupported ? 'success' : 'critical'}`}>
                    {validationResult.nistCompliance}
                  </span>
                </div>
                <div className="validation-details-list">
                  <div><span>strongSwan Support:</span> <strong>{validationResult.strongSwanSupport ? 'Yes' : 'No'}</strong></div>
                  <div><span>Kernel XFRM Support:</span> <strong>{validationResult.kernelXfrmSupport ? 'Yes' : 'No'}</strong></div>
                  <div><span>PFS Assessment:</span> <strong>{validationResult.pfs ? 'PFS Active' : 'PFS Inactive (Warning)'}</strong></div>
                  {validationResult.proposedEspSuite && (
                    <div><span>Swanctl ESP Proposal:</span> <code className="monospace">{validationResult.proposedEspSuite}</code></div>
                  )}
                  {validationResult.proposedIkeSuite && (
                    <div><span>Swanctl IKE Proposal:</span> <code className="monospace">{validationResult.proposedIkeSuite}</code></div>
                  )}
                </div>
                {validationResult.warnings?.length > 0 && (
                  <ul className="validation-warnings">
                    {validationResult.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                )}
                {validationResult.errors?.length > 0 && (
                  <ul className="validation-errors">
                    {validationResult.errors.map((e, i) => (
                      <li key={i}>{e}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Live eBPF Telemetry Timeline */}
      <section className="testbed-events" aria-labelledby="testbed-events-title">
        <div className="testbed-events-heading">
          <div>
            <h3 id="testbed-events-title">Live eBPF Telemetry &amp; Ring Buffer Stream</h3>
            <p>
              Host-wide records from Linux kernel probes: <code>kprobe:xfrm_input</code>, <code>kprobe:xfrm_output</code>, <code>kprobe:sock_sendmsg</code>. Events are not attributed to PC1, PC2, or this tunnel without verified correlation.
            </p>
          </div>
          <span className="section-meta">{events.length} observed events in buffer</span>
        </div>
        {eventError ? (
          <p className="inspector-message">Unable to receive live eBPF telemetry: {eventError}</p>
        ) : events.length === 0 ? (
          <p className="inspector-message">
            {!eventError && !collectorStatus
              ? 'Loading collector events…'
              : 'No events are buffered. This does not establish whether the PC1 ↔ PC2 tunnel carried traffic.'}
          </p>
        ) : (
          <div className="testbed-event-scroll">
            <div className="testbed-event-header" aria-hidden="true">
              <span>Timestamp</span>
              <span>Event</span>
              <span>Process</span>
              <span>PID</span>
              <span>Bytes</span>
              <span>Packets</span>
            </div>
            <div className="testbed-event-list">
              {events.map((event, index) => {
                const identity = eventIdentity(event);
                const selected = selectedEvent && eventIdentity(selectedEvent) === identity;
                return (
                  <button
                    className={`testbed-event-row${selected ? ' is-selected' : ''}`}
                    key={`${identity}-${index}`}
                    type="button"
                    onClick={() => inspectEvent(event)}
                  >
                    <time dateTime={event.timestamp || undefined}>{formatTimestamp(event.timestamp)}</time>
                    <strong>{fieldValue(event.eventType)}</strong>
                    <span>{fieldValue(event.process_name)}</span>
                    <span>PID {fieldValue(event.pid)}</span>
                    <span>{fieldValue(event.bytes)}</span>
                    <span>{fieldValue(event.packets)}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
