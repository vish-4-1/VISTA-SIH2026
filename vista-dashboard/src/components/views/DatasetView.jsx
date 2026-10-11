import { useEffect, useState, useMemo, useRef } from 'react';
import {
  Database,
  Plus,
  Search,
  Download,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  FileText,
  Layers,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  RotateCcw,
  X,
  Activity,
  Check,
  Loader2,
} from 'lucide-react';
import {
  fetchDatasets,
  fetchDatasetDetails,
  fetchDatasetCapabilities,
  fetchTestbedLiveStatus,
  fetchShapStatus,
  runDatasetPreflight,
  startDatasetGeneration,
  pollDatasetJob,
  cancelDatasetJob,
  validateDatasetQuality,
  getDatasetExportUrl,
} from '../../utils/apiClient';

function getDatasetDisplayStatus(dataset) {
  const sampleOriginVerified = dataset.source !== 'representative_sample' || (
    dataset.originType === 'testbed_collected' && dataset.provenanceStatus === 'declared'
  );
  return sampleOriginVerified ? dataset.status : 'UNVERIFIED';
}

export default function DatasetView({ generationJob = null, setGenerationJob = () => {} }) {
  // Registry state
  const [datasets, setDatasets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');

  // Inspection drawer state
  const [inspectId, setInspectId] = useState(null);
  const [inspectDetails, setInspectDetails] = useState(null);
  const [inspectLoading, setInspectLoading] = useState(false);
  const [qualityAuditResult, setQualityAuditResult] = useState(null);
  const [validatingQuality, setValidatingQuality] = useState(false);

  // Wizard state
  const [wizardOpen, setWizardOpen] = useState(Boolean(generationJob));
  const [wizardStage, setWizardStage] = useState(generationJob ? 3 : 1);
  const [capabilities, setCapabilities] = useState(null);
  const [capabilitiesError, setCapabilitiesError] = useState('');
  const [liveTestbed, setLiveTestbed] = useState(null);
  const [testbedStatusError, setTestbedStatusError] = useState('');
  const [datasetSchema, setDatasetSchema] = useState(null);
  const [preflightReport, setPreflightReport] = useState(null);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [jobError, setJobError] = useState('');

  // Wizard Form Config
  const [config, setConfig] = useState({
    name: '',
    ipVersion: 'IPv4',
    mode: 'tunnel',
    cipher: 'aes256gcm16',
    dhGroup: 14,
    pfs: true,
    trafficType: 'icmpv4',
    recipeMode: 'standard',
    sessions: 3,
  });

  const pollIntervalRef = useRef(null);

  // Load datasets and capabilities on mount
  const refreshRegistry = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await fetchDatasets();
      setDatasets(data.datasets || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initialLoad = window.setTimeout(() => {
      void refreshRegistry();
      fetchDatasetCapabilities()
        .then((data) => { setCapabilities(data); setCapabilitiesError(''); })
        .catch((requestError) => setCapabilitiesError(requestError instanceof Error ? requestError.message : String(requestError)));
      fetchTestbedLiveStatus()
        .then((data) => { setLiveTestbed(data); setTestbedStatusError(''); })
        .catch((requestError) => setTestbedStatusError(requestError instanceof Error ? requestError.message : String(requestError)));
      fetchShapStatus().then(setDatasetSchema).catch(() => {});
    }, 0);
    return () => window.clearTimeout(initialLoad);
  }, []);

  // Poll active generation job
  useEffect(() => {
    if (generationJob && ['RUNNING', 'PRECHECK', 'CANCELLING'].includes(generationJob.status)) {
      pollIntervalRef.current = setInterval(async () => {
        try {
          const updated = await pollDatasetJob(generationJob.jobId);
          setGenerationJob({ ...updated, clientObservedAt: new Date().toISOString() });
          setJobError('');
          if (updated.status === 'COMPLETED' || updated.status === 'FAILED' || updated.status === 'CANCELLED') {
            clearInterval(pollIntervalRef.current);
            refreshRegistry();
          }
        } catch (pollError) {
          setJobError(`Job status refresh failed; showing the last received backend response${generationJob.clientObservedAt ? ` from ${new Date(generationJob.clientObservedAt).toLocaleTimeString()}` : ''}. ${pollError instanceof Error ? pollError.message : String(pollError)}`);
        }
      }, 1500);
    }
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [generationJob, setGenerationJob]);

  // Open dataset inspector drawer
  const handleInspect = async (id) => {
    try {
      setInspectId(id);
      setInspectLoading(true);
      setQualityAuditResult(null);
      const details = await fetchDatasetDetails(id);
      setInspectDetails(details);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInspectLoading(false);
    }
  };

  // Trigger live quality validation from inspector
  const handleRunQualityAudit = async (id) => {
    try {
      setValidatingQuality(true);
      const audit = await validateDatasetQuality(id);
      setQualityAuditResult(audit);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setValidatingQuality(false);
    }
  };

  // Run preflight check
  const handlePreflight = async () => {
    try {
      setPreflightLoading(true);
      setJobError('');
      const report = await runDatasetPreflight(config);
      setPreflightReport(report);
      if (report.canProceed) {
        setWizardStage(2);
      }
    } catch (err) {
      setJobError(err instanceof Error ? err.message : String(err));
    } finally {
      setPreflightLoading(false);
    }
  };

  // Launch real dataset generation experiment
  const handleLaunchGeneration = async () => {
    try {
      setJobError('');
      if (!window.confirm('Run this bounded scenario on the isolated PC1 ↔ PC2 lab testbed?')) return;
      const job = await startDatasetGeneration({ ...config, confirmedIsolatedLab: true });
      setGenerationJob({ ...job, clientObservedAt: new Date().toISOString() });
      setWizardStage(3);
    } catch (err) {
      setJobError(err instanceof Error ? err.message : String(err));
    }
  };

  // Cancel generation job
  const handleCancelJob = async () => {
    if (!generationJob) return;
    try {
      await cancelDatasetJob(generationJob.jobId);
      const updated = await pollDatasetJob(generationJob.jobId);
      setGenerationJob({ ...updated, clientObservedAt: new Date().toISOString() });
    } catch (err) {
      setJobError(err instanceof Error ? err.message : String(err));
    }
  };

  // Filter datasets
  const filteredDatasets = useMemo(() => {
    return datasets.filter((d) => {
      const matchesSearch =
        searchQuery === '' ||
        d.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.campaignId?.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus = statusFilter === 'ALL' || getDatasetDisplayStatus(d) === statusFilter;
      const matchesSource = sourceFilter === 'ALL' || d.source === sourceFilter;

      return matchesSearch && matchesStatus && matchesSource;
    });
  }, [datasets, searchQuery, statusFilter, sourceFilter]);

  // High-level KPI aggregations
  const totalFlows = useMemo(() => {
    if (!datasets.every((dataset) => dataset.sampleCount != null && Number.isFinite(Number(dataset.sampleCount)))) {
      return null;
    }
    return datasets.reduce((sum, dataset) => sum + Number(dataset.sampleCount), 0);
  }, [datasets]);

  const totalCampaigns = useMemo(() => {
    return datasets.filter((d) => d.source === 'testbed_campaign').length;
  }, [datasets]);
  const datasetInventoryAvailable = !loading && !error;
  const liveTestbedAvailable = Boolean(liveTestbed && !testbedStatusError);

  return (
    <div className="dashboard-content">
      <div className="dataset-studio">
        {/* Header Bar */}
        <div className="dataset-header-bar">
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Dataset Studio
            </h1>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>
              Testbed-driven IPsec flow dataset registry, controlled workload generation, and leakage-aware quality auditing.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="soc-btn"
              onClick={refreshRegistry}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              title="Refresh Dataset Registry"
            >
              <RotateCcw size={14} />
              Refresh
            </button>
            <button
              type="button"
              className="soc-btn primary"
              onClick={() => {
                setWizardOpen(!wizardOpen);
                if (!wizardOpen) setWizardStage(1);
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: 'var(--accent-sage)',
                color: '#FFFFFF',
              }}
            >
              <Plus size={15} />
              {wizardOpen ? 'Close Generator' : 'Generate New Dataset'}
            </button>
          </div>
        </div>

        {error && (
          <div className="dashboard-empty" role="alert" style={{ color: 'var(--accent-coral)' }}>
            <AlertTriangle size={16} /> {datasets.length ? `Registry refresh failed; showing stale last-known inventory. ${error}` : `Dataset registry unavailable. ${error}`}
          </div>
        )}

        {/* Section A: Dataset Overview KPI Cards */}
        <div className="dataset-overview-grid">
          <div className="dataset-kpi-card">
            <span className="dataset-kpi-label">Registered Datasets</span>
            <span className="dataset-kpi-value">{datasetInventoryAvailable ? datasets.length : '—'}</span>
            <span className="dataset-kpi-meta">
              <Database size={13} /> {datasetInventoryAvailable ? `${totalCampaigns} campaign datasets, ${datasets.length - totalCampaigns} sample` : loading ? 'Loading registry' : 'Registry unavailable'}
            </span>
          </div>

          <div className="dataset-kpi-card">
            <span className="dataset-kpi-label">Registered Flow Records</span>
            <span className="dataset-kpi-value">{datasetInventoryAvailable && totalFlows != null ? totalFlows.toLocaleString() : '—'}</span>
            <span className="dataset-kpi-meta">
              <Layers size={13} /> unit: bidirectional outer-ESP flows
            </span>
          </div>

          <div className="dataset-kpi-card">
            <span className="dataset-kpi-label">Feature Schema</span>
            <span className="dataset-kpi-value" style={{ fontSize: 17, marginTop: 4 }}>
              {datasetSchema?.featureSchema || 'Unavailable'}
            </span>
            <span className="dataset-kpi-meta">
              <ShieldCheck size={13} /> {datasetSchema?.featureCount != null ? `${datasetSchema.featureCount} features` : 'Feature count unavailable'}
            </span>
          </div>

          <div className="dataset-kpi-card">
            <span className="dataset-kpi-label">Testbed Status</span>
            <span
              className="dataset-kpi-value"
              style={{
                fontSize: 17,
                marginTop: 4,
                color: liveTestbedAvailable && liveTestbed?.endpoints?.pc1?.status === 'running' && liveTestbed?.endpoints?.pc2?.status === 'running' ? 'var(--accent-sage)' : 'var(--text-muted)',
              }}
            >
              {liveTestbedAvailable
                ? `${liveTestbed.endpoints?.pc1?.status || 'UNKNOWN'} / ${liveTestbed.endpoints?.pc2?.status || 'UNKNOWN'} · ${liveTestbed.tunnel?.state || 'UNKNOWN'}`
                : testbedStatusError ? 'UNAVAILABLE' : 'Loading'}
            </span>
            <span className="dataset-kpi-meta">
              <Activity size={13} /> {liveTestbed?.endpoints?.pc1?.daemon || capabilities?.strongswanVersion || capabilitiesError || 'Runtime version unavailable'}
            </span>
          </div>
        </div>

        {/* Section C: Guided Generate Dataset Wizard */}
        {wizardOpen && (
          <div className="dataset-wizard-card">
            <div className="wizard-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={16} className="text-sage" />
                <span style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Testbed Dataset Generation Wizard
                </span>
              </div>
              <button
                type="button"
                className="soc-btn"
                style={{ padding: '2px 8px' }}
                onClick={() => setWizardOpen(false)}
              >
                <X size={14} />
              </button>
            </div>

            {/* Stepper Navigation */}
            <div className="wizard-stepper-bar">
              {[
                { num: 1, label: '1. Configure' },
                { num: 2, label: '2. Preflight' },
                { num: 3, label: '3. Run Experiment' },
                { num: 4, label: '4. Extract Features' },
                { num: 5, label: '5. Ground Truth' },
                { num: 6, label: '6. Quality Audit' },
                { num: 7, label: '7. Finalize & Save' },
              ].map((step) => {
                const isActive = wizardStage === step.num;
                const isCompleted = wizardStage > step.num || (generationJob?.status === 'COMPLETED' && step.num <= 7);
                return (
                  <div
                    key={step.num}
                    className={`stepper-step ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`}
                  >
                    <div className="stepper-circle">
                      {isCompleted ? <Check size={11} /> : step.num}
                    </div>
                    <span>{step.label}</span>
                  </div>
                );
              })}
            </div>

            <div className="wizard-body">
              {jobError && (
                <div style={{ padding: '8px 12px', background: 'rgba(184, 77, 66, 0.08)', border: '1px solid var(--accent-coral)', borderRadius: 4, color: 'var(--accent-coral)', fontSize: 12, marginBottom: 14 }}>
                  <AlertTriangle size={14} style={{ display: 'inline', marginRight: 6 }} />
                  {jobError}
                </div>
              )}

              {/* Stage 1: Configuration Form */}
              {wizardStage === 1 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', margin: 0 }}>
                    Configure one implemented scenario. Collected results remain unverified until independent evidence and leakage checks pass.
                  </p>

                  <div className="wizard-form-grid">
                    <div className="form-field-group">
                      <label className="form-field-label">Dataset Name</label>
                      <input
                        type="text"
                        className="dataset-search-input"
                        placeholder="e.g. Robustness-Sweep-AES256GCM"
                        value={config.name}
                        onChange={(e) => setConfig({ ...config, name: e.target.value })}
                      />
                      <span className="form-field-help">Will be assigned an immutable version upon finalization.</span>
                    </div>

                    <div className="form-field-group">
                      <label className="form-field-label">
                        <span>Traffic Generator</span>
                        <span className={`pill-badge ${config.trafficType.startsWith('controlled_') && config.trafficType !== 'controlled_icmpv4' ? 'pill-coral' : 'pill-sage'}`}>
                          {config.trafficType.startsWith('controlled_') && config.trafficType !== 'controlled_icmpv4' ? 'Suspicious Lab' : 'Benign Control'}
                        </span>
                      </label>
                      <select
                        className="dataset-select"
                        value={config.trafficType}
                        onChange={(e) => setConfig({ ...config, trafficType: e.target.value })}
                      >
                        <optgroup label="Implemented, bounded scenarios">
                          <option value="controlled_port_scan">PORT_SCAN behavior (bounded TCP probes)</option>
                          <option value="icmpv4">ICMPv4 Echo (controlled_icmpv4)</option>
                        </optgroup>
                      </select>
                      <span className="form-field-help">PORT_SCAN is a time-window behavior label; it does not establish malicious intent or label every encrypted flow.</span>

                      {config.trafficType.startsWith('controlled_') && config.trafficType !== 'controlled_icmpv4' && (
                        <div style={{ marginTop: 8, padding: '8px 10px', background: 'rgba(184, 77, 66, 0.06)', border: '1px solid rgba(184, 77, 66, 0.25)', borderRadius: 4, fontSize: 11.5, color: 'var(--text-secondary)' }}>
                          <div style={{ fontWeight: 600, color: 'var(--accent-coral)', marginBottom: 3, display: 'flex', alignItems: 'center', gap: 6 }}>
                            <ShieldAlert size={13} />
                            Safe Isolated Testbed Protocol
                          </div>
                          Target: 172.20.0.3 (PC2 only) · bounded allowlisted probes · target-side PCAP required. The outer ESP capture does not reveal inner application identity.
                        </div>
                      )}
                    </div>

                    <div className="form-field-group">
                      <label className="form-field-label">
                        <span>Encryption Cipher</span>
                        <span className="pill-badge pill-sage">AEAD & CBC</span>
                      </label>
                      <select
                        className="dataset-select"
                        value={config.cipher}
                        onChange={(e) => setConfig({ ...config, cipher: e.target.value })}
                      >
                        <option value="aes256gcm16">AES-256-GCM (NIST Recommended)</option>
                        <option value="aes128gcm16">AES-128-GCM</option>
                        <option value="aes256">AES-256-CBC + HMAC-SHA256</option>
                        <option value="aes128">AES-128-CBC + HMAC-SHA256</option>
                      </select>
                      <span className="form-field-help">Verified in StrongSwan kernel XFRM transforms.</span>
                    </div>

                    <div className="form-field-group">
                      <label className="form-field-label">
                        <span>Diffie-Hellman Group</span>
                        <span className="pill-badge pill-sage">MODP</span>
                      </label>
                      <select
                        className="dataset-select"
                        value={config.dhGroup}
                        onChange={(e) => setConfig({ ...config, dhGroup: Number(e.target.value) })}
                      >
                        <option value={14}>Group 14 (MODP-2048) - NIST Compliant</option>
                        <option value={15}>Group 15 (MODP-3072) - NIST Compliant</option>
                        <option value={19} disabled>Group 19 (ECP-256) - BLOCKED (Missing charon plugin)</option>
                        <option value={2} disabled>Group 2 (MODP-1024) - BLOCKED (Deprecated by NIST)</option>
                      </select>
                      <span className="form-field-help">IKEv2 SA key exchange parameter.</span>
                    </div>

                    <div className="form-field-group">
                      <label className="form-field-label">Recipe Mode</label>
                      <select
                        className="dataset-select"
                        value={config.recipeMode}
                        onChange={(e) => setConfig({ ...config, recipeMode: e.target.value })}
                      >
                        <option value="standard">Standard Recipe (Fixed schedules & interval)</option>
                        <option value="varied">Varied Recipe (Randomized count 4-12, jitter 0.15-0.75s)</option>
                      </select>
                      <span className="form-field-help">Tests protocol generalization vs recipe shortcut risks.</span>
                    </div>

                    <div className="form-field-group">
                      <label className="form-field-label">
                        <span>Independent Sessions</span>
                        <span className="monospace" style={{ fontWeight: 700 }}>{config.sessions}</span>
                      </label>
                      <input
                        type="range"
                        min={1}
                        max={10}
                        step={1}
                        value={config.sessions}
                        onChange={(e) => setConfig({ ...config, sessions: Number(e.target.value) })}
                        style={{ accentColor: 'var(--accent-sage)', cursor: 'pointer' }}
                      />
                      <span className="form-field-help">Each session negotiates a fresh IKE_SA with distinct SPIs.</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
                    <button
                      type="button"
                      className="soc-btn primary"
                      onClick={handlePreflight}
                      disabled={preflightLoading}
                      style={{ backgroundColor: 'var(--accent-sage)', color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      {preflightLoading ? <Loader2 size={14} className="spin" /> : <ArrowRight size={14} />}
                      Run Preflight Verification
                    </button>
                  </div>
                </div>
              )}

              {/* Stage 2: Preflight Verification */}
              {wizardStage === 2 && preflightReport && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                        Preflight Verification Checklist
                      </h3>
                      <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                        Verifying testbed integrity, crypto proposals, and daemon concurrency locks.
                      </p>
                    </div>
                    <span className={`pill-badge ${preflightReport.canProceed ? 'pill-sage' : 'pill-coral'}`}>
                      {preflightReport.canProceed ? 'PREFLIGHT PASSED' : 'PREFLIGHT BLOCKED'}
                    </span>
                  </div>

                  <div className="preflight-check-list">
                    {preflightReport.checks.map((check, idx) => (
                      <div key={idx} className={`preflight-item ${check.passed ? 'passed' : 'blocked'}`}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          {check.passed ? (
                            <CheckCircle2 size={16} className="text-sage" />
                          ) : (
                            <XCircle size={16} className="text-coral" />
                          )}
                          <div>
                            <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)' }}>
                              {check.name}
                            </div>
                            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                              {check.details}
                            </div>
                          </div>
                        </div>
                        <span className={`pill-badge ${check.passed ? 'pill-sage' : 'pill-coral'}`}>
                          {check.passed ? 'PASS' : 'BLOCKED'}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    <button type="button" className="soc-btn" onClick={() => setWizardStage(1)}>
                      Back to Configuration
                    </button>
                    {preflightReport.canProceed ? (
                      <button
                        type="button"
                        className="soc-btn primary"
                        onClick={handleLaunchGeneration}
                        style={{ backgroundColor: 'var(--accent-sage)', color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: 6 }}
                      >
                        <Activity size={14} /> Launch Experiment
                      </button>
                    ) : (
                      <span style={{ fontSize: 12, color: 'var(--accent-coral)' }}>
                        Cannot proceed: resolve blocked requirements first.
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Stage 3 - 7: Active Experiment Execution & Results */}
              {wizardStage >= 3 && generationJob && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {jobError && <div className="dashboard-empty is-warning" role="alert">{jobError}</div>}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                    <div>
                      <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                        Job: {generationJob.datasetName} ({generationJob.jobId})
                      </h3>
                      <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                        Sessions: {generationJob.completedSessions} of {generationJob.totalSessions} completed ·
                        Status: <strong style={{ textTransform: 'uppercase' }}>{generationJob.status}</strong>
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {['RUNNING', 'CANCELLING'].includes(generationJob.status) && (
                        <button type="button" className="soc-btn" onClick={handleCancelJob} style={{ color: 'var(--accent-coral)' }}>
                          Cancel Job
                        </button>
                      )}
                      <span className={`pill-badge ${generationJob.status === 'COMPLETED' ? 'pill-sage' : generationJob.status === 'FAILED' ? 'pill-coral' : 'pill-amber'}`}>
                        {generationJob.status}
                      </span>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  {generationJob.progressPercent != null && Number.isFinite(Number(generationJob.progressPercent))
                    ? <div style={{ width: '100%', height: 6, background: '#E5E2DB', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${Math.max(0, Math.min(100, Number(generationJob.progressPercent)))}%`, height: '100%', background: generationJob.status === 'FAILED' ? 'var(--accent-coral)' : 'var(--accent-sage)', transition: 'width 0.3s ease' }} />
                    </div>
                    : <p className="inspector-message">Job progress percentage was not provided by the backend.</p>}

                  {/* Detailed Execution Stages */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
                    {generationJob.stages.map((st, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '10px 12px',
                          background: st.status === 'COMPLETED' ? 'var(--bg-card)' : st.status === 'IN_PROGRESS' ? '#FAF7F2' : '#FDFCFA',
                          border: `1px solid ${st.status === 'IN_PROGRESS' ? 'var(--accent-sage)' : 'var(--border-subtle)'}`,
                          borderRadius: 6,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          {st.status === 'COMPLETED' ? (
                            <CheckCircle2 size={15} className="text-sage" />
                          ) : st.status === 'IN_PROGRESS' ? (
                            <Loader2 size={15} className="text-sage spin" />
                          ) : (
                            <Clock size={15} color="var(--text-muted)" />
                          )}
                          <span style={{ fontSize: 12, fontWeight: st.status === 'IN_PROGRESS' ? 600 : 500, color: 'var(--text-primary)' }}>
                            {st.label}
                          </span>
                        </div>
                        <span className={`pill-badge ${st.status === 'COMPLETED' ? 'pill-sage' : st.status === 'IN_PROGRESS' ? 'pill-amber' : 'pill-slate'}`}>
                          {st.status}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Finalized Summary Card */}
                  {generationJob.status === 'COMPLETED' && (
                    <div style={{ padding: 14, background: '#FAF7F2', border: '1px solid var(--accent-sage-border)', borderRadius: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-sage)' }}>
                          Collection Finished
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                          Collected {generationJob.acceptedObservations} candidate observations across {generationJob.completedSessions} completed sessions. Admission: {generationJob.datasetAdmissionStatus || 'PENDING_VALIDATION'}.
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 8 }}>
                        {generationJob.generatedDatasetId && (
                          <button
                            type="button"
                            className="soc-btn"
                            onClick={() => handleInspect(generationJob.generatedDatasetId)}
                            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                          >
                            <FileText size={14} /> Inspect Dataset
                          </button>
                        )}
                        <button
                          type="button"
                          className="soc-btn primary"
                          onClick={() => {
                            setWizardStage(1);
                            setGenerationJob(null);
                          }}
                          style={{ backgroundColor: 'var(--accent-sage)', color: '#FFFFFF' }}
                        >
                          Generate Another
                        </button>
                      </div>
                    </div>
                  )}
                  {generationJob.logEvents?.length > 0 && (
                    <div style={{ padding: 10, border: '1px solid var(--border-subtle)', borderRadius: 4, maxHeight: 150, overflow: 'auto' }}>
                      <strong style={{ fontSize: 12 }}>Run log</strong>
                      {generationJob.logEvents.map((entry, idx) => (
                        <div key={`${entry.at}-${idx}`} style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                          {entry.at} · {entry.level} · {entry.message}
                        </div>
                      ))}
                    </div>
                  )}
                  {generationJob.artifacts?.length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      Evidence references: {generationJob.artifacts.length} experiment record(s). Dataset admission remains governed by manifest and evidence validation.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Section B: Dataset Registry Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div className="dataset-toolbar glass-toolbar">
            <div className="dataset-filter-group">
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Search size={14} style={{ position: 'absolute', left: 9, color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  className="dataset-search-input"
                  style={{ paddingLeft: 28 }}
                  placeholder="Search datasets, campaigns, IDs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              <select
                className="dataset-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="ALL">All Statuses</option>
                <option value="VALIDATED">Validated</option>
                <option value="UNVERIFIED">Unverified</option>
                <option value="SYNTHETIC_FIXTURE">Synthetic Fixture</option>
                <option value="BLOCKED">Blocked</option>
              </select>

              <select
                className="dataset-select"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
              >
                <option value="ALL">All Sources</option>
                <option value="testbed_campaign">Testbed Campaign</option>
                <option value="representative_sample">Representative Sample</option>
              </select>
            </div>

            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Showing {filteredDatasets.length} of {datasets.length} datasets
            </span>
          </div>

          {loading ? (
            <div className="dashboard-empty">
              <Loader2 size={18} className="spin text-sage" /> Loading registered datasets...
            </div>
          ) : filteredDatasets.length === 0 ? (
            <div className="dashboard-empty">
              No datasets match the current filter criteria.
            </div>
          ) : (
            <div className="dashboard-table-wrap">
              <table className="dashboard-table">
                <thead>
                  <tr>
                    <th>Dataset Name / ID</th>
                    <th>Source</th>
                    <th style={{ textAlign: 'right' }}>Sample Count</th>
                    <th>Class Distribution</th>
                    <th>Feature Schema</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th style={{ textAlign: 'center' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDatasets.map((ds) => {
                    const classEntries = Object.entries(ds.classDistribution || {});
                    const sampleOrigin = ds.originType?.trim() || 'unknown';
                    const displayStatus = getDatasetDisplayStatus(ds);
                    const provenanceBlocked = ds.source === 'representative_sample' && displayStatus === 'UNVERIFIED' && ds.status !== 'UNVERIFIED';
                    return (
                      <tr key={ds.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ds.name}</div>
                          <div className="monospace" style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                            {ds.id} {ds.campaignId ? `(${ds.campaignId.slice(0, 8)})` : ''}
                          </div>
                        </td>
                        <td>
                          <div>
                            <span className={`pill-badge ${ds.originType === 'synthetic_fixture' ? 'pill-amber' : ds.source === 'representative_sample' && sampleOrigin === 'unknown' ? 'pill-slate' : ds.source === 'representative_sample' ? 'pill-blue' : 'pill-slate'}`}>
                              {ds.originType === 'synthetic_fixture' ? 'Synthetic Fixture' : ds.source === 'representative_sample' ? (sampleOrigin === 'unknown' ? 'Sample · origin unknown' : `Sample · ${sampleOrigin}`) : ds.source === 'testbed_campaign' ? 'Testbed Campaign' : ds.source}
                            </span>
                            {ds.source === 'representative_sample' && sampleOrigin === 'unknown' && (
                              <div className="dataset-provenance-note">Source evidence is incomplete</div>
                            )}
                          </div>
                        </td>
                        <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                          {ds.sampleCount} <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 400 }}>flows</span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {classEntries.length === 0 ? (
                              <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                            ) : (
                              classEntries.map(([cls, cnt]) => {
                                const isIcmp = cls.includes('icmp');
                                const isTcp = cls.includes('tcp');
                                const isHttp = cls.includes('http');
                                const isSuspicious = cls.includes('suspicious') || cls.includes('attack') || cls.includes('scan') || cls.includes('burst') || cls.includes('beacon') || cls.includes('bulk') || cls.includes('auth');
                                const pillClass = isSuspicious ? 'pill-coral' : isIcmp ? 'pill-sage' : isTcp ? 'pill-amber' : isHttp ? 'pill-lilac' : 'pill-blue';
                                return (
                                  <span key={cls} className={`pill-badge ${pillClass}`} style={{ fontSize: 10 }}>
                                    {cls.replace('controlled_', '')}: {cnt}
                                  </span>
                                );
                              })
                            )}
                          </div>
                        </td>
                        <td>
                          <code className="monospace" style={{ fontSize: 11 }}>{ds.featureSchema}</code>
                        </td>
                        <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                          {ds.createdAt ? new Date(ds.createdAt).toLocaleDateString() : '—'}
                        </td>
                        <td>
                          <span
                            className={`pill-badge ${displayStatus === 'VALIDATED' ? 'pill-sage' : displayStatus === 'READY_FOR_REVIEW' ? 'pill-amber' : 'pill-coral'}`}
                            title={provenanceBlocked ? `API reported ${ds.status}; shown as UNVERIFIED because sample origin/provenance is not established.` : undefined}
                          >
                            {displayStatus}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'inline-flex', gap: 6 }}>
                            <button
                              type="button"
                              className="soc-btn"
                              style={{ padding: '3px 8px', fontSize: 11 }}
                              onClick={() => handleInspect(ds.id)}
                            >
                              Inspect
                            </button>
                            <a
                              className="soc-btn"
                              style={{ padding: '3px 8px', fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4 }}
                              href={getDatasetExportUrl(ds.id, 'csv')}
                              download={`${ds.id}.csv`}
                              title="Export CSV"
                            >
                              <Download size={12} /> CSV
                            </a>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Section: Inspection Drawer / Modal */}
        {inspectId && (
          <div className="dataset-modal-overlay" onClick={() => setInspectId(null)}>
            <div className="dataset-modal-panel" onClick={(e) => e.stopPropagation()}>
              <div className="dataset-modal-header">
                <div>
                  <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                    Dataset Inspection: {inspectDetails?.name || inspectId}
                  </h2>
                  <div className="monospace" style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>
                    ID: {inspectId} · Storage: {inspectDetails?.storageLocation || '—'}
                  </div>
                </div>
                <button
                  type="button"
                  className="soc-btn"
                  style={{ padding: '4px 8px' }}
                  onClick={() => setInspectId(null)}
                >
                  <X size={16} />
                </button>
              </div>

              <div className="dataset-modal-body">
                {inspectLoading ? (
                  <div className="dashboard-empty">
                    <Loader2 size={20} className="spin text-sage" /> Loading dataset details and sample records...
                  </div>
                ) : inspectDetails ? (
                  <>
                    {/* Metadata Summary Cards */}
                    <div className="dataset-overview-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
                      <div className="dataset-kpi-card">
                        <span className="dataset-kpi-label">Sample Count</span>
                        <span className="dataset-kpi-value">{inspectDetails.sampleCount}</span>
                        <span className="dataset-kpi-meta">unit: {inspectDetails.unit}</span>
                      </div>
                      <div className="dataset-kpi-card">
                        <span className="dataset-kpi-label">Feature Schema</span>
                        <span className="dataset-kpi-value" style={{ fontSize: 16 }}>{inspectDetails.featureSchema}</span>
                        <span className="dataset-kpi-meta">{inspectDetails.featureCount != null ? `${inspectDetails.featureCount} features reported by API` : 'Feature count unavailable'}</span>
                      </div>
                      <div className="dataset-kpi-card">
                        <span className="dataset-kpi-label">Validation Status</span>
                        <span className="dataset-kpi-value" style={{ fontSize: 16, color: inspectDetails.status === 'VALIDATED' ? 'var(--accent-sage)' : 'var(--accent-amber)' }}>
                          {inspectDetails.status}
                        </span>
                        <span className="dataset-kpi-meta">Evaluated under Phase 11 & 12 gates</span>
                      </div>
                      <div className="dataset-kpi-card">
                        <span className="dataset-kpi-label">SHA-256 Digest</span>
                        <code className="monospace" style={{ fontSize: 10.5, wordBreak: 'break-all', marginTop: 4 }}>
                          {inspectDetails.sha256 ? inspectDetails.sha256.slice(0, 16) + '...' : 'Pending recomputation'}
                        </code>
                        <span className="dataset-kpi-meta">Verified on disk</span>
                      </div>
                    </div>

                    {/* Quality & Leakage Audit Action */}
                    <div style={{ padding: 14, background: '#FAF7F2', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <div>
                          <h4 style={{ fontSize: 13, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                            Data Quality & Leakage Audit
                          </h4>
                          <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                            Checks row structure and evidence gates; session isolation is reported only when split evidence exists.
                          </p>
                        </div>
                        <button
                          type="button"
                          className="soc-btn primary"
                          onClick={() => handleRunQualityAudit(inspectId)}
                          disabled={validatingQuality}
                          style={{ backgroundColor: 'var(--accent-sage)', color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: 6 }}
                        >
                          {validatingQuality ? <Loader2 size={13} className="spin" /> : <ShieldCheck size={14} />}
                          Run Quality Audit
                        </button>
                      </div>

                      {qualityAuditResult && (
                        <div style={{ marginTop: 10, padding: 10, background: '#FFFFFF', border: '1px solid var(--border-medium)', borderRadius: 4, fontSize: 12 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                            <strong style={{ color: 'var(--text-primary)' }}>Quality Status: {qualityAuditResult.qualityStatus}</strong>
                            <span className="pill-badge pill-sage">{qualityAuditResult.featureSchemaCompliance}</span>
                          </div>
                          <ul style={{ paddingLeft: 16, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                            <li>Total Rows Audited: <strong>{qualityAuditResult.totalRows}</strong> across <strong>{qualityAuditResult.independentSessions}</strong> sessions</li>
                            <li>Missing / Non-finite Values: <strong>{qualityAuditResult.missingValuesCount}</strong></li>
                            <li>Duplicate Feature Vectors: <strong>{qualityAuditResult.duplicateVectorsCount}</strong></li>
                            <li>Target Contamination: {qualityAuditResult.leakageCheck.targetContamination}</li>
                            <li>Session Isolation: {qualityAuditResult.leakageCheck.sessionIsolation}</li>
                          </ul>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
                            Recommendation: {qualityAuditResult.recommendation}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Session-Level Split Summary */}
                    {inspectDetails.splitManifest && (
                      <div style={{ padding: 14, background: '#FAF7F2', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, flexWrap: 'wrap', gap: 6 }}>
                          <div>
                            <h4 style={{ fontSize: 13, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                              Session-Level Disjoint Splits (Leakage Prevention)
                            </h4>
                            <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                              Strategy: {inspectDetails.splitManifest.strategy || 'Deterministic GroupShuffleSplit by verified IKE_SA identity'}
                            </p>
                          </div>
                          <span className="pill-badge pill-slate">Split metadata available</span>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8, marginTop: 8 }}>
                          <div style={{ padding: 8, background: '#FFFFFF', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Train Split</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                              {inspectDetails.splitManifest.row_counts?.train ?? 0} <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--text-muted)' }}>flows</span>
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>
                              {inspectDetails.splitManifest.session_ids?.train?.length ?? 0} sessions
                            </div>
                          </div>
                          <div style={{ padding: 8, background: '#FFFFFF', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Validation Split</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                              {inspectDetails.splitManifest.row_counts?.validation ?? 0} <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--text-muted)' }}>flows</span>
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>
                              {inspectDetails.splitManifest.session_ids?.validation?.length ?? 0} sessions
                            </div>
                          </div>
                          <div style={{ padding: 8, background: '#FFFFFF', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Test Split</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                              {inspectDetails.splitManifest.row_counts?.test ?? 0} <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--text-muted)' }}>flows</span>
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>
                              {inspectDetails.splitManifest.session_ids?.test?.length ?? 0} sessions
                            </div>
                          </div>
                          <div style={{ padding: 8, background: '#FFFFFF', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Session Overlap</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-sage)' }}>
                              See manifest
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>
                              Overlap evidence
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Sample Records Table */}
                    <div>
                      <h4 style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px', color: 'var(--text-primary)' }}>
                        Sample Flow Records (First 15 Rows)
                      </h4>
                      {inspectDetails.sampleRows && inspectDetails.sampleRows.length > 0 ? (
                        <div className="dashboard-table-wrap" style={{ maxHeight: 320, overflow: 'auto' }}>
                          <table className="dashboard-table" style={{ fontSize: 11 }}>
                            <thead>
                              <tr>
                                {inspectDetails.columns.slice(0, 8).map((col) => (
                                  <th key={col}>{col}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {inspectDetails.sampleRows.map((row, idx) => (
                                <tr key={idx}>
                                  {inspectDetails.columns.slice(0, 8).map((col) => (
                                    <td key={col} className={col === 'label' || col === 'flow_id' ? 'monospace' : ''}>
                                      {row[col] ?? '—'}
                                    </td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="dashboard-empty">No sample records available for preview.</div>
                      )}
                    </div>

                    {/* Export Actions Footer */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 10, borderTop: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                        Export immutable dataset package for offline model validation.
                      </span>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <a
                          className="soc-btn"
                            href={getDatasetExportUrl(inspectId, 'zip')}
                            download={`${inspectId}.zip`}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                        >
                          <Download size={14} /> Download Dataset Package
                        </a>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="dashboard-empty">Dataset details not found.</div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
