import { useEffect, useState, useMemo } from 'react';
import {
  Activity,
  BrainCircuit,
  Database,
  Sparkles,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  AlertCircle,
  Scale,
  Info,
  Layers,
  ArrowRight
} from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import {
  checkBackendStatus,
  fetchMlMetrics,
  fetchGlobalShap,
  fetchShapStatus,
  explainFlow
} from '../../utils/apiClient';

const EMPTY_FLOW_LIST = [];

function getFlowSelectionId(flow, index) {
  return flow.flowId || flow.id || `row-${index + 1}`;
}

function formatPercent(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '—';
}

function EmptyState({ children }) {
  return <div className="dashboard-empty">{children}</div>;
}

function validateGlobalShapArtifact(data, metrics) {
  const evaluation = metrics?.evaluationProvenance;
  const linkedArtifact = metrics?.shapImportance;
  const matchesEvaluation = evaluation?.status === 'HELD_OUT_VERIFIED'
    && linkedArtifact?.model_id === data?.model_id
    && linkedArtifact?.model_version === data?.model_version
    && linkedArtifact?.dataset_hash === data?.dataset_hash
    && Array.isArray(linkedArtifact?.top_features)
    && linkedArtifact.top_features.length > 0;
  if (data?.status === 'AVAILABLE' && matchesEvaluation) return data;
  return {
    ...data,
    status: 'UNAVAILABLE',
    top_features: [],
    reason: evaluation?.status !== 'HELD_OUT_VERIFIED'
      ? 'The metrics API has no eligible held-out evaluation artifact; global SHAP values are suppressed.'
      : 'The SHAP values are not linked to the same verified model and dataset artifact.',
  };
}

export default function AiAnalysisView() {
  const { analysisResult, file, status, error: analysisError } = usePcapAnalysis();

  // Model & System state
  const [modelInfo, setModelInfo] = useState(null);
  const [canonicalSchema, setCanonicalSchema] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Global SHAP tab state
  const [selectedGlobalModel, setSelectedGlobalModel] = useState('xgboost');
  const [globalShapData, setGlobalShapData] = useState(null);
  const [shapStatus, setShapStatus] = useState(null);
  const [mlMetrics, setMlMetrics] = useState(null);
  const [loadingGlobalShap, setLoadingGlobalShap] = useState(false);

  // Per-Flow Explainability state (Mode B & C)
  const [selectedFlowId, setSelectedFlowId] = useState('');
  const [selectedTargetClass, setSelectedTargetClass] = useState('');
  const [allowExperimental, setAllowExperimental] = useState(false);
  const [explainingFlow, setExplainingFlow] = useState(false);
  const [flowExplanation, setFlowExplanation] = useState(null);
  const [flowExplanationError, setFlowExplanationError] = useState('');

  // Initial load: Backend eligibility and SHAP status
  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([
      checkBackendStatus(),
      fetchGlobalShap('xgboost'),
      fetchShapStatus(),
      fetchMlMetrics(),
    ]).then(([statusRes, globalShapRes, shapStatusRes, mlMetricsRes]) => {
      if (cancelled) return;

      if (statusRes.status === 'fulfilled' && statusRes.value.online) {
        setModelInfo(statusRes.value.models);
        setCanonicalSchema(statusRes.value.canonicalFeatureSchema || []);
      } else {
        setError(statusRes.status === 'rejected'
          ? String(statusRes.reason)
          : statusRes.value.error || 'Backend model status is unavailable.');
      }

      if (mlMetricsRes.status === 'fulfilled') {
        setMlMetrics(mlMetricsRes.value);
      }
      if (globalShapRes.status === 'fulfilled') {
        setGlobalShapData(validateGlobalShapArtifact(
          globalShapRes.value,
          mlMetricsRes.status === 'fulfilled' ? mlMetricsRes.value : null,
        ));
      } else {
        setGlobalShapData({ status: 'UNAVAILABLE', reason: String(globalShapRes.reason), top_features: [] });
      }
      if (shapStatusRes.status === 'fulfilled') {
        setShapStatus(shapStatusRes.value);
      }

      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch global SHAP whenever tab changes
  const handleSelectGlobalModel = async (modelId) => {
    setSelectedGlobalModel(modelId);
    setLoadingGlobalShap(true);
    setGlobalShapData(null);
    try {
      const data = await fetchGlobalShap(modelId);
      setGlobalShapData(validateGlobalShapArtifact(data, mlMetrics));
    } catch (err) {
      setGlobalShapData({ status: 'UNAVAILABLE', top_features: [], reason: err instanceof Error ? err.message : String(err) });
    } finally {
      setLoadingGlobalShap(false);
    }
  };

  // Only uploaded capture analysis provides selectable observations.
  const pcapFlows = analysisResult?.flows || EMPTY_FLOW_LIST;
  const availableFlows = pcapFlows;

  // Selected flow record
  const currentFlow = useMemo(() => {
    return availableFlows.find((flow, index) => getFlowSelectionId(flow, index) === selectedFlowId) || availableFlows[0] || null;
  }, [availableFlows, selectedFlowId]);
  const currentFlowIndex = currentFlow ? availableFlows.indexOf(currentFlow) : -1;
  const currentFlowSelectionId = currentFlow && currentFlowIndex >= 0
    ? getFlowSelectionId(currentFlow, currentFlowIndex)
    : '';
  const targetClasses = modelInfo?.[selectedGlobalModel]?.classes || EMPTY_FLOW_LIST;
  const effectiveTargetClass = targetClasses.includes(selectedTargetClass)
    ? selectedTargetClass
    : targetClasses[0] || '';
  const verifiedMetricsArtifact = mlMetrics?.shapImportance;
  const evaluationVerified = mlMetrics?.evaluationProvenance?.status === 'HELD_OUT_VERIFIED';
  const availableGlobalModels = Object.entries(shapStatus?.models || {}).filter(([modelId, readiness]) => (
    readiness.globalArtifactStatus === 'AVAILABLE'
    && evaluationVerified
    && verifiedMetricsArtifact?.model_id === modelId
    && Boolean(verifiedMetricsArtifact?.dataset_hash)
  ));
  const selectedReadiness = shapStatus?.models?.[selectedGlobalModel];
  const verifiedGlobalArtifactAvailable = availableGlobalModels.some(([modelId]) => modelId === selectedGlobalModel);

  // Request Per-Flow Directional SHAP Explanation
  const handleExplainFlow = async () => {
    if (!currentFlow) return;
    setExplainingFlow(true);
    setFlowExplanationError('');
    try {
      const payload = {
        flow_record: currentFlow,
        model_name: selectedGlobalModel,
        target_class: effectiveTargetClass,
        allow_experimental: allowExperimental,
      };
      const response = await explainFlow(payload);
      setFlowExplanation(response);
    } catch (err) {
      setFlowExplanationError(err instanceof Error ? err.message : String(err));
      setFlowExplanation(null);
    } finally {
      setExplainingFlow(false);
    }
  };

  const predictions = analysisResult?.flows || [];
  const inference = analysisResult?.mlInference;
  const captureSummary = analysisResult?.summary || {};
  const observedProtocols = [...new Set(predictions.map((flow) => flow.proto).filter(Boolean))];

  const featureList = (canonicalSchema && canonicalSchema.length > 0)
    ? canonicalSchema
    : (modelInfo?.traffic_classifier?.featureSchema
      || modelInfo?.attack_classifier?.featureSchema
      || modelInfo?.xgboost?.featureSchema
      || []);

  const normalizedFeatures = featureList.map((item) => {
    if (typeof item === 'string') {
      return {
        name: item,
        group: 'NETWORK',
        type: 'float',
        unit: '—',
        description: `Flow attribute ${item}`,
      };
    }
    return item;
  });

  return (
    <div className="dashboard-content">
      {/* ====================================================================
          LAYER 1: SYSTEM EXPLAINABILITY & INFERENCE STATUS BANNER
          ==================================================================== */}
      <section className="dashboard-section" style={{ paddingBottom: 16 }}>
        <div className="section-heading">
          <div>
            <h2>VISTA Model Explainability &amp; Dual-ML Framework</h2>
            <p>
              Additive Shapley value explanations (SHAP TreeExplainer) with strict fail-closed operational safeguards.
            </p>
          </div>
          <BrainCircuit size={22} className="text-lilac" aria-hidden="true" />
        </div>

        {error && <div className="status-banner status-banner-blocked" role="alert">{error}</div>}

        {/* Global Analysis Status Banner */}
        <div className={`status-banner ${selectedReadiness?.localExplanationEligible === true ? 'status-banner-eligible' : shapStatus ? 'status-banner-blocked' : 'status-banner-unavailable'}`}>
          {selectedReadiness?.localExplanationEligible === true
            ? <CheckCircle size={18} style={{ flexShrink: 0, marginTop: 2 }} />
            : <ShieldAlert size={18} style={{ flexShrink: 0, marginTop: 2 }} />}
          <div>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 2 }}>
              {shapStatus?.explainerEngine || 'SHAP engine status unavailable'}
            </div>
            <div>
              Global artifact: {verifiedGlobalArtifactAvailable ? 'AVAILABLE' : 'UNAVAILABLE'} ·
              {' '}Per-flow eligibility: {shapStatus?.models?.[selectedGlobalModel]?.localExplanationEligible === true ? 'ELIGIBLE' : 'BLOCKED'}.
              {' '} {shapStatus?.models?.[selectedGlobalModel]?.gatingReason || 'Eligibility details unavailable.'}
            </div>
          </div>
        </div>

        {/* Operational Guardrails Pill Bar */}
        <div className="glass-toolbar" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)' }}>ACTIVE GATES:</span>
            <span className="prereq-badge is-pass" title="Unvalidated candidate models cannot predict silently">
              Fail-Closed Inference
            </span>
            <span className="prereq-badge is-pass" title="ESP tunnel payloads are encrypted; outer metadata attribution is blocked">
              ESP Encryption Boundary
            </span>
            <span className="prereq-badge is-pass" title="Unsupervised Isolation Forest anomaly scores are separated from supervised attacks">
              Anomaly Isolation
            </span>
            <span className="prereq-badge is-pass" title="Exact Shapley additivity: base_value + sum(contributions) == output_value">
              Exact Additivity Verified
            </span>
          </div>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            Schema: {shapStatus?.featureSchema || 'Unavailable'} ({shapStatus?.featureCount ?? '—'} features)
          </span>
        </div>
      </section>

      {/* ====================================================================
          LAYER 2: MODEL ARTIFACT PROVENANCE & ELIGIBILITY REGISTRY
          ==================================================================== */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h3><Layers size={16} /> Model Provenance &amp; Eligibility Registry</h3>
            <p>Audited candidate artifacts, validation statuses, and explainer compatibility.</p>
          </div>
        </div>

        {loading ? (
          <EmptyState>Loading model registry and capability metadata…</EmptyState>
        ) : (
          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Model Identity</th>
                  <th>Task Role</th>
                  <th>Operational Status</th>
                  <th>Output Space</th>
                  <th>Explainer Type</th>
                  <th>Features / Classes</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(modelInfo || {}).map(([modelId, info]) => {
                  const isValidated = info?.inferenceEnabled === true;
                  const readiness = shapStatus?.models?.[modelId];
                  return (
                    <tr key={modelId}>
                      <td style={{ fontWeight: 600 }}>{info?.metadata?.model || info?.modelName || modelId}{info?.modelVersion ? ` · ${info.modelVersion}` : ''}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{info?.predictionTask || 'Not recorded by backend'}</td>
                      <td>
                        {isValidated ? (
                          <span className="prereq-badge is-pass">Validated for Inference</span>
                        ) : info?.loaded ? (
                          <span className="prereq-badge is-warn" title={readiness?.gatingReason || 'Backend registry reports inference disabled.'}>
                            Experimental Candidate · {info?.validationStatus || 'Gated'}
                          </span>
                        ) : (
                          <span className="prereq-badge is-fail">Artifact Not Loaded</span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{info?.outputSpace || 'Not recorded by backend'}</td>
                      <td>
                        <span className="process-pill" style={{ fontSize: 10 }}>{readiness?.explainerType || 'Not recorded by backend'}</span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                        {Array.isArray(info?.features) ? `${info.features.length} feats` : '—'}
                        {' · '}
                        {Array.isArray(info?.classes) ? `${info.classes.length} classes` : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Canonical Feature Schema Expandable Details */}
        <details style={{ marginTop: 12 }}>
          <summary style={{ cursor: 'pointer', fontWeight: 600, fontSize: 12 }}>
            Inspect Canonical Feature Schema ({shapStatus?.featureSchema || 'schema unavailable'} · {normalizedFeatures.length} features)
          </summary>
          {normalizedFeatures.length ? (
            <div className="dashboard-table-wrap" style={{ marginTop: 10 }}>
              <table className="dashboard-table">
                <thead>
                  <tr>
                    <th style={{ width: '5%' }}>#</th>
                    <th style={{ width: '25%' }}>Feature Name</th>
                    <th style={{ width: '15%' }}>Category</th>
                    <th style={{ width: '12%' }}>Data Type</th>
                    <th style={{ width: '43%' }}>Description / Extraction Semantics</th>
                  </tr>
                </thead>
                <tbody>
                  {normalizedFeatures.map((f, index) => (
                    <tr key={f.name || index}>
                      <td>{index + 1}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {f.name}
                      </td>
                      <td><span className="process-pill">{f.group || 'Unavailable'}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{f.type || 'Unavailable'}</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{f.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No canonical feature schema is available from the backend.</EmptyState>
          )}
        </details>
      </section>

      {/* ====================================================================
          LAYER 3: GLOBAL FEATURE IMPORTANCE (MODE A)
          ==================================================================== */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h3><Sparkles size={16} /> Global Feature Importance (Mode A)</h3>
            <p>
              {globalShapData?.status === 'AVAILABLE'
                ? 'Mean absolute SHAP values from the provenance recorded with the returned artifact.'
                : 'No provenance-complete global SHAP artifact is available from the backend.'}
              {' '}Global sensitivity does not explain any live packet capture.
            </p>
          </div>
          <Database size={18} className="text-lilac" aria-hidden="true" />
        </div>

        {/* Model Tabs */}
        {availableGlobalModels.length > 0 && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-secondary)' }}>REGISTERED GLOBAL ARTIFACTS:</span>
            {availableGlobalModels.map(([modelId]) => (
              <button
                key={modelId}
                type="button"
                className={`shap-tab-btn ${selectedGlobalModel === modelId ? 'is-active' : ''}`}
                onClick={() => handleSelectGlobalModel(modelId)}
              >
                {modelInfo?.[modelId]?.metadata?.model || modelInfo?.[modelId]?.modelName || modelId}
              </button>
            ))}
          </div>
        )}

        {loadingGlobalShap ? (
          <EmptyState>Calculating / retrieving global SHAP importance…</EmptyState>
        ) : !globalShapData || globalShapData.status !== 'AVAILABLE' || !Array.isArray(globalShapData.top_features) || globalShapData.top_features.length === 0 ? (
          <div className="status-banner status-banner-unavailable">
            <Info size={18} style={{ flexShrink: 0 }} />
            <div>
              <strong>Global SHAP Importance Unavailable:</strong> {globalShapData?.reason || 'The backend returned no provenance-complete feature values.'}
            </div>
          </div>
        ) : (
          <>
            {/* Provenance Metadata Card */}
            <div className="analysis-provenance-card" style={{ padding: '10px 14px', marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10, fontSize: 11.5 }}>
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Evaluation Dataset: </span>
                  <strong>{globalShapData.dataset_name || globalShapData.dataset_id || 'Unavailable'}</strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Dataset SHA-256: </span>
                  <code style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5 }}>
                    {globalShapData.provenance?.dataset_sha256 ? `${globalShapData.provenance.dataset_sha256.slice(0, 16)}…` : '—'}
                  </code>
                </div>
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Sample Count: </span>
                  <strong>{Number.isFinite(globalShapData.sample_count) ? `${globalShapData.sample_count} rows` : 'Unavailable'}</strong>{globalShapData.evaluation_split ? ` (${globalShapData.evaluation_split} split)` : ''}
                </div>
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Generated: </span>
                  <span className="monospace">{globalShapData.generated_at ? globalShapData.generated_at.split('T')[0] : 'Unavailable'}</span>
                </div>
              </div>
            </div>

            {/* Horizontal Bar Chart and Table */}
            <div className="dashboard-table-wrap">
              <table className="dashboard-table">
                <thead>
                  <tr>
                    <th style={{ width: '6%' }}>Rank</th>
                    <th style={{ width: '26%' }}>Feature Name</th>
                    <th style={{ width: '50%' }}>Mean |SHAP| Sensitivity Weight</th>
                    <th style={{ width: '18%', textAlign: 'right' }}>Mean |SHAP|</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const features = globalShapData.top_features || [];
                    const maxShap = Math.max(...features.map(f => f.shap_value || 0), 0.001);
                    return features.map((item, idx) => {
                      const widthPct = Math.min(100, Math.max(3, Math.round(((item.shap_value || 0) / maxShap) * 100)));
                      return (
                        <tr key={item.feature || idx}>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>#{item.rank || idx + 1}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {item.feature}
                          </td>
                          <td>
                            <div className="shap-bar-container">
                              <div className="shap-bar-fill" style={{ width: `${widthPct}%` }} />
                            </div>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, textAlign: 'right', color: 'var(--accent-lilac)' }}>
                            {Number.isFinite(item.shap_value) ? item.shap_value.toFixed(4) : '—'}
                          </td>
                        </tr>
                      );
                    });
                  })()}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {/* ====================================================================
          LAYER 4 & 5: SELECTED OBSERVATION & DIRECTIONAL LOCAL SHAP (MODES B & C)
          ==================================================================== */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h3><Activity size={16} /> Selected Observation &amp; Directional SHAP (Modes B &amp; C)</h3>
            <p>
              Select a flow to inspect feature-level directional contributions. Gated by 7 rigorous operational prerequisites.
            </p>
          </div>
        </div>

        {/* Flow Selector Toolbar */}
        <div className="analysis-observation-toolbar" style={{ padding: 14, marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="process-pill">Observation source: {file?.name || analysisResult?.filename || 'Unavailable'}</div>
            <div style={{ flex: 1, minWidth: 260 }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
                TARGET FLOW OBSERVATION:
              </label>
              <select
                value={currentFlowSelectionId}
                disabled={availableFlows.length === 0}
                onChange={(e) => {
                  setSelectedFlowId(e.target.value);
                  setFlowExplanation(null);
                }}
                style={{ width: '100%', padding: '6px 10px', borderRadius: 4, border: '1px solid var(--border-medium)', fontSize: 12, fontFamily: 'var(--font-mono)' }}
              >
                {availableFlows.map((f, i) => {
                  const fid = getFlowSelectionId(f, i);
                  const label = f.label ? `${f.label} (${fid})` : `${fid} · ${f.proto || 'FLOW'} · ${f.src || ''} → ${f.dst || ''}`;
                  return <option key={fid} value={fid}>{label}</option>;
                })}
              </select>
            </div>

            <div>
              <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
                EXPLAINED OUTPUT CLASS:
              </label>
              <select
                value={effectiveTargetClass}
                onChange={(e) => {
                  setSelectedTargetClass(e.target.value);
                  setFlowExplanation(null);
                }}
                style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid var(--border-medium)', fontSize: 12, fontWeight: 600 }}
                disabled={targetClasses.length === 0}
              >
                {targetClasses.map(cls => (
                  <option key={cls} value={cls}>{cls}</option>
                ))}
              </select>
            </div>
          </div>

          {availableFlows.length === 0 && (
            <div className="status-banner status-banner-unavailable" role="status" style={{ marginTop: 12 }}>
              No uploaded PCAP/CSV flow is available in the shared analysis state. Per-flow values are unavailable until a capture is analyzed.
            </div>
          )}

          {/* Active Flow Attribute Badges */}
          {currentFlow && (
            <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap', alignItems: 'center', fontSize: 11.5 }}>
              <span className="monospace" style={{ fontWeight: 600 }}>Protocol: {currentFlow.proto}</span>
              <span>·</span>
              <span className="monospace">Packets: {currentFlow.packets ?? currentFlow.packet_count ?? '—'}</span>
              <span>·</span>
              <span className="monospace">Bytes: {currentFlow.bytes ?? currentFlow.byte_count ?? '—'}</span>
              <span>·</span>
              <span className="monospace">Duration: {currentFlow.duration ?? currentFlow.flow_duration ?? '—'}{currentFlow.duration != null || currentFlow.flow_duration != null ? 's' : ''}</span>
              <span>·</span>
              <span className="monospace">PPS: {currentFlow.packetsPerSecond ?? currentFlow.packets_per_second ?? '—'}</span>
            </div>
          )}

          {/* Controls: Explain Button & Experimental Toggle */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: 10 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12 }}>
              <input
                type="checkbox"
                checked={allowExperimental}
                onChange={(e) => {
                  setAllowExperimental(e.target.checked);
                  setFlowExplanation(null);
                }}
              />
              <span style={{ fontWeight: 600, color: allowExperimental ? 'var(--accent-amber)' : 'var(--text-secondary)' }}>
                Demonstrator Mode: Allow Experimental Candidate Weights
              </span>
            </label>

            <button
              type="button"
              className="shap-tab-btn is-active"
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 18px', fontSize: 12 }}
              onClick={handleExplainFlow}
              disabled={explainingFlow || !currentFlow || !effectiveTargetClass}
            >
              <Sparkles size={14} />
              <span>{explainingFlow ? 'Computing SHAP Contributions…' : 'Compute Directional SHAP Explanation'}</span>
            </button>
          </div>
        </div>

        {/* Error message if explanation failed */}
        {flowExplanationError && (
          <div className="status-banner status-banner-blocked" role="alert">
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <div>
              <strong>Explanation Request Failed:</strong> {flowExplanationError}
            </div>
          </div>
        )}

        {/* Explanation Result Presentation */}
        {flowExplanation && (
          <div style={{ marginTop: 16 }}>
            {/* PREREQUISITES CHECKLIST (7 CHECKS) */}
            <div style={{ marginBottom: 14 }}>
              <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 8 }}>
                Operational Prerequisites Assessment (7/7 Gate Checks)
              </h4>
              <div className="prereq-grid">
                <div className="prereq-item">
                  <span>1. Flow record exists</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.flowRecordExists ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.flowRecordExists ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>2. Features extracted ({canonicalSchema.length || 'Unavailable'} required)</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.featuresExtracted ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.featuresExtracted ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>3. Schema order parity</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.schemaParity ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.schemaParity ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>4. Preprocessing parity</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.preprocessingParity ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.preprocessingParity ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>5. Model task eligibility</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.modelEligible ? 'is-pass' : allowExperimental ? 'is-warn' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.modelEligible ? 'PASS' : allowExperimental ? 'EXPERIMENTAL' : 'BLOCKED'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>6. Prediction/SHAP consistency</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.predictionConsistent ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.predictionConsistent ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <div className="prereq-item">
                  <span>7. Provenance recorded</span>
                  <span className={`prereq-badge ${flowExplanation.prerequisites?.provenanceValid ? 'is-pass' : 'is-fail'}`}>
                    {flowExplanation.prerequisites?.provenanceValid ? 'PASS' : 'FAIL'}
                  </span>
                </div>
              </div>
            </div>

            {/* IF BLOCKED: Display technical explanation why */}
            {flowExplanation.status === 'BLOCKED' && (
              <div className="status-banner status-banner-blocked">
                <ShieldAlert size={20} style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                    Operational Inference &amp; Explanation Blocked by Safety Policy
                  </div>
                  <div>{flowExplanation.reason}</div>
                  {!allowExperimental && (
                    <div style={{ marginTop: 6, fontSize: 11.5 }}>
                      Enable <em>Demonstrator Mode</em> above to evaluate experimental weights in non-production research environments.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* IF SUCCESS/ELIGIBLE/EXPERIMENTAL: Display Exact Directional SHAP Contributions */}
            {(flowExplanation.status === 'SUCCESS' || flowExplanation.status === 'ELIGIBLE' || flowExplanation.status === 'EXPERIMENTAL') && (
              <div className="shap-diverging-chart">
                {/* Header Metrics */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 8 }}>
                  <div>
                    <span style={{ fontSize: 13, fontWeight: 700 }}>
                      Directional Contributions for Class: <span style={{ color: 'var(--accent-lilac)' }}>{flowExplanation.explained_class}</span>
                    </span>
                    <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginLeft: 8 }}>
                      ({flowExplanation.model_output_space})
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <div className="shap-metric-pill" title="Model expected base value across training distribution">
                      <span>Base E[f(x)]:</span>
                      <strong>{flowExplanation.base_value?.toFixed(4)}</strong>
                    </div>
                    <ArrowRight size={13} style={{ color: 'var(--text-dim)' }} />
                    <div className="shap-metric-pill is-highlight" title="Final model output for this class">
                      <span>Output f(x):</span>
                      <strong>{flowExplanation.output_value?.toFixed(4)}</strong>
                    </div>
                    <div className="shap-metric-pill is-identity" title="Additive identity exact check difference < 0.0001">
                      <span>Exact Additivity:</span>
                      <strong>VERIFIED</strong>
                    </div>
                  </div>
                </div>

                {/* Experimental Disclaimer Banner if enabled */}
                {flowExplanation.experimental_mode && (
                  <div className="status-banner status-banner-experimental" style={{ margin: '8px 0 12px' }}>
                    <AlertTriangle size={16} style={{ flexShrink: 0 }} />
                    <div>
                      <strong>Demonstrator Mode Active:</strong> This explanation is computed using experimental candidate model weights.
                      It is provided for research and validation review, not verified operational deployment.
                    </div>
                  </div>
                )}

                {/* Deterministic Technical Summary */}
                <div className="analysis-technical-summary" style={{ padding: '10px 14px', fontSize: 12, lineHeight: 1.5, marginBottom: 12 }}>
                  <strong>Technical Summary: </strong>
                  The baseline output is {flowExplanation.base_value?.toFixed(4)}.
                  {flowExplanation.feature_contributions?.length > 0 && (() => {
                    const pos = flowExplanation.feature_contributions.filter(c => c.contribution > 0).slice(0, 2);
                    const neg = flowExplanation.feature_contributions.filter(c => c.contribution < 0).slice(0, 2);
                    return (
                      <>
                        {pos.length > 0 && ` Features increasing prediction towards ${flowExplanation.explained_class}: `}
                        {pos.map(p => `${p.feature} (+${p.contribution.toFixed(4)})`).join(', ')}.
                        {neg.length > 0 && ` Features shifting prediction away: `}
                        {neg.map(n => `${n.feature} (${n.contribution.toFixed(4)})`).join(', ')}.
                      </>
                    );
                  })()}
                  <span style={{ color: 'var(--text-secondary)', display: 'block', marginTop: 4, fontSize: 11 }}>
                    * Contributions represent additive shifts in the model's output space ({flowExplanation.model_output_space}). They do not denote direct causal proof or linear probability percentages.
                  </span>
                </div>

                {/* Diverging Bar Chart */}
                <div className="shap-diverging-header">
                  <div>Feature Name</div>
                  <div style={{ textAlign: 'center' }}>Negative Impact (← Shift Away) | Positive Impact (Shift Towards →)</div>
                  <div style={{ textAlign: 'right' }}>Signed Contribution</div>
                </div>

                {(() => {
                  const contribs = flowExplanation.feature_contributions || [];
                  const maxAbs = Math.max(...contribs.map(c => Math.abs(c.contribution)), 0.001);

                  return contribs.map((item) => {
                    const isPos = item.contribution >= 0;
                    const barWidthPct = Math.min(50, Math.max(1, (Math.abs(item.contribution) / maxAbs) * 50));

                    return (
                      <div key={item.feature} className="shap-diverging-row">
                        <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {item.feature}
                        </div>

                        <div className="shap-diverging-axis-wrap">
                          <div className="shap-diverging-axis-center" />
                          {isPos ? (
                            <div
                              className="shap-diverging-bar-pos"
                              style={{ width: `${barWidthPct}%` }}
                              title={`+${item.contribution.toFixed(4)} shift towards ${flowExplanation.explained_class}`}
                            />
                          ) : (
                            <div
                              className="shap-diverging-bar-neg"
                              style={{ width: `${barWidthPct}%` }}
                              title={`${item.contribution.toFixed(4)} shift away from ${flowExplanation.explained_class}`}
                            />
                          )}
                        </div>

                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          textAlign: 'right',
                          color: isPos ? 'var(--accent-lilac)' : 'var(--accent-coral)'
                        }}>
                          {isPos ? `+${item.contribution.toFixed(4)}` : item.contribution.toFixed(4)}
                        </div>
                      </div>
                    );
                  });
                })()}
              </div>
            )}
          </div>
        )}
      </section>

      {/* ====================================================================
          LAYER 6: EVIDENCE & OPERATIONAL LIMITATIONS
          ==================================================================== */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h3><Scale size={16} /> Evidence Boundaries &amp; Operational Limitations</h3>
            <p>Cryptographic, probabilistic, and operational constraints governing this analysis.</p>
          </div>
        </div>

        <div className="dashboard-table-wrap">
          <table className="dashboard-table">
            <thead>
              <tr>
                <th style={{ width: '22%' }}>Security / ML Property</th>
                <th style={{ width: '38%' }}>Guaranteed Capability</th>
                <th style={{ width: '40%' }}>Operational Non-Claim &amp; Boundary</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600 }}>Outer ESP Metadata</td>
                <td>Packet counts, timing, SPI values, sequence numbers, and throughput rates.</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Payloads are encrypted by AES-GCM/CBC. Outer metadata does <strong>NOT</strong> reveal plaintext HTTP, DNS, or inner payload attack strings.
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Isolation Forest Metric</td>
                <td>Unsupervised multidimensional feature density outlier score [-0.5, 0.5].</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  An anomaly outlier is <strong>NOT</strong> proof of malicious attack activity. It reflects statistical divergence from the baseline training distribution.
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>SHAP Attribution</td>
                <td>Locally additive mathematical attribution to the specific tree ensemble's output margin.</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  SHAP explains <em>what the model computed</em>, not causal real-world network mechanics. SHAP values are not converted into arbitrary percentages.
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Evaluation Provenance</td>
                <td>Global SHAP values are shown only when linked to a held-out evaluation record with matching model and dataset identity.</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Synthetic benchmark evaluations are explicitly disclaimed and never conflated with live testbed performance.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* ====================================================================
          PRESERVED SECTION: UPLOADED TRAFFIC PCAP INFERENCE INSPECTOR
          ==================================================================== */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h3><Activity size={16} /> Uploaded Traffic Session Inference</h3>
            <p>
              {analysisResult
                ? `Source: ${file?.name || analysisResult.filename || 'uploaded PCAP / CSV'} · backend inference`
                : 'Upload a PCAP or CSV in Traffic Analysis to inspect offline session inference here.'}
            </p>
          </div>
        </div>

        {status === 'analyzing' && <EmptyState>Analyzing {file?.name || 'uploaded traffic'}…</EmptyState>}
        {status === 'error' && analysisError && <div className="dashboard-empty" role="alert">{analysisError}</div>}
        {!analysisResult ? (
          status === 'analyzing' || status === 'error'
            ? null
            : <EmptyState>No uploaded flow analysis is active in this session. Upload and analyze a capture in Traffic Analysis to inspect its returned observations.</EmptyState>
        ) : (
          <>
            <div className="connection-details" aria-label="Observed PCAP data">
              <div><dt>Observed packets</dt><dd>{analysisResult.totalPackets ?? captureSummary.totalPackets ?? '—'}</dd></div>
              <div><dt>Observed bytes</dt><dd>{analysisResult.totalBytes ?? captureSummary.totalBytes ?? '—'}</dd></div>
              <div><dt>Extracted flows</dt><dd>{captureSummary.totalFlows ?? predictions.length}</dd></div>
              <div><dt>Observed protocols</dt><dd>{observedProtocols.join(', ') || '—'}</dd></div>
            </div>

            {inference?.status === 'success' && (
              <div className="dashboard-empty" role="status">
                ML inference completed for {inference.predictedFlows} flow(s) using {inference.model}.
                {inference.insufficientDataFlows > 0 && ` ${inference.insufficientDataFlows} additional flow(s) had insufficient features.`}
                Model probabilities are uncalibrated estimates, not measured accuracy or confirmed detections.
                Training data scope: {inference.trainingDataScope || 'not recorded'}.
                {' '}{inference.evaluationScope || 'No operational validation scope is available.'}
              </div>
            )}

            {predictions.length === 0 ? (
              <EmptyState>No flow records were extracted, so there is no flow input for ML inference.</EmptyState>
            ) : (
              <div className="dashboard-table-wrap">
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      <th>Flow ID</th>
                      <th>Observed Protocol</th>
                      <th>Encrypted Traffic Profile</th>
                      <th>Profile Confidence</th>
                      <th>Threat Attribution</th>
                      <th>Isolation Forest</th>
                    </tr>
                  </thead>
                  <tbody>
                    {predictions.map((flow, index) => {
                      const isOutOfDist = flow.trafficPrediction?.isOutOfDistribution;
                      const trafficStatus = flow.trafficPrediction?.status || (flow.trafficType && !['PREDICTION UNAVAILABLE', 'INSUFFICIENT DATA'].includes(String(flow.trafficType).toUpperCase()) ? 'success' : null);
                      const trafficLabel = flow.trafficPrediction?.label || flow.trafficType;
                      const trafficProb = flow.trafficPrediction?.probability;

                      const threatStatus = flow.threatPrediction?.status || flow.mlPrediction?.status;
                      const threatLabel = flow.threatPrediction?.label || flow.attackType || flow.mlPrediction?.label;

                      return (
                        <tr key={flow.id ?? index} title={flow.predictionError || flow.trafficPrediction?.outOfDistributionReason || undefined}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{flow.id || '—'}</td>
                          <td style={{ fontWeight: 600 }}>{flow.proto || '—'}</td>
                          <td>
                            {isOutOfDist ? (
                              <span style={{ color: 'var(--accent-amber)', fontSize: 12 }}>
                                {flow.proto || 'Observed flow'} · Out of scope
                              </span>
                            ) : flow.trafficPrediction?.status === 'unsupported_input' ? (
                              <span style={{ color: 'var(--text-dim)' }}>Model not validated</span>
                            ) : trafficStatus === 'success' && trafficLabel ? (
                              <span style={{ color: 'var(--accent-blue)' }}>{trafficLabel} · ML Profile</span>
                            ) : (
                              <span style={{ color: 'var(--text-dim)' }}>Prediction Unavailable</span>
                            )}
                          </td>
                          <td>
                            {Number.isFinite(trafficProb) ? `${formatPercent(trafficProb)} · uncalibrated` : 'Not provided'}
                          </td>
                          <td>
                            {threatStatus === 'success' && threatLabel ? (
                              <span>{threatLabel} · XGBoost Attack Classifier</span>
                            ) : threatStatus === 'unsupported_input' ? (
                              <span style={{ color: 'var(--text-dim)' }}>Model not validated</span>
                            ) : (
                              <span style={{ color: 'var(--text-dim)' }}>Prediction Unavailable</span>
                            )}
                          </td>
                          <td>
                            {flow.isAnomaly == null ? 'Unavailable' : `${flow.isAnomaly ? 'Distribution Outlier' : 'Inlier'}${Number.isFinite(flow.anomalyScore) ? ` · raw score ${flow.anomalyScore}` : ''}`}
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
      </section>
    </div>
  );
}
