import { useEffect, useState } from 'react';
import { Activity, BrainCircuit, Database, Sparkles } from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import { checkBackendStatus, fetchMlMetrics } from '../../utils/apiClient';

const MODELS = [
  { id: 'traffic_classifier', apiId: 'traffic_classifier', metricId: 'traffic_classifier', label: 'Traffic Classifier (Encrypted Apps)' },
  { id: 'attack_classifier', apiId: 'attack_classifier', metricId: 'attack_classifier', label: 'Attack Classifier — XGBoost (Threat Attribution)' },
  { id: 'random_forest', apiId: 'random_forest', metricId: 'random_forest', label: 'Random Forest Baseline (Comparative Evaluation)' },
  { id: 'isolation_forest', apiId: 'isolation_forest', label: 'Isolation Forest (Unsupervised Anomaly)' },
];

function formatPercent(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '—';
}

function EmptyState({ children }) {
  return <div className="dashboard-empty">{children}</div>;
}

export default function AiAnalysisView() {
  const { analysisResult, file, status, error: analysisError, analysisId } = usePcapAnalysis();
  const [modelInfo, setModelInfo] = useState(null);
  const [canonicalSchema, setCanonicalSchema] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([checkBackendStatus(), fetchMlMetrics()])
      .then(([statusResult, metricsResult]) => {
        if (cancelled) return;
        if (statusResult.status === 'fulfilled' && statusResult.value.online) {
          setModelInfo(statusResult.value.models);
          setCanonicalSchema(statusResult.value.canonicalFeatureSchema || []);
        } else {
          setError(statusResult.status === 'rejected'
            ? String(statusResult.reason)
            : statusResult.value.error || 'Backend model status is unavailable.');
        }
        if (metricsResult.status === 'fulfilled') {
          setMetrics(metricsResult.value);
        } else {
          setError((previous) => [previous, String(metricsResult.reason)].filter(Boolean).join(' '));
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const predictions = analysisResult?.flows || [];
  const shapFeatures = metrics?.shapImportance?.top_features || [];
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
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>AI &amp; Dual-ML Analysis</h2>
            <p>
              {file
                ? `Capture inference: ${file.name} · Session ID: ${analysisId || analysisResult?.analysisId || 'ANL-ACTIVE'}`
                : 'Observed capture data and predictions from backend model artifacts.'}
            </p>
            <p>Source: trained flow classifiers (traffic_classifier, attack_classifier) and offline evaluation artifacts.</p>
          </div>
          <BrainCircuit size={20} className="text-sage" aria-hidden="true" />
        </div>
        {error && <div className="dashboard-empty" role="alert">{error}</div>}
        {loading ? (
          <EmptyState>Loading model and evaluation information…</EmptyState>
        ) : (
          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Backend status</th>
                  <th>Offline accuracy</th>
                  <th>Offline macro F1</th>
                  <th>Features</th>
                  <th>Classes</th>
                </tr>
              </thead>
              <tbody>
                {MODELS.map((model) => {
                  const info = modelInfo?.[model.apiId];
                  const evaluation = model.metricId ? metrics?.metrics?.[model.metricId] : null;
                  return (
                    <tr key={model.id}>
                      <td>{model.label}</td>
                      <td>{info?.loaded ? 'Loaded' : info ? 'Not loaded' : '—'}</td>
                      <td>{evaluation ? formatPercent(evaluation.accuracy) : 'Unavailable'}</td>
                      <td>{evaluation ? formatPercent(evaluation.macro_f1) : 'Unavailable'}</td>
                      <td>{info?.features?.length ?? '—'}</td>
                      <td>{info?.classes?.length ? info.classes.join(', ') : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {!loading && metrics?.evaluationProvenance && (
          <p className="section-meta" style={{ marginTop: 10 }}>
            Offline evaluation: {metrics.evaluationProvenance.dataset}. {metrics.evaluationProvenance.method}
            {' '}{metrics.evaluationProvenance.limitations}
          </p>
        )}
        {!loading && (
          <details style={{ marginTop: 12 }}>
            <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
              Backend Canonical Feature Schema ({normalizedFeatures.length || 'unavailable'})
            </summary>
            {normalizedFeatures.length ? (
              <div className="dashboard-table-wrap" style={{ marginTop: 10 }}>
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      <th style={{ width: '5%' }}>#</th>
                      <th style={{ width: '22%' }}>Feature Name</th>
                      <th style={{ width: '15%' }}>Category</th>
                      <th style={{ width: '10%' }}>Data Type</th>
                      <th style={{ width: '12%' }}>Unit</th>
                      <th style={{ width: '36%' }}>Description / Extraction Semantics</th>
                    </tr>
                  </thead>
                  <tbody>
                    {normalizedFeatures.map((f, index) => (
                      <tr key={f.name || index}>
                        <td>{index + 1}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {f.name}
                        </td>
                        <td>
                          <span className="process-pill">{f.group || 'CANONICAL'}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{f.type || 'float'}</td>
                        <td style={{ color: 'var(--text-secondary)' }}>{f.unit || '—'}</td>
                        <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{f.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState>No canonical model input feature schema is available from the backend.</EmptyState>
            )}
          </details>
        )}
      </section>

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2><Activity size={15} /> Uploaded traffic inference</h2>
            <p>
              {analysisResult
                ? `Source: ${file?.name || analysisResult.filename || 'uploaded PCAP / CSV'} · backend inference`
                : 'Upload a PCAP or CSV in Traffic Analysis to run inference and inspect its results here.'}
            </p>
          </div>
        </div>
        {status === 'analyzing' && <EmptyState>Analyzing {file?.name || 'uploaded traffic'}…</EmptyState>}
        {status === 'error' && analysisError && <div className="dashboard-empty" role="alert">{analysisError}</div>}
        {!analysisResult ? (
          status === 'analyzing' || status === 'error'
            ? null
            : <EmptyState>No uploaded flow analysis is available in this session.</EmptyState>
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
            {inference?.status === 'insufficient_data' && (
              <div className="dashboard-empty" role="status">
                Insufficient Data for Prediction
                {inference.insufficientDataFlows > 0 && ` · ${inference.insufficientDataFlows} flow(s) lack required model features.`}
              </div>
            )}
            {inference?.status === 'unavailable' && (
              <div className="dashboard-empty" role="alert">
                Prediction Unavailable{inference.error ? `: ${inference.error}` : '.'}
              </div>
            )}
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ fontSize: '13px', marginBottom: '8px' }}>Observed and unsupported protocol properties</h3>
              <div className="dashboard-table-wrap">
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      <th>Property</th>
                      <th>Value / Status</th>
                      <th>Evidence source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(analysisResult.predictions || {}).map(([key, info]) => (
                      <tr key={key}>
                        <td style={{ textTransform: 'capitalize' }}>{key.replace(/([A-Z])/g, ' $1')}</td>
                        <td>{info?.value ?? (
                          <span style={{ color: 'var(--text-dim)' }}>
                            {info?.source === "Not supported by the current model" ? "Not supported by the current model" : "Insufficient Data"}
                          </span>
                        )}</td>
                        <td>
                          {info?.source === "ML Prediction" ? (
                            <span style={{ color: 'var(--cyan)' }}>ML Prediction</span>
                          ) : (
                            info?.source || '—'
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {predictions.length === 0 ? (
              <EmptyState>No flow records were extracted, so there is no flow input for ML inference.</EmptyState>
            ) : (
              <>
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
                                <span style={{ color: 'var(--amber)', fontSize: 12 }} title={flow.trafficPrediction?.outOfDistributionReason}>
                                  IKE Control Plane · Out of scope
                                </span>
                              ) : trafficStatus === 'success' && trafficLabel ? (
                                <span style={{ color: 'var(--cyan)' }}>{trafficLabel} · ML Profile</span>
                              ) : flow.trafficPrediction?.status === 'insufficient_data' ? (
                                <span style={{ color: 'var(--text-dim)' }}>Insufficient Data</span>
                              ) : (
                                <span style={{ color: 'var(--text-dim)' }}>Prediction Unavailable</span>
                              )}
                            </td>
                            <td>
                              {isOutOfDist ? (
                                <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>Not applicable</span>
                              ) : Number.isFinite(trafficProb) ? (
                                `${formatPercent(trafficProb)} · uncalibrated`
                              ) : (
                                'Not provided'
                              )}
                            </td>
                            <td>
                              {threatStatus === 'success' && threatLabel ? (
                                <span>{threatLabel} · XGBoost Attack Classifier</span>
                              ) : threatStatus === 'insufficient_data' ? (
                                <span style={{ color: 'var(--text-dim)' }}>Insufficient Data</span>
                              ) : (
                                <span style={{ color: 'var(--text-dim)' }}>Prediction Unavailable</span>
                              )}
                            </td>
                            <td>
                              {flow.isAnomaly == null ? (
                                'Unavailable'
                              ) : (
                                `${flow.isAnomaly ? 'Distribution Outlier' : 'Inlier'}${Number.isFinite(flow.anomalyScore) ? ` · raw score ${flow.anomalyScore}` : ''}`
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div style={{ marginTop: 12, fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.6 }}>
                  <strong>Operational Interpretation:</strong>
                  <ul style={{ paddingLeft: 18, marginTop: 4 }}>
                    <li><strong>Observed Protocol:</strong> Network/transport layer headers observed directly in the packet capture.</li>
                    <li><strong>Encrypted Traffic Profile:</strong> Inferred application class from side-channel packet length and timing features inside encrypted ESP tunnels. IKE control-plane negotiations are outside the domain of the encapsulated application payload model.</li>
                    <li><strong>Isolation Forest:</strong> Unsupervised outlier score (<code>score_samples</code>). Flags feature-space deviation from training baseline; an outlier flag is not proof of a malicious attack.</li>
                  </ul>
                </div>
              </>
            )}
          </>
        )}
      </section>

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2><Sparkles size={15} /> SHAP feature importance</h2>
            <p>Global feature importance from the saved SHAP analysis; this is not an explanation for the current capture.</p>
          </div>
          <Database size={16} color="var(--cyan)" aria-hidden="true" />
        </div>
        {shapFeatures.length === 0 ? (
          <EmptyState>No feature-importance report is available from the backend.</EmptyState>
        ) : (
          <>
          <p className="section-meta">
            {metrics?.shapProvenance?.dataset || 'Dataset provenance unavailable'}.
            {' '}{metrics?.shapProvenance?.scope || ''}
          </p>
          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th style={{ width: '32%' }}>Feature</th>
                  <th style={{ width: '48%' }}>Relative Impact Weight</th>
                  <th style={{ width: '20%', textAlign: 'right' }}>SHAP Value</th>
                </tr>
              </thead>
              <tbody>
                {(() => {
                  const maxShap = Math.max(...shapFeatures.map(f => Math.abs(f.shap_value || 0)), 0.001);
                  return shapFeatures.map((item) => {
                    const widthPct = Math.min(100, Math.max(3, Math.round((Math.abs(item.shap_value || 0) / maxShap) * 100)));
                    return (
                      <tr key={item.feature}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-primary)' }}>
                          {item.feature}
                        </td>
                        <td>
                          <div className="shap-bar-container">
                            <div className="shap-bar-fill" style={{ width: `${widthPct}%` }} />
                          </div>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, fontWeight: 600, textAlign: 'right', color: 'var(--cyan)' }}>
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
    </div>
  );
}
