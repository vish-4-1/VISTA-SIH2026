import { useEffect, useState } from 'react';
import { AlertTriangle, AlertCircle, CheckCircle, Shield, Database, Cpu } from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import { fetchThreats } from '../../utils/apiClient';

const SEVERITY_CLASS = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

function severityBadgeClass(severity) {
  return SEVERITY_CLASS[String(severity || '').toLowerCase()] || 'low';
}

function provenanceBadgeClass(source) {
  if (source === 'ML Prediction') return 'success';
  if (source === 'Dataset ground-truth label') return 'low';
  return 'low';
}

function EmptyState({ children, role = 'status' }) {
  return <div className="dashboard-empty" role={role}>{children}</div>;
}

export default function ThreatIntelligenceView() {
  const { analysisResult, file, status: analysisStatus, error: analysisError } = usePcapAnalysis();
  const [dataState, setDataState] = useState({
    threats: [],
    loading: true,
    fetchError: '',
    dataSource: '',
  });

  useEffect(() => {
    let cancelled = false;

    // Don't fetch while analysis is still in progress or has errored before completing.
    if (file && (analysisStatus === 'analyzing' || analysisStatus === 'error')) {
      return undefined;
    }

    const flows = analysisResult?.flows;
    fetchThreats(flows)
      .then((results) => {
        if (cancelled) return;
        setDataState({
          threats: Array.isArray(results) ? results : [],
          loading: false,
          fetchError: '',
          dataSource: flows
            ? file?.name || 'Uploaded PCAP / CSV inference'
            : 'Repository flow dataset (realFlows.json)',
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setDataState((prev) => ({
            ...prev,
            loading: false,
            fetchError: err instanceof Error ? err.message : String(err),
          }));
        }
      });

    return () => { cancelled = true; };
  }, [analysisResult, file, analysisStatus, analysisError]);

  const { threats, loading, fetchError, dataSource } = dataState;

  const flows = analysisResult?.flows || [];
  const mlInference = analysisResult?.mlInference || {};
  const isLiveAnalysis = Boolean(analysisResult?.flows);
  const isBlocked = Boolean(file && (analysisStatus === 'analyzing' || analysisStatus === 'error'));
  const isLoading = loading && !isBlocked;

  // Flow classification statistics (when live analysis is active)
  const totalExtracted = flows.length;
  const successfulPredictions = flows.filter(f => f.predictionStatus === 'success');
  const evaluatedCount = successfulPredictions.length;
  const benignFlows = flows.filter(
    f => f.predictionStatus === 'success' && (f.isAttack === 0 || ['NORMAL', 'BENIGN'].includes(String(f.attackType || '').toUpperCase()))
  );
  const benignCount = benignFlows.length;
  const attackFlows = flows.filter(
    f => f.predictionStatus === 'success' && (f.isAttack === 1 || !['NORMAL', 'BENIGN', 'INSUFFICIENT DATA', 'PREDICTION UNAVAILABLE'].includes(String(f.attackType || '').toUpperCase()))
  );
  const attackCount = attackFlows.length;
  const insufficientDataFlows = flows.filter(f => f.predictionStatus === 'insufficient_data');
  const insufficientCount = insufficientDataFlows.length;
  const inferenceErrorFlows = flows.filter(f => f.predictionStatus === 'unavailable');
  const errorCount = inferenceErrorFlows.length;
  const skippedFlows = flows.filter(f => !f.predictionStatus || f.predictionStatus === 'skipped');
  const skippedCount = skippedFlows.length;

  const inferenceStatus = mlInference.status;
  const isModelFailure = inferenceStatus === 'unavailable' || Boolean(mlInference.error);

  // Provenance counts for threats
  const liveCount = threats.filter(t => t.classificationSource === 'ML Prediction').length;
  const datasetCount = threats.filter(t => t.classificationSource === 'Dataset ground-truth label').length;

  const sectionMetaText = isLoading
    ? 'Loading\u2026'
    : isLiveAnalysis
      ? `${evaluatedCount} of ${totalExtracted} flows evaluated · ${attackCount} attack, ${benignCount} benign`
      : `${threats.length} repository threat records`;

  return (
    <div className="dashboard-content">
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Threat intelligence</h2>
            <p>
              {isLiveAnalysis
                ? 'ML-predicted attack classifications from the uploaded PCAP. These are unverified model predictions, not confirmed incidents.'
                : 'Attack-labelled flows from the VISTA repository dataset. These are training/evaluation records, not live detections.'}
            </p>
            <p>Source: {dataSource || (isLiveAnalysis ? file?.name || 'Uploaded analysis' : 'Repository dataset')}</p>
          </div>
          <span className="section-meta">
            {sectionMetaText}
          </span>
        </div>

        {/* Analysis state guards */}
        {file && analysisStatus === 'analyzing' && (
          <EmptyState>Analyzing {file.name}… threat intelligence will be available when analysis completes.</EmptyState>
        )}
        {file && analysisStatus === 'error' && (
          <EmptyState role="alert">
            Unable to analyze {file.name}: {analysisError || 'The uploaded analysis did not complete.'}
          </EmptyState>
        )}
        {fetchError && (
          <EmptyState role="alert">Unable to load threat analysis: {fetchError}</EmptyState>
        )}

        {/* Baseline dataset banner (when no PCAP is loaded) */}
        {!file && !isLoading && !fetchError && (
          <div style={{ marginBottom: 16, padding: '10px 14px', borderRadius: 6, background: 'rgba(0,240,255,0.06)', border: '1px solid var(--border-subtle)', fontSize: 12, color: 'var(--text-secondary)' }}>
            <Shield size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Upload a PCAP in Traffic Analysis to run live ML inference. The findings below are from the repository evaluation dataset (<code>realFlows.json</code>) — they are dataset labels, not real-time detections.
          </div>
        )}

        {/* 7-Metric Inference Execution Summary Card for Live PCAP Analysis */}
        {isLiveAnalysis && !isLoading && !isBlocked && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '10px',
            marginBottom: '16px',
            padding: '12px 14px',
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
          }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Flows Extracted</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{totalExtracted}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Evaluated by Model</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{evaluatedCount}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Successful Predictions</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{successfulPredictions.length}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Benign Predictions</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>{benignCount}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Attack Classifications</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: attackCount > 0 ? 'var(--danger)' : 'var(--text-secondary)' }}>{attackCount}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Skipped / Missing Features</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: (insufficientCount + skippedCount) > 0 ? 'var(--amber)' : 'var(--text-secondary)' }}>{insufficientCount + skippedCount}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Inference Errors</span>
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: errorCount > 0 ? 'var(--danger)' : 'var(--text-secondary)' }}>{errorCount}</span>
            </div>
          </div>
        )}

        {/* Inference Outcome Status Banners */}
        {isLiveAnalysis && !isLoading && !isBlocked && (
          <div style={{ marginBottom: 16 }}>
            {isModelFailure && (
              <div style={{ padding: '14px 16px', borderRadius: 6, background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.35)', fontSize: 12 }} role="alert">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--danger)', fontWeight: 600, marginBottom: 4 }}>
                  <AlertCircle size={15} />
                  Inference Execution Failure
                </div>
                <div style={{ color: 'var(--text-secondary)' }}>
                  The model failed to execute on extracted flows: {mlInference.error || 'Model service unavailable'}. Zero attack-classified flows cannot be reported as evidence of benign traffic because model inference did not run.
                </div>
              </div>
            )}

            {!isModelFailure && evaluatedCount > 0 && attackCount === 0 && (
              <div style={{ padding: '14px 16px', borderRadius: 6, background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.35)', fontSize: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--green)', fontWeight: 600, marginBottom: 4 }}>
                  <CheckCircle size={15} />
                  Model Verified Benign Traffic — Zero Threat Events Detected
                </div>
                <div style={{ color: 'var(--text-secondary)' }}>
                  The {mlInference.model || 'XGBoost'} model successfully evaluated all {evaluatedCount} extracted flow{evaluatedCount !== 1 ? 's' : ''} from <code>{file?.name}</code> and classified {evaluatedCount === 1 ? 'it' : 'both of them'} as <strong>NORMAL</strong> (benign). No attack-classified signatures or anomalous beaconing were detected.
                </div>
              </div>
            )}

            {!isModelFailure && insufficientCount > 0 && evaluatedCount === 0 && (
              <div style={{ padding: '14px 16px', borderRadius: 6, background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.35)', fontSize: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--amber)', fontWeight: 600, marginBottom: 4 }}>
                  <AlertTriangle size={15} />
                  Insufficient Features for Model Inference
                </div>
                <div style={{ color: 'var(--text-secondary)' }}>
                  Flows could not be evaluated by the model because required features were missing from the capture.
                </div>
              </div>
            )}

            {!isModelFailure && totalExtracted === 0 && (
              <EmptyState>No flows qualified for inference in this capture.</EmptyState>
            )}
          </div>
        )}

        {/* Per-Flow ML Evaluation Results Table (Live PCAP) */}
        {isLiveAnalysis && !isLoading && !isBlocked && flows.length > 0 && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Cpu size={14} color="var(--cyan)" />
                Per-Flow ML Evaluation Results
              </h3>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Model: {mlInference.model || 'XGBoost'} ({mlInference.modelArtifact || 'xgboost_classifier.joblib'})
              </span>
            </div>
            <div className="dashboard-table-wrap">
              <table className="dashboard-table">
                <thead>
                  <tr>
                    <th>Flow ID</th>
                    <th>Endpoints</th>
                    <th>Packets / Bytes</th>
                    <th>Inference Status</th>
                    <th>Predicted Class</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Probabilities / Provenance</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.map((flow, index) => {
                    const isSuccess = flow.predictionStatus === 'success';
                    const isAtk = flow.isAttack === 1 || (!['NORMAL', 'BENIGN'].includes(String(flow.attackType || '').toUpperCase()) && isSuccess);
                    const statusClass = isSuccess ? 'success' : flow.predictionStatus === 'insufficient_data' ? 'medium' : 'critical';
                    const classLabel = isSuccess ? (isAtk ? 'Attack' : 'Benign') : '—';
                    const classBadge = isSuccess ? (isAtk ? 'critical' : 'success') : 'low';

                    const probaStr = flow.probabilities
                      ? Object.entries(flow.probabilities)
                          .sort((a, b) => b[1] - a[1])
                          .slice(0, 2)
                          .map(([k, v]) => `${k}: ${(v * 100).toFixed(1)}%`)
                          .join(' · ')
                      : flow.predictionError || 'Live ML Inference';

                    return (
                      <tr key={flow.flowId || flow.id || index}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {flow.flowId || flow.id || `FLW-${index + 1}`}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {flow.src && flow.dst ? `${flow.src} → ${flow.dst}` : '—'}
                          {flow.proto ? <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>({flow.proto})</span> : null}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {flow.packets != null ? `${flow.packets} pkts` : '—'} / {flow.bytes != null ? `${flow.bytes} B` : '—'}
                        </td>
                        <td>
                          <span className={`soc-badge ${statusClass}`} style={{ fontSize: 10 }}>
                            {flow.predictionStatus || 'unknown'}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600 }}>
                          {flow.attackType || '—'}
                        </td>
                        <td>
                          <span className={`soc-badge ${classBadge}`} style={{ fontSize: 10 }}>
                            {classLabel}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {flow.confidence || '—'}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={probaStr}>
                          {probaStr}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Threat Detections Section */}
        {isLoading && !file && <EmptyState>Loading backend threat analysis…</EmptyState>}

        {!isLoading && !fetchError && !isBlocked && (
          threats.length > 0 ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <AlertTriangle size={14} color="var(--danger)" />
                  Detected Attack Classifications (MITRE ATT&CK)
                </h3>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {liveCount > 0 && (
                    <span className="soc-badge success" style={{ fontSize: 11 }}>
                      <AlertTriangle size={11} />
                      {liveCount} ML prediction{liveCount !== 1 ? 's' : ''} (unverified)
                    </span>
                  )}
                  {datasetCount > 0 && (
                    <span className="soc-badge low" style={{ fontSize: 11 }}>
                      <Database size={11} />
                      {datasetCount} dataset record{datasetCount !== 1 ? 's' : ''} (training/evaluation data)
                    </span>
                  )}
                </div>
              </div>

              <div className="dashboard-table-wrap">
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      <th>Attack label</th>
                      <th>Evidence</th>
                      <th>Verification</th>
                      <th>MITRE technique</th>
                      <th>Tactic</th>
                      <th>Severity</th>
                      <th>Flow</th>
                      {isLiveAnalysis && <th>Src → Dst</th>}
                      {isLiveAnalysis && <th>Confidence</th>}
                      <th>Packets</th>
                      <th>Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.map((threat, index) => (
                      <tr key={threat.id || `${threat.flowId || threat.attackType}-${index}`}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {threat.attackType || '—'}
                        </td>
                        <td>
                          <span
                            className={`soc-badge ${provenanceBadgeClass(threat.classificationSource)}`}
                            style={{ fontSize: 10 }}
                            title={threat.classificationSource === 'Dataset ground-truth label'
                              ? 'This label is from the VISTA repository training dataset, not from live detection.'
                              : 'This label was produced by the ML model at inference time.'}
                          >
                            {threat.classificationSource === 'ML Prediction' ? 'ML Prediction' : 'Dataset Label'}
                          </span>
                        </td>
                        <td style={{ fontSize: 10, color: 'var(--text-secondary)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {threat.verificationStatus || '—'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          {threat.mitreId ? `${threat.mitreId} · ${threat.mitreName}` : '—'}
                        </td>
                        <td style={{ fontSize: 11 }}>{threat.tactic || '—'}</td>
                        <td>
                          <span className={`soc-badge ${severityBadgeClass(threat.severity)}`} style={{ fontSize: 10 }}>
                            {threat.severity || '—'}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{threat.flowId || '—'}</td>
                        {isLiveAnalysis && (
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                            {threat.src && threat.dst ? `${threat.src} → ${threat.dst}` : '—'}
                          </td>
                        )}
                        {isLiveAnalysis && (
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                            {threat.confidence || '—'}
                          </td>
                        )}
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{threat.packets ?? '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{threat.bytes ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <p style={{ marginTop: 10, fontSize: 11, color: 'var(--text-dim)' }}>
                {isLiveAnalysis
                  ? 'ML Predictions are unverified model outputs. They are not confirmed security incidents. Confidence values are model probabilities, not probability of real-world attack occurrence.'
                  : 'Dataset Labels are ground-truth labels from the VISTA IPsec traffic classification dataset (ipsec_traffic_classification_v2.csv). These records exist for training and evaluation purposes only.'}
              </p>
            </>
          ) : (
            !isLiveAnalysis && (
              <EmptyState>
                No attack-labelled flows are available in the repository dataset for the current filter.
              </EmptyState>
            )
          )
        )}
      </section>
    </div>
  );
}
