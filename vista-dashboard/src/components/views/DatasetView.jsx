import { useEffect, useState } from 'react';
import { Database, Download, FileSpreadsheet } from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import realDatasetSummary from '../../data/realDatasetSummary.json';
import { fetchMlMetrics } from '../../utils/apiClient';

const DATASET_FILES = [
  {
    name: 'ipsec_traffic_classification_v2.csv',
    label: 'IPsec traffic classification flows',
    description: 'Flow features and classification labels from the repository dataset.',
  },
  {
    name: 'ipsec_security_audit_v2.csv',
    label: 'Generated IPsec audit scenarios',
    description: 'Synthetic posture scenarios for offline evaluation; not live or operational audit sessions.',
  },
  {
    name: 'vista_correlated_sessions_v2.csv',
    label: 'Correlated sessions',
    description: 'Generated flow and audit scenario records joined by session identifiers; not live testbed data.',
  },
];

function percent(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '—';
}

export default function DatasetView() {
  const { file, analysisResult, status, error, analysisId } = usePcapAnalysis();
  const [mlMetrics, setMlMetrics] = useState(null);
  const [metricsError, setMetricsError] = useState('');
  const totalFlows = realDatasetSummary.totalFlows;
  const totalSessions = realDatasetSummary.totalSessions;
  const successfulPredictions = (analysisResult?.flows || [])
    .filter((flow) => flow.predictionStatus === 'success');
  const predictionClasses = successfulPredictions.reduce((counts, flow) => {
    const label = flow.mlPrediction?.label;
    if (label) counts[label] = (counts[label] || 0) + 1;
    return counts;
  }, {});
  const models = [
    { name: 'XGBoost', metrics: mlMetrics?.metrics?.xgboost },
    { name: 'Random Forest', metrics: mlMetrics?.metrics?.random_forest },
    { name: 'Isolation Forest', metrics: null },
  ];

  useEffect(() => {
    let cancelled = false;
    fetchMlMetrics()
      .then((result) => {
        if (!cancelled) setMlMetrics(result);
      })
      .catch((requestError) => {
        if (!cancelled) setMetricsError(requestError instanceof Error ? requestError.message : String(requestError));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="dashboard-content">
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Dataset</h2>
            <p>Repository datasets and exported model-evaluation artifacts; these are not live telemetry.</p>
            <p>Source: DATASET/ CSV files and VISTA model evaluation reports.</p>
          </div>
          <Database size={18} className="text-sage" aria-hidden="true" />
        </div>
        <div className="connection-details">
          <div><dt>Flow records</dt><dd>{totalFlows?.toLocaleString() ?? '—'}</dd></div>
          <div><dt>Generated audit scenarios</dt><dd>{totalSessions?.toLocaleString() ?? '—'}</dd></div>
          <div><dt>Benign-labeled flows</dt><dd>{realDatasetSummary.benignCount?.toLocaleString() ?? '—'}</dd></div>
          <div><dt>Attack-labeled flows</dt><dd>{realDatasetSummary.attackCount?.toLocaleString() ?? '—'}</dd></div>
        </div>
      </section>

      {file && (
        <section className="dashboard-section">
          <div className="section-heading">
            <div>
              <h2>Current Uploaded Analysis Session</h2>
              <p>Backend analysis shared with Traffic Analysis, AI Analysis, Threat Intelligence, and Reports.</p>
            </div>
          </div>
          <dl className="connection-details">
            <div><dt>File</dt><dd>{file.name}</dd></div>
            <div><dt>Session ID</dt><dd className="monospace">{analysisId || analysisResult?.analysisId || 'ANL-ACTIVE'}</dd></div>
            <div><dt>Status</dt><dd>{status === 'success' ? 'Analysis complete' : status === 'analyzing' ? 'Analyzing' : status === 'error' ? 'Error' : '—'}</dd></div>
            <div><dt>File size</dt><dd>{file.size.toLocaleString()} bytes</dd></div>
            {status === 'success' && (
              <>
                <div><dt>Flow records</dt><dd>{analysisResult?.flows?.length ?? '—'}</dd></div>
                <div><dt>Packets in capture</dt><dd>{analysisResult?.summary?.totalPackets ?? '—'}</dd></div>
                <div><dt>Flows predicted by ML</dt><dd>{analysisResult?.mlInference?.predictedFlows ?? 'Unavailable'}</dd></div>
                <div><dt>Predicted classes (unverified)</dt><dd>
                  {Object.entries(predictionClasses).map(([label, count]) => `${label}: ${count}`).join(', ') || 'No successful predictions'}
                </dd></div>
              </>
            )}
          </dl>
          {error && <div className="dashboard-empty" role="alert">{error}</div>}
        </section>
      )}

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Dataset artifacts</h2>
            <p>Download files shipped with this repository.</p>
          </div>
          <FileSpreadsheet size={17} color="var(--cyan)" aria-hidden="true" />
        </div>
        <div className="dashboard-secondary-grid">
          {DATASET_FILES.map((file) => (
            <div key={file.name} className="soc-card" style={{ padding: 16 }}>
              <h3 style={{ color: 'var(--text-primary)', fontSize: 13, marginBottom: 6 }}>{file.label}</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.5, marginBottom: 12 }}>{file.description}</p>
              <code className="monospace">{file.name}</code>
              <a
                className="soc-btn"
                href={`/data/${file.name}`}
                download={file.name}
                style={{ display: 'flex', marginTop: 12, textDecoration: 'none' }}
              >
                <Download size={14} />
                Download CSV
              </a>
            </div>
          ))}
        </div>
      </section>

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Recorded class distribution</h2>
            <p>Counts are read from the repository dataset summary.</p>
          </div>
        </div>
        {!Object.keys(realDatasetSummary.attackTypes || {}).length ? (
          <div className="dashboard-empty">No class-distribution summary is available.</div>
        ) : (
          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead><tr><th>Label</th><th>Rows</th><th>Share</th></tr></thead>
              <tbody>
                {Object.entries(realDatasetSummary.attackTypes).map(([label, count]) => (
                  <tr key={label}>
                    <td>{label}</td>
                    <td>{count.toLocaleString()}</td>
                    <td>{totalFlows ? `${((count / totalFlows) * 100).toFixed(1)}%` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Model evaluation reports</h2>
            <p>Offline experiment-aware evaluation; not per-upload accuracy or measured real-world attack detection.</p>
          </div>
        </div>
        {metricsError && <div className="dashboard-empty" role="alert">{metricsError}</div>}
        <div className="dashboard-table-wrap">
          <table className="dashboard-table">
            <thead><tr><th>Model</th><th>Offline accuracy</th><th>Offline macro F1</th></tr></thead>
            <tbody>
              {models.map(({ name, metrics }) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td>{metrics ? percent(metrics.accuracy) : 'Unavailable'}</td>
                  <td>{metrics ? percent(metrics.macro_f1) : 'Unavailable'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {mlMetrics?.evaluationProvenance && (
          <p className="section-meta">
            {mlMetrics.evaluationProvenance.dataset}. {mlMetrics.evaluationProvenance.method}
            {' '}{mlMetrics.evaluationProvenance.limitations}
          </p>
        )}
      </section>
    </div>
  );
}
