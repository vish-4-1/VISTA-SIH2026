import { useRef, useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import { generateReport } from '../../utils/apiClient';

export default function ReportsView() {
  const analysis = usePcapAnalysis();
  const analysisKey = `${analysis.file?.name || 'repository'}:${analysis.file?.size || 0}:${analysis.analyzedAt || analysis.status}`;
  return <ReportContent key={analysisKey} {...analysis} />;
}

function ReportContent({
  analysisResult,
  file,
  status: analysisStatus,
  error: analysisError,
}) {
  const [reportType, setReportType] = useState('Technical Assessment');
  const [reportState, setReportState] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const requestId = useRef(0);
  const report = reportState;

  const handleGenerate = async () => {
    const currentRequestId = ++requestId.current;
    setLoading(true);
    setError('');
    try {
      const result = await generateReport(
        reportType,
        analysisStatus === 'success' ? analysisResult?.flows : undefined,
      );
      if (requestId.current === currentRequestId) setReportState(result);
    } catch (requestError) {
      if (requestId.current === currentRequestId) {
        setError(requestError instanceof Error ? requestError.message : String(requestError));
      }
    } finally {
      if (requestId.current === currentRequestId) setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!report?.content) return;
    const blobUrl = URL.createObjectURL(new Blob([report.content], { type: 'text/markdown;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = 'vista-security-assessment.md';
    link.click();
    URL.revokeObjectURL(blobUrl);
  };

  return (
    <div className="dashboard-content">
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Reports</h2>
            <p>Generate an assessment from existing backend audit records and optional uploaded analysis.</p>
            <p>
              Source: POST /api/reports/generate · {analysisResult
                ? `includes ${file?.name || 'current uploaded analysis'}`
                : 'repository audit and flow datasets'}
            </p>
          </div>
          <FileText size={18} color="var(--cyan)" aria-hidden="true" />
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
          <label htmlFor="report-type">Report type</label>
          <select
            id="report-type"
            value={reportType}
            onChange={(event) => setReportType(event.target.value)}
            style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', padding: 8 }}
          >
            <option>Technical Assessment</option>
            <option>Executive Summary</option>
          </select>
          <button
            className="soc-btn soc-btn-primary"
            type="button"
            disabled={loading || analysisStatus === 'analyzing'}
            onClick={handleGenerate}
          >
            {loading ? 'Generating…' : 'Generate report'}
          </button>
          {report?.content && (
            <button className="soc-btn" type="button" onClick={handleDownload}>
              <Download size={14} />
              Download Markdown
            </button>
          )}
        </div>
        {analysisStatus === 'analyzing' && (
          <div className="dashboard-empty" role="status" style={{ marginTop: 14 }}>
            Waiting for {file?.name || 'uploaded traffic'} to finish analyzing before generating a report.
          </div>
        )}
        {analysisStatus === 'error' && analysisError && (
          <div className="dashboard-empty" role="alert" style={{ marginTop: 14 }}>
            The uploaded analysis is unavailable: {analysisError}
          </div>
        )}
        {error && <div className="dashboard-empty" role="alert" style={{ marginTop: 14 }}>Unable to generate report: {error}</div>}
      </section>

      <section className="dashboard-section">
        <h2 style={{ marginBottom: 12 }}>Generated assessment</h2>
        {report ? (
          <>
            <p className="section-meta" style={{ marginBottom: 12 }}>
              Source: {report.source || 'Backend report service'} · Score: {report.score ?? '—'}
            </p>
            <pre style={{
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              color: 'var(--text-secondary)',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              padding: 16,
              font: '12px/1.6 var(--font-mono)',
            }}>
              {report.content}
            </pre>
          </>
        ) : (
          <div className="dashboard-empty" role="status">
            No report has been generated yet. Generate a report to fetch the current backend assessment.
          </div>
        )}
      </section>
    </div>
  );
}
