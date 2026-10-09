import { useMemo, useState } from 'react';
import { 
  AlertCircle, 
  Download, 
  Search, 
  UploadCloud, 
  FileCode, 
  Sparkles
} from 'lucide-react';
import { usePcapAnalysis } from '../../context/usePcapAnalysis';
import { fetchSampleCaptureBlob } from '../../utils/apiClient';

const fieldLabels = {
  id: 'Flow ID',
  time: 'Time',
  sessionId: 'Session ID',
  proto: 'Protocol',
  spi: 'ESP SPI',
  src: 'Source',
  dst: 'Destination',
  packets: 'Packets',
  bytes: 'Bytes',
  duration: 'Duration',
  meanPacketLen: 'Mean packet (B)',
  meanIat: 'Mean IAT (s)',
  trafficType: 'Encrypted App Profile',
  attackType: 'Threat Assessment',
  confidence: 'Confidence'
};

const escapeCsvValue = (value) => {
  const text = value == null ? '' : String(value);
  return `"${text.replaceAll('"', '""')}"`;
};

const EMPTY_FLOWS = [];

export default function TrafficAnalysisView() {
  const {
    file,
    analysisResult,
    status,
    error,
    analyzeFile,
    clearAnalysis,
    analysisId,
  } = usePcapAnalysis();
  const flows = analysisResult?.flows ?? EMPTY_FLOWS;
  const [searchQuery, setSearchQuery] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [sampleLoading, setSampleLoading] = useState(false);
  const isAnalyzing = status === 'analyzing';

  const columns = useMemo(
    () => Object.entries(fieldLabels).filter(([field]) => flows.some((flow) => flow[field] != null)),
    [flows]
  );

  const visibleFlows = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return flows;
    return flows.filter((flow) => Object.values(flow).some((value) => (
      value != null && String(value).toLowerCase().includes(query)
    )));
  }, [flows, searchQuery]);

  const handleFileUpload = (event) => {
    const uploadedFile = event.target.files?.[0];
    event.target.value = '';
    if (!uploadedFile) return;

    setSearchQuery('');
    void analyzeFile(uploadedFile);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    const droppedFile = event.dataTransfer.files?.[0];
    if (droppedFile) {
      setSearchQuery('');
      void analyzeFile(droppedFile);
    }
  };

  const handleLoadSample = async (sampleName) => {
    try {
      setSampleLoading(true);
      const sampleFile = await fetchSampleCaptureBlob(sampleName);
      setSearchQuery('');
      await analyzeFile(sampleFile);
    } catch (err) {
      console.error('Failed to load sample capture:', err);
    } finally {
      setSampleLoading(false);
    }
  };

  const handleExportCsv = () => {
    if (visibleFlows.length === 0 || columns.length === 0) return;
    const csv = [
      columns.map(([, label]) => escapeCsvValue(label)).join(','),
      ...visibleFlows.map((flow) => columns.map(([field]) => escapeCsvValue(flow[field])).join(','))
    ].join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'vista-flow-analysis.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleClearAnalysis = () => {
    setSearchQuery('');
    clearAnalysis();
  };

  return (
    <div className="dashboard-content">
      {/* Header */}
      <section className="dashboard-section" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>Traffic Analysis & Flow Extraction</h2>
            <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
              Upload an observed IPsec packet capture (.pcap, .pcapng) or flow CSV for deterministic decoding and dual-ML inference.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <label className="header-refresh-btn" style={{ cursor: isAnalyzing || sampleLoading ? 'wait' : 'pointer', background: 'var(--cyan-subtle)', borderColor: 'rgba(56, 189, 248, 0.4)', color: '#7dd3fc' }}>
              <UploadCloud size={15} />
              <span>{isAnalyzing ? 'Analyzing…' : 'Upload Capture'}</span>
              <input
                type="file"
                accept=".pcap,.pcapng,.cap,.csv"
                onChange={handleFileUpload}
                disabled={isAnalyzing || sampleLoading}
                style={{ display: 'none' }}
              />
            </label>
            {file && (
              <>
                {flows.length > 0 && (
                  <button className="header-refresh-btn" onClick={handleExportCsv} type="button">
                    <Download size={14} />
                    <span>Export CSV</span>
                  </button>
                )}
                <button className="header-refresh-btn" onClick={handleClearAnalysis} type="button" style={{ color: 'var(--danger)' }}>
                  Clear
                </button>
              </>
            )}
          </div>
        </div>

        {/* Quick Sample Presets Bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
            <Sparkles size={12} color="var(--cyan)" />
            Quick Test Presets:
          </span>
          <button
            type="button"
            className="nav-connection-pill"
            style={{ cursor: isAnalyzing || sampleLoading ? 'wait' : 'pointer' }}
            disabled={isAnalyzing || sampleLoading}
            onClick={() => handleLoadSample('ikev2_s2s_ipsec_vpn_aes_gcm.pcapng')}
          >
            <FileCode size={12} />
            <span style={{ fontFamily: 'var(--font-mono)' }}>ikev2_s2s_ipsec_vpn_aes_gcm.pcapng</span>
            <span style={{ color: 'var(--cyan)', fontSize: '10px' }}>Site-to-Site</span>
          </button>
          <button
            type="button"
            className="nav-connection-pill"
            style={{ cursor: isAnalyzing || sampleLoading ? 'wait' : 'pointer' }}
            disabled={isAnalyzing || sampleLoading}
            onClick={() => handleLoadSample('vista-outer-esp-probe.pcap')}
          >
            <FileCode size={12} />
            <span style={{ fontFamily: 'var(--font-mono)' }}>vista-outer-esp-probe.pcap</span>
            <span style={{ color: 'var(--cyan)', fontSize: '10px' }}>ESP Probe</span>
          </button>
        </div>
      </section>

      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 16px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.35)', color: 'var(--danger)', fontSize: '13px' }}>
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Main Flow Table or Interactive Upload Dropzone */}
      {isAnalyzing || sampleLoading ? (
        <section className="dashboard-section" style={{ padding: '48px', textAlign: 'center' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            <div className="status-indicator-ping" style={{ width: '16px', height: '16px' }}>
              <span className="ping-dot" style={{ width: '16px', height: '16px', background: 'var(--cyan)' }} />
              <span className="ping-ring" style={{ background: 'var(--cyan)' }} />
            </div>
            <p style={{ margin: 0, fontWeight: 650, fontSize: '15px', color: 'var(--text-primary)' }}>Analyzing PCAP & Extracting IPsec Flows…</p>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>
              Decoding IKEv2 proposals, ESP SPIs, calculating side-channel features, and running dual-ML classifiers.
            </p>
          </div>
        </section>
      ) : flows.length === 0 ? (
        <section
          className={`dashboard-section ${isDragging ? 'is-dragging' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          style={{
            padding: '48px 24px',
            textAlign: 'center',
            border: isDragging ? '2px dashed var(--cyan)' : '2px dashed var(--border-medium)',
            background: isDragging ? 'rgba(56, 189, 248, 0.04)' : 'var(--bg-card)',
            borderRadius: '10px',
            transition: 'all 0.2s ease',
            cursor: 'pointer'
          }}
          onClick={() => document.getElementById('main-dropzone-input')?.click()}
        >
          <input
            id="main-dropzone-input"
            type="file"
            accept=".pcap,.pcapng,.cap,.csv"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
            <div style={{ width: '56px', height: '56px', borderRadius: '14px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--cyan)' }}>
              <UploadCloud size={26} />
            </div>
            <div>
              <p style={{ margin: 0, fontWeight: 700, fontSize: '16px', color: 'var(--text-primary)' }}>
                Drag & drop IPsec PCAP or flow CSV here
              </p>
              <p style={{ margin: '6px 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
                Supports .pcap, .pcapng, and pre-extracted CSV flow datasets. Click to browse.
              </p>
            </div>
          </div>
        </section>
      ) : (
        <section className="dashboard-section" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap', padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255, 255, 255, 0.01)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="section-meta-pill">
                {visibleFlows.length.toLocaleString()} of {flows.length.toLocaleString()} flows
              </span>
              {file && (
                <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  File: {file.name} {analysisId ? `(${analysisId})` : ''}
                </span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '240px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', width: '100%', padding: '6px 10px', background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                <Search size={14} color="var(--text-muted)" />
                <input
                  type="search"
                  placeholder="Filter flows by IP, SPI, proto…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', fontSize: '12px', outline: 'none', width: '100%' }}
                />
              </div>
            </div>
          </div>

          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead>
                <tr>
                  {columns.map(([field, label]) => (
                    <th key={field} scope="col">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleFlows.map((flow, index) => (
                  <tr key={flow.id ?? flow.flowId ?? index}>
                    {columns.map(([field]) => {
                      const value = flow[field];
                      const isStatusCol = field === 'trafficType' || field === 'attackType';
                      return (
                        <td key={field} className={field === 'spi' || field === 'id' ? 'monospace' : undefined}>
                          {isStatusCol ? (
                            <span className="event-badge badge-default" style={{ color: 'var(--cyan)' }}>
                              {value != null ? String(value) : '—'}
                            </span>
                          ) : (
                            value != null ? String(value) : '—'
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
