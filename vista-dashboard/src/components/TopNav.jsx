import { useCallback, useEffect, useState } from 'react';
import { 
  RotateCw, 
  FileCode, 
  Server, 
  Activity, 
  ShieldCheck, 
  BrainCircuit, 
  Cpu, 
  AlertTriangle, 
  FileText, 
  Database,
  LayoutDashboard
} from 'lucide-react';
import { usePcapAnalysis } from '../context/usePcapAnalysis';
import { checkBackendStatus, fetchEbpfStatus } from '../utils/apiClient';

const TAB_TITLES = {
  overview: { label: 'System Overview', icon: LayoutDashboard },
  testbed: { label: '3D Testbed Monitor', icon: Cpu },
  traffic: { label: 'Traffic Analysis', icon: Activity },
  ai: { label: 'AI & Dual-ML Analysis', icon: BrainCircuit },
  security: { label: 'NIST Security Assessment', icon: ShieldCheck },
  threat: { label: 'Threat Intelligence', icon: AlertTriangle },
  reports: { label: 'Compliance Reports', icon: FileText },
  dataset: { label: 'Datasets & Provenance', icon: Database },
};

function ConnectionPill({ label, connected, detail, icon: Icon }) {
  return (
    <div className={`nav-connection-pill ${connected ? 'is-connected' : 'is-disconnected'}`} title={detail || label}>
      <span className="pill-dot">
        <span className="pill-dot-core" />
        {connected && <span className="pill-dot-pulse" />}
      </span>
      {Icon && <Icon size={12} className="pill-icon" />}
      <span className="pill-label">{label}</span>
      <span className="pill-status">{connected ? 'Online' : 'Unavailable'}</span>
    </div>
  );
}

export default function TopNav({ onRefresh, activeTab = 'overview' }) {
  const { file, status: analysisStatus, error: analysisError, analysisId } = usePcapAnalysis();
  const [backendOnline, setBackendOnline] = useState(false);
  const [backendDetail, setBackendDetail] = useState('');
  const [collectorOnline, setCollectorOnline] = useState(false);
  const [collectorDetail, setCollectorDetail] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const refreshStatus = useCallback(async () => {
    const backendPromise = checkBackendStatus().then((status) => {
      setBackendOnline(status.online);
      setBackendDetail(status.online ? '' : status.error || 'Backend status request failed');
    });
    const collectorPromise = fetchEbpfStatus().then((status) => {
      const connected = status.status === 'RUNNING' && status.mode === 'NATIVE_KERNEL_EBPF';
      setCollectorOnline(connected);
      setCollectorDetail(status.error || status.bpfError || status.mode || '');
    }).catch((error) => {
      setCollectorOnline(false);
      setCollectorDetail(error instanceof Error ? error.message : String(error));
    });
    await Promise.all([backendPromise, collectorPromise]);
  }, []);

  useEffect(() => {
    refreshStatus();
    const interval = window.setInterval(refreshStatus, 10000);
    return () => window.clearInterval(interval);
  }, [refreshStatus]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await Promise.all([
        refreshStatus(),
        Promise.resolve(onRefresh?.()),
      ]);
    } finally {
      setTimeout(() => setIsRefreshing(false), 500);
    }
  };

  const activeMeta = TAB_TITLES[activeTab] || { label: 'Dashboard', icon: LayoutDashboard };
  const ActiveIcon = activeMeta.icon;

  return (
    <header className="app-header">
      {/* Dynamic View Breadcrumb */}
      <div className="header-breadcrumb-wrap">
        <div className="breadcrumb-brand">
          <span className="brand-dot" />
          <span>VISTA</span>
        </div>
        <span className="breadcrumb-slash">/</span>
        <div className="breadcrumb-current">
          <ActiveIcon size={15} className="breadcrumb-icon" />
          <span className="breadcrumb-title">{activeMeta.label}</span>
        </div>
      </div>

      {/* Header Controls & Telemetry Pills */}
      <div className="header-controls">
        {file && (
          <div
            className={`active-capture-chip ${analysisStatus === 'success' ? 'is-analyzed' : analysisStatus === 'analyzing' ? 'is-analyzing' : 'is-error'}`}
            title={analysisError || `${file.name} · ${analysisId || ''} · ${analysisStatus}`}
          >
            <FileCode size={13} className="capture-icon" />
            <span className="capture-name">{file.name}</span>
            {analysisId && <span className="capture-id-badge monospace">{analysisId}</span>}
            <span className="capture-badge">
              {analysisStatus === 'success' ? 'Analyzed' : analysisStatus === 'analyzing' ? 'Processing…' : 'Error'}
            </span>
          </div>
        )}

        <ConnectionPill
          label="FastAPI"
          connected={backendOnline}
          detail={backendDetail}
          icon={Server}
        />
        <ConnectionPill
          label="eBPF"
          connected={collectorOnline}
          detail={collectorDetail}
          icon={Activity}
        />

        <button
          className={`header-refresh-btn ${isRefreshing ? 'is-spinning' : ''}`}
          type="button"
          onClick={handleRefresh}
          disabled={isRefreshing}
          aria-label="Refresh status and telemetry"
          title="Refresh live telemetry and model state"
        >
          <RotateCw size={13} className="refresh-icon" />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
}
