import { 
  LayoutDashboard, 
  Cpu, 
  Activity, 
  BrainCircuit, 
  ShieldCheck, 
  AlertTriangle, 
  FileText, 
  Database,
  Shield
} from 'lucide-react';

const NAV_GROUPS = [
  {
    title: 'MONITORING',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard },
      { id: 'testbed', label: '3D Testbed', icon: Cpu, badge: 'Live 3D' },
      { id: 'traffic', label: 'Traffic Analysis', icon: Activity, badge: 'PCAP' },
    ],
  },
  {
    title: 'SECURITY INTELLIGENCE',
    items: [
      { id: 'ai', label: 'AI Analysis', icon: BrainCircuit, badge: 'Dual ML' },
      { id: 'security', label: 'Security Assessment', icon: ShieldCheck, badge: 'NIST' },
      { id: 'threat', label: 'Threat Intelligence', icon: AlertTriangle, badge: 'ATT&CK' },
    ],
  },
  {
    title: 'OPERATIONS',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText },
      { id: 'dataset', label: 'Dataset & Provenance', icon: Database },
    ],
  },
];

export default function Sidebar({ activeTab, onNavigate = () => {} }) {
  return (
    <aside className="app-sidebar">
      {/* Brand Header */}
      <a
        className="sidebar-brand"
        href="/?tab=overview"
        onClick={(event) => {
          event.preventDefault();
          onNavigate('overview');
        }}
      >
        <div className="brand-header-wrap">
          <div className="brand-logo-badge">
            <Shield className="brand-logo-icon" size={18} />
            <div className="brand-logo-glow" />
          </div>
          <div className="brand-titles">
            <span className="brand-name">VISTA</span>
            <span className="brand-caption">AI-Powered IPsec Security</span>
          </div>
        </div>
        <div className="brand-tag">SIH26160 · NTRO</div>
      </a>

      {/* Navigation Sections */}
      <nav className="sidebar-nav" aria-label="Dashboard sections">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="nav-group">
            <span className="nav-group-title">{group.title}</span>
            {group.items.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-item${isActive ? ' is-active' : ''}`}
                  aria-current={isActive ? 'page' : undefined}
                  onClick={() => onNavigate(item.id)}
                >
                  <span className="nav-item-icon-wrap">
                    <Icon size={16} className="nav-item-icon" />
                  </span>
                  <span className="nav-item-label">{item.label}</span>
                  {item.badge && (
                    <span className={`nav-item-badge ${isActive ? 'is-active-badge' : ''}`}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && <span className="nav-active-pill" />}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Sidebar Footer */}
      <div className="sidebar-footer">
        <div className="system-status-indicator">
          <span className="status-indicator-ping">
            <span className="ping-dot" />
            <span className="ping-ring" />
          </span>
          <div className="system-status-text">
            <span className="system-status-title">VISTA Engine v2.1.0</span>
            <span className="system-status-sub">eBPF + Dual-ML Active</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
