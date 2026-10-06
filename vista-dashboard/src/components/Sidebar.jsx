import React from 'react';
import { 
  LayoutDashboard, 
  Box, 
  Activity, 
  Cpu, 
  ShieldCheck, 
  Crosshair, 
  FileText, 
  Database,
  Radio,
  Lock,
  ChevronRight,
  Terminal
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'overview', number: '01', label: 'Overview', icon: LayoutDashboard },
    { id: 'testbed', number: '02', label: '3D Testbed', icon: Box, highlight: true },
    { id: 'traffic', number: '03', label: 'Traffic Analysis', icon: Activity },
    { id: 'ai', number: '04', label: 'AI Analysis', icon: Cpu },
    { id: 'security', number: '05', label: 'Security Assessment', icon: ShieldCheck },
    { id: 'threats', number: '06', label: 'Threat Intelligence', icon: Crosshair },
    { id: 'reports', number: '07', label: 'Reports', icon: FileText },
    { id: 'dataset', number: '08', label: 'Dataset', icon: Database },
  ];

  return (
    <aside style={{
      width: '260px',
      minWidth: '260px',
      height: '100vh',
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      zIndex: 30,
      userSelect: 'none'
    }}>
      {/* Brand Header */}
      <div>
        <div style={{
          padding: '20px 20px 16px 20px',
          borderBottom: '1px solid var(--border-subtle)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.25), rgba(59, 130, 246, 0.15))',
                border: '1px solid var(--cyan)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 12px rgba(0, 240, 255, 0.2)'
              }}>
                <Lock size={16} color="var(--cyan)" />
              </div>
              <span style={{ fontSize: '18px', fontWeight: '800', letterSpacing: '1.2px', color: '#fff' }}>
                VISTA
              </span>
            </div>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 6px',
              background: 'rgba(59, 130, 246, 0.15)',
              border: '1px solid rgba(59, 130, 246, 0.35)',
              borderRadius: '4px',
              color: 'var(--blue)',
              fontWeight: '700'
            }}>
              NTRO • SIH26160
            </span>
          </div>

          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            lineHeight: '1.4',
            letterSpacing: '0.1px'
          }}>
            Encrypted IPsec Telemetry & AI-Powered Security Assessment
          </div>
        </div>

        {/* Navigation Items */}
        <nav style={{ padding: '14px 12px', display: 'flex', flexDirection: 'column', gap: '3px' }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '9px 12px',
                  borderRadius: '6px',
                  border: isActive 
                    ? '1px solid rgba(0, 240, 255, 0.35)' 
                    : '1px solid transparent',
                  background: isActive 
                    ? 'rgba(0, 240, 255, 0.08)' 
                    : 'transparent',
                  color: isActive ? '#fff' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: isActive ? '600' : '500',
                  transition: 'all 0.15s ease',
                  textAlign: 'left'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                    e.currentTarget.style.color = '#fff';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '11px' }}>
                  <Icon 
                    size={16} 
                    color={isActive ? 'var(--cyan)' : 'var(--text-muted)'} 
                  />
                  <span>{item.label}</span>
                </div>

                {item.highlight && (
                  <span style={{
                    fontSize: '9px',
                    fontFamily: 'var(--font-mono)',
                    padding: '1px 5px',
                    background: 'rgba(0, 240, 255, 0.15)',
                    border: '1px solid rgba(0, 240, 255, 0.3)',
                    borderRadius: '3px',
                    color: 'var(--cyan)',
                    fontWeight: '700'
                  }}>
                    3D
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Strip */}
      <div style={{
        padding: '14px 16px',
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(6, 9, 15, 0.6)',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-dim)' }}>eBPF PROBES:</span>
          <span style={{ color: 'var(--green)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span className="status-pulse green" style={{ width: '5px', height: '5px' }}></span>
            3 ACTIVE
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-dim)' }}>AI INFERENCE:</span>
          <span style={{ color: 'var(--cyan)' }}>1.2 ms / flow</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-dim)' }}>POSTURE AUDIT:</span>
          <span style={{ color: '#fff', fontWeight: '600' }}>98/100 PASS</span>
        </div>
      </div>
    </aside>
  );
}
