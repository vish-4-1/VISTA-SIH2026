import React, { useState, useEffect } from 'react';
import { 
  Bell, 
  Settings, 
  ShieldCheck, 
  ShieldAlert, 
  Radio, 
  User, 
  CheckCircle2, 
  Flame, 
  Search, 
  UploadCloud, 
  KeyRound, 
  Terminal,
  ExternalLink,
  Cpu,
  Wifi
} from 'lucide-react';
import { ATTACK_SCENARIOS } from '../data/networkData';
import { checkBackendStatus } from '../utils/apiClient';

export default function TopNav({ 
  currentScenario, 
  onSelectScenario, 
  onOpenTestbed,
  notificationsCount = 3 
}) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);
  const isDanger = currentScenario.threatLevel === 'CRITICAL';
  const isWarning = currentScenario.threatLevel === 'ELEVATED';

  useEffect(() => {
    let isMounted = true;
    const probe = async () => {
      const res = await checkBackendStatus();
      if (isMounted) setBackendOnline(res.online);
    };
    probe();
    const interval = setInterval(probe, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const scenarios = [
    { id: 'NORMAL', label: 'Normal Traffic', icon: ShieldCheck, color: 'var(--green)' },
    { id: 'DOS_FLOOD', label: 'DoS Flood', icon: Flame, color: 'var(--danger)' },
    { id: 'DATA_EXFILTRATION', label: 'Data Exfil', icon: UploadCloud, color: '#ff6600' },
    { id: 'PORT_SCAN', label: 'Port Scan', icon: Search, color: 'var(--amber)' },
    { id: 'C2_BEACONING', label: 'C2 Beaconing', icon: Radio, color: 'var(--purple)' },
    { id: 'BRUTE_FORCE', label: 'Brute Force', icon: KeyRound, color: '#ff4d6d' }
  ];

  return (
    <header style={{
      height: '56px',
      minHeight: '56px',
      background: 'var(--bg-topbar)',
      borderBottom: '1px solid var(--border-subtle)',
      padding: '0 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      zIndex: 25,
      userSelect: 'none'
    }}>
      {/* Left: Quick System & Scenario Injector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px 10px',
          borderRadius: '5px',
          background: isDanger 
            ? 'rgba(239, 68, 68, 0.12)' 
            : (isWarning ? 'rgba(245, 158, 11, 0.12)' : 'rgba(16, 185, 129, 0.1)'),
          border: `1px solid ${isDanger ? 'rgba(239, 68, 68, 0.35)' : (isWarning ? 'rgba(245, 158, 11, 0.35)' : 'rgba(16, 185, 129, 0.25)')}`
        }}>
          <span className={`status-pulse ${isDanger ? 'red' : 'green'}`}></span>
          <span style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            fontWeight: '700',
            letterSpacing: '0.4px',
            color: isDanger ? 'var(--danger)' : (isWarning ? 'var(--amber)' : 'var(--green)')
          }}>
            VPN: {isDanger ? 'ATTACK DETECTED' : 'SECURE / MONITORED'}
          </span>
        </div>

        {/* Live AI Core Backend Status Pill */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 10px',
          borderRadius: '5px',
          background: backendOnline ? 'rgba(0, 240, 255, 0.12)' : 'rgba(255, 255, 255, 0.05)',
          border: `1px solid ${backendOnline ? 'rgba(0, 240, 255, 0.4)' : 'var(--border-subtle)'}`
        }} title={backendOnline ? 'Connected to FastAPI backend with XGBoost, Random Forest & Scapy' : 'Running in client-side cached mode'}>
          <Cpu size={12} color={backendOnline ? 'var(--cyan)' : 'var(--text-muted)'} />
          <span style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            fontWeight: '600',
            letterSpacing: '0.3px',
            color: backendOnline ? 'var(--cyan)' : 'var(--text-muted)'
          }}>
            AI CORE: {backendOnline ? 'LIVE API (ONLINE)' : 'STANDALONE (CLIENT)'}
          </span>
        </div>

        {/* Minimal Scenario Selector Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            Scenario:
          </span>
          <div style={{ position: 'relative' }}>
            <select
              value={currentScenario.id}
              onChange={(e) => onSelectScenario(ATTACK_SCENARIOS[e.target.value] || ATTACK_SCENARIOS.NORMAL)}
              style={{
                appearance: 'none',
                WebkitAppearance: 'none',
                background: 'rgba(10, 16, 29, 0.85)',
                border: `1px solid ${isDanger ? 'rgba(239, 68, 68, 0.5)' : (isWarning ? 'rgba(245, 158, 11, 0.5)' : 'var(--border-subtle)')}`,
                borderRadius: '5px',
                padding: '4px 28px 4px 10px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                fontWeight: '600',
                color: isDanger ? 'var(--danger)' : (isWarning ? 'var(--amber)' : '#fff'),
                cursor: 'pointer',
                outline: 'none',
                transition: 'border-color 0.15s ease'
              }}
            >
              {scenarios.map((sc) => (
                <option key={sc.id} value={sc.id} style={{ background: '#0a101d', color: '#fff' }}>
                  {sc.label}
                </option>
              ))}
            </select>
            <div style={{
              position: 'absolute',
              right: '8px',
              top: '50%',
              transform: 'translateY(-50%)',
              pointerEvents: 'none',
              fontSize: '9px',
              color: 'var(--text-muted)'
            }}>
              ▼
            </div>
          </div>
        </div>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
        {/* Live Telemetry Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-secondary)'
        }}>
          <Radio size={13} color="var(--cyan)" />
          <span>TELEMETRY:</span>
          <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>
            {currentScenario.packetRate || '48 pkts/sec'}
          </span>
        </div>

        <div style={{ width: '1px', height: '18px', background: 'var(--border-subtle)' }} />

        {/* Notifications Icon with Badge */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              padding: '6px',
              borderRadius: '6px'
            }}
          >
            <Bell size={16} />
            <span style={{
              position: 'absolute',
              top: '2px',
              right: '2px',
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: isDanger ? 'var(--danger)' : 'var(--cyan)'
            }} />
          </button>

          {/* Notifications Dropdown Modal */}
          {showNotifications && (
            <div style={{
              position: 'absolute',
              top: '36px',
              right: '0',
              width: '320px',
              background: 'var(--bg-card-elevated)',
              border: '1px solid var(--border-medium)',
              borderRadius: '8px',
              boxShadow: '0 12px 32px rgba(0, 0, 0, 0.7)',
              padding: '12px',
              zIndex: 50
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                borderBottom: '1px solid var(--border-subtle)',
                paddingBottom: '8px',
                marginBottom: '8px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                fontWeight: '700'
              }}>
                <span>SECURITY ALERTS (NTRO-SOC)</span>
                <span style={{ color: 'var(--cyan)' }}>3 NEW</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11px' }}>
                <div style={{ padding: '6px', background: 'rgba(239, 68, 68, 0.08)', borderLeft: '2px solid var(--danger)', borderRadius: '3px' }}>
                  <div style={{ fontWeight: '600', color: '#fff' }}>Volumetric ESP Burst</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Threshold exceeded (1,240 pps) on SPI 0xb3b1799d.</div>
                </div>
                <div style={{ padding: '6px', background: 'rgba(245, 158, 11, 0.08)', borderLeft: '2px solid var(--amber)', borderRadius: '3px' }}>
                  <div style={{ fontWeight: '600', color: '#fff' }}>IKE Proposal Probe (MODP-1024)</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Rejected non-compliant Diffie-Hellman proposal.</div>
                </div>
                <div style={{ padding: '6px', background: 'rgba(0, 240, 255, 0.08)', borderLeft: '2px solid var(--cyan)', borderRadius: '3px' }}>
                  <div style={{ fontWeight: '600', color: '#fff' }}>Automated Rekey Sync</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Child SA refreshed with PFS (Group 14).</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* User Profile Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px 10px',
          background: 'rgba(255, 255, 255, 0.04)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '6px'
        }}>
          <User size={13} color="var(--cyan)" />
          <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
            <span style={{ color: '#fff', fontWeight: '600' }}>ANALYST_01</span>
            <span style={{ color: 'var(--text-dim)', marginLeft: '6px' }}>[NTRO]</span>
          </div>
        </div>
      </div>
    </header>
  );
}
