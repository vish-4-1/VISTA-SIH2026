import React from 'react';
import { Shield, ShieldAlert, Activity, Cpu, Network, Radio, Terminal } from 'lucide-react';

export default function Header({ scenario, onResetScenario }) {
  const isDanger = scenario.threatLevel === 'CRITICAL';
  const isWarning = scenario.threatLevel === 'ELEVATED';

  return (
    <header style={{
      height: '64px',
      padding: '0 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      background: 'rgba(7, 11, 20, 0.85)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-subtle)',
      zIndex: 20
    }}>
      {/* Brand & Project Identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '10px',
          background: isDanger
            ? 'linear-gradient(135deg, rgba(255, 42, 85, 0.3), rgba(255, 42, 85, 0.1))'
            : 'linear-gradient(135deg, rgba(0, 240, 255, 0.3), rgba(0, 255, 136, 0.1))',
          border: `1px solid ${isDanger ? 'var(--danger)' : 'var(--cyan)'}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: isDanger ? '0 0 16px var(--danger-glow)' : '0 0 16px var(--cyan-glow)'
        }}>
          {isDanger ? (
            <ShieldAlert size={20} color="var(--danger)" />
          ) : (
            <Shield size={20} color="var(--cyan)" />
          )}
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '18px', fontWeight: '800', letterSpacing: '1px', color: '#fff' }}>
              VISTA
            </span>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 6px',
              background: 'rgba(0, 240, 255, 0.15)',
              border: '1px solid rgba(0, 240, 255, 0.3)',
              borderRadius: '4px',
              color: 'var(--cyan)',
              fontWeight: '600'
            }}>
              3D TESTBED v2.1
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', letterSpacing: '0.2px' }}>
            Encrypted IPsec Telemetry & eBPF Kernel Security Center
          </div>
        </div>
      </div>

      {/* Middle Status Telemetry Bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {/* StrongSwan Tunnel Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)'
        }}>
          <Network size={14} color="var(--cyan)" />
          <span>IKEv2 / IPsec:</span>
          <span style={{ color: '#fff', fontWeight: '600' }}>AES-GCM-256</span>
          <span style={{ fontSize: '10px', color: 'var(--cyan)' }}>[DH 19 / PFS]</span>
        </div>

        <div style={{ width: '1px', height: '24px', background: 'var(--border-subtle)' }} />

        {/* eBPF Probe Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)'
        }}>
          <Cpu size={14} color="var(--green)" />
          <span>eBPF Hooks:</span>
          <span style={{ color: 'var(--green)', fontWeight: '600' }}>3 PROBES RUNNING</span>
        </div>

        <div style={{ width: '1px', height: '24px', background: 'var(--border-subtle)' }} />

        {/* Outer ESP SPI Key */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)'
        }}>
          <Radio size={14} color="var(--purple)" />
          <span>ESP SPI:</span>
          <span style={{ color: 'var(--purple)', fontWeight: '600' }}>0xb3b1799d</span>
        </div>
      </div>

      {/* Right Composite Threat Score Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '6px 14px',
          borderRadius: '8px',
          background: isDanger
            ? 'rgba(255, 42, 85, 0.15)'
            : (isWarning ? 'rgba(255, 170, 0, 0.15)' : 'rgba(0, 255, 136, 0.1)'),
          border: `1px solid ${isDanger ? 'var(--border-danger)' : (isWarning ? 'var(--amber)' : 'rgba(0, 255, 136, 0.3)')}`
        }}>
          <span className={`status-dot ${isDanger ? 'danger' : (isWarning ? 'warning' : 'online')}`}></span>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
              THREAT LEVEL
            </span>
            <span style={{
              fontSize: '13px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              color: isDanger ? 'var(--danger)' : (isWarning ? 'var(--amber)' : 'var(--green)')
            }}>
              {scenario.threatLevel} ({scenario.compositeScore}/100)
            </span>
          </div>
        </div>

        {scenario.id !== 'NORMAL' && (
          <button
            className="cyber-btn"
            onClick={onResetScenario}
            style={{ fontSize: '11px', padding: '6px 10px' }}
          >
            Reset
          </button>
        )}
      </div>
    </header>
  );
}
