import React from 'react';
import { Shield, Zap, UploadCloud, Search, Radio, KeyRound } from 'lucide-react';
import { ATTACK_SCENARIOS } from '../data/networkData';

export default function AttackSimulatorBar({ currentScenario, onSelectScenario }) {
  const scenariosList = [
    { id: 'NORMAL', label: 'Normal Traffic', icon: Shield, color: 'var(--cyan)' },
    { id: 'DOS_FLOOD', label: 'DoS Flood', icon: Zap, color: 'var(--danger)' },
    { id: 'DATA_EXFILTRATION', label: 'Data Exfil', icon: UploadCloud, color: '#ff6600' },
    { id: 'PORT_SCAN', label: 'Port Scan', icon: Search, color: 'var(--amber)' },
    { id: 'C2_BEACONING', label: 'C2 Beaconing', icon: Radio, color: 'var(--purple)' },
    { id: 'BRUTE_FORCE', label: 'Brute Force', icon: KeyRound, color: '#ff4d6d' }
  ];

  return (
    <div style={{
      position: 'absolute',
      top: '16px',
      left: '50%',
      transform: 'translateX(-50%)',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      background: 'rgba(7, 11, 20, 0.82)',
      backdropFilter: 'blur(16px)',
      padding: '6px 10px',
      borderRadius: '12px',
      border: '1px solid var(--border-subtle)',
      zIndex: 10,
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
    }}>
      <div style={{
        fontSize: '10px',
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-dim)',
        paddingRight: '6px',
        borderRight: '1px solid var(--border-subtle)',
        textTransform: 'uppercase',
        letterSpacing: '0.5px'
      }}>
        SCENARIO:
      </div>

      {scenariosList.map((sc) => {
        const IconComponent = sc.icon;
        const isActive = currentScenario.id === sc.id;
        const isAttack = sc.id !== 'NORMAL';

        return (
          <button
            key={sc.id}
            className={`cyber-btn ${isActive ? (isAttack ? 'danger active' : 'active') : ''}`}
            onClick={() => onSelectScenario(ATTACK_SCENARIOS[sc.id])}
            style={{
              padding: '6px 12px',
              fontSize: '11px',
              borderColor: isActive ? sc.color : undefined
            }}
          >
            <IconComponent size={13} color={isActive ? sc.color : 'var(--text-muted)'} />
            <span>{sc.label}</span>
          </button>
        );
      })}
    </div>
  );
}
