import React from 'react';
import { 
  Crosshair, 
  ShieldAlert, 
  Flame, 
  UploadCloud, 
  Search, 
  Radio, 
  KeyRound, 
  ExternalLink,
  Clock,
  AlertTriangle,
  Layers
} from 'lucide-react';
import { MITRE_ATTACK_MAPPINGS, THREAT_EVENTS } from '../../data/socData';

export default function ThreatIntelligenceView() {
  const iocs = [
    { type: "ESP SPI Key", value: "0xb3b1799d", label: "Subject of Volumetric Egress", risk: "Elevated" },
    { type: "IP Address", value: "198.51.100.44", label: "Malicious IKE Scanner (MODP-1024)", risk: "High" },
    { type: "Hash Signature", value: "sha256:4a819b...f021", label: "C2 Beaconing Pattern Signature", risk: "Medium" },
    { type: "Socket Port", value: "UDP 500 / 4500", label: "IKE Auth Brute Force Target", risk: "High" },
  ];

  return (
    <div style={{
      padding: '24px 32px 48px 32px',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px',
      maxWidth: '1680px',
      margin: '0 auto',
      width: '100%'
    }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: '24px', fontWeight: '800', color: '#fff', marginBottom: '4px' }}>
          Threat Intelligence & Attack Attribution
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          MITRE ATT&CK enterprise mapping, indicators of compromise (IOCs), and historical anomaly correlations
        </p>
      </div>

      {/* MITRE ATT&CK Matrix Card */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div className="soc-card-title">
            <Layers size={16} color="var(--cyan)" />
            <span>MITRE ATT&CK® Enterprise Matrix Mapping (IPsec Vectors)</span>
          </div>
          <span className="soc-badge info">5 Techniques Identified</span>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>Technique ID</th>
              <th>Technique Name</th>
              <th>Tactic</th>
              <th>Simulated in VISTA</th>
              <th>Severity</th>
              <th>Mitigation State</th>
            </tr>
          </thead>
          <tbody>
            {MITRE_ATTACK_MAPPINGS.map((m, idx) => (
              <tr key={idx}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: '600' }}>
                  {m.technique}
                </td>
                <td style={{ fontWeight: '600', color: '#fff' }}>{m.name}</td>
                <td><span className="soc-badge low">{m.tactic}</span></td>
                <td style={{ color: 'var(--text-secondary)' }}>{m.detectedIn}</td>
                <td>
                  <span className={`soc-badge ${m.severity.toLowerCase()}`}>{m.severity}</span>
                </td>
                <td>
                  <span style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: '600' }}>
                    {m.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* IOC Grid & Historical Progression */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        
        {/* Indicators of Compromise (IOCs) */}
        <div className="soc-card" style={{ padding: '20px' }}>
          <div className="soc-card-title" style={{ marginBottom: '14px' }}>
            <Crosshair size={16} color="var(--danger)" />
            <span>Active Indicators of Compromise (IOCs)</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {iocs.map((ioc, i) => (
              <div key={i} style={{
                background: 'rgba(6, 9, 15, 0.6)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '12px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{ioc.type}</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{ioc.value}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{ioc.label}</div>
                </div>
                <span className={`soc-badge ${ioc.risk.toLowerCase()}`}>{ioc.risk}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Timeline Progression */}
        <div className="soc-card" style={{ padding: '20px' }}>
          <div className="soc-card-title" style={{ marginBottom: '14px' }}>
            <Clock size={16} color="var(--amber)" />
            <span>Attack Progression Timeline (NTRO Testbed)</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {THREAT_EVENTS.slice(0, 4).map((th, i) => (
              <div key={i} style={{
                borderLeft: `2px solid ${th.severity === 'High' ? 'var(--danger)' : 'var(--amber)'}`,
                paddingLeft: '12px',
                marginLeft: '4px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--text-dim)' }}>{th.time}</span>
                  <span className={`soc-badge ${th.severity.toLowerCase()}`} style={{ fontSize: '9px' }}>{th.severity}</span>
                </div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#fff', marginTop: '2px' }}>
                  {th.event}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {th.impact}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
