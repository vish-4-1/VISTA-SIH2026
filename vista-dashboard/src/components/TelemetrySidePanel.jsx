import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Cpu, 
  ShieldAlert, 
  Terminal, 
  Layers, 
  Gauge, 
  TrendingUp, 
  AlertTriangle,
  Lock,
  Zap,
  Info
} from 'lucide-react';

export default function TelemetrySidePanel({ scenario, onInspectDetails }) {
  const [kernelLogs, setKernelLogs] = useState([]);
  const isDanger = scenario.threatLevel === 'CRITICAL';
  const isWarning = scenario.threatLevel === 'ELEVATED';

  // Simulate real-time streaming eBPF events
  useEffect(() => {
    const eventsPool = [
      `[kprobe:esp_output] spi=0xb3b1799d seq=${Math.floor(4000 + Math.random()*2000)} len=${scenario.meanPacketSize} iat=${scenario.meanIat}`,
      `[tracepoint:sock:sock_exceed_buf] drops=${scenario.socketBufferDrops} qlen=${isDanger ? 128 : 12}`,
      `[kprobe:tcp_retransmit_skb] state=ESTABLISHED skb_drops=${scenario.tcpRetrans}`,
      `[kprobe:esp_input] inbound SPI=0x49c812a0 auth=AEAD_PASS icv=VALID`,
      `[sys_enter_connect] pid=${Math.floor(1000 + Math.random()*800)} comm="strongswan" fd=7`,
      `[classifier:xgboost] flow_pred="${scenario.attackType}" conf=0.984 latency=1.2ms`
    ];

    const interval = setInterval(() => {
      const randomEvent = eventsPool[Math.floor(Math.random() * eventsPool.length)];
      const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
      setKernelLogs(prev => [
        `[${timestamp}] ${randomEvent}`,
        ...prev.slice(0, 16)
      ]);
    }, isDanger ? 400 : 1200);

    return () => clearInterval(interval);
  }, [scenario, isDanger]);

  return (
    <aside style={{
      width: '420px',
      height: 'calc(100% - 64px)',
      background: 'rgba(9, 15, 28, 0.92)',
      backdropFilter: 'blur(20px)',
      borderLeft: '1px solid var(--border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 15,
      overflowY: 'auto'
    }}>
      {/* Panel Header */}
      <div style={{
        padding: '16px 20px',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Gauge size={16} color="var(--cyan)" />
          <span style={{ fontSize: '13px', fontWeight: '700', letterSpacing: '0.8px', color: '#fff', textTransform: 'uppercase' }}>
            Live Telemetry & AI Stream
          </span>
        </div>
        <button
          className="cyber-btn"
          style={{ fontSize: '10px', padding: '4px 8px' }}
          onClick={onInspectDetails}
        >
          <Info size={12} /> Inspect
        </button>
      </div>

      <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>

        {/* 1. REAL-TIME FLOW METRICS */}
        <div className="glass-panel" style={{ padding: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              OBSERVED ESP FLOW METRICS
            </span>
            <span style={{ fontSize: '10px', color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>
              Side-Channel (Payload Encrypted)
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px' }}>BITRATE (bps)</div>
              <div style={{ fontSize: '16px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: isDanger ? 'var(--danger)' : '#fff' }}>
                {scenario.bitRate}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px' }}>PACKET RATE</div>
              <div style={{ fontSize: '16px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: isDanger ? 'var(--danger)' : 'var(--cyan)' }}>
                {scenario.packetRate}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px' }}>MEAN PACKET SIZE</div>
              <div style={{ fontSize: '14px', fontWeight: '600', fontFamily: 'var(--font-mono)', color: '#fff' }}>
                {scenario.meanPacketSize}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px' }}>INTER-ARRIVAL (IAT)</div>
              <div style={{ fontSize: '14px', fontWeight: '600', fontFamily: 'var(--font-mono)', color: '#fff' }}>
                {scenario.meanIat}
              </div>
            </div>
          </div>

          {/* Buffer drops alert if present */}
          {(scenario.socketBufferDrops > 0 || scenario.tcpRetrans > 2) && (
            <div style={{
              marginTop: '10px',
              padding: '8px 10px',
              background: 'rgba(255, 42, 85, 0.12)',
              border: '1px solid var(--border-danger)',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: 'var(--danger)'
            }}>
              <AlertTriangle size={14} />
              <span>Kernel Drops: {scenario.socketBufferDrops} pkts | TCP Retrans: {scenario.tcpRetrans}</span>
            </div>
          )}
        </div>

        {/* 2. VISTA AI INFERENCE & CLASSIFIER */}
        <div className="glass-panel" style={{
          padding: '14px',
          borderColor: isDanger ? 'var(--border-danger)' : (isWarning ? 'var(--amber)' : 'var(--border-subtle)')
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Zap size={15} color={isDanger ? 'var(--danger)' : 'var(--cyan)'} />
              <span style={{ fontSize: '11px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: '#fff' }}>
                VISTA AI INFERENCE (TIER A & B)
              </span>
            </div>
            <span style={{
              fontSize: '9px',
              padding: '2px 6px',
              background: isDanger ? 'rgba(255, 42, 85, 0.2)' : 'rgba(0, 255, 136, 0.15)',
              color: isDanger ? 'var(--danger)' : 'var(--green)',
              borderRadius: '4px',
              fontWeight: '700',
              fontFamily: 'var(--font-mono)'
            }}>
              {scenario.attackType === 'BENIGN' ? 'NORMAL FLOW' : 'ANOMALY FLAGGED'}
            </span>
          </div>

          {/* Classification details */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Classified Traffic:</span>
              <span style={{ fontWeight: '600', color: '#fff', fontFamily: 'var(--font-mono)' }}>{scenario.trafficType}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Attack Attribution:</span>
              <span style={{
                fontWeight: '700',
                color: isDanger ? 'var(--danger)' : (isWarning ? 'var(--amber)' : 'var(--green)'),
                fontFamily: 'var(--font-mono)'
              }}>
                {scenario.attackType}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Zero-Day Anomaly:</span>
              <span style={{
                color: isDanger ? 'var(--danger)' : 'var(--green)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px'
              }}>
                {isDanger ? 'Isolation Forest Flagged (-1)' : 'Inlier Baseline (+1)'}
              </span>
            </div>
          </div>

          {/* SHAP Feature Attribution Weights */}
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '8px', fontFamily: 'var(--font-mono)' }}>
              SHAP EXPLAINABILITY (TOP CONTRIBUTING FEATURES)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {scenario.shapFeatures.map((feat, idx) => {
                const absVal = Math.abs(feat.weight);
                const pct = Math.min(100, Math.round(absVal * 100));
                return (
                  <div key={idx} style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>{feat.name}</span>
                      <span style={{ color: isDanger ? 'var(--danger)' : 'var(--cyan)', fontWeight: '600' }}>
                        {(feat.weight > 0 ? '+' : '') + feat.weight.toFixed(3)}
                      </span>
                    </div>
                    <div style={{ height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${pct}%`,
                        height: '100%',
                        background: isDanger ? 'var(--danger)' : 'var(--cyan)',
                        borderRadius: '2px'
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* 3. NIST COMPOSITE RISK & MITIGATION */}
        <div className="glass-panel" style={{ padding: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
            <Lock size={14} color="var(--purple)" />
            <span style={{ fontSize: '11px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: '#fff' }}>
              POSTURE RISK & MITIGATION
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5', marginBottom: '8px' }}>
            {scenario.mitigation}
          </div>
          <div style={{
            fontSize: '10px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-dim)',
            display: 'flex',
            justifyContent: 'space-between',
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '6px'
          }}>
            <span>NIST SP 800-77 Rev. 1: Pass</span>
            <span>BSI TR-02102: Compliant</span>
          </div>
        </div>

        {/* 4. REAL-TIME eBPF TERMINAL */}
        <div style={{
          background: '#04070e',
          border: '1px solid var(--border-subtle)',
          borderRadius: '10px',
          padding: '12px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', color: 'var(--text-dim)' }}>
            <Terminal size={12} color="var(--green)" />
            <span>eBPF KERNEL EVENT STREAM</span>
            <span className="status-dot online" style={{ marginLeft: 'auto', width: '6px', height: '6px' }}></span>
          </div>
          <div style={{
            height: '120px',
            overflowY: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            gap: '4px',
            color: '#a7f3d0'
          }}>
            {kernelLogs.map((log, i) => (
              <div key={i} style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', opacity: 1 - i * 0.15 }}>
                {log}
              </div>
            ))}
          </div>
        </div>

      </div>
    </aside>
  );
}
