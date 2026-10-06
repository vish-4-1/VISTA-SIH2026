import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Cpu, 
  Layers, 
  Lock, 
  Terminal, 
  ExternalLink, 
  CheckCircle2, 
  AlertTriangle, 
  FileText, 
  Download, 
  Zap, 
  Server, 
  Radio, 
  ArrowRight,
  TrendingUp,
  BarChart2,
  Clock,
  Sparkles,
  Play,
  Box
} from 'lucide-react';
import { 
  SYSTEM_STATUS, 
  SECURITY_POSTURE_BREAKDOWN, 
  TOPOLOGY_DATA, 
  THREAT_EVENTS, 
  METADATA_EXPOSURE_ITEMS, 
  EBPF_LIVE_EVENTS 
} from '../../data/socData';
import { fetchSocStatus, fetchEbpfEvents } from '../../utils/apiClient';

export default function OverviewView({ 
  scenario = {}, 
  onNavigateToTab, 
  onSelectScenario 
}) {
  const currentScenario = scenario || {};
  const [activeTrafficTab, setActiveTrafficTab] = useState('throughput');
  const [reportState, setReportState] = useState('idle'); // idle | generating | ready
  const [socMetrics, setSocMetrics] = useState(SYSTEM_STATUS);
  const [ebpfEvents, setEbpfEvents] = useState(EBPF_LIVE_EVENTS);

  const isDanger = currentScenario.threatLevel === 'CRITICAL';
  const isWarning = currentScenario.threatLevel === 'ELEVATED';

  // Fetch dynamic metrics from live backend if online
  useEffect(() => {
    let isMounted = true;
    fetchSocStatus()
      .then(data => {
        if (isMounted && data) {
          setSocMetrics(prev => ({
            ...prev,
            securityScore: data.securityScore || prev.securityScore,
            packetsAnalyzed: data.packetsAnalyzed || prev.packetsAnalyzed,
            threatsDetectedCount: data.threatsDetectedCount ?? prev.threatsDetectedCount,
            aiConfidence: data.aiConfidence || prev.aiConfidence,
          }));
        }
      })
      .catch(() => {
        // Fall back gracefully to dynamically computed SYSTEM_STATUS
      });
    return () => { isMounted = false; };
  }, []);

  // Poll live eBPF kernel event stream every 2.5 seconds
  useEffect(() => {
    let isMounted = true;
    const pollEbpf = () => {
      fetchEbpfEvents(6)
        .then(res => {
          if (isMounted && res && res.events && res.events.length > 0) {
            setEbpfEvents(res.events);
          }
        })
        .catch(() => {
          // Keep default buffered events if backend is offline
        });
    };
    pollEbpf();
    const interval = setInterval(pollEbpf, 2500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Handle report generation simulation
  const handleGenerateReport = () => {
    setReportState('generating');
    setTimeout(() => {
      setReportState('ready');
    }, 1200);
  };

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

      {/* 1. HEADER & SYSTEM STATUS STRIP */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div>
            <h1 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.3px', color: '#fff', marginBottom: '4px' }}>
              IPsec Security Overview
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              Real-time protocol analysis, encrypted traffic intelligence and security posture
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button 
              className="soc-btn soc-btn-primary"
              onClick={() => onNavigateToTab('testbed')}
              style={{ fontSize: '12px' }}
            >
              <span>OPEN 3D TESTBED</span>
              <ArrowRight size={14} />
            </button>
            <button 
              className="soc-btn"
              onClick={() => onNavigateToTab('reports')}
              style={{ fontSize: '12px' }}
            >
              <FileText size={14} />
              <span>REPORTS</span>
            </button>
          </div>
        </div>

        {/* Minimal System Status Strip */}
        <div style={{
          padding: '8px 16px',
          background: 'rgba(10, 16, 29, 0.6)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Status:</span>
            <span style={{ color: isDanger ? 'var(--danger)' : 'var(--green)', fontWeight: '700' }}>
              {isDanger ? 'COMPROMISED' : 'ACTIVE (Proto 50)'}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Suite:</span>
            <span style={{ color: '#fff', fontWeight: '600' }}>AES-256-GCM · DH 19 · PFS</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>eBPF Probes:</span>
            <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>3 Active</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>AI Inference:</span>
            <span style={{ color: 'var(--green)', fontWeight: '600' }}>ONLINE (1.2ms)</span>
          </div>
        </div>
      </div>

      {/* 2. KEY METRIC CARDS (4 CLEAN, MINIMAL CARDS) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '16px'
      }}>
        {/* Card 1: SECURITY SCORE */}
        <div 
          className="soc-card" 
          onClick={() => onNavigateToTab('security')}
          style={{ padding: '18px 20px', cursor: 'pointer' }}
        >
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px', letterSpacing: '0.4px' }}>
            SECURITY SCORE
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
            <span style={{
              fontSize: '30px',
              fontWeight: '800',
              fontFamily: 'var(--font-mono)',
              color: isDanger ? 'var(--danger)' : 'var(--green)'
            }}>
              {isDanger ? '42' : socMetrics.securityScore}
            </span>
            <span style={{ fontSize: '13px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>/100</span>
          </div>
          <div style={{
            fontSize: '11px',
            color: isDanger ? 'var(--danger)' : 'var(--green)',
            fontWeight: '600',
            marginTop: '6px',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}>
            <CheckCircle2 size={12} />
            <span>{isDanger ? 'Critical Risk' : 'NIST SP 800-77 Evaluated'}</span>
          </div>
        </div>

        {/* Card 2: ACTIVE PEERS */}
        <div 
          className="soc-card" 
          onClick={() => onNavigateToTab('traffic')}
          style={{ padding: '18px 20px', cursor: 'pointer' }}
        >
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px', letterSpacing: '0.4px' }}>
            ACTIVE PEERS & TUNNELS
          </div>
          <div style={{ fontSize: '30px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#fff' }}>
            2 Tunnels
          </div>
          <div style={{ fontSize: '11px', color: 'var(--green)', fontWeight: '600', marginTop: '6px' }}>
            Mode B Duplex Active
          </div>
        </div>

        {/* Card 3: PACKETS ANALYZED */}
        <div 
          className="soc-card" 
          onClick={() => onNavigateToTab('traffic')}
          style={{ padding: '18px 20px', cursor: 'pointer' }}
        >
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px', letterSpacing: '0.4px' }}>
            PACKETS ANALYZED
          </div>
          <div style={{ fontSize: '30px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#fff' }}>
            {socMetrics.packetsAnalyzed}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--cyan)', fontWeight: '600', marginTop: '6px' }}>
            5,531 Verified Flows
          </div>
        </div>

        {/* Card 4: AI CLASSIFICATION */}
        <div 
          className="soc-card" 
          onClick={() => onNavigateToTab('ai')}
          style={{ padding: '18px 20px', cursor: 'pointer' }}
        >
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px', letterSpacing: '0.4px' }}>
            AI ATTRIBUTION
          </div>
          <div style={{ fontSize: '30px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: isDanger ? 'var(--danger)' : 'var(--cyan)' }}>
            {isDanger ? 'ATTACK' : socMetrics.aiConfidence}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            {isDanger ? 'Volumetric Flood' : 'XGBoost & Random Forest'}
          </div>
        </div>
      </div>

      {/* 3. ROW: SECURITY POSTURE + CRYPTO COMPLIANCE CARD */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>

        {/* Security Posture Breakdown Card */}
        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
            <div>
              <div className="soc-card-title">
                <ShieldCheck size={16} color="var(--cyan)" />
                <span>Security Posture & Compliance Evaluation</span>
              </div>
              <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
                Evaluated against NIST SP 800-77 Rev. 1 & BSI TR-02102-3 Standards
              </div>
            </div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '5px 12px',
              background: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: '6px'
            }}>
              <span className="status-pulse green"></span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--green)' }}>
                {socMetrics.securityScore}/100 SCORE
              </span>
            </div>
          </div>

          {/* Posture Progress Bars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {SECURITY_POSTURE_BREAKDOWN.map((item, idx) => (
              <div key={idx}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: '600', color: '#fff' }}>{item.name}</span>
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>({item.standard})</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{item.details}</span>
                    <span style={{ fontWeight: '700', color: item.score >= 95 ? 'var(--green)' : 'var(--cyan)' }}>
                      {item.score}%
                    </span>
                  </div>
                </div>
                <div style={{ height: '5px', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${item.score}%`,
                    height: '100%',
                    background: item.score >= 95 
                      ? 'linear-gradient(90deg, #10b981, #00f0ff)' 
                      : 'linear-gradient(90deg, #00f0ff, #3b82f6)',
                    borderRadius: '3px'
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Cryptographic Compliance Summary Card */}
        <div className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div className="soc-card-title" style={{ marginBottom: '4px' }}>
              <Lock size={16} color="var(--cyan)" />
              <span>Cryptographic Profile</span>
            </div>
            <div className="soc-card-subtitle" style={{ marginBottom: '16px' }}>
              Active cipher suite and key exchange validation
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Cipher Algorithm</span>
                <span style={{ color: '#fff', fontWeight: '600' }}>AES-256-GCM (AEAD)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Diffie-Hellman</span>
                <span style={{ color: 'var(--green)', fontWeight: '600' }}>Group 19 (ECP-256)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Forward Secrecy</span>
                <span style={{ color: 'var(--green)', fontWeight: '600' }}>PFS Enabled</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Anti-Replay Window</span>
                <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>64-Packet (RFC 4303)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Rekey Lifetime</span>
                <span style={{ color: '#fff', fontWeight: '600' }}>28,800s Compliant</span>
              </div>
            </div>
          </div>

          <div style={{
            marginTop: '16px',
            padding: '10px 12px',
            background: 'rgba(16, 185, 129, 0.06)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '11px',
            fontFamily: 'var(--font-mono)'
          }}>
            <span style={{ color: 'var(--text-muted)' }}>NIST SP 800-77 Status:</span>
            <span style={{ color: 'var(--green)', fontWeight: '700' }}>COMPLIANT</span>
          </div>
        </div>

      </div>

      {/* 4. LIVE 2D HOST-TO-HOST DUPLEX VPN TOPOLOGY (MODE B) */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <div className="soc-card-title">
              <Layers size={16} color="var(--cyan)" />
              <span>Live Host-to-Host IPsec Peering & SA Topology (Mode B)</span>
            </div>
            <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
              Full-Duplex Host-to-Host Transport Mode Traffic & Security Association Mapping (Option B eBPF Telemetry)
            </div>
          </div>

          <button 
            className="soc-btn soc-btn-primary"
            onClick={() => onNavigateToTab('testbed')}
            style={{ fontSize: '11px' }}
          >
            <span>OPEN 3D TESTBED →</span>
          </button>
        </div>

        {/* 2D Visual Network Pipeline — Mode B Duplex Peering */}
        <div style={{
          background: 'rgba(6, 9, 15, 0.6)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '24px 20px',
          display: 'grid',
          gridTemplateColumns: '300px 1fr 300px',
          alignItems: 'center',
          gap: '20px'
        }}>
          {/* PC 1 (WORKSTATION A) */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '16px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={15} color="var(--cyan)" />
                <span style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>PC 1 (WORKSTATION A)</span>
              </div>
              <span className="soc-badge success" style={{ fontSize: '10px' }}>PEER A</span>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
              <div>Host / IP: <span style={{ color: 'var(--cyan)' }}>{TOPOLOGY_DATA.pc1?.ip || '172.20.0.2'}</span> (vista-pc1)</div>
              <div>Outbound SPI: <span style={{ color: '#fff' }}>{TOPOLOGY_DATA.pc1?.spi || '0xb3b1799d'}</span></div>
              <div>eBPF Probe: <span style={{ color: 'var(--green)' }}>{TOPOLOGY_DATA.pc1?.ebpfProbe || 'kprobe_esp_output'}</span></div>
              <div>Mode / State: <span style={{ color: 'var(--green)' }}>Transport / ESTABLISHED</span></div>
            </div>
          </div>

          {/* FULL-DUPLEX IPSEC TRANSPORT ENCRYPTION CONNECTOR */}
          <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
            <div style={{
              width: '100%',
              height: '4px',
              background: isDanger ? 'var(--danger)' : 'var(--cyan)',
              borderRadius: '2px',
              boxShadow: isDanger ? '0 0 12px var(--danger)' : '0 0 12px var(--cyan)',
              position: 'relative'
            }}>
              {/* Bidirectional Animated Packet Dots */}
              <div style={{
                position: 'absolute',
                top: '-4px',
                left: '25%',
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: '#fff',
                boxShadow: '0 0 8px #fff'
              }} />
              <div style={{
                position: 'absolute',
                top: '-4px',
                left: '75%',
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: 'var(--green)',
                boxShadow: '0 0 8px var(--green)'
              }} />
            </div>

            <div style={{
              marginTop: '14px',
              textAlign: 'center',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: isDanger ? 'var(--danger)' : 'var(--cyan)',
              background: 'rgba(7, 11, 20, 0.9)',
              padding: '6px 14px',
              borderRadius: '6px',
              border: `1px solid ${isDanger ? 'rgba(239, 68, 68, 0.4)' : 'rgba(0, 240, 255, 0.35)'}`,
              display: 'flex',
              flexDirection: 'column',
              gap: '2px'
            }}>
              <span style={{ fontWeight: '700' }}>🔐 Full-Duplex Host-to-Host Transport Mode</span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                ESP Proto 50 · AES-256-GCM AEAD · DH Group 19 (ECP-256) · PFS Active
              </span>
            </div>
          </div>

          {/* PC 2 (WORKSTATION B) */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '16px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={15} color="var(--green)" />
                <span style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>PC 2 (WORKSTATION B)</span>
              </div>
              <span className="soc-badge success" style={{ fontSize: '10px' }}>PEER B</span>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
              <div>Host / IP: <span style={{ color: 'var(--green)' }}>{TOPOLOGY_DATA.pc2?.ip || '172.20.0.10'}</span> (vista-pc2)</div>
              <div>Inbound SPI: <span style={{ color: '#fff' }}>{TOPOLOGY_DATA.pc2?.spi || '0x49c812a0'}</span></div>
              <div>eBPF Probe: <span style={{ color: 'var(--green)' }}>{TOPOLOGY_DATA.pc2?.ebpfProbe || 'kprobe_esp_input'}</span></div>
              <div>Mode / State: <span style={{ color: 'var(--green)' }}>Transport / ESTABLISHED</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* 5. ROW: LIVE TRAFFIC ANALYTICS + VISTA AI INFERENCE */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: '20px' }}>

        {/* Live Traffic Analytics Chart */}
        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div>
              <div className="soc-card-title">
                <Activity size={16} color="var(--cyan)" />
                <span>Encrypted Traffic Behaviour</span>
              </div>
              <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
                Real-time side-channel metrics over 100ms sliding windows
              </div>
            </div>

            <span className="soc-badge info">
              Encrypted Web Traffic — 94.2% confidence
            </span>
          </div>

          {/* Metric Tabs */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
            {[
              { id: 'throughput', label: 'Throughput', val: scenario.bitRate || '310 Kbps' },
              { id: 'rate', label: 'Packet Rate', val: scenario.packetRate || '48 pps' },
              { id: 'size', label: 'Packet Size', val: scenario.meanPacketSize || '460 B' },
              { id: 'iat', label: 'IAT Jitter', val: scenario.meanIat || '0.021 s' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTrafficTab(tab.id)}
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  borderRadius: '6px',
                  background: activeTrafficTab === tab.id ? 'rgba(0, 240, 255, 0.12)' : 'rgba(10, 16, 29, 0.6)',
                  border: activeTrafficTab === tab.id ? '1px solid var(--cyan)' : '1px solid var(--border-subtle)',
                  color: activeTrafficTab === tab.id ? '#fff' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  textAlign: 'left'
                }}
              >
                <div style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{tab.label}</div>
                <div style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '2px' }}>
                  {tab.val}
                </div>
              </button>
            ))}
          </div>

          {/* SVG Traffic Waveform */}
          <div style={{
            height: '160px',
            background: '#04070d',
            borderRadius: '6px',
            border: '1px solid var(--border-subtle)',
            padding: '12px',
            position: 'relative'
          }}>
            <svg viewBox="0 0 500 120" style={{ width: '100%', height: '100%' }}>
              <defs>
                <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={isDanger ? '#ef4444' : '#00f0ff'} stopOpacity="0.4" />
                  <stop offset="100%" stopColor={isDanger ? '#ef4444' : '#00f0ff'} stopOpacity="0.0" />
                </linearGradient>
              </defs>
              <path
                d={isDanger 
                  ? "M0,90 Q50,10 100,85 T200,15 T300,95 T400,10 T500,80 L500,120 L0,120 Z" 
                  : "M0,75 Q60,40 120,65 T240,55 T360,70 T440,50 T500,60 L500,120 L0,120 Z"
                }
                fill="url(#trafficGradient)"
              />
              <path
                d={isDanger 
                  ? "M0,90 Q50,10 100,85 T200,15 T300,95 T400,10 T500,80" 
                  : "M0,75 Q60,40 120,65 T240,55 T360,70 T440,50 T500,60"
                }
                fill="none"
                stroke={isDanger ? '#ef4444' : '#00f0ff'}
                strokeWidth="2"
              />
            </svg>
            <div style={{
              position: 'absolute', bottom: '8px', right: '12px',
              fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)'
            }}>
              Window: 60s @ 100ms eBPF intervals
            </div>
          </div>
        </div>

        {/* VISTA AI Inference Panel */}
        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div className="soc-card-title">
              <Zap size={16} color="var(--cyan)" />
              <span>VISTA AI INFERENCE</span>
            </div>
            <span className="soc-badge success">ONLINE</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px' }}>
            <div style={{ background: 'rgba(6, 9, 15, 0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>TRAFFIC CLASSIFICATION</div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff', marginTop: '2px' }}>
                {scenario.trafficType || 'Encrypted Web Traffic'}
              </div>
            </div>

            <div style={{ background: 'rgba(6, 9, 15, 0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>MODEL CONFIDENCE</div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--cyan)', marginTop: '2px' }}>
                96.8%
              </div>
            </div>

            <div style={{ background: 'rgba(6, 9, 15, 0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>ATTACK ATTRIBUTION</div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: isDanger ? 'var(--danger)' : 'var(--green)', marginTop: '2px' }}>
                {scenario.attackType || 'BENIGN'}
              </div>
            </div>

            <div style={{ background: 'rgba(6, 9, 15, 0.6)', padding: '10px', borderRadius: '6px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>ZERO-DAY ANOMALY</div>
              <div style={{ fontSize: '12px', fontWeight: '600', color: isDanger ? 'var(--danger)' : 'var(--green)', marginTop: '2px' }}>
                {isDanger ? 'Anomaly Detected (-1)' : 'Inlier Baseline (+1)'}
              </div>
            </div>
          </div>

          {/* SHAP-style Explainability Panel */}
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
              TOP CONTRIBUTING FEATURES (SHAP VALUES)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {[
                { name: 'outbound_bytes_ratio', val: '+0.280', pct: 85 },
                { name: 'total_bytes', val: '+0.210', pct: 70 },
                { name: 'max_packet_length', val: '+0.165', pct: 55 },
                { name: 'mean_iat_sec', val: '+0.095', pct: 35 }
              ].map((feat, i) => (
                <div key={i} style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{feat.name}</span>
                    <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>{feat.val}</span>
                  </div>
                  <div style={{ height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${feat.pct}%`, height: '100%', background: 'var(--cyan)', borderRadius: '2px' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* 6. THREAT DETECTION & RESPONSE TABLE */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div>
            <div className="soc-card-title">
              <ShieldAlert size={16} color="var(--amber)" />
              <span>Threat Detection & Security Response Log</span>
            </div>
            <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
              Correlated eBPF kernel drops, AI anomalies, and protocol probes
            </div>
          </div>

          <button 
            className="soc-btn"
            onClick={() => onNavigateToTab('threats')}
            style={{ fontSize: '11px' }}
          >
            <span>VIEW ALL THREATS</span>
          </button>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Detection Method</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {THREAT_EVENTS.map((thr) => (
              <tr key={thr.id}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{thr.time}</td>
                <td style={{ fontWeight: '600', color: '#fff' }}>{thr.event}</td>
                <td>
                  <span className={`soc-badge ${thr.severity.toLowerCase()}`}>
                    {thr.severity}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{thr.source}</td>
                <td>{thr.detectionMethod}</td>
                <td>
                  <span style={{
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    color: thr.status === 'Blocked' ? 'var(--green)' : (thr.status === 'Open' ? 'var(--danger)' : 'var(--amber)')
                  }}>
                    {thr.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 7. ROW: IPSEC CONFIGURATION + METADATA EXPOSURE + REPORT GENERATION */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>

        {/* IPsec Configuration Card */}
        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <div className="soc-card-title">
              <Lock size={15} color="var(--cyan)" />
              <span>Detected IPsec Config</span>
            </div>
            <span className="soc-badge success">
              <CheckCircle2 size={11} />
              <span>Compliant</span>
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
            {[
              { k: 'Protocol', v: 'IPsec (RFC 4301)' },
              { k: 'IKE Daemon', v: 'IKEv2 (strongSwan 5.9)' },
              { k: 'Mode', v: 'Tunnel Mode' },
              { k: 'ESP Cipher', v: 'AES-256-GCM (AEAD)' },
              { k: 'Authentication', v: 'SHA-256 (ICV-128)' },
              { k: 'Key Exchange', v: 'DH Group 14 (MODP-2048)' },
              { k: 'PFS Secrecy', v: 'Enabled' },
              { k: 'Replay Protection', v: 'Enabled (64-bit)' },
              { k: 'Key Lifetime', v: '3600 sec' },
              { k: 'IP Stack', v: 'IPv4 / IPv6 Dual Stack' }
            ].map((cfg, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '3px' }}>
                <span style={{ color: 'var(--text-dim)' }}>{cfg.k}:</span>
                <span style={{ color: '#fff' }}>{cfg.v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Metadata Exposure Card */}
        <div className="soc-card" style={{ padding: '18px' }}>
          <div className="soc-card-title" style={{ marginBottom: '4px' }}>
            <Radio size={15} color="var(--amber)" />
            <span>Side-Channel Exposure</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '12px', lineHeight: '1.4' }}>
            Payload is encrypted, but traffic metadata can still reveal behavioural patterns.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '7px' }}>
            {METADATA_EXPOSURE_ITEMS.slice(0, 6).map((item, i) => (
              <div key={i} style={{ fontSize: '11px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                  <span style={{ color: '#fff' }}>{item.category}</span>
                  <span className={`soc-badge ${item.level.toLowerCase()}`} style={{ fontSize: '9px', padding: '1px 5px' }}>
                    {item.level}
                  </span>
                </div>
                <div style={{ height: '3px', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '2px' }}>
                  <div style={{
                    width: `${item.exposure}%`,
                    height: '100%',
                    background: item.level === 'High' ? 'var(--danger)' : (item.level === 'Medium' ? 'var(--amber)' : 'var(--blue)'),
                    borderRadius: '2px'
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Assessment Report Card */}
        <div className="soc-card" style={{ padding: '18px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div className="soc-card-title" style={{ marginBottom: '8px' }}>
              <FileText size={15} color="var(--cyan)" />
              <span>Security Assessment Report</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '8px' }}>
              <span style={{ fontSize: '24px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>
                98/100
              </span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: '600' }}>
                RISK LEVEL: LOW
              </span>
            </div>

            <p style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4', marginBottom: '14px' }}>
              Generates formal cryptographic assessment documentation compliant with NTRO guidelines.
            </p>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}>
              <span className="soc-badge info" style={{ flex: 1, textAlign: 'center' }}>[ Executive Report ]</span>
              <span className="soc-badge info" style={{ flex: 1, textAlign: 'center' }}>[ Technical Report ]</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <button 
              className="soc-btn soc-btn-primary" 
              onClick={handleGenerateReport}
              style={{ width: '100%' }}
            >
              <Download size={13} />
              <span>{reportState === 'generating' ? 'Generating Report...' : (reportState === 'ready' ? 'Report Ready (Download)' : 'Generate Report')}</span>
            </button>
            <button 
              className="soc-btn" 
              onClick={() => onNavigateToTab('reports')}
              style={{ width: '100%' }}
            >
              <span>View All Findings</span>
            </button>
          </div>
        </div>

      </div>

      {/* 8. BOTTOM SYSTEM TELEMETRY: eBPF EVENT STREAM */}
      <div className="soc-card" style={{ padding: '14px 18px', background: '#04070d' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#fff' }}>
            <Terminal size={14} color="var(--green)" />
            <span style={{ fontWeight: '700' }}>eBPF KERNEL EVENT STREAM</span>
            <span className="status-pulse green" style={{ width: '6px', height: '6px' }}></span>
          </div>
          <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            Filter: kprobe:esp_* | tracepoint:sock_*
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(6, 1fr)',
          gap: '12px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
          color: '#a7f3d0'
        }}>
          {ebpfEvents.map((ev, i) => (
            <div key={ev.id || i} style={{ 
              background: 'rgba(255,255,255,0.02)', 
              padding: '8px 10px', 
              borderRadius: '5px', 
              border: '1px solid rgba(255,255,255,0.05)',
              display: 'flex',
              flexDirection: 'column',
              gap: '2px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-dim)', fontSize: '10px' }}>{ev.time}</span>
                <span style={{ 
                  fontSize: '9px', 
                  padding: '1px 4px', 
                  borderRadius: '3px',
                  background: ev.flag === 'DROP_ALERT' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(0, 240, 255, 0.1)',
                  color: ev.flag === 'DROP_ALERT' ? 'var(--danger)' : 'var(--cyan)'
                }}>
                  {ev.flag || 'ACTIVE'}
                </span>
              </div>
              <div style={{ color: '#fff', fontWeight: '700', fontSize: '11px' }}>{ev.fn}</div>
              <div style={{ color: 'var(--cyan)', fontSize: '10px' }}>{ev.target}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: '9px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.detail}>
                {ev.detail || `spi=${ev.spi || '0x0'} bytes=${ev.bytes || 0}`}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
