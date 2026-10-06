import React, { useState } from 'react';
import ThreeCanvas from '../ThreeCanvas';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  Download, 
  Shield, 
  Flame, 
  UploadCloud, 
  Search, 
  Radio, 
  KeyRound, 
  Clock, 
  Cpu, 
  Server, 
  Activity, 
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';
import { ATTACK_SCENARIOS, NODES_DATA } from '../../data/networkData';

export default function TestbedView({ scenario, onSelectScenario }) {
  const [isPaused, setIsPaused] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState('pc1');
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [cameraPreset, setCameraPreset] = useState('overview');
  const [pcapCaptured, setPcapCaptured] = useState(false);

  const selectedNode = NODES_DATA[selectedNodeId] || NODES_DATA.pc1;

  const handleCapturePcap = () => {
    setPcapCaptured(true);
    setTimeout(() => setPcapCaptured(false), 3000);
  };

  const scenariosList = [
    { id: 'NORMAL', label: 'Normal Traffic', icon: Shield, color: 'var(--green)' },
    { id: 'DOS_FLOOD', label: 'DoS Flood', icon: Flame, color: 'var(--danger)' },
    { id: 'DATA_EXFILTRATION', label: 'Data Exfil', icon: UploadCloud, color: '#ff6600' },
    { id: 'PORT_SCAN', label: 'Port Scan', icon: Search, color: 'var(--amber)' },
    { id: 'C2_BEACONING', label: 'C2 Beaconing', icon: Radio, color: 'var(--purple)' },
    { id: 'BRUTE_FORCE', label: 'Brute Force', icon: KeyRound, color: '#ff4d6d' }
  ];

  const timelineEvents = [
    { type: 'IKE', time: '18:42:01', label: 'IKE_SA_INIT: Initiator SPI 0x19f4a1.. responder exchange OK' },
    { type: 'ESP', time: '18:42:02', label: 'Child SA installed: SPI 0xb3b1799d AES-256-GCM / DH14' },
    { type: 'eBPF', time: '18:42:05', label: 'kprobe:esp_output attached on veth1 (PID 4821)' },
    { type: 'AI', time: '18:42:08', label: `Inference stream active: ${scenario.attackType} detected (96.8% conf)` },
    { type: 'PKT', time: '18:42:10', label: `Flow stream: 48 pkts/sec rate | ${scenario.bitRate} bandwidth` }
  ];

  return (
    <div style={{
      width: '100%',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      background: 'var(--bg-app)',
      overflow: 'hidden'
    }}>
      {/* Top Testbed Controls Bar */}
      <div style={{
        height: '52px',
        background: 'var(--bg-card)',
        borderBottom: '1px solid var(--border-subtle)',
        padding: '0 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        zIndex: 10
      }}>
        {/* Scenarios Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
            SCENARIO:
          </span>
          <div style={{ display: 'flex', gap: '5px' }}>
            {scenariosList.map((sc) => {
              const Icon = sc.icon;
              const isActive = scenario.id === sc.id;
              return (
                <button
                  key={sc.id}
                  onClick={() => onSelectScenario(ATTACK_SCENARIOS[sc.id])}
                  className={`soc-btn ${isActive ? 'soc-btn-primary' : ''}`}
                  style={{
                    padding: '4px 10px',
                    fontSize: '11px',
                    borderColor: isActive ? sc.color : undefined
                  }}
                >
                  <Icon size={12} color={isActive ? sc.color : 'var(--text-muted)'} />
                  <span>{sc.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Playback & PCAP Capture Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button 
            className="soc-btn"
            onClick={() => setIsPaused(!isPaused)}
            style={{ padding: '5px 10px', fontSize: '11px' }}
          >
            {isPaused ? <Play size={13} color="var(--green)" /> : <Pause size={13} color="var(--amber)" />}
            <span>{isPaused ? 'RESUME' : 'PAUSE'}</span>
          </button>

          <button 
            className="soc-btn"
            onClick={() => onSelectScenario(ATTACK_SCENARIOS.NORMAL)}
            style={{ padding: '5px 10px', fontSize: '11px' }}
          >
            <RotateCcw size={13} />
            <span>RESET</span>
          </button>

          <button 
            className="soc-btn soc-btn-primary"
            onClick={handleCapturePcap}
            style={{ padding: '5px 12px', fontSize: '11px' }}
          >
            <Download size={13} />
            <span>{pcapCaptured ? 'PCAP CAPTURED (1.8MB)' : 'CAPTURE PCAP'}</span>
          </button>
        </div>
      </div>

      {/* Main Center Area: 75-80% 3D Viewport + Right-side Inspector */}
      <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
        
        {/* 75% 3D Viewport (Existing 3D Simulation Embedded Here) */}
        <div style={{ flex: 1, height: '100%', position: 'relative' }}>
          <ThreeCanvas
            scenario={scenario}
            selectedNode={selectedNodeId}
            onSelectNode={(nodeId) => setSelectedNodeId(nodeId)}
            onSelectPacket={(pkt) => setSelectedPacket(pkt)}
            cameraPreset={cameraPreset}
            setCameraPreset={setCameraPreset}
          />
        </div>

        {/* 25% Right-Side Inspector Panel */}
        <div style={{
          width: '380px',
          height: '100%',
          background: 'var(--bg-card)',
          borderLeft: '1px solid var(--border-subtle)',
          padding: '18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          overflowY: 'auto'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
            <span style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: '#fff' }}>
              NODE & SA INSPECTOR
            </span>
            <span className="soc-badge info">eBPF HOOKED</span>
          </div>

          {/* Node Metadata Card */}
          <div className="soc-card" style={{ padding: '14px', background: 'rgba(6, 9, 15, 0.6)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>SELECTED ENDPOINT</div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: 'var(--cyan)', marginBottom: '10px' }}>
              {selectedNode.label || selectedNode.name}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>IP Address:</span>
                <span style={{ color: '#fff' }}>{selectedNode.outerIp || '172.20.0.2'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Role:</span>
                <span style={{ color: 'var(--text-secondary)' }}>{selectedNode.role}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Tunnel State:</span>
                <span style={{ color: 'var(--green)', fontWeight: '600' }}>ESTABLISHED</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>ESP State:</span>
                <span style={{ color: 'var(--cyan)' }}>ACTIVE (AES-256-GCM)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Throughput:</span>
                <span style={{ color: '#fff' }}>{scenario.bitRate}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Packet Rate:</span>
                <span style={{ color: 'var(--cyan)' }}>{scenario.packetRate}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Active Scenario:</span>
                <span style={{ color: scenario.threatLevel === 'CRITICAL' ? 'var(--danger)' : 'var(--green)', fontWeight: '700' }}>
                  {scenario.name}
                </span>
              </div>
            </div>
          </div>

          {/* SA Cryptographic State */}
          <div className="soc-card" style={{ padding: '14px', background: 'rgba(6, 9, 15, 0.6)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '8px' }}>CHILD SA SPI DUMP</div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: '5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Inbound SPI:</span>
                <span style={{ color: 'var(--purple)', fontWeight: '600' }}>0x49c812a0</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Outbound SPI:</span>
                <span style={{ color: 'var(--purple)', fontWeight: '600' }}>0xb3b1799d</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Replay Window:</span>
                <span style={{ color: '#fff' }}>64 packets (0 drops)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>PFS Group:</span>
                <span style={{ color: 'var(--green)' }}>Group 14 (MODP-2048)</span>
              </div>
            </div>
          </div>

          {/* AI Inference on Selected Stream */}
          <div className="soc-card" style={{ padding: '14px', background: 'rgba(6, 9, 15, 0.6)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '6px' }}>VISTA AI REAL-TIME INFERENCE</div>
            <div style={{ fontSize: '12px', fontWeight: '700', color: '#fff', marginBottom: '4px' }}>
              {scenario.trafficType}
            </div>
            <div style={{ fontSize: '11px', color: scenario.threatLevel === 'CRITICAL' ? 'var(--danger)' : 'var(--green)', fontFamily: 'var(--font-mono)' }}>
              Attribution: {scenario.attackType} (96.8% confidence)
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '8px', lineHeight: '1.4' }}>
              Mitigation: {scenario.mitigation}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline: Packet, IKE, ESP, eBPF Events & AI Alerts */}
      <div style={{
        height: '92px',
        background: 'var(--bg-topbar)',
        borderTop: '1px solid var(--border-subtle)',
        padding: '10px 20px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        zIndex: 10
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-dim)' }}>CORRELATED EVENT TIMELINE:</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="soc-badge info">IKE Events</span>
            <span className="soc-badge success">ESP State</span>
            <span className="soc-badge medium">eBPF Telemetry</span>
            <span className="soc-badge critical">AI Alerts</span>
          </div>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: '10px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)'
        }}>
          {timelineEvents.map((ev, i) => (
            <div key={i} style={{
              background: 'rgba(6, 9, 15, 0.6)',
              padding: '6px 8px',
              borderRadius: '4px',
              border: '1px solid var(--border-subtle)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }}>
              <span style={{ color: 'var(--cyan)', marginRight: '6px' }}>[{ev.type}]</span>
              <span style={{ color: '#fff' }}>{ev.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
