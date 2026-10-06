import { X, Server, Shield, Cpu, Network, Radio, Box, Terminal, Hash, Zap } from 'lucide-react';
import { NODES_DATA } from '../data/networkData';

export default function InspectorModal({ target, onClose }) {
  if (!target) return null;

  const isPacket = target.isPacket;
  const node = !isPacket ? NODES_DATA[target] : null;

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.65)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 50
    }} onClick={onClose}>
      <div style={{
        width: '600px',
        maxHeight: '85vh',
        background: 'rgba(12, 18, 33, 0.95)',
        border: '1px solid var(--border-active)',
        borderRadius: '16px',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px var(--cyan-glow)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(18, 28, 52, 0.6)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Box size={18} color="var(--cyan)" />
            <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff', letterSpacing: '0.5px' }}>
              {isPacket ? `PACKET INSPECTOR: ${target.packetId}` : `${node?.label} (${node?.name})`}
            </span>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '20px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {isPacket ? (
            /* Packet Inspector Details */
            <>
              <div className="glass-panel" style={{ padding: '14px' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)', marginBottom: '8px' }}>
                  RFC 4303 ENCAPSULATING SECURITY PAYLOAD (ESP)
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Security Parameter Index (SPI):</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--purple)' }}>{target.spi}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Sequence Number:</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: '#fff' }}>#{target.seq}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Total Packet Length:</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--green)' }}>{target.size} Bytes</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Direction:</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--cyan)' }}>
                      {target.direction === 1 ? 'Outbound (Client → GW)' : 'Inbound (GW → Client)'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Raw Packet Hex representation */}
              <div style={{
                background: '#04070e',
                borderRadius: '8px',
                padding: '12px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                border: '1px solid var(--border-subtle)'
              }}>
                <div style={{ color: 'var(--text-dim)', marginBottom: '6px' }}>ESP FRAME DUMP (ENCRYPTED CIPHERTEXT)</div>
                <div style={{ color: '#38bdf8', lineHeight: '1.6' }}>
                  0000  45 00 05 dc 7b 42 40 00 40 32 e1 98 ac 16 00 02  E...B@.@2......<br />
                  0010  ac 16 00 0a b3 b1 79 9d 00 00 12 d4 a4 7f 92 1e  ......y.........<br />
                  0020  77 e8 42 b9 14 02 89 fa 1b e4 73 99 d2 10 5a 8b  w.B.......s...Z.<br />
                  0030  [... {target.size - 64} BYTES AES-GCM ENCRYPTED PAYLOAD ...]<br />
                  0040  9a fc 12 88 bc 74 e1 29 44 8a c9 12 fe 49 10 8c  .....t.)D....I..
                </div>
              </div>
            </>
          ) : node?.id === 'vistaAi' ? (
            /* Dedicated VISTA AI & eBPF Engine View */
            <>
              {/* Architecture Overview */}
              <div className="glass-panel" style={{ padding: '14px', border: '1px solid var(--border-active)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <Cpu size={16} color="var(--amber)" />
                  <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--amber)', fontWeight: '700' }}>
                    VISTA UNIFIED INTELLIGENCE CORE (USERS-SPACE SERVICE)
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5', marginBottom: '10px' }}>
                  Combines the <strong>Option B Host eBPF Ring Buffer Consumer</strong> with the <strong>Real-Time ML Inference Engine</strong>. Runs as an autonomous host-level security daemon that monitors PC-1 and PC-2 without touching workload containers.
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <div><span style={{ color: 'var(--text-dim)' }}>Inference Latency:</span> <span style={{ color: 'var(--green)', fontWeight: '600' }}>1.2 ms / flow</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Feature Aggregation:</span> <span style={{ color: 'var(--cyan)' }}>15 Side-Channel Features</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Payload Inspection:</span> <span style={{ color: 'var(--green)' }}>ZERO (Encrypted Safe)</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Actuator:</span> <span style={{ color: 'var(--purple)' }}>eBPF XDP/tc Wire Drop</span></div>
                </div>
              </div>

              {/* Model Registry Card */}
              <div className="glass-panel" style={{ padding: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <Zap size={14} color="var(--cyan)" />
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: '700' }}>
                    LOADED MACHINE LEARNING MODELS
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ color: '#fff', fontWeight: '600' }}>XGBoost Classifier (Primary Supervised)</div>
                    <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>Macro F1: 0.974 | Multi-class attack detection (DoS, Exfil, Port Scan, C2)</div>
                  </div>
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ color: '#fff', fontWeight: '600' }}>Random Forest Baseline</div>
                    <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>Macro F1: 0.961 | Encrypted application traffic classification</div>
                  </div>
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ color: '#fff', fontWeight: '600' }}>Isolation Forest (Unsupervised Anomaly)</div>
                    <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>Trained on 0 attack samples | Zero-day attack recall: 96.3%</div>
                  </div>
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ color: '#fff', fontWeight: '600' }}>SHAP Fast TreeExplainer</div>
                    <div style={{ color: 'var(--text-dim)', fontSize: '10px' }}>Real-time feature attribution weighting for explainable alerts</div>
                  </div>
                </div>
              </div>

              {/* eBPF Probes Attached */}
              <div className="glass-panel" style={{ padding: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <Radio size={14} color="var(--green)" />
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: '700' }}>
                    INGESTED eBPF KERNEL HOOKS
                  </span>
                </div>
                <ul style={{ paddingLeft: '18px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#a7f3d0', lineHeight: '1.6' }}>
                  <li>kprobe/esp_output & kprobe/esp_input (ESP Sequence & Ciphertext profiling)</li>
                  <li>tracepoint/sock/sock_exceed_buf (Kernel socket buffer overrun detection)</li>
                  <li>kprobe/tcp_retransmit_skb (Side-channel packet loss detection)</li>
                  <li>sys_enter_connect (Process-to-socket correlation)</li>
                </ul>
              </div>
            </>
          ) : (
            /* Workstation Node Inspector Details (PC1 / PC2) */
            <>
              {/* Docker metadata */}
              <div className="glass-panel" style={{ padding: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '10px' }}>
                  <Server size={14} color="var(--cyan)" />
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: '700' }}>
                    DOCKER CONTAINER RUNTIME
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px' }}>
                  <div><span style={{ color: 'var(--text-dim)' }}>Container ID:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{node.containerId}</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Outer Docker IP:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{node.outerIp}</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Inner Overlay IP:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>{node.innerIp}</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Status:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: '700' }}>{node.status}</span></div>
                  <div style={{ gridColumn: 'span 2' }}>
                    <span style={{ color: 'var(--text-dim)' }}>Privileges:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>{node.privileges}</span>
                  </div>
                </div>
              </div>

              {/* Swanctl details if available */}
              {node.swanctl && (
                <div className="glass-panel" style={{ padding: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '10px' }}>
                    <Shield size={14} color="var(--purple)" />
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--purple)', fontWeight: '700' }}>
                      STRONGSWAN / SWANCTL SECURITY ASSOCIATION (SA)
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px' }}>
                    <div><span style={{ color: 'var(--text-dim)' }}>IKE Protocol:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{node.swanctl.ikeVersion}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Mode:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>{node.swanctl.mode}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Cipher:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{node.swanctl.encryption}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Diffie-Hellman:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{node.swanctl.dhGroup}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>PFS Secrecy:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>{node.swanctl.pfs}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Anti-Replay:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{node.swanctl.antiReplay}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Local SPI:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)' }}>{node.swanctl.spiLocal}</span></div>
                    <div><span style={{ color: 'var(--text-dim)' }}>Remote SPI:</span> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)' }}>{node.swanctl.spiRemote}</span></div>
                  </div>
                </div>
              )}

              {/* eBPF Attached Probes */}
              {node.ebpf && (
                <div className="glass-panel" style={{ padding: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                    <Cpu size={14} color="var(--green)" />
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: '700' }}>
                      ACTIVE eBPF KERNEL TRACEPOINTS
                    </span>
                  </div>
                  <ul style={{ paddingLeft: '18px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#a7f3d0', lineHeight: '1.6' }}>
                    {node.ebpf.probes.map((probe, i) => (
                      <li key={i}>{probe}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 20px',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'flex-end',
          background: 'rgba(18, 28, 52, 0.4)'
        }}>
          <button className="cyber-btn" onClick={onClose}>Close Inspector</button>
        </div>
      </div>
    </div>
  );
}
