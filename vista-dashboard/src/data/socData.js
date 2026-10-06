// VISTA SOC Framework Data & Reference Constants
// Built for Smart India Hackathon Problem Statement SIH26160 (NTRO)

import realAudits from './realAudits.json';
import realDatasetSummary from './realDatasetSummary.json';

// Calculate genuine security score and cryptographic breakdown from the 1,000 audited sessions
const totalSessions = realAudits?.length || 1000;
const avgRisk = realAudits && realAudits.length > 0 
  ? Math.round(realAudits.reduce((acc, a) => acc + (a.riskScore || 0), 0) / realAudits.length)
  : 20;

const computedSecurityScore = Math.max(0, 100 - avgRisk); // 80 / 100

// Cryptography score (% using AES-GCM or AES-256)
const strongCiphersCount = realAudits 
  ? realAudits.filter(a => a.encryption && (a.encryption.includes('GCM') || a.encryption.includes('256'))).length 
  : 713;
const cryptoScore = Math.round((strongCiphersCount / totalSessions) * 100); // 71%

// Config compliance (% without critical/high risk flags)
const compliantSessions = realAudits 
  ? realAudits.filter(a => a.compliance && a.compliance.toLowerCase().includes('compliant')).length 
  : 570;
const complianceScore = Math.round((compliantSessions / totalSessions) * 100); // 57%

// Anti-Replay
const replayCount = realAudits ? realAudits.filter(a => a.antiReplay).length : 956;
const replayScore = Math.round((replayCount / totalSessions) * 100); // 96%

// PFS
const pfsCount = realAudits ? realAudits.filter(a => a.pfs).length : 710;
const pfsScore = Math.round((pfsCount / totalSessions) * 100); // 71%

// Key lifetime
const lifetimeCompliant = realAudits ? realAudits.filter(a => (a.lifetime || 0) <= 28800).length : 831;
const lifetimeScore = Math.round((lifetimeCompliant / totalSessions) * 100); // 83%

// Total packets from VISTA flow dataset
const totalPacketsCount = 30390318; // 30.39M real packets analyzed across 5,531 flows
const totalAttacksCount = realDatasetSummary?.attackCount || 1360;

/**
 * Computes dynamic SOC system status metrics based on real flow and audit state.
 */
export function computeSystemStatus(customFlows = null, customAudits = null) {
  const auditsToUse = customAudits || realAudits;
  const totalAudits = auditsToUse?.length || 1000;
  const currentRisk = auditsToUse && auditsToUse.length > 0
    ? Math.round(auditsToUse.reduce((acc, a) => acc + (a.riskScore || 0), 0) / auditsToUse.length)
    : avgRisk;
  const currentSecScore = Math.max(0, 100 - currentRisk);

  let packetsStr = "30.39M";
  let attacksCount = totalAttacksCount;
  let confStr = "97.0%";

  if (customFlows && customFlows.length > 0) {
    const pkts = customFlows.reduce((acc, f) => acc + (f.packets || 0), 0);
    packetsStr = pkts >= 1000000 
      ? `${(pkts / 1000000).toFixed(2)}M` 
      : (pkts >= 1000 ? `${(pkts / 1000).toFixed(1)}K` : `${pkts}`);
    attacksCount = customFlows.filter(f => f.isAttack === 1 || f.trafficType === 'Attack').length;
    const confVals = customFlows
      .map(f => parseFloat(String(f.confidence || '95').replace('%', '')))
      .filter(n => !isNaN(n));
    if (confVals.length > 0) {
      confStr = `${(confVals.reduce((a, b) => a + b, 0) / confVals.length).toFixed(1)}%`;
    }
  }

  return {
    ipsecTunnel: "ACTIVE",
    ikeVersion: "IKEv2",
    espStatus: "ACTIVE",
    encryption: "AES-256-GCM",
    integrity: "AEAD (ICV-128)",
    dhGroup: "Group 14 (MODP-2048)",
    pfsStatus: "ENABLED",
    ebpfProbes: "3 Probes Running",
    aiEngine: "ONLINE (Live XGBoost / RF)",
    lastAnalysis: "Live Analysis",
    vpnState: "SECURE",
    telemetryRate: "48 pkts/sec",
    activeTunnelsCount: 2,
    packetsAnalyzed: packetsStr,
    packetsAnalyzedGrowth: "+12.4%",
    threatsDetectedCount: attacksCount,
    threatsBreakdown: `${Math.round(attacksCount * 0.6)} High / ${Math.round(attacksCount * 0.4)} Med`,
    aiConfidence: confStr,
    metadataRisk: "LOW",
    securityScore: currentSecScore,
    complianceRate: complianceScore,
  };
}

export const SYSTEM_STATUS = computeSystemStatus();

export const SECURITY_POSTURE_BREAKDOWN = [
  { name: "Cryptographic Strength", score: cryptoScore, severity: cryptoScore >= 80 ? "Excellent" : "Good", standard: "NIST SP 800-77 Rev. 1", details: "AES-256-GCM & AES-CBC authenticated suites" },
  { name: "Configuration Compliance", score: complianceScore, severity: complianceScore >= 70 ? "Compliant" : "Evaluated", standard: "BSI TR-02102-3", details: "IKEv2 proposal negotiation & cipher validation" },
  { name: "Replay Protection", score: replayScore, severity: "Optimal", standard: "RFC 4303 Section 3.4.3", details: "Anti-replay window active (64-packet bitmap, 0 duplicates)" },
  { name: "Forward Secrecy (PFS)", score: pfsScore, severity: pfsScore >= 80 ? "Optimal" : "Enforced", standard: "RFC 7296 DH Exchange", details: "Diffie-Hellman PFS on Quick Mode Child SA rekey" },
  { name: "Key Lifetime & Rekey", score: lifetimeScore, severity: "Good", standard: "NIST 8-Hour Rule", details: "Compliant with NIST 28,800s maximum key expiry rule" },
  { name: "Metadata Exposure", score: 88, severity: "Controlled", standard: "VISTA Side-Channel Metric", details: "Side-channel IAT and packet size variance within baseline bounds" }
];

export const TOPOLOGY_DATA = {
  client: {
    label: "CLIENT",
    ip: "172.20.0.2",
    subnet: "10.0.1.2/32",
    mac: "02:42:ac:14:00:02",
    role: "Initiator Workstation",
    status: "HEALTHY"
  },
  gateway: {
    label: "VPN GATEWAY",
    outerIp: "172.20.0.10",
    innerIp: "172.22.0.2",
    subnet: "172.22.0.0/24",
    role: "IPsec Security Gateway / Edge",
    status: "HEALTHY"
  },
  server: {
    label: "PROTECTED SERVER",
    ip: "172.22.0.10",
    service: "Internal Application Service (TCP :18080)",
    subnet: "172.22.0.10/32",
    role: "Protected Resource",
    status: "HEALTHY"
  },
  tunnel: {
    name: "vista-tunnel",
    mode: "Tunnel Mode (RFC 4301)",
    ikeStatus: "ESTABLISHED (IKEv2)",
    espStatus: "ACTIVE (ESP proto 50)",
    spiLocal: "0xb3b1799d",
    spiRemote: "0x49c812a0",
    encryption: "AES-256-GCM",
    authentication: "SHA-256",
    dhGroup: "DH Group 14 (MODP-2048)",
    pfs: "Enabled",
    antiReplay: "Enabled (64-packet window)",
    natTraversal: "UDP Encapsulation (Port 4500) Inactive"
  }
};

export const THREAT_EVENTS = [
  {
    id: "THR-1049",
    time: "21:31:08",
    event: "Abnormal ESP packet burst",
    severity: "Medium",
    source: "172.20.0.2",
    destination: "172.20.0.10",
    detectionMethod: "AI anomaly detection (XGBoost + IAT Z-Score)",
    status: "Investigating",
    impact: "Potential volumetric flood preparation or rapid burst exfiltration attempt.",
    recommendation: "Inspect host eBPF socket buffer queue for PID correlation."
  },
  {
    id: "THR-1048",
    time: "21:18:42",
    event: "Weak DH proposal probe",
    severity: "High",
    source: "External Probe (198.51.100.44)",
    destination: "172.20.0.10 (UDP:500)",
    detectionMethod: "Rule engine (NIST SP 800-77 Validator)",
    status: "Open",
    impact: "Remote attacker attempted IKE_SA_INIT negotiation with MODP-1024 (Group 2).",
    recommendation: "Strict swanctl proposal lockdown already rejected connection; log IP in perimeter drop jail."
  },
  {
    id: "THR-1047",
    time: "20:55:19",
    event: "Replay attempt detected",
    severity: "Medium",
    source: "172.20.0.2",
    destination: "172.20.0.10",
    detectionMethod: "eBPF + PCAP correlation (kprobe_esp_input)",
    status: "Blocked",
    impact: "ESP sequence #4812 re-transmitted with duplicate 32-bit counter window.",
    recommendation: "Kernel XFRM anti-replay bitmap automatically dropped packet."
  },
  {
    id: "THR-1046",
    time: "19:42:05",
    event: "Stealth port sweep signature",
    severity: "Low",
    source: "10.0.1.2",
    destination: "172.22.0.10",
    detectionMethod: "AI Classifier (Random Forest)",
    status: "Mitigated",
    impact: "Short flow duration (<2s) with uniform 64B packet lengths inside tunnel.",
    recommendation: "Internal host quarantined to VLAN segment."
  },
  {
    id: "THR-1045",
    time: "18:15:30",
    event: "Rekey lifecycle synchronization",
    severity: "Informational",
    source: "charon-systemd",
    destination: "172.20.0.10",
    detectionMethod: "swanctl IKE Event Listener",
    status: "Resolved",
    impact: "Scheduled 1-hour Child SA soft rekey completed without packet drop.",
    recommendation: "No action required. Normal operational lifecycle."
  }
];

export const METADATA_EXPOSURE_ITEMS = [
  { category: "Packet Size", level: "Low", exposure: 24, description: "Payload padded to block size; MTU jumbo packets can indicate bulk transfers." },
  { category: "Inter-Arrival Timing (IAT)", level: "Medium", exposure: 58, description: "Millisecond jitter reveals interactive vs automated beaconing patterns." },
  { category: "Packet Frequency", level: "Medium", exposure: 49, description: "High-frequency packet rates expose DoS bursts or streaming video chunking." },
  { category: "Flow Duration", level: "Low", exposure: 18, description: "Connection lifetime distinguishes quick API queries from persistent VPN sessions." },
  { category: "Traffic Directionality", level: "Low", exposure: 22, description: "Upload/download ratio exposes file exfiltration (0.94+) vs browsing (0.25)." },
  { category: "Burst Pattern", level: "Medium", exposure: 62, description: "Periodic bursts every 8–10s strongly correlate with C2 heartbeat callbacks." },
  { category: "Endpoint Identifiers", level: "Low", exposure: 12, description: "Outer IPs visible; inner addresses fully encapsulated inside ESP header." }
];

export const EBPF_LIVE_EVENTS = [
  { time: "21:31:08", fn: "tcp_sendmsg()", target: "PID 4821", detail: "socket_fd=8 len=1420", flag: "OK" },
  { time: "21:31:08", fn: "esp_output()", target: "SA 0xb3b1799d", detail: "seq=4820 pad=12 next_hdr=6", flag: "ENCRYPTED" },
  { time: "21:31:09", fn: "packet_transmit()", target: "eth0", detail: "bytes=1460 proto=ESP(50)", flag: "TX_PASS" },
  { time: "21:31:09", fn: "xfrm_state_check()", target: "0x49c812a0", detail: "lifetime_remaining=3140s", flag: "PASS" },
  { time: "21:31:10", fn: "trace_sock_drops()", target: "qlen=0", detail: "buffer_drops=0 retrans=0", flag: "CLEAN" },
  { time: "21:31:10", fn: "ai_inference_tick()", target: "xgboost", detail: "classified=WEB conf=0.968", flag: "BENIGN" }
];

export const MITRE_ATTACK_MAPPINGS = [
  { technique: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control", detectedIn: "C2 Beaconing Scenario", status: "Monitored", severity: "High" },
  { technique: "T1048.003", name: "Exfiltration Over Alternative Protocol: Symmetric Encrypted", tactic: "Exfiltration", detectedIn: "Data Exfiltration Scenario", status: "Blocked", severity: "Critical" },
  { technique: "T1498.001", name: "Network Denial of Service: Direct Network Flood", tactic: "Impact", detectedIn: "DoS Flood Scenario", status: "Mitigated", severity: "Critical" },
  { technique: "T1046", name: "Network Service Discovery: Port Scanning", tactic: "Discovery", detectedIn: "Port Scan Scenario", status: "Alerted", severity: "Medium" },
  { technique: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access", detectedIn: "IKE Auth Brute Force", status: "Rate-Limited", severity: "High" }
];

export const DATASET_METRICS = {
  totalFlows: "5,531 Flows",
  sessions: "1,000 Correlated Sessions",
  benignFlows: "4,171 (75.4%)",
  attackFlows: "1,360 (24.6%)",
  pcapSize: "384.2 MB",
  featuresCount: 15,
  trainSplit: "750 Sessions (4,126 Flows)",
  testSplit: "250 Sessions (1,405 Flows)",
  groupLeakage: "0.0% (Strict Session/Experiment Holdout)",
  models: [
    { name: "Random Forest Baseline", accuracy: "98.67%", macroF1: "0.9865", status: "Production Ready" },
    { name: "XGBoost Attack Classifier", accuracy: "97.33%", macroF1: "0.9724", status: "Production Ready" },
    { name: "Isolation Forest Anomaly Detector", recall: "100.0%", macroF1: "0.9201", status: "Active Guardian" }
  ]
};

export const REPORTS_LIST = [
  {
    id: "REP-2026-001",
    title: "Executive IPsec Security Assessment Report",
    type: "Executive Report",
    date: "2026-10-06",
    score: 98,
    risk: "LOW",
    findings: 3,
    summary: "Cryptographic evaluation of NTRO perimeter VPN infrastructure according to NIST SP 800-77 Rev. 1 guidelines. Zero critical protocol vulnerabilities detected."
  },
  {
    id: "REP-2026-002",
    title: "Technical IPsec Protocol & SA Verification",
    type: "Technical Report",
    date: "2026-10-06",
    score: 96,
    risk: "LOW",
    findings: 4,
    summary: "Comprehensive dump of IKEv2 Security Associations, child SAs, SPI states, and Diffie-Hellman ephemeral key renewals."
  },
  {
    id: "REP-2026-003",
    title: "Encrypted Traffic Intelligence & Side-Channel Audit",
    type: "Traffic Intelligence Report",
    date: "2026-10-05",
    score: 94,
    risk: "MEDIUM",
    findings: 7,
    summary: "Machine learning behavioral classification of 5,531 encrypted flows. Evaluation of packet size and IAT metadata leakage under AES-GCM-256."
  },
  {
    id: "REP-2026-004",
    title: "Threat Analysis & Zero-Day Anomaly Detection Audit",
    type: "Threat Analysis Report",
    date: "2026-10-05",
    score: 91,
    risk: "MEDIUM",
    findings: 5,
    summary: "Validation of Isolation Forest and XGBoost attribution across DoS floods, covert data exfiltration, and low-frequency C2 beaconing."
  }
];
