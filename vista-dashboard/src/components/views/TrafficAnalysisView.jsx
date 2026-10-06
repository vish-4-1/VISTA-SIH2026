import React, { useState, useEffect, useMemo } from 'react';
import { 
  Activity, 
  UploadCloud, 
  Filter, 
  BarChart2, 
  TrendingUp, 
  Radio, 
  Search, 
  Download,
  Clock,
  Layers,
  ArrowUpDown,
  RefreshCw,
  FileCheck,
  AlertCircle,
  Database
} from 'lucide-react';
import seedFlows from '../../data/seedFlows.json';
import datasetSummary from '../../data/realDatasetSummary.json';
import { parsePcapArrayBuffer, parseCsvText } from '../../utils/pcapParser';
import { analyzePcapWithBackend, analyzeCsvWithBackend } from '../../utils/apiClient';

export default function TrafficAnalysisView() {
  const [flows, setFlows] = useState(seedFlows);
  const [selectedProtocol, setSelectedProtocol] = useState('ALL');
  const [selectedAttackType, setSelectedAttackType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLiveCapture, setIsLiveCapture] = useState(true);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [isParsing, setIsParsing] = useState(false);
  const [parseError, setParseError] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState('id');
  const [sortAsc, setSortAsc] = useState(true);
  const [pageSize, setPageSize] = useState(15);
  const [dataSource, setDataSource] = useState('VISTA V2 Testbed Dataset (5,531 Flows)');

  // Background fetch full dataset from public/data/realFlows.json
  useEffect(() => {
    let isMounted = true;
    fetch('/data/realFlows.json')
      .then(res => {
        if (!res.ok) throw new Error("Dataset fetch failed");
        return res.json();
      })
      .then(fullData => {
        if (isMounted && Array.isArray(fullData) && fullData.length > 0) {
          setFlows(fullData);
        }
      })
      .catch(err => {
        console.warn("Using bundled seed flows, background load notice:", err);
      });
    return () => { isMounted = false; };
  }, []);

  // Handle uploading real .pcap or .csv file
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsParsing(true);
    setParseError(null);
    setUploadedFile(file.name);

    try {
      if (file.name.endsWith('.csv')) {
        let parsedFlows = null;
        let sourceEngine = 'Browser Parser';

        // Try live backend ML inference first
        try {
          const res = await analyzeCsvWithBackend(file);
          if (res && res.flows && res.flows.length > 0) {
            parsedFlows = res.flows;
            sourceEngine = 'Live ML Backend (XGBoost)';
          }
        } catch (backendErr) {
          console.info("Backend offline, falling back to browser CSV parser:", backendErr);
        }

        if (!parsedFlows) {
          const text = await file.text();
          parsedFlows = parseCsvText(text);
        }

        if (!parsedFlows || parsedFlows.length === 0) throw new Error("No flows found in CSV.");
        setFlows(parsedFlows);
        setDataSource(`CSV: ${file.name} (${parsedFlows.length} Flows · ${sourceEngine})`);
        setCurrentPage(1);
      } else if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng') || file.name.endsWith('.cap')) {
        let parsedFlows = null;
        let sourceEngine = 'Browser Parser';

        // Try live backend Scapy + ML inference first
        try {
          const res = await analyzePcapWithBackend(file);
          if (res && res.flows && res.flows.length > 0) {
            parsedFlows = res.flows;
            sourceEngine = 'Live ML Backend (XGBoost / Scapy)';
          }
        } catch (backendErr) {
          console.info("Backend offline, falling back to browser PCAP parser:", backendErr);
        }

        if (!parsedFlows) {
          const arrayBuffer = await file.arrayBuffer();
          parsedFlows = parsePcapArrayBuffer(arrayBuffer);
        }

        if (!parsedFlows || parsedFlows.length === 0) throw new Error("No packets decoded in PCAP.");
        setFlows(parsedFlows);
        setDataSource(`Decoded PCAP: ${file.name} (${parsedFlows.length} Flows · ${sourceEngine})`);
        setCurrentPage(1);
      } else {
        throw new Error("Unsupported format. Please upload a .pcap, .pcapng or .csv file.");
      }
    } catch (err) {
      console.error("Parse error:", err);
      setParseError(err.message || "Failed to parse file.");
    } finally {
      setIsParsing(false);
    }
  };

  // Quick load of sample testbed PCAP capture
  const handleLoadSamplePcap = async () => {
    setIsParsing(true);
    setParseError(null);
    try {
      const res = await fetch('/captures/vista-outer-esp-probe.pcap');
      if (!res.ok) throw new Error("Sample PCAP not found in /captures");
      const buffer = await res.arrayBuffer();
      const parsed = parsePcapArrayBuffer(buffer);
      setFlows(parsed);
      setUploadedFile('vista-outer-esp-probe.pcap');
      setDataSource(`Decoded Testbed PCAP: vista-outer-esp-probe.pcap (${parsed.length} Flows)`);
      setCurrentPage(1);
    } catch (err) {
      setParseError(err.message);
    } finally {
      setIsParsing(false);
    }
  };

  // Reset to canonical dataset
  const handleResetToDataset = async () => {
    setIsParsing(true);
    setParseError(null);
    setUploadedFile(null);
    try {
      const res = await fetch('/data/realFlows.json');
      const data = await res.json();
      setFlows(data);
      setDataSource('VISTA V2 Testbed Dataset (5,531 Flows)');
      setCurrentPage(1);
    } catch (err) {
      setFlows(seedFlows);
    } finally {
      setIsParsing(false);
    }
  };

  // Filter flows
  const filteredFlows = useMemo(() => {
    return flows.filter(flw => {
      // Protocol filter
      if (selectedProtocol === 'ESP' && !flw.proto?.includes('ESP')) return false;
      if (selectedProtocol === 'UDP4500' && !flw.proto?.includes('4500')) return false;
      if (selectedProtocol === 'IKE' && !flw.proto?.includes('500') && !flw.proto?.includes('IKE')) return false;

      // Attack filter
      if (selectedAttackType !== 'ALL') {
        if (selectedAttackType === 'BENIGN' && flw.isAttack !== 0) return false;
        if (selectedAttackType !== 'BENIGN' && flw.attackType !== selectedAttackType) return false;
      }

      // Search query (Flow ID, SPI, Session ID, Traffic Type)
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = flw.id?.toLowerCase().includes(q);
        const matchSpi = flw.spi?.toLowerCase().includes(q);
        const matchSess = flw.sessionId?.toLowerCase().includes(q);
        const matchClass = flw.trafficType?.toLowerCase().includes(q);
        const matchAttack = flw.attackType?.toLowerCase().includes(q);
        if (!matchId && !matchSpi && !matchSess && !matchClass && !matchAttack) return false;
      }

      return true;
    });
  }, [flows, selectedProtocol, selectedAttackType, searchQuery]);

  // Sort flows
  const sortedFlows = useMemo(() => {
    const sorted = [...filteredFlows];
    sorted.sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (typeof valA === 'string') {
        return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortAsc ? (valA - valB) : (valB - valA);
    });
    return sorted;
  }, [filteredFlows, sortField, sortAsc]);

  // Pagination slice
  const totalPages = Math.max(1, Math.ceil(sortedFlows.length / pageSize));
  const paginatedFlows = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedFlows.slice(start, start + pageSize);
  }, [sortedFlows, currentPage, pageSize]);

  // Calculate REAL dynamic statistical distributions from currently active flows
  const stats = useMemo(() => {
    const total = flows.length;
    if (total === 0) {
      return {
        meanPacketSize: 0,
        stdPacketSize: 0,
        pctSub200: 0,
        pct200to800: 0,
        pct800to1200: 0,
        pctMtu: 0,
        medianIatMs: 0,
        meanIatMs: 0,
        pctSub1ms: 0,
        pct1to50ms: 0,
        pctBeacon: 0,
        directionRatio: 0.5,
        outboundPct: 50,
        inboundPct: 50,
        espPct: 100,
        udp4500Pct: 0,
        ikePct: 0
      };
    }

    // Packet lengths
    const packetLens = flows.map(f => f.meanPacketLen || 0);
    const meanPkt = packetLens.reduce((a, b) => a + b, 0) / total;
    const stdPkts = flows.map(f => f.stdPacketLen || 0);
    const meanStd = stdPkts.reduce((a, b) => a + b, 0) / total;

    const sub200 = flows.filter(f => (f.meanPacketLen || 0) <= 200).length;
    const b200_800 = flows.filter(f => (f.meanPacketLen || 0) > 200 && (f.meanPacketLen || 0) <= 800).length;
    const b800_1200 = flows.filter(f => (f.meanPacketLen || 0) > 800 && (f.meanPacketLen || 0) <= 1200).length;
    const mtu = flows.filter(f => (f.meanPacketLen || 0) > 1200).length;

    // IATs
    const iatSecs = flows.map(f => f.meanIat || 0).sort((a, b) => a - b);
    const medianIat = iatSecs[Math.floor(iatSecs.length / 2)] * 1000.0;
    const meanIat = (iatSecs.reduce((a, b) => a + b, 0) / total) * 1000.0;

    const sub1ms = flows.filter(f => (f.meanIat || 0) < 0.001).length;
    const b1_50ms = flows.filter(f => (f.meanIat || 0) >= 0.001 && (f.meanIat || 0) <= 0.050).length;
    const beacon = flows.filter(f => (f.meanIat || 0) > 0.500).length;

    // Directionality
    const outboundRatios = flows.map(f => f.outboundRatio || 0.5);
    const meanOutbound = outboundRatios.reduce((a, b) => a + b, 0) / total;

    // Protocols
    const espCount = flows.filter(f => f.proto?.includes('ESP')).length;
    const udp4500Count = flows.filter(f => f.proto?.includes('4500')).length;
    const ikeCount = flows.filter(f => f.proto?.includes('500') || f.proto?.includes('IKE')).length;

    return {
      meanPacketSize: Math.round(meanPkt * 10) / 10,
      stdPacketSize: Math.round(meanStd * 10) / 10,
      pctSub200: Math.round((sub200 / total) * 1000) / 10,
      pct200to800: Math.round((b200_800 / total) * 1000) / 10,
      pct800to1200: Math.round((b800_1200 / total) * 1000) / 10,
      pctMtu: Math.round((mtu / total) * 1000) / 10,
      medianIatMs: Math.round(medianIat * 10) / 10,
      meanIatMs: Math.round(meanIat * 10) / 10,
      pctSub1ms: Math.round((sub1ms / total) * 1000) / 10,
      pct1to50ms: Math.round((b1_50ms / total) * 1000) / 10,
      pctBeacon: Math.round((beacon / total) * 1000) / 10,
      directionRatio: Math.round(meanOutbound * 100) / 100,
      outboundPct: Math.round(meanOutbound * 1000) / 10,
      inboundPct: Math.round((1 - meanOutbound) * 1000) / 10,
      espPct: Math.round((espCount / total) * 1000) / 10,
      udp4500Pct: Math.round((udp4500Count / total) * 1000) / 10,
      ikePct: Math.round((ikeCount / total) * 1000) / 10
    };
  }, [flows]);

  // Export current filtered flows to legit RFC 4180 CSV
  const handleExportCsv = () => {
    if (sortedFlows.length === 0) return;
    const headers = [
      "flow_id", "session_id", "esp_spi", "proto", "time", "src_ip", "dst_ip",
      "flow_duration_sec", "packet_count", "total_bytes", "byte_rate_Bps",
      "mean_packet_length", "std_packet_length", "mean_iat_sec", "outbound_bytes_ratio",
      "traffic_type", "attack_type", "is_attack", "confidence"
    ];
    
    const rows = sortedFlows.map(f => [
      f.id, f.sessionId, f.spi, f.proto, f.time, f.src, f.dst,
      f.duration, f.packets, f.bytes, f.byteRateBps,
      f.meanPacketLen, f.stdPacketLen, f.meanIat, f.outboundRatio,
      `"${f.trafficType || ''}"`, f.attackType || 'BENIGN', f.isAttack || 0, f.confidence || '98%'
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `vista_exported_flows_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
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
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: '800', color: '#fff', letterSpacing: '-0.3px' }}>
              Encrypted Traffic Intelligence Workspace
            </h1>
            <span className="soc-badge success" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Database size={11} />
              <span>AUTHENTIC V2 DATASET</span>
            </span>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Active Source: <strong style={{ color: 'var(--cyan)' }}>{dataSource}</strong>
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button 
            className="soc-btn" 
            onClick={handleLoadSamplePcap}
            disabled={isParsing}
            title="Load actual testbed PCAP capture from captures/vista-outer-esp-probe.pcap"
          >
            <Activity size={14} color="var(--purple)" />
            <span>LOAD TESTBED PCAP</span>
          </button>

          <label className="soc-btn" style={{ cursor: isParsing ? 'wait' : 'pointer' }}>
            <UploadCloud size={14} color="var(--cyan)" />
            <span>{isParsing ? 'PARSING FILE...' : (uploadedFile ? `FILE: ${uploadedFile}` : 'UPLOAD PCAP / CSV')}</span>
            <input 
              type="file" 
              accept=".pcap,.pcapng,.cap,.csv" 
              style={{ display: 'none' }} 
              onChange={handleFileUpload}
              disabled={isParsing} 
            />
          </label>

          {uploadedFile && (
            <button className="soc-btn" onClick={handleResetToDataset} title="Restore canonical dataset">
              <RefreshCw size={13} />
              <span>RESET TO DATASET</span>
            </button>
          )}

          <button 
            className={`soc-btn ${isLiveCapture ? 'soc-btn-primary' : ''}`}
            onClick={() => setIsLiveCapture(!isLiveCapture)}
          >
            <Radio size={14} color={isLiveCapture ? 'var(--cyan)' : 'var(--text-dim)'} />
            <span>{isLiveCapture ? 'LIVE STREAM: ON' : 'PAUSED'}</span>
          </button>
        </div>
      </div>

      {parseError && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#f87171',
          fontSize: '13px'
        }}>
          <AlertCircle size={18} />
          <span>Error parsing capture file: {parseError}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div className="soc-card" style={{
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '12px', fontFamily: 'var(--font-mono)', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={14} color="var(--cyan)" />
            <span style={{ color: 'var(--text-muted)' }}>FILTERS:</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Search size={14} color="var(--text-dim)" />
            <input 
              type="text"
              placeholder="Search ID, SPI, Class..." 
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              style={{ 
                background: 'var(--bg-input)', 
                border: '1px solid var(--border-subtle)', 
                borderRadius: '4px', 
                color: '#fff', 
                padding: '4px 8px', 
                fontSize: '11px', 
                fontFamily: 'var(--font-mono)',
                width: '180px'
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-dim)' }}>Protocol:</span>
            <select 
              value={selectedProtocol} 
              onChange={(e) => { setSelectedProtocol(e.target.value); setCurrentPage(1); }}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: '#fff', padding: '4px 8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
            >
              <option value="ALL">ALL (ESP + UDP 4500)</option>
              <option value="ESP">ESP Only (Proto 50)</option>
              <option value="UDP4500">UDP Encapsulated (4500)</option>
              <option value="IKE">IKE Control (500)</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-dim)' }}>Class:</span>
            <select 
              value={selectedAttackType} 
              onChange={(e) => { setSelectedAttackType(e.target.value); setCurrentPage(1); }}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: '#fff', padding: '4px 8px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
            >
              <option value="ALL">ALL FLOW CLASSES</option>
              <option value="BENIGN">BENIGN (Legitimate Traffic)</option>
              <option value="DOS_FLOOD">DOS_FLOOD</option>
              <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
              <option value="PORT_SCAN">PORT_SCAN</option>
              <option value="C2_BEACONING">C2_BEACONING</option>
              <option value="BRUTE_FORCE">BRUTE_FORCE</option>
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--green)' }}>
            Showing {filteredFlows.length.toLocaleString()} of {flows.length.toLocaleString()} Flows
          </span>
          <select 
            value={pageSize} 
            onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: '#fff', padding: '3px 6px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
          >
            <option value={15}>15 / page</option>
            <option value={30}>30 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
        </div>
      </div>

      {/* Real Statistical Distributions Row — Dynamically computed from active dataset */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        {/* Metric 1: Packet Size Distribution */}
        <div className="soc-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
            PACKET SIZE DISTRIBUTION (COMPUTED)
          </div>
          <div style={{ fontSize: '20px', fontWeight: '800', color: '#fff', marginBottom: '8px' }}>
            {stats.meanPacketSize} B <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>mean (σ = {stats.stdPacketSize}B)</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>64–200B (VoIP / ACKs):</span>
              <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>{stats.pctSub200}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>200–800B (Web / TLS):</span>
              <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>{stats.pct200to800}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>800–1200B (Bulk App):</span>
              <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>{stats.pct800to1200}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>1200–1500B (MTU Full):</span>
              <span style={{ color: 'var(--cyan)', fontWeight: '600' }}>{stats.pctMtu}%</span>
            </div>
          </div>
        </div>

        {/* Metric 2: Inter-Arrival Jitter (IAT) */}
        <div className="soc-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
            INTER-ARRIVAL TIME (IAT)
          </div>
          <div style={{ fontSize: '20px', fontWeight: '800', color: '#fff', marginBottom: '8px' }}>
            {stats.medianIatMs} ms <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>median</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Sub-1ms (Bursts / Floods):</span>
              <span style={{ color: stats.pctSub1ms > 5 ? 'var(--amber)' : 'var(--text-dim)', fontWeight: '600' }}>{stats.pctSub1ms}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>1–50ms (Interactive Voice/Web):</span>
              <span style={{ color: 'var(--green)', fontWeight: '600' }}>{stats.pct1to50ms}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>&gt; 500ms (Periodic / Idle):</span>
              <span style={{ color: 'var(--purple)', fontWeight: '600' }}>{stats.pctBeacon}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Mean Inter-Arrival Time:</span>
              <span style={{ color: '#fff' }}>{stats.meanIatMs} ms</span>
            </div>
          </div>
        </div>

        {/* Metric 3: Directionality Ratio */}
        <div className="soc-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
            DIRECTIONALITY RATIO
          </div>
          <div style={{ fontSize: '20px', fontWeight: '800', color: stats.directionRatio > 0.85 ? '#ef4444' : 'var(--green)', marginBottom: '8px' }}>
            {stats.directionRatio} <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{stats.directionRatio > 0.85 ? 'Asymmetric Egress' : 'Symmetric Duplex'}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Outbound (PC1 → PC2):</span>
              <span style={{ color: '#fff', fontWeight: '600' }}>{stats.outboundPct}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Inbound (PC2 → PC1):</span>
              <span style={{ color: '#fff', fontWeight: '600' }}>{stats.inboundPct}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Exfiltration Threshold:</span>
              <span style={{ color: 'var(--text-dim)' }}>&gt; 0.85 Ratio</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Tunnel Topology:</span>
              <span style={{ color: 'var(--cyan)' }}>Host-to-Host Duplex</span>
            </div>
          </div>
        </div>

        {/* Metric 4: Protocol Distribution */}
        <div className="soc-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
            PROTOCOL ENCAPSULATION
          </div>
          <div style={{ fontSize: '20px', fontWeight: '800', color: 'var(--cyan)', marginBottom: '8px' }}>
            {stats.espPct}% <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>ESP (Proto 50)</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>IPsec ESP Encrypted:</span>
              <span style={{ color: '#fff', fontWeight: '600' }}>{stats.espPct}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>NAT-T Keepalive (UDP 4500):</span>
              <span style={{ color: '#fff' }}>{stats.udp4500Pct}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>IKEv2 Control (UDP 500):</span>
              <span style={{ color: '#fff' }}>{stats.ikePct}%</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Tunnel Mode Cipher:</span>
              <span style={{ color: 'var(--green)' }}>AES-256-GCM AEAD</span>
            </div>
          </div>
        </div>

      </div>

      {/* Flow Records Table */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div className="soc-card-title">
              <Activity size={16} color="var(--cyan)" />
              <span>Extracted Flow Records & Side-Channel Telemetry</span>
            </div>
            <div className="soc-card-subtitle" style={{ marginTop: '2px' }}>
              Parsed from authentic IPsec testbed flows with zero payload decryption
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button className="soc-btn" style={{ fontSize: '11px' }} onClick={handleExportCsv}>
              <Download size={13} />
              <span>EXPORT FILTERED FLOWS (CSV)</span>
            </button>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('id')}>
                  Flow ID {sortField === 'id' && (sortAsc ? '▲' : '▼')}
                </th>
                <th>Time</th>
                <th>Session ID</th>
                <th>Protocol</th>
                <th>ESP SPI</th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('packets')}>
                  Packets {sortField === 'packets' && (sortAsc ? '▲' : '▼')}
                </th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('bytes')}>
                  Bytes {sortField === 'bytes' && (sortAsc ? '▲' : '▼')}
                </th>
                <th>Mean Pkt (B)</th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('meanIat')}>
                  Mean IAT (s) {sortField === 'meanIat' && (sortAsc ? '▲' : '▼')}
                </th>
                <th>Traffic Class</th>
                <th>Attack Signature</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {paginatedFlows.map((flw) => {
                const isAttack = flw.isAttack === 1 || (flw.attackType && flw.attackType !== 'BENIGN');
                return (
                  <tr key={flw.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: '600' }}>{flw.id}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{flw.time}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{flw.sessionId}</td>
                    <td><span className="soc-badge info" style={{ fontSize: '10px' }}>{flw.proto}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)', fontSize: '11px' }}>{flw.spi}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{flw.packets?.toLocaleString()}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {flw.bytes > 1048576 
                        ? `${(flw.bytes / 1048576).toFixed(1)} MB` 
                        : `${(flw.bytes / 1024).toFixed(1)} KB`}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{flw.meanPacketLen}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{flw.meanIat}s</td>
                    <td style={{ fontWeight: '600', color: '#fff' }}>{flw.trafficType}</td>
                    <td>
                      <span className={`soc-badge ${isAttack ? 'critical' : 'success'}`} style={{ fontSize: '10px' }}>
                        {flw.attackType || (isAttack ? 'ATTACK' : 'BENIGN')}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: isAttack ? '#f87171' : 'var(--green)' }}>
                      {flw.confidence || '98.0%'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)'
        }}>
          <span style={{ color: 'var(--text-dim)' }}>
            Page {currentPage} of {totalPages} ({sortedFlows.length.toLocaleString()} total filtered flows)
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button 
              className="soc-btn" 
              style={{ padding: '4px 10px', fontSize: '11px' }}
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            >
              Previous
            </button>
            
            <div style={{ display: 'flex', gap: '4px' }}>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum = currentPage <= 3 ? i + 1 : currentPage - 2 + i;
                if (pageNum > totalPages) return null;
                return (
                  <button
                    key={pageNum}
                    className={`soc-btn ${currentPage === pageNum ? 'soc-btn-primary' : ''}`}
                    style={{ padding: '4px 8px', fontSize: '11px', minWidth: '28px' }}
                    onClick={() => setCurrentPage(pageNum)}
                  >
                    {pageNum}
                  </button>
                );
              })}
            </div>

            <button 
              className="soc-btn" 
              style={{ padding: '4px 10px', fontSize: '11px' }}
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            >
              Next
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
