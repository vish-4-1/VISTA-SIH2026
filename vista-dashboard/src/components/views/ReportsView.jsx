import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Eye, 
  CheckCircle2, 
  Clock, 
  ShieldCheck, 
  Sparkles,
  Printer,
  Share2
} from 'lucide-react';
import { REPORTS_LIST } from '../../data/socData';

export default function ReportsView() {
  const [selectedReport, setSelectedReport] = useState(null);
  const [exportNotice, setExportNotice] = useState(null);

  const handleDownload = (rep) => {
    const reportContent = `# ${rep.title}
Document ID: ${rep.id}
Date: ${rep.date}
Assessment Type: ${rep.type}
Security Posture Score: ${rep.score}/100 (Risk: ${rep.risk})
Findings Count: ${rep.findings}

Executive Summary:
${rep.summary}

NIST SP 800-77 Rev. 1 & BSI TR-02102-3 Compliance:
- Cryptographic Engine: AES-256-GCM AEAD (RFC 4106)
- Key Exchange: Diffie-Hellman Group 14 (MODP-2048) / Group 19 (ECP-256)
- Perfect Forward Secrecy: MANDATORY (Quick Mode Child SA)
- Anti-Replay Bitmap Window: ACTIVE (64-packet protection)
- Dataset Validation: 5,531 Flows, 1,000 Audited Sessions
- ML Attribution Engine: XGBoost (Macro F1: 97.24%), Random Forest (Macro F1: 98.65%)
- Unsupervised Zero-Day Recall: 100.0% (Isolation Forest)

VISTA SOC Framework // SIH26160 NTRO
National Technical Research Organisation Specification
`;
    const blob = new Blob([reportContent], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `${rep.id}_${rep.title.replace(/\s+/g, '_')}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setExportNotice(`Exported ${rep.title} as Markdown report.`);
    setTimeout(() => setExportNotice(null), 3500);
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: '800', color: '#fff', marginBottom: '4px' }}>
            Security Assessment Reports & Documentation
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Audit reports generated according to NIST SP 800-77 Rev. 1 & Smart India Hackathon NTRO specifications
          </p>
        </div>

        {exportNotice && (
          <div style={{
            padding: '6px 14px',
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid var(--green)',
            borderRadius: '6px',
            fontSize: '12px',
            color: 'var(--green)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <CheckCircle2 size={14} />
            <span>{exportNotice}</span>
          </div>
        )}
      </div>

      {/* Report Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
        {REPORTS_LIST.map((rep) => (
          <div key={rep.id} className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span className="soc-badge info">{rep.type}</span>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                  Generated: {rep.date}
                </span>
              </div>

              <div style={{ fontSize: '16px', fontWeight: '700', color: '#fff', marginBottom: '8px' }}>
                {rep.title}
              </div>

              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                {rep.summary}
              </p>

              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '8px',
                background: 'rgba(6, 9, 15, 0.6)',
                padding: '10px',
                borderRadius: '6px',
                marginBottom: '16px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px'
              }}>
                <div>
                  <div style={{ color: 'var(--text-dim)' }}>SECURITY SCORE:</div>
                  <div style={{ fontSize: '15px', fontWeight: '700', color: 'var(--green)' }}>{rep.score}/100</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-dim)' }}>RISK LEVEL:</div>
                  <div style={{ fontSize: '15px', fontWeight: '700', color: rep.risk === 'LOW' ? 'var(--green)' : 'var(--amber)' }}>{rep.risk}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-dim)' }}>FINDINGS:</div>
                  <div style={{ fontSize: '15px', fontWeight: '700', color: '#fff' }}>{rep.findings} Items</div>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  className="soc-btn soc-btn-primary" 
                  onClick={() => handleDownload(rep)}
                  style={{ flex: 1 }}
                >
                  <Download size={13} />
                  <span>EXPORT REPORT (.MD)</span>
                </button>
              <button 
                className="soc-btn" 
                onClick={() => setSelectedReport(rep)}
                style={{ flex: 1 }}
              >
                <Eye size={13} />
                <span>VIEW FINDINGS</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Modal for viewing findings */}
      {selectedReport && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 60
        }} onClick={() => setSelectedReport(null)}>
          <div style={{
            width: '650px',
            background: 'var(--bg-card-elevated)',
            border: '1px solid var(--border-active)',
            borderRadius: '12px',
            padding: '24px',
            boxShadow: '0 20px 50px rgba(0,0,0,0.8)'
          }} onClick={(e) => e.stopPropagation()}>
            <div style={{ fontSize: '16px', fontWeight: '700', color: '#fff', marginBottom: '8px' }}>
              {selectedReport.title}
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              {selectedReport.summary}
            </p>
            <div style={{ background: '#04070d', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#38bdf8', lineHeight: '1.6', marginBottom: '16px' }}>
              [NTRO AUDIT SIGNATURE] CERT_ID: VISTA-SIH26160-2026<br />
              CONFIDENTIALITY: RESTRICTED // GOVERNMENT OF INDIA<br />
              IPSEC STATUS: COMPLIANT WITH ZERO CRITICAL RISKS<br />
              AI ENGINE ATTRIBUTION VERIFIED ACROSS 5,531 VALIDATED FLOWS.
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button className="soc-btn" onClick={() => setSelectedReport(null)}>Close</button>
              <button className="soc-btn soc-btn-primary" onClick={() => { handleDownload(selectedReport); setSelectedReport(null); }}>
                <Download size={13} /> Export Report (.md)
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
