/**
 * VISTA API Client
 * Facilitates communication with the FastAPI VISTA AI Core.
 * Provides transparent fallback to client-side heuristics if the backend is offline.
 */

const API_BASE = '/api';

/**
 * Checks if the backend AI Core API is reachable.
 */
export async function checkBackendStatus() {
  try {
    const res = await fetch(`${API_BASE}/status`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { online: false };
    const data = await res.json();
    return { online: true, ...data };
  } catch (err) {
    return { online: false, error: err.message };
  }
}

/**
 * Uploads a PCAP file to the FastAPI backend for full Scapy decoding and ML inference.
 */
export async function analyzePcapWithBackend(file, modelName = 'xgboost') {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze/pcap?model=${encodeURIComponent(modelName)}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Backend PCAP Analysis error (${res.status}): ${errorText}`);
  }

  return await res.json();
}

/**
 * Uploads a CSV flow dataset to the backend for live ML inference.
 */
export async function analyzeCsvWithBackend(file, modelName = 'xgboost') {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze/csv?model=${encodeURIComponent(modelName)}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Backend CSV Analysis error (${res.status}): ${errorText}`);
  }

  return await res.json();
}

/**
 * Fetches dynamic SOC posture and packet metrics.
 */
export async function fetchSocStatus() {
  const res = await fetch(`${API_BASE}/soc/status`);
  if (!res.ok) throw new Error('Failed to fetch SOC status');
  return await res.json();
}

/**
 * Fetches audit sessions evaluated against NIST SP 800-77.
 */
export async function fetchAuditSessions(limit = 500) {
  const res = await fetch(`${API_BASE}/audit/sessions?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch audit sessions');
  return await res.json();
}

/**
 * Fetches model metrics and SHAP feature importance.
 */
export async function fetchMlMetrics() {
  const res = await fetch(`${API_BASE}/ml/metrics`);
  if (!res.ok) throw new Error('Failed to fetch ML metrics');
  return await res.json();
}

/**
 * Generates dynamic assessment report markdown.
 */
export async function generateReport(reportType = 'Technical Assessment') {
  const res = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reportType }),
  });
  if (!res.ok) throw new Error('Failed to generate report');
  return await res.json();
}

/**
 * Fetches live eBPF kernel telemetry stream from the backend.
 */
export async function fetchEbpfEvents(limit = 12) {
  const res = await fetch(`${API_BASE}/ebpf/events?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch eBPF events');
  return await res.json();
}

/**
 * Fetches eBPF probe status and ring buffer capacity.
 */
export async function fetchEbpfStatus() {
  const res = await fetch(`${API_BASE}/ebpf/status`);
  if (!res.ok) throw new Error('Failed to fetch eBPF status');
  return await res.json();
}
