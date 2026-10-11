/**
 * VISTA API Client
 * Facilitates communication with the FastAPI VISTA AI Core.
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

export async function fetchAuditSummary() {
  const res = await fetch(`${API_BASE}/audit/summary`);
  if (!res.ok) throw new Error('Failed to fetch audit summary');
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
 * Fetches SHAP explainer readiness, model gating status, and supported modes.
 */
export async function fetchShapStatus() {
  const res = await fetch(`${API_BASE}/ml/shap/status`);
  if (!res.ok) throw new Error('Failed to fetch SHAP status');
  return await res.json();
}

/**
 * Fetches global feature importance with audited evaluation provenance.
 */
export async function fetchGlobalShap(modelId = 'xgboost') {
  const res = await fetch(`${API_BASE}/ml/shap/global?model=${encodeURIComponent(modelId)}`);
  if (!res.ok) throw new Error(`Failed to fetch global SHAP importance for ${modelId}`);
  return await res.json();
}

/**
 * Requests directional SHAP explanation for an individual flow record.
 */
export async function explainFlow(payload) {
  const res = await fetch(`${API_BASE}/ml/shap/explain-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`SHAP Flow Explanation error (${res.status}): ${errorText}`);
  }
  return await res.json();
}

/**
 * Generates dynamic assessment report markdown.
 */
export async function generateReport(reportType = 'Technical Assessment', flows, analysisId, filename) {
  const payload = { reportType };
  if (flows) payload.flows = flows;
  if (analysisId) payload.analysisId = analysisId;
  if (filename) payload.filename = filename;

  const res = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to generate report');
  return await res.json();
}

export async function fetchThreats(flows) {
  const options = flows
    ? {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flows }),
      }
    : {};
  const res = await fetch(`${API_BASE}/soc/threats`, options);
  if (!res.ok) throw new Error('Failed to fetch threat analysis');
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

/**
 * Fetches available sample PCAPs in the repository.
 */
export async function fetchSampleCaptures() {
  const res = await fetch(`${API_BASE}/captures/samples`);
  if (!res.ok) throw new Error(`Failed to fetch sample capture inventory (${res.status})`);
  const data = await res.json();
  if (!Array.isArray(data) || data.some((capture) => (
    !capture || typeof capture.name !== 'string' || !Number.isFinite(capture.sizeBytes)
  ))) throw new Error('Sample capture inventory response is invalid.');
  return data;
}

/**
 * Downloads a sample capture as a File object ready for analyzeFile().
 */
export async function fetchSampleCaptureBlob(filename) {
  const res = await fetch(`${API_BASE}/captures/samples/${encodeURIComponent(filename)}`);
  if (!res.ok) throw new Error(`Failed to load sample capture ${filename}`);
  const blob = await res.blob();
  return new File([blob], filename, { type: 'application/octet-stream' });
}

/**
 * Fetches verified IPsec testbed swanctl profiles and capability matrix.
 */
export async function fetchTestbedProfiles() {
  const res = await fetch(`${API_BASE}/testbed/profiles`);
  if (!res.ok) throw new Error('Failed to fetch testbed profiles');
  return await res.json();
}

/**
 * Fetches authoritative live runtime status of the IPsec VPN testbed.
 * Returns endpoint IP addresses, StrongSwan IKE/CHILD SA state, eBPF telemetry, and active captures.
 */
export async function fetchTestbedLiveStatus(signal) {
  const options = signal ? { signal } : {};
  const res = await fetch(`${API_BASE}/testbed/live-status`, options);
  if (!res.ok) throw new Error(`Failed to fetch testbed live status (${res.status})`);
  return await res.json();
}

/**
 * Validates a candidate IPsec configuration against testbed constraints.
 */
export async function validateTestbedConfig(config) {
  const res = await fetch(`${API_BASE}/testbed/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error('Failed to validate testbed configuration');
  return await res.json();
}

/**
 * Dataset Studio: Lists registered datasets.
 */
export async function fetchDatasets() {
  const res = await fetch(`${API_BASE}/datasets`);
  if (!res.ok) throw new Error('Failed to fetch dataset registry');
  return await res.json();
}

/**
 * Dataset Studio: Fetches full dataset details, schema, sample rows, and quality audits.
 */
export async function fetchDatasetDetails(datasetId) {
  const res = await fetch(`${API_BASE}/datasets/${encodeURIComponent(datasetId)}`);
  if (!res.ok) throw new Error(`Failed to fetch dataset details for ${datasetId}`);
  return await res.json();
}

/**
 * Dataset Studio: Fetches verified testbed capabilities for dataset generation.
 */
export async function fetchDatasetCapabilities() {
  const res = await fetch(`${API_BASE}/datasets/capabilities`);
  if (!res.ok) throw new Error('Failed to fetch dataset generation capabilities');
  return await res.json();
}

/**
 * Dataset Studio: Runs preflight check before generating a dataset.
 */
export async function runDatasetPreflight(config) {
  const res = await fetch(`${API_BASE}/datasets/preflight`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error('Failed to run dataset preflight check');
  return await res.json();
}

/**
 * Dataset Studio: Dispatches an asynchronous dataset generation job.
 */
export async function startDatasetGeneration(config) {
  const res = await fetch(`${API_BASE}/datasets/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Generation job failed to start: ${errorText}`);
  }
  return await res.json();
}

/**
 * Dataset Studio: Polls real-time stage progress of a generation job.
 */
export async function pollDatasetJob(jobId) {
  const res = await fetch(`${API_BASE}/datasets/jobs/${encodeURIComponent(jobId)}`);
  if (!res.ok) throw new Error(`Failed to poll job ${jobId}`);
  return await res.json();
}

/**
 * Dataset Studio: Cancels an active dataset generation job.
 */
export async function cancelDatasetJob(jobId) {
  const res = await fetch(`${API_BASE}/datasets/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to cancel job ${jobId}`);
  return await res.json();
}

/**
 * Dataset Studio: Executes quality and leakage validation on an existing dataset.
 */
export async function validateDatasetQuality(datasetId) {
  const res = await fetch(`${API_BASE}/datasets/${encodeURIComponent(datasetId)}/validate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to validate dataset ${datasetId}`);
  return await res.json();
}

/**
 * Dataset Studio: Returns safe export/download URL for a dataset.
 */
export function getDatasetExportUrl(datasetId, format = 'csv') {
  return `${API_BASE}/datasets/${encodeURIComponent(datasetId)}/export?format=${encodeURIComponent(format)}`;
}
