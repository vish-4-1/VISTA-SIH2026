# VISTA Dashboard

This directory contains the React frontend for the VISTA IPsec analysis framework.

## Run and validate

```bash
npm run dev
npm run lint
npm run build
```

The dashboard uses the VISTA backend for PCAP/CSV analysis, model inference,
audit data, reports, threat mapping, and live eBPF testbed telemetry. Checked-in
dataset and model-evaluation artifacts are identified separately from live or
uploaded data.

## Uploaded analysis lifecycle

PCAP and CSV uploads are analyzed by the backend. The complete backend response,
selected file metadata, status, and any error are held in the
`PcapAnalysisProvider` above the dashboard views. This keeps the active analysis
available while navigating between dashboard sections. A new upload replaces
the prior result; **Clear** removes the active result across all views.

Analysis state is held in memory for the lifetime of the dashboard application.
It is not persisted to `sessionStorage` or across a browser refresh, and the raw
uploaded file is not retained by the frontend after the backend request.

AI Analysis, Threat Intelligence, Reports, Dataset, and Security Assessment
consume the active uploaded result where supported. PCAP-derived traffic
metadata is not presented as negotiated IPsec security posture. The bundled
audit CSV/JSON is generated scenario data and is excluded from operational
Security Assessment results. No live SA audit source is currently configured.
Testbed continues to show separate live PC1↔PC2 eBPF telemetry.

AI Analysis displays only labels returned by the loaded flow classifier. Its
model probabilities are uncalibrated estimates; incomplete inputs and model
errors are shown as separate statuses without discarding observed packet
analysis. Current root classifier artifacts and offline metrics use synthetic
development data and are not validated real-world attack detections. Global
SHAP values are not explanations for the active upload. Reports are associated
with the active analysis and are hidden when a new upload replaces it.
