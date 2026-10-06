# VISTA Dashboard

This directory contains the React frontend for the VISTA IPsec analysis prototype.

## Current role

The dashboard is a static front-end prototype intended to present:

- IPsec and VPN posture information
- traffic summaries
- packet-flow exploration
- ML metrics
- security assessment panels
- report and threat views

## Verified status

The app compiles successfully with Vite:

```bash
cd vista-dashboard
npm install
npm run build
```

## What it does

- accepts uploaded `.pcap`, `.pcapng`, `.cap`, and CSV files
- parses packet metadata in-browser
- computes flow-level aggregates such as packet counts, byte totals, and IAT statistics
- loads packaged JSON summary data for demo/scenario dashboards

## Important limitation

This dashboard is not connected to a live backend analysis service. It is a standalone client-side prototype and should not be mistaken for a complete operational product.

## Files of interest

- `src/App.jsx` – shell and navigation
- `src/components/views/TrafficAnalysisView.jsx` – file upload and flow display
- `src/utils/pcapParser.js` – in-browser PCAP parsing
- `src/data/*.js` and `src/data/*.json` – demo and dataset-backed UI values

## Realistic usage

Use the dashboard for:

- prototype interaction
- static data review
- local PCAP inspection
- presentational UI validation

Do not use it as evidence of a complete end-to-end monitored IPsec environment without a working backend and capture pipeline behind it.
