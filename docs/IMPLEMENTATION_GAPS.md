# VISTA Implementation Gap Report
## SIH26160 · NTRO · Smart India Hackathon 2026

This document lists the remaining technical gaps and boundaries in the VISTA framework.

---

## Gap 1: Live Continuous Packet Ingestion Daemon

- **Requirement:** Continuously sniff a live physical or virtual network interface (`eth0`, `veth*`) without requiring user file upload.
- **Current State:** Traffic is captured offline or on-demand via `tcpdump` into `.pcap` files, or uploaded to `POST /api/analyze/pcap`.
- **Why It Matters:** In an enterprise SOC deployment, an automated tap daemon feeds incoming flows without manual intervention.
- **Existing Code:** `backend/services/pcap_analyzer.py` handles complete Scapy packet parsing; `train_testbed_normal.py` controls `tcpdump`.
- **Required Implementation:** Add a background `AsyncSniffer` thread in `pcap_analyzer.py` listening on a designated interface.
- **Priority:** P1
- **Estimated Complexity:** Medium

---

## Gap 2: Live SA State Extraction from StrongSwan

- **Requirement:** Extract running Security Association state directly from the strongSwan charon daemon (`swanctl --list-sas --raw`).
- **Current State:** The deterministic NIST rule engine can evaluate supplied session parameters, but the bundled audit CSV/JSON is generated scenario data and is excluded from operational Security Assessment APIs. No live SA audit source is currently configured; active configs are parsed statically.
- **Why It Matters:** Evaluators running `docker-compose up` will want to see running SA SPIs, lifetimes, and byte counters pulled straight from the kernel XFRM state table.
- **Existing Code:** `backend/services/posture_engine.py` evaluates SAs; `configs/` contains swanctl configs.
- **Required Implementation:** Implement a `docker exec pc1 swanctl --list-sas --raw` parser in `posture_engine.py`; the direct testbed has only `pc1` and `pc2`.
- **Priority:** P1
- **Estimated Complexity:** Low

---

## Gap 3: Realistic Application Traffic Generators

- **Requirement:** Generate live Web, VoIP (RTP/SIP), video streaming, and email traffic through the tunnel.
- **Current State:** Testbed generates real ICMP ping traffic and TCP marker traffic (`nc`); application traffic classes in the dataset rely on realistic statistical models and benchmark distributions.
- **Why It Matters:** Technical evaluators may ask to generate a live video stream or VoIP call through the tunnel to observe live classification.
- **Existing Code:** `train_testbed_normal.py` generates ICMP and TCP marker traffic directly between `pc1` and `pc2`.
- **Required Implementation:** Add scripts in `testbed/` to generate `curl` HTTP loops, `iperf3` UDP bursts (VoIP), and bulk transfers.
- **Priority:** P1
- **Estimated Complexity:** Medium

---

## Gap 4: Native IPv6 Testbed Subnet

- **Requirement:** Demonstrate IPsec over native IPv6 (`::1`, `fd00::/8`).
- **Current State:** Packet analyzer supports IPv6 NextHeader (ESP) decoding; Docker Compose defines one direct IPv4 bridge for `pc1` and `pc2`.
- **Why It Matters:** Government and defence deployments increasingly mandate IPv6 compliance.
- **Existing Code:** `pcap_analyzer.py` handles IPv6 headers; Compose defines one direct IPv4 subnet.
- **Required Implementation:** Enable IPv6 driver in `docker-compose.yml` with `enable_ipv6: true` and add IPv6 connection stanzas to `swanctl.conf`.
- **Priority:** P2
- **Estimated Complexity:** Low

---

## Gap 5: Direct PDF Report Rendering

- **Requirement:** Export audit reports as `.pdf` binary documents in addition to structured Markdown.
- **Current State:** `ReportsView.jsx` exports clean `.md` reports; backend returns Markdown text.
- **Why It Matters:** Executive management prefers presentation-ready PDF deliverables.
- **Existing Code:** `ReportsView.jsx` has client-side download; `backend/main.py: /api/reports/generate` creates structured reports.
- **Required Implementation:** Add `jsPDF` or `html2pdf.js` in the frontend or `reportlab` in the backend.
- **Priority:** P2
- **Estimated Complexity:** Low
