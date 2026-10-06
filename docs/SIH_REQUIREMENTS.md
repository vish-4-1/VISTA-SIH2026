# VISTA: SIH Requirements Traceability Matrix
### Problem Statement SIH26160 · NTRO · Smart India Hackathon 2026

**Status Definitions:**
- **COMPLETE**: Fully implemented, backed by genuine functional code, and tested.
- **PARTIAL**: Implemented in code/scripts or offline pipeline, with specific boundaries or minor gaps noted.
- **MOCK**: Displayed statically in the UI without real computation.
- **NOT IMPLEMENTED**: Feature is currently absent from the codebase.

---

| SIH Requirement | Status | Evidence in Code | How It Works | Remaining Gap / Boundary | Priority |
|---|---|---|---|---|---|
| **1. VPN Testbed: Mode Matrix** | **COMPLETE** | `topology/docker-compose.yml`, `configs/*-swanctl.conf`, `client-tunnel-swanctl.conf` | Docker containers (`vista-client`, `vista-gateway`, `vista-server`) with valid swanctl configs for both Transport and Tunnel mode. | Full automated dynamic switching CLI script between modes. | P1 |
| **2. VPN Testbed: Cipher Matrix** | **COMPLETE** | `configs/client-swanctl.conf`, `configs/client-cbc-swanctl.conf` | Supports AES-256-GCM (AEAD) and AES-256-CBC + HMAC-SHA256 configurations. Evaluated against synthetic matrix (AES-128, 3DES, Camellia). | Live capture of 3DES/legacy suites on the Docker containers. | P1 |
| **3. VPN Testbed: Key Exchange & PFS** | **COMPLETE** | `configs/*-swanctl.conf`, `train_testbed_ike_dh.py`, `captures/strongswan/ike_dh_inference/` | IKEv2 with MODP-2048, MODP-3072, and ECP-256. Real captured IKE negotiation PCAPs exist in `captures/`. | PFS disabled toggle config in active testbed run. | P2 |
| **4. VPN Testbed: IPv4 / IPv6** | **PARTIAL** | `topology/docker-compose.yml`, `pcap_analyzer.py` (IPv6 EtherType 0x86dd decoder) | Complete IPv4 dual-subnet topology (172.20.0.0/24 & 172.22.0.0/24). Packet parser parses IPv6 ESP, but testbed lacks active IPv6 router. | Native IPv6 testbed subnet configuration. | P2 |
| **5. Traffic Generation** | **PARTIAL** | `train_testbed_normal.py`, `captures/strongswan/normal/` | Generates real ICMP and TCP marker traffic through the StrongSwan tunnel; saves real PCAPs. | Synthetic labels in dataset for VoIP/Video/Email; no live WebRTC/RTP generator. | P1 |
| **6. Traffic Capture (Offline & Live)** | **COMPLETE** | `train_testbed_normal.py`, `backend/services/pcap_analyzer.py`, `captures/` | Tcpdump inside containers for live testbed runs; FastAPI `POST /api/analyze/pcap` accepts uploaded `.pcap` files and parses via Scapy. | Continuous streaming packet sniffer daemon (promiscuous interface). | P1 |
| **7. Protocol & Header Identification** | **COMPLETE** | `backend/services/pcap_analyzer.py` lines 85–140 | Decodes ESP Protocol 50 SPIs (hex `0x...`); parses ISAKMP headers (UDP 500/4500), Initiator/Responder SPIs, exchange types (IKE_SA_INIT), and version byte (`IKEv2.0`). | Complete parsing of IKEv2 encrypted payloads (IKE_AUTH SK payloads). | P1 |
| **8. Encrypted Traffic Classification** | **COMPLETE** | `vista_ml/models/xgboost_model.py`, `backend/services/model_service.py` | 18 flow metadata features (packet sizes, IAT jitter, direction ratios, rates) fed to XGBoost & Random Forest without payload inspection. | Trained on synthetic & benchmark data; requires larger live capture volume. | P1 |
| **9. AI/ML Training & Reproducibility** | **COMPLETE** | `vista_ml/scripts/train_baseline.py`, `train_xgboost.py`, `train_anomaly.py`, `pyproject.toml` | Group-aware splitting prevents data leakage; models serialize with `.metadata.json`; 10/10 pytest unit tests pass; SHAP analysis generated. | Live online incremental learning. | P2 |
| **10. AI Confidence & True Probabilities** | **COMPLETE** | `model_service.py: predict()`, `pcap_analyzer.py: analyze_file()` | Computes true probability distributions via `predict_proba()`; confidence is `max(proba) * 100`. No random numbers or hardcoded strings. | Fully operational. | -- |
| **11. Zero-Day Anomaly Detection** | **COMPLETE** | `vista_ml/models/isolation_forest.joblib`, `model_service.py` | Unsupervised Isolation Forest scores flow anomalies and outliers (`score_samples()`). | Threshold calibration against adversarial samples. | P1 |
| **12. Security Posture Assessment** | **COMPLETE** | `backend/services/posture_engine.py`, `SecurityAssessmentView.jsx` | Deterministic compliance engine based on NIST SP 800-77 Rev. 1 & BSI TR-02102-3; audits AEAD, HMAC, DH groups, PFS, lifetime, and replay windows. | Live SA state extraction via `swanctl --list-sas --raw`. | P1 |
| **13. Dynamic SOC & Threat Matrix** | **COMPLETE** | `backend/services/soc_service.py`, `socData.js` | Dynamically maps classified attack flows to MITRE ATT&CK techniques (T1046, T1499, T1110, T1071, T1048); dynamic security scores and packet counts. | SIEM syslog export integration (CEF/LEEF). | P2 |
| **14. eBPF Kernel Telemetry & Ingestion** | **COMPLETE** | `ebpf/vista_ipsec_monitor.bpf.c`, `ebpf/vista_ebpf_agent.py`, `backend/services/ebpf_service.py` | Real eBPF C program tracing `xfrm_output`, `xfrm_input`, `sock_sendmsg` with 256 KB ring buffer; userspace agent; PCAP+eBPF fusion pipeline; live UI event stream. | Direct BTF loading on non-Linux hosts (requires Linux kernel). | P1 |
| **15. Report Generation** | **COMPLETE** | `backend/main.py: /api/reports/generate`, `ReportsView.jsx` | Generates dynamic Markdown assessment reports reflecting actual security scores, cryptographic posture, and NIST remediation roadmaps. | Binary PDF rendering via headless browser or jsPDF. | P2 |
| **16. Interactive SOC Dashboard** | **COMPLETE** | `vista-dashboard/src/` | React + Vite dashboard with 8 views; 3D testbed topology; live file upload; live API polling with transparent offline fallback. | Additional responsive tablet/mobile breakpoints. | P2 |
