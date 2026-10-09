# VISTA: AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
### Smart India Hackathon 2026 · Problem Statement SIH26160
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  

---

## 1. Overview

VISTA is an end-to-end cybersecurity intelligence platform designed to analyze IPsec VPN deployments from captured or live network traffic. Without breaking or inspecting encrypted payloads, VISTA extracts flow-level and protocol metadata (ESP SPIs, packet timing, direction ratios, IKE negotiation headers) and applies trained Machine Learning models (XGBoost, Random Forest, Isolation Forest) to infer traffic patterns, detect cyberattacks, and audit cryptographic compliance against **NIST SP 800-77 Rev. 1** and **BSI TR-02102-3**.

---

## 2. User Interface Showcase

The VISTA SOC platform provides a unified operations console for defense analysts, SOC operators, and cryptographic auditors.

### 2.1 IPsec Security Overview & Posture Dashboard
> Real-time protocol status (IKEv2, ESP Proto 50, AES-256-GCM), Mode B host-to-host duplex peering topology (Workstation A ↔ Workstation B), NIST SP 800-77 compliance scores, side-channel metadata risk, and live eBPF stream status.

![IPsec Security Overview](docs/screenshots/01_overview.png)

---

### 2.2 Encrypted Traffic Intelligence & Flow Inspector
> Inspection of 5,531+ encrypted testbed flows with zero payload decryption. Computes packet size distributions, inter-arrival time (IAT) variance, directionality ratios, and per-flow AI classification.

![Encrypted Traffic Intelligence Workspace](docs/screenshots/02_traffic_analysis.png)

---

### 2.3 3D Interactive PC1 ↔ PC2 IPsec Testbed & Kernel eBPF Telemetry
> Interactive WebGL Three.js visualization of one direct PC1 ↔ PC2 IPsec tunnel with packet-flow animations, XFRM SA state inspector, and eBPF kernel hooks.

![3D IPsec Testbed and Node Inspector](docs/screenshots/06_testbed_3d.png)

---

### 2.4 AI Intelligence & ML Model Registry
> The backend loads XGBoost and Random Forest flow-label classifiers plus an Isolation Forest anomaly model. The supervised artifacts and their checked-in offline metrics are based on synthetic development data; they are not validated real-world attack detectors. Captured-flow outputs are model predictions, not confirmed incidents or cryptographic-configuration findings.

![AI Intelligence and ML Pipeline](docs/screenshots/03_ai_analysis.png)

---

### 2.5 Security Posture & NIST SP 800-77 Compliance Engine
> Automated cryptographic evaluation of 1,000+ IPsec sessions against NIST SP 800-77 Rev. 1 & BSI TR-02102-3. Flags SWEET32 (3DES), legacy CBC padding oracles, broken HMACs (MD5/SHA1), and sub-2048-bit DH groups.

![Security Posture and Compliance Assessment](docs/screenshots/04_security_assessment.png)

---

### 2.6 Threat Intelligence & MITRE ATT&CK® Enterprise Mapping
> Correlation of active IPsec attacks (DoS floods, data exfiltration, C2 beaconing, port sweeps, and IKE brute-force) to MITRE ATT&CK techniques with live Indicators of Compromise (IOCs) and progression timelines.

![Threat Intelligence and MITRE ATTACK Mapping](docs/screenshots/05_threat_intelligence.png)

---

### 2.7 Canonical Dataset Management & Benchmark Validation
> Transparent management of 5,531 flows across 1,000 correlated sessions with GroupKFold session-aware zero-leakage splits, cryptographic cipher distributions, and verifiable benchmark metrics.

![Dataset and ML Experiment Management](docs/screenshots/08_dataset_hub.png)

---

### 2.8 Audit Documentation & Automated Compliance Reporting
> One-click generation and export of technical and executive audit documentation according to NTRO defense specifications.

![Security Assessment Reports and Documentation](docs/screenshots/07_reports.png)

---

## 3. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   VISTA MODE B ARCHITECTURE MAP                        │
│                                                                        │
│  [ frontend: vista-dashboard/ ] ──(REST / WebSocket)──┐                │
│    • React + Vite SOC Dashboard                       │                │
│    • In-browser PCAP & CSV parser (fallback)          ▼                │
│    • 3D WebGL Duplex Peering Canvas        [ backend: FastAPI API ]    │
│    • Dynamic Security Scorecard              • /api/analyze/pcap       │
│                                              • /api/analyze/csv        │
│  [ topology: Mode B IPsec Testbed ]          • /api/audit/sessions     │
│    • pc1 (IPsec endpoint: 172.20.0.2)         • /api/soc/status         │
│    • pc2 (IPsec endpoint: 172.20.0.3)         • /api/ml/metrics         │
│    • Direct Tunnel Mode (ESP / Proto 50)     • /api/ebpf/events        │
│    • AES-256-GCM / SHA256 / DH Group 19               │                │
│                                                       ▼                │
│                                            [ vista-ml: AI Engine ]     │
│  [ captures/ ] ──(PCAP Replay)─────────────> • Scapy Packet Decoder    │
│    • Real StrongSwan ESP & IKE PCAPs         • XGBoost (Attack Class)  │
│    • eBPF Socket / XFRM Kernel Telemetry     • Random Forest (98.7% F1)│
│                                              • Isolation Forest (Anom) │
│                                              • SHAP Explainability     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Quick Start & Execution

### Option A: One-Click Launch (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File .\start_vista.ps1
```
This automatically starts:
1. **FastAPI AI Core API** at `http://localhost:8000` (Interactive docs at `/docs`)
2. **Vite Cyber SOC Dashboard** at `http://localhost:5173`

---

### Option B: Manual Execution

#### 1. Start the FastAPI Backend
```bash
# Using the preconfigured virtual environment:
.\vista-ml\.venv\Scripts\python run_backend.py --port 8000
```
- API Health: `http://localhost:8000/`
- Swagger UI: `http://localhost:8000/docs`

#### 2. Start the Frontend Dashboard
```bash
cd vista-dashboard
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 5. Key Capabilities & Implemented Features

### 5.1 Real Packet Analysis & IKE Parsing
- **ESP Packet Extraction (Protocol 50):** Automatically decodes Security Parameter Index (SPI) values directly from raw packets (e.g., `0xc6dd300d`).
- **IKEv1 / IKEv2 Negotiation Parsing (UDP 500 & NAT-T 4500):** Decodes ISAKMP headers, Initiator/Responder SPIs, exchange types (IKE_SA_INIT), and extracts the exact major/minor protocol version byte.

### 5.2 Flow Classification and Anomaly Scores
- **Loaded Classifiers:** XGBoost (`xgboost_classifier.joblib`) and Random Forest (`random_forest_baseline.joblib`) classify flow labels using the numeric feature order recorded in each model's metadata.
- **Supported Labels:** Read from the loaded classifier artifacts; the current checked-in models expose `NORMAL`, `DOS`, `PORT_SCAN`, `BRUTE_FORCE`, `C2_BEACONING`, and `DATA_EXFILTRATION`.
- **Model Probabilities:** The classifiers' `predict_proba()` outputs are exposed as uncalibrated model probabilities, not guarantees of correctness. Missing required features are reported rather than imputed.
- **Anomaly Scores:** The checked-in Isolation Forest exposes its outlier flag and raw `score_samples()` value. These outputs are not calibrated real-world threat scores.
- **Training and evaluation limits:** The root models are trained/evaluated using the synthetic VISTA development dataset. Its offline held-out metrics and global SHAP summary do not establish performance on real-world traffic; the SHAP report is not a per-capture explanation.
- **ONNX Model Artifacts:** Standalone `.onnx` models in `vista-ml/models/onnx/` (`xgboost_classifier.onnx`, `random_forest_baseline.onnx`, `isolation_forest.onnx`) for cross-platform deployment on ONNX Runtime (C++, Rust, Go, WebAssembly).
- **Explainability:** A saved global SHAP summary is available for the synthetic development dataset; no local explanation is generated for an uploaded capture.

### 5.3 Deterministic NIST Compliance Engine
Evaluates session configurations against:
- **NIST SP 800-77 Rev. 1** (Guide to IPsec VPNs)
- **BSI TR-02102-3** (Cryptographic Mechanisms for IPsec)
Identifies vulnerabilities:
- Legacy 3DES (SWEET32) & CBC Padding Oracle risks
- Deprecated HMAC algorithms (MD5 / SHA-1)
- Sub-2048-bit Diffie-Hellman groups
### 5.4 Live eBPF Kernel Ingestion & Correlation
- **Linux collector (`ebpf/`):** Uses `bpftool` to generate `vmlinux.h` from `/sys/kernel/btf/vmlinux`, Clang to build a CO-RE `.bpf.o`, and libbpf to load/attach kprobes to XFRM (`xfrm_output`, `xfrm_input`) and socket send paths (`sock_sendmsg`, `udp_sendmsg`, `__sys_sendto`). Events use a libbpf ring buffer.
- **Runtime status:** `/api/ebpf/status` reports actual BTF availability and probe attachment. If BTF, capabilities, loading, or attachment fails, `/status` reports `UNAVAILABLE` and `/events` is empty; no synthetic kernel events are generated.
- **Collection boundary:** XFRM events include the skb length; inbound XFRM events include SPI. The socket hook records process metadata only. Current events do not reliably correlate to a particular flow.

To run the collector, use `docker compose --profile ebpf -f topology/docker-compose.yml up --build` on Linux or Docker Desktop WSL2 with readable kernel BTF and effective `CAP_BPF`/`CAP_PERFMON`. The `ebpf` profile is opt-in; the local collector API is exposed at `http://127.0.0.1:8765`.

---

## 6. Direct PC1 ↔ PC2 IPsec Testbed

`topology/docker-compose.yml` builds exactly two StrongSwan endpoints from `debian:bookworm-slim`: `pc1` (`172.20.0.2`) and `pc2` (`172.20.0.3`). They share one Compose-managed Docker bridge (`vista-pc-net`) and negotiate one direct IKEv2 tunnel with host-specific tunnel selectors (`172.20.0.2/32` ↔ `172.20.0.3/32`). IKE uses AES-256/SHA-256/MODP-2048 and ESP uses AES-256-GCM. There is no VPN gateway, protected server, forwarding, or SNAT service. The separate `vista-ebpf-monitor` profile is a passive host-kernel monitor, not an IPsec endpoint.

Start the two endpoints and the real CO-RE collector:
```powershell
docker compose --profile ebpf -f topology/docker-compose.yml up -d --build pc1 pc2 vista-ebpf-monitor
docker exec pc1 swanctl --list-sas
docker exec pc2 swanctl --list-sas
docker exec pc1 ping -c 10 172.20.0.3
docker exec pc2 ping -c 10 172.20.0.2
docker exec pc1 ip xfrm state
docker exec pc1 ip xfrm policy
docker exec pc2 ip xfrm state
docker exec pc2 ip xfrm policy
Invoke-RestMethod http://127.0.0.1:8765/status
Invoke-RestMethod 'http://127.0.0.1:8765/events?limit=500'
```

`pc1-cbc-swanctl.conf` / `pc2-cbc-swanctl.conf` are direct-peer AES-256-CBC comparison configurations; the default Compose tunnel uses AES-256-GCM.

The Overview dashboard's eBPF stream polls the backend API and shows received native collector events; it does not generate fallback/demo kernel events.

---

## 7. Verification & Test Suite

Run backend integration test suite:
```bash
.\vista-ml\.venv\Scripts\python backend\test_api.py
```
Run ML unit tests:
```bash
cd vista-ml
.\.venv\Scripts\pytest -q
```
Verify frontend build:
```bash
cd vista-dashboard
npm run build
```
