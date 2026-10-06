# VISTA: AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
### Smart India Hackathon 2026 · Problem Statement SIH26160
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  

---

## 1. Overview

VISTA is an end-to-end cybersecurity intelligence platform designed to analyze IPsec VPN deployments from captured or live network traffic. Without breaking or inspecting encrypted payloads, VISTA extracts flow-level and protocol metadata (ESP SPIs, packet timing, direction ratios, IKE negotiation headers) and applies trained Machine Learning models (XGBoost, Random Forest, Isolation Forest) to infer traffic patterns, detect cyberattacks, and audit cryptographic compliance against **NIST SP 800-77 Rev. 1** and **BSI TR-02102-3**.

---

## 2. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VISTA ARCHITECTURE MAP                          │
│                                                                        │
│  [ frontend: vista-dashboard/ ] ──(REST / WebSocket)──┐                │
│    • React + Vite SOC Dashboard                       │                │
│    • In-browser PCAP & CSV parser (fallback)          ▼                │
│    • 3D IPsec Tunnel Visualization         [ backend: FastAPI API ]    │
│    • Dynamic Security Scorecard              • /api/analyze/pcap       │
│                                              • /api/analyze/csv        │
│  [ topology: Docker Testbed ]                • /api/audit/sessions     │
│    • vista-client  (172.20.0.2)              • /api/soc/status         │
│    • vista-gateway (172.20.0.10)             • /api/ml/metrics         │
│    • vista-server  (172.22.0.10)                      │                │
│    • Transport, Tunnel & CBC configs                  ▼                │
│                                            [ vista-ml: AI Engine ]     │
│  [ captures/ ] ──(PCAP Replay)─────────────> • Scapy Packet Decoder    │
│    • Real StrongSwan ESP & IKE PCAPs         • XGBoost (Attack Class)  │
│                                              • Random Forest (98.7% F1)│
│                                              • Isolation Forest (Anom) │
│                                              • SHAP Explainability     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Quick Start & Execution

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

## 4. Key Capabilities & Implemented Features

### 4.1 Real Packet Analysis & IKE Parsing
- **ESP Packet Extraction (Protocol 50):** Automatically decodes Security Parameter Index (SPI) values directly from raw packets (e.g., `0xc6dd300d`).
- **IKEv1 / IKEv2 Negotiation Parsing (UDP 500 & NAT-T 4500):** Decodes ISAKMP headers, Initiator/Responder SPIs, exchange types (IKE_SA_INIT), and extracts the exact major/minor protocol version byte.

### 4.2 Live Machine Learning Inference
- **Trained Classifiers:** XGBoost (`xgboost_classifier.joblib`) and Random Forest (`random_forest_baseline.joblib`).
- **Attack Classes:** `NORMAL`, `DOS`, `PORT_SCAN`, `BRUTE_FORCE`, `C2_BEACONING`, `DATA_EXFILTRATION`.
- **Honest Probability Outputs:** Real probability distributions and confidence scores via `predict_proba()`.
- **Zero-Day Anomaly Detection:** Scored via scikit-learn Isolation Forest (`isolation_forest.joblib`).
- **Explainability:** SHAP feature attribution metrics generated via TreeExplainer.

### 4.3 Deterministic NIST Compliance Engine
Evaluates session configurations against:
- **NIST SP 800-77 Rev. 1** (Guide to IPsec VPNs)
- **BSI TR-02102-3** (Cryptographic Mechanisms for IPsec)
Identifies vulnerabilities:
- Legacy 3DES (SWEET32) & CBC Padding Oracle risks
- Deprecated HMAC algorithms (MD5 / SHA-1)
- Sub-2048-bit Diffie-Hellman groups
### 4.4 Live eBPF Kernel Ingestion & Correlation
- **Kernel Program (`ebpf/vista_ipsec_monitor.bpf.c`):** Implements BPF CO-RE tracing on Linux kernel `kprobe/xfrm_output`, `kprobe/xfrm_input`, and `tracepoint:sock:sock_sendmsg`. Streams events via a 256 KB BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`).
- **Telemetry Agent (`ebpf/vista_ebpf_agent.py`):** Collects kernel events, tracking PID, process name (`comm`), SPI, sequence counters, and packet lengths.
- **PCAP + eBPF Feature Fusion:** Correlates wire-level ESP flows with host socket telemetry using `vista_ml.features.fusion.fuse_pcap_ebpf()` to identify the exact origin process behind encrypted tunnels without inspecting payloads.
- **Dashboard Stream:** Live streaming telemetry panel in `OverviewView.jsx` connected to `/api/ebpf/events`.

---

## 5. IPsec Testbed Configuration Matrix

Located in `configs/`:
- `client-swanctl.conf` / `gateway-swanctl.conf`: IKEv2 Transport Mode with AES-256-GCM.
- `client-tunnel-swanctl.conf` / `gateway-tunnel-swanctl.conf`: IKEv2 Tunnel Mode with subnet selectors.
- `client-cbc-swanctl.conf` / `gateway-cbc-swanctl.conf`: IKEv2 AES-256-CBC with HMAC-SHA256 for cipher comparison.

---

## 6. Verification & Test Suite

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
