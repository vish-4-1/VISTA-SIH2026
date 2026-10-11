# VISTA Phase 9 — Independent Dataset Audit and Baseline Eligibility

## Executive Summary

Phase 9 independently audits the unified multi-workload dataset generated in Phase 8 ([`76adc766-ef41-45f5-b677-1d950c7ff052`](file:///c:/vista/captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052)) across 15 independent IKE_SA sessions and 60 observations.

This phase is strictly an **evidence and eligibility gate**. It verifies that all minimum data integrity, ground-truth provenance, and leakage controls are satisfied to authorize a controlled, reproducible **baseline experiment specification**.

> [!IMPORTANT]
> **Boundary Notice:** Phase 9 does **not** train, promote, deploy, or integrate an ML model into production runtime. The dataset is qualified solely for exploratory baseline research on controlled outer-ESP workload recognition, and does not establish arbitrary application identification, operational attack detection, or production protocol classification.

---

## 1. Independent Artifact Recomputation Audit

The audit script [`scripts/audit_phase9_dataset.py`](file:///c:/vista/scripts/audit_phase9_dataset.py) recomputed evidence directly from stored campaign artifacts rather than trusting pre-generated summary files.

### 1.1 Recomputed Artifact Integrity

| Artifact Category | Verified Count / Total | Recomputation Method | Integrity Status |
|---|---|---|---|
| **Raw PCAPs** | 60 / 60 | SHA-256 computed on disk matches `capture.raw_pcap_sha256`; classic PCAP global headers valid; size matches metadata. | **PASS** |
| **Outer ESP Frames** | 60 / 60 | Parsed with Scapy `PcapReader`; confirmed non-zero outer IPv4 ESP (proto 50) or NAT-T UDP 4500 non-keepalive frames. | **PASS** |
| **Packet Tables (`packets.csv`)** | 60 / 60 | SHA-256 computed on disk matches `capture.sha256`. | **PASS** |
| **Feature Extraction Parity** | 60 / 60 | Extracted 18 `vista-flow-v1` flow features from raw `packets.csv` using `extract_flow_features()`; checked numerical parity against `prepared_dataset.csv`. Zero discrepancies (`1e-4` tolerance). | **PASS** |
| **Ground Truth Records** | 60 / 60 | SHA-256 computed on disk matches `ground_truth.record_sha256`. | **PASS** |
| **Session Records** | 60 / 60 | SHA-256 computed on disk matches `session_record_sha256`. | **PASS** |
| **Negotiated SA Evidence** | 60 / 60 | SHA-256 computed on disk matches `vpn.negotiated_sa_evidence_sha256`. | **PASS** |
| **Workload Measurements** | 60 / 60 | SHA-256 computed on disk matches `workload.measurement_sha256`. | **PASS** |
| **Independent Receiver Evidence** | 60 / 60 | SHA-256 of PC2 server evidence matches recorded hashes; client and server records agree. | **PASS** |

### 1.2 Endpoint Ground Truth Verification

Every observation was cross-referenced against independent endpoint records:
1. **ICMPv4 (`controlled_icmpv4`, 15 observations):**
   - PC1 sender `packetsSent` == PC1 sender `packetsReceived` == `requestedPackets`.
   - PC2 receiver `receiverEchoRequests` == `requestedPackets`.
   - 100% echo reply success through the IPsec tunnel.
2. **TCP Marker (`controlled_tcp_marker`, 15 observations):**
   - PC1 sender `bytesSent` == PC2 OpenBSD `nc` receiver `bytesReceived`.
   - PC1 sender payload SHA-256 == PC2 receiver payload SHA-256.
   - 100% payload integrity across all transferred sequences.
3. **HTTP/1.1 (`controlled_http`, 30 observations across 15 GET and 15 POST):**
   - PC1 client `requestsCompleted` == `requestsRequested` == PC2 Perl server `totalRequestsReceived`.
   - PC2 server returned HTTP status code `200 OK` for 100% of requests.
   - PC1 client response body SHA-256 digest matched PC2 server response body SHA-256 digest for every individual request.
   - Server evidence SHA-256 matched the hash recorded in `ground_truth.serverEvidenceSha256`.

---

## 2. Prediction Target and Feature Contract Audit

### 2.1 Formal Target Ontology
The target label schema [`vista-target-label-schema-v1.json`](file:///c:/vista/vista-ml/schemas/vista-target-label-schema-v1.json) formally defines the classification objective:

- **Intended Prediction Target:** Controlled benign workload classification from encrypted IPv4 outer-ESP metadata (`vista-flow-v1`).
- **Canonical Classes:**
  1. `controlled_icmpv4` (15 observations; subtype: `icmpv4_echo`)
  2. `controlled_tcp_marker` (15 observations; subtype: `tcp_marker`)
  3. `controlled_http` (30 observations; subtypes: `http_get`, `http_post`)
- **Workload Subtypes:** HTTP GET and POST are explicitly maintained as metadata subtypes rather than distinct classes. This avoids artificial class fragmentation while capturing realistic HTTP transaction diversity.

### 2.2 Feature Contract & Domain Boundary
- All observations adhere to the 18-feature contract in [`vista-flow-v1.json`](file:///c:/vista/vista-ml/schemas/vista-flow-v1.json):
  `packet_count`, `byte_count`, `flow_duration`, `mean_packet_size`, `std_packet_size`, `min_packet_size`, `max_packet_size`, `mean_inter_arrival_time`, `std_inter_arrival_time`, `min_inter_arrival_time`, `max_inter_arrival_time`, `packets_per_second`, `bytes_per_second`, `forward_packet_count`, `backward_packet_count`, `forward_bytes`, `backward_bytes`, `direction_ratio`.
- **Inference Availability:** All 18 features are derived solely from bidirectional outer IPv4 ESP/NAT-T packet arrival timestamps and IP payload lengths (ESP frame size). No transport-layer ports, cleartext headers, HTTP URLs, GET/POST payloads, query parameters, or cookies are accessible or inspected.
- **Target Independence:** Model features do not contain or derive from experiment IDs, session IDs, capture filenames, or hidden metadata.

> [!CAUTION]
> **Scope Disclaimer:** This dataset qualifies only controlled workload discrimination under fixed testbed conditions. It does **not** support:
> - Production IPsec traffic identification under arbitrary user traffic.
> - Identification of inner application protocols beyond the controlled lab benchmarks.
> - Operational attack classification or anomaly detection.

---

## 3. Leakage and Generalization Audit

### 3.1 Split Integrity & Overlap Controls
The dataset is partitioned using deterministic nested `GroupShuffleSplit` (seed 42) strictly by independent IKE_SA lifecycle identity:

| Split | Independent Sessions | Observations | `controlled_http` | `controlled_icmpv4` | `controlled_tcp_marker` |
|---|---|---|---|---|---|
| **Train (60%)** | 9 | 36 | 18 (9 GET + 9 POST) | 9 | 9 |
| **Validation (20%)** | 3 | 12 | 6 (3 GET + 3 POST) | 3 | 3 |
| **Held-Out Test (20%)** | 3 | 12 | 6 (3 GET + 3 POST) | 3 | 3 |
| **Total** | **15** | **60** | **30** (15 GET + 15 POST) | **15** | **15** |

- **Session Overlap:**
  - `train` ∩ `validation`: **0**
  - `train` ∩ `test`: **0**
  - `validation` ∩ `test`: **0**
- **IKE_SA Identity Overlap:**
  - `train` ∩ `validation`: **0**
  - `train` ∩ `test`: **0**
  - `validation` ∩ `test`: **0**
- **SPI Key Overlap:** Zero SPI overlap across session lifecycles.
- **Duplicate Vectors:** **0** exact duplicates and **0** near-duplicates (within `1e-6` relative tolerance) across the entire dataset.

### 3.2 Shortcut Analysis & Feature Distribution
An in-depth analysis of feature distributions across the three classes revealed:

1. **Packet Count:**
   - `controlled_icmpv4`: range `[6, 14]`, sampled values `{6, 10, 14}`.
   - `controlled_tcp_marker`: range `[12, 34]`, sampled values `{12, 16, 20, 26, 34}`.
   - `controlled_http`: range `[21, 74]`, sampled values `{21, 22, 32, 33, 43, 44, 54, 55, 64, 65, 72, 74}`.
   - *Finding:* While the continuous parameter ranges overlap (TCP 12..34 overlaps with ICMP 6..14 and HTTP 21..74), the discrete profile space sampled in this 60-observation campaign produced distinct packet count sets. Single-feature models must be tested to ensure the model does not exploit packet count as a shortcut.
2. **Byte Count:**
   - `controlled_http`: `3,028` to `10,036` bytes (mean: `6,224.5`).
   - `controlled_icmpv4`: `1,480` to `20,776` bytes (mean: `6,950.9`).
   - `controlled_tcp_marker`: `1,696` to `13,460` bytes (mean: `6,439.2`).
   - *Finding:* Heavily overlapping across all three classes.
3. **Flow Duration:**
   - `controlled_http`: `0.26` to `2.47` seconds (mean: `1.06`).
   - `controlled_icmpv4`: `0.41` to `4.98` seconds (mean: `2.20`).
   - `controlled_tcp_marker`: `0.70` to `5.29` seconds (mean: `2.49`).
   - *Finding:* Heavily overlapping across all three classes.
4. **Mean Packet Size:**
   - `controlled_http`: `134.2` to `162.9` bytes (mean: `144.2`).
   - `controlled_icmpv4`: `148.0` to `1,484.0` bytes (mean: `658.9`).
   - `controlled_tcp_marker`: `120.0` to `502.5` bytes (mean: `303.2`).
   - *Finding:* Substantial pairwise overlap across all classes.

### 3.3 Generalization Boundaries & Testbed Limits
- **Single Testbed Topology:** All observations were collected over one direct PC1↔PC2 Docker bridge network with StrongSwan 5.9.8.
- **Fixed Cryptographic Transforms:** All sessions ran AES-CBC-256 / HMAC-SHA2-256 for IKE and AES-GCM-16-256 (tunnel mode) for ESP.
- **Absence of Independent Campaign Validation:** Within-campaign session splitting ensures statistical session independence, but does **not** evaluate cross-campaign, multi-day, or multi-host generalization.

---

## 4. Baseline Eligibility Decision Gates

Each gate is evaluated based on recomputed evidence in [`vista-ml/reports/phase9_dataset_audit.json`](file:///c:/vista/vista-ml/reports/phase9_dataset_audit.json):

| Gate Identifier | Decision | Evidence Reference & Evaluation |
|---|---|---|
| `artifact_integrity` | **PASS** | 60/60 raw PCAPs readable with outer ESP/NAT-T frames; 60/60 packet CSVs verified; 60/60 session records verified; all SHA-256 hashes match. |
| `ground_truth_integrity` | **PASS** | 60/60 experiments verified with 100% endpoint agreement (ICMP reply counters, TCP payload hashes, HTTP 200 status codes with response body SHA-256 digests). |
| `label_integrity` | **PASS** | 3 canonical target classes defined in [`vista-target-label-schema-v1.json`](file:///c:/vista/vista-ml/schemas/vista-target-label-schema-v1.json); HTTP GET and POST maintained as metadata subtypes; zero label-bearing tokens in IDs or filenames. |
| `feature_integrity` | **PASS** | 18/18 flow features in [`vista-flow-v1.json`](file:///c:/vista/vista-ml/schemas/vista-flow-v1.json) reproduce exactly (60/60 matches); extractor operates strictly on outer IPv4 ESP metadata without inner payload inspection. |
| `leakage_controls` | **PASS** | Zero session, IKE_SA identity, or SPI overlap across splits; zero exact duplicate feature vectors; zero near-duplicate vectors within `1e-6` relative tolerance. |
| `class_coverage` | **PASS** | All 3 target classes are represented in train (18 HTTP, 9 ICMP, 9 TCP), validation (6 HTTP, 3 ICMP, 3 TCP), and test (6 HTTP, 3 ICMP, 3 TCP) splits. |
| `split_validity` | **PASS** | Deterministic nested `GroupShuffleSplit` (seed 42) partitions strictly by independent session/IKE_SA lifecycle identity (9/3/3 sessions; 36/12/12 observations). |
| `independent_campaign_validation` | **BLOCKED** | Dataset is drawn from a single 15-session campaign ([`76adc766-ef41-45f5-b677-1d950c7ff052`](file:///c:/vista/captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052)) on one direct PC1-PC2 testbed. Cross-campaign, multi-day, or multi-host validation has not been performed. |
| `baseline_eligibility` | **PASS** | All 7 prerequisite integrity and leakage gates pass. Dataset is authorized solely for an explicitly scoped exploratory baseline experiment specification; **NOT authorized for production promotion or operational deployment.** |

---

## 5. Baseline ML Experiment Design Specification

*(Specification only — execution deliberately withheld in Phase 9)*

### 5.1 Models to Evaluate
1. **Majority Class Baseline:**
   - Algorithm: `DummyClassifier(strategy='most_frequent')`
   - Target: Predicts `controlled_http` for all observations (the majority class, 50% of the dataset: 18/36 in train, 6/12 in val/test).
   - Expected Metrics: Accuracy: `0.500`, Macro-Precision: `0.167`, Macro-Recall: `0.333`, Macro-F1: `0.222`.
2. **Interpretable Baseline (Shallow Decision Tree):**
   - Algorithm: `DecisionTreeClassifier(max_depth=3, min_samples_leaf=2, random_state=26160)`
   - Purpose: Establish rule-based decision paths and inspect feature boundaries.
3. **Tabular Ensemble Classifier (Random Forest):**
   - Algorithm: `RandomForestClassifier(n_estimators=100, max_depth=5, min_samples_split=3, class_weight='balanced', random_state=26160)`
   - Purpose: Benchmark non-linear tabular feature classification on flow aggregates.

### 5.2 Split & Validation Protocol
- **Training Set (36 observations, 9 sessions):** Used strictly for model parameter fitting and class-weight computation.
- **Validation Set (12 observations, 3 sessions):** Used strictly for hyperparameter tuning and decision threshold calibration.
- **Held-Out Test Set (12 observations, 3 sessions):** Evaluated strictly once on the final selected model configuration. Never inspected during tuning.

### 5.3 Class Imbalance Strategy
- Training split proportions: 18 `controlled_http` (50%), 9 `controlled_icmpv4` (25%), 9 `controlled_tcp_marker` (25%).
- Class weights must be computed strictly from the training split:
  $$\text{weight}_c = \frac{N_{\text{train}}}{K \cdot N_c}$$
  - $\text{weight}_{\text{http}} = \frac{36}{3 \cdot 18} = 0.667$
  - $\text{weight}_{\text{icmp}} = \frac{36}{3 \cdot 9} = 1.333$
  - $\text{weight}_{\text{tcp}} = \frac{36}{3 \cdot 9} = 1.333$
- Validation and test labels must never be used to calculate weights.

### 5.4 Feature Ablations & Shortcut Verifications
- **Single-Feature Baselines:** Fit decision trees on each of the 18 features individually. Verify whether any single feature (such as `packet_count` or `flow_duration`) achieves perfect accuracy in isolation.
- **Leave-One-Out Ablation:** Systematically remove the top 3 features and recompute macro-F1 to measure reliance on individual metrics.
- **Subtype Generalization Audit:** For observations classified as `controlled_http`, evaluate whether performance differs significantly between `http_get` and `http_post` subtypes.

### 5.5 Evaluation Metrics & Deliverables
- **Metrics:** Accuracy, Macro Precision, Macro Recall, Macro-F1, per-class Precision/Recall/F1, and a full 3×3 Confusion Matrix.
- **Artifact Versioning:**
  - Candidate model metadata: `vista-ml/models/candidates/controlled_workload_baseline_v1/model_metadata.json`
  - Explicit flag: `validated_for_inference: false`
  - Candidate evaluation report: `vista-ml/reports/candidates/controlled_workload_baseline_v1/evaluation.json`

---

## 6. Recommendations for Future Independent Campaign Validation

To resolve the `BLOCKED` status on `independent_campaign_validation`:
1. **Multi-Campaign Protocol:** Execute a second campaign on a separate calendar day with a different pseudorandom seed.
2. **Network Variation:** Introduce varied synthetic latency (5–25ms) and packet jitter using Linux `tc netem` on the PC1/PC2 veth interfaces.
3. **Cross-Campaign Evaluation:** Train on Campaign A (e.g., `76adc766-ef41-45f5-b677-1d950c7ff052`), evaluate on Campaign B without retraining.
