# VISTA Phase 12 — Robustness Validation Under Changed Traffic Recipes

## SIH26160 · NTRO · Smart India Hackathon 2026

**Audit Date:** 2026-10-10
**Phase:** 12 — Robustness Validation Under Changed Traffic Recipes
**Verdict:** `ROBUSTNESS_SUPPORTED_WITHIN_TESTED_SCOPE`
**Candidate Model Status:** Frozen (`validated_for_inference = false`, `production_eligible = false`)
**Evaluation Target:** Optuna-Tuned Random Forest Candidate (`20261010T082308Z-6b8eb840`)

---

## 1. Executive Summary

Phase 11 established that the perfect held-out score ($1.0000$) achieved by the Phase 10 candidate classifier was not caused by data leakage or label contamination, but was heavily facilitated by recipe-specific feature correlations (e.g., discrete packet counts and uniform ICMP packet sizes) within the original Phase 8 training campaign (`76adc766-ef41-45f5-b677-1d950c7ff052`).

In Phase 12, we conducted an empirical robustness investigation by perturbing the traffic-generation recipes across all three supported workload classes (`controlled_icmpv4`, `controlled_tcp_marker`, and `controlled_http`) and capturing a live 15-session campaign with newly negotiated IPsec security associations.

### Key Results

1. **Robustness Confirmed Under Recipe Perturbations:**
   When evaluated against the newly captured campaign (`d645e930-010c-4f8a-a10a-fe7f22aef309`) containing 60 observations generated with randomized packet counts (4–12), inter-arrival intervals (0.15–0.75s), and payload sizes (48–1200 bytes), the frozen Phase 10 model achieved:
   - **Overall Accuracy:** **96.67%** (58/60 observations correct)
   - **Macro-F1 Score:** **0.9654**
   - **Wilson 95% Confidence Interval:** $[0.8864, 0.9908]$
   - **Cluster-Robust Session Bootstrap 95% Confidence Interval:** $[0.9167, 1.0000]$

2. **Error Pattern & Failure Mode:**
   - `controlled_icmpv4`: **15/15 correct** ($F_1 = 1.0000$)
   - `controlled_http`: **30/30 correct** ($F_1 = 0.9677$)
   - `controlled_tcp_marker`: **13/15 correct** ($F_1 = 0.9286$)
   - Exactly 2 TCP marker observations (`0cc87473-...` and `cd5cbe4e-...`) were misclassified as `controlled_http`. In both cases, larger TCP transfer bursts (14–22 packets, 1720–8532 bytes) crossed into the volume profile of small HTTP transactions, demonstrating that TCP marker classification is sensitive to payload volume scaling when relying solely on outer ESP metadata.

3. **Invariance Mechanisms:**
   The classifier does not collapse when packet counts change because it exploits fundamental protocol invariants:
   - `controlled_icmpv4`: Characterized by `direction_ratio = 0.500` (exact request-response symmetry) and `std_packet_size = 0.0` (identical payload per ping). These physical invariants held across all 15 ICMP observations despite count and rate variation.
   - `controlled_http`: Characterized by asymmetric bidirectional transfer, larger packet size variability, and multi-stage TCP handshakes/teardowns.

4. **Multiplexing Experiment Assessment:**
   We assessed whether background traffic can be multiplexed inside the same IPsec tunnel during flow collection. Under the `vista-flow-v1` flow definition (`50|172.20.0.2:0|172.20.0.3:0`), all inner flows are encrypted into an indistinguishable outer ESP flow. Concurrent traffic streams merge into a single aggregate flow record, destroying isolated flow ground truth. Disentangling multiplexed application streams requires either separate negotiated CHILD_SAs with dedicated SPIs or inner-payload access.

5. **Formal Verdict:**
   `ROBUSTNESS_SUPPORTED_WITHIN_TESTED_SCOPE`. The frozen model generalizes well beyond the discrete counts of its training recipe, but remains bounded to isolated controlled workloads under the existing direct PC1↔PC2 tunnel.

---

## 2. Baseline Preservation & Model Provenance

The baseline candidate model and feature schema remained completely frozen throughout Phase 12. No retraining, fine-tuning, threshold adjustment, or hyperparameter updates were performed.

| Property | Value | Verification Source |
|---|---|---|
| **Git Working Directory** | Clean working tree; no uncommitted core code changes | `git status` |
| **Model Artifact** | `models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib` | Persisted candidate directory |
| **Model SHA-256** | `de9d6334309ad1b286ce917c28de49833d4f186e2022fc3b03d53b2c2a826de8` | Verified via `hashlib.sha256` |
| **Feature Schema** | `vista-flow-v1.json` (18 flow features) | `vista-ml/schemas/vista-flow-v1.json` |
| **Target Label Schema** | `vista-target-label-schema-v1.json` (3 classes) | `vista-ml/schemas/vista-target-label-schema-v1.json` |
| **Inference Gates** | `validated_for_inference = false`, `production_eligible = false` | Preserved in metadata |
| **Historical Baseline (Phase 10 Test)** | Accuracy = 1.0000, Macro-F1 = 1.0000 (12 observations) | `phase10_baseline_report.json` |
| **Historical Cross-Campaign (Phase 11)** | Accuracy = 0.9667 (58/60 correct across Phase 5 & Phase 7) | `phase11_leakage_audit_report.json` |

---

## 3. Collection Pipeline Audit & Perturbation Implementation

### Pipeline Inspection

Inspection of [`scripts/run_collection_campaign.py`](file:///c:/vista/scripts/run_collection_campaign.py) revealed:
- Standard profile spaces (`PROFILE_SPACE`, `HTTP_GET_PROFILE_SPACE`, `HTTP_POST_PROFILE_SPACE`) used fixed count distributions:
  - ICMP & TCP: packet counts $\in \{3, 5, 7, 10\}$, intervals $\in \{0.2, 0.4, 0.6, 0.8\}$, payloads $\in \{32, 64, 128, 256, 512, 1024, 1400\}$.
  - HTTP: small/medium/large payload distributions with fixed repetition counts (1 to 6).
- The CLI lacked an explicit switch to decouple the collection runner from these standard schedules without breaking legacy reproducibility.

### Perturbation Implementation

To enable systematic robustness testing, we implemented a non-breaking, backward-compatible `--recipe-mode [standard|varied]` option in [`scripts/run_collection_campaign.py`](file:///c:/vista/scripts/run_collection_campaign.py):
- **`VARIED_PROFILE_SPACE`:**
  - Packet Counts: $\in \{4, 6, 8, 12\}$ (disjoint from $\{3, 5, 7, 10\}$)
  - Intervals: $\in \{0.15, 0.35, 0.55, 0.75\}$ seconds (disjoint from standard $\{0.2, 0.4, 0.6, 0.8\}$)
  - Payloads: $\in \{48, 96, 192, 384, 768, 1200\}$ bytes
- **`VARIED_HTTP_GET_PROFILE_SPACE`:**
  - Repetition counts: $\in \{2, 4, 7\}$
  - Concurrency: $\in \{1, 2\}$
  - Payload profiles: `tiny_varied` (128 bytes), `medium_varied` (2048 bytes), `large_varied` (8192 bytes)
- **`VARIED_HTTP_POST_PROFILE_SPACE`:**
  - Repetition counts: $\in \{2, 5, 8\}$
  - Concurrency: $\in \{1, 2\}$
  - Payload profiles: `small_varied` (512 bytes), `medium_varied` (4096 bytes), `large_varied` (16384 bytes)
- **Controlled Fixed Parameters:**
  - IPsec tunnel topology: Direct PC1 (`172.20.0.2`) to PC2 (`172.20.0.3`) via StrongSwan 5.9.8.
  - Network MTU: Preserved standard 1500 bytes to avoid tunnel fragmentation.
  - Directional endpoint bindings: PC1 as traffic initiator/client, PC2 as target/server.

---

## 4. Live Campaign Collection & Provenance

We executed a live collection campaign against the running testbed:

```powershell
python scripts/run_collection_campaign.py --sessions 15 --seed 26162 --workload-set unified --recipe-mode varied
```

### Campaign Provenance Details

- **Campaign ID:** `d645e930-010c-4f8a-a10a-fe7f22aef309`
- **Timestamp:** `2026-10-10T12:00:15Z` to `2026-10-10T12:10:47Z` (Duration: 632 seconds)
- **Seed:** `26162`
- **Total Sessions:** 15 independent IKE_SAs (fresh IKE and CHILD SA re-established per session)
- **Total Observations:** 60 captured flows (15 ICMP, 15 TCP marker, 30 HTTP)
- **Execution Quality:** 60/60 PASS (0 failed, 0 quarantined)
- **Endpoint Agreement:** 100% (60/60 matched endpoint logs, payload hashes, and HTTP status codes)
- **Outer ESP Verification:** 100% of PCAPs confirmed containing valid outer ESP encapsulation.
- **Dataset Preparation:** Ran `prepare_experiment_dataset.py` with 9/3/3 session split; generated `dataset.parquet` (60 rows, 18 features, status `READY_FOR_REVIEW`).

---

## 5. Quantitative Robustness Evaluation

We evaluated the frozen Phase 10 model against the new campaign, comparing it with baseline and historical campaigns:

### Campaign Performance Comparison

| Campaign | Description | Samples | Accuracy | Macro-F1 | Wilson 95% CI | Bootstrap 95% CI |
|---|---|---|---|---|---|---|
| **Phase 8 (Train)** | Standard recipe (seed 26160) | 36 | 1.0000 | 1.0000 | $[0.9036, 1.0000]$ | $[1.0000, 1.0000]$ |
| **Phase 8 (Test)** | Standard recipe held-out split | 12 | 1.0000 | 1.0000 | $[0.7575, 1.0000]$ | $[1.0000, 1.0000]$ |
| **Phase 5** | Historical ICMP & TCP marker | 30 | 0.9333 | 0.9333 | $[0.8037, 0.9850]$ | $[0.8667, 1.0000]$ |
| **Phase 7** | Historical HTTP GET & POST | 30 | 1.0000 | 1.0000 | $[0.8865, 1.0000]$ | $[1.0000, 1.0000]$ |
| **Phases 5+7 Combined** | Historical independent suite | 60 | 0.9667 | 0.9654 | $[0.8864, 0.9908]$ | $[0.9167, 1.0000]$ |
| **Phase 12 (New Campaign)** | **Varied recipe (`d645e930...`)** | **60** | **0.9667** | **0.9654** | **$[0.8864, 0.9908]$** | **$[0.9167, 1.0000]$** |

### Per-Class Performance on Phase 12 Varied Campaign

| Class | Support | Precision | Recall | F1-Score | Status |
|---|---|---|---|---|---|
| `controlled_icmpv4` | 15 | 1.0000 | 1.0000 | **1.0000** | Perfect separation |
| `controlled_http` | 30 | 0.9375 | 1.0000 | **0.9677** | High recall, slight precision dilution |
| `controlled_tcp_marker` | 15 | 1.0000 | 0.8667 | **0.9286** | 2 misclassified as HTTP |
| **Macro Average** | **60** | **0.9792** | **0.9556** | **0.9654** | **Robust generalization** |

### Confusion Matrix (Phase 12 Varied Campaign)

```text
Actual \ Predicted       controlled_icmpv4  controlled_tcp_marker  controlled_http
controlled_icmpv4               15                     0                   0
controlled_tcp_marker            0                    13                   2
controlled_http                  0                     0                  30
```

### Analysis of Misclassified Samples

Exactly two observations were misclassified:

1. **Observation `0cc87473-bcae-4f7f-827c-9b8e21727c95` (Session `25fe1f9c-...`):**
   - True Label: `controlled_tcp_marker`
   - Predicted: `controlled_http`
   - Key Features: `packet_count = 22`, `byte_count = 8532`, `mean_packet_size = 387.82`, `forward_bytes = 4692`, `backward_bytes = 3840`, `duration_ms = 478.4`
   - Diagnostic Cause: A high payload size (1200 bytes) and 12-message TCP marker transfer produced 22 ESP packets totaling 8,532 bytes. The random forest decision boundaries associate multi-kilobyte bidirectional volume with `controlled_http`.

2. **Observation `cd5cbe4e-76e9-40a2-94b5-6f103b41793d` (Session `2a6ea0b6-...`):**
   - True Label: `controlled_tcp_marker`
   - Predicted: `controlled_http`
   - Key Features: `packet_count = 14`, `byte_count = 1720`, `mean_packet_size = 122.86`, `duration_ms = 111.4`
   - Diagnostic Cause: Fast 111ms transfer with 14 packets and 1,720 bytes closely matched the profile of a tiny single HTTP GET request.

---

## 6. Traffic Feature Distribution Shifts

The varied recipe induced substantial distribution shifts compared to the baseline Phase 8 training set:

| Feature | Baseline Mean | Varied Mean | Relative Shift | Physical Explanation |
|---|---|---|---|---|
| `packet_count` | 14.71 pkts | 18.25 pkts | **+24.0%** | Varied recipe included higher counts (up to 12 msgs/8 HTTP reps) |
| `mean_packet_size` | 312.60 B | 226.11 B | **-27.7%** | Inclusion of smaller payload profiles (48B, 128B) |
| `max_packet_size` | 543.90 B | 433.62 B | **-20.3%** | Lower MTU-capped packet limits in varied HTTP profiles |
| `duration_ms` | 2,752.5 ms | 2,829.4 ms | **+2.8%** | Perturbed intervals balanced out over longer counts |
| `direction_ratio` | 0.540 | 0.540 | **-0.1%** | Symmetric request-reply behavior preserved across protocols |
| `std_packet_size` (ICMP) | 0.00 B | 0.00 B | **0.0%** | **Strict physical invariant:** Ping payloads remain constant |

### Why Did the Model Not Collapse?

Despite a 24% shift in packet count and a 28% shift in mean packet size, accuracy remained at 96.67%. This occurs because:
1. **ICMP Invariance:** Ping traffic universally exhibits `std_packet_size = 0.0` and `direction_ratio = 0.500`. No matter how many pings are sent or at what interval, these features cleanly isolate ICMP.
2. **HTTP Multi-Packet Asymmetry:** HTTP workloads retain distinct client-server asymmetry (small request, larger response, multiple TCP handshake/FIN/ACK packets).
3. **Redundancy:** The approved 18-feature schema provides redundant directional and statistical features that prevent single-feature reliance.

---

## 7. Methodological Verification & Uncertainty Calculations

### Within-Session Permutation Test

In Phase 11, a block permutation test was performed across entire sessions. In Phase 12, we conducted a rigorous **Within-Session Permutation Test** to preserve the exact marginal class distributions within each session:
- Within each of the 9 training sessions (which each contain 1 ICMP, 1 TCP marker, and 2 HTTP flows), the labels were randomly permuted among the 4 flows.
- Over 100 permutations:
  - Real Model Macro-F1: **0.9692**
  - Permuted Null Mean Macro-F1: **0.3065** ($\sigma = 0.0895$, Range: $0.1451$ to $0.6147$)
  - Empirical $p$-value: **$p = 0.0099$**
- **Conclusion:** Rejects the hypothesis that classification performance is driven by session-level chance or marginal class balance artifacts ($p < 0.01$).

### Cluster-Robust Session Bootstrap

Because observations generated within the same IKE_SA session share cryptographic state and temporal conditions, standard i.i.d. confidence intervals underestimate variance.
- We implemented a **Cluster-Robust Session Bootstrap** (1,000 resamples of intact sessions with replacement):
  - 95% Confidence Interval for Accuracy: $[0.9167, 1.0000]$
  - 95% Confidence Interval for Macro-F1: $[0.9113, 1.0000]$
- The lower bound confirms that even under session-clustered sampling variance, model accuracy remains above 91.6%.

---

## 8. Multiplexed Traffic Feasibility Assessment

As required by the Phase 12 scope, we evaluated the feasibility of capturing target flows while background traffic traverses the same tunnel.

### Architectural Finding: Blocked Under Single ESP SA

1. **Outer-ESP Flow Encapsulation:**
   Under the `vista-flow-v1` schema, flows are identified by:
   $$\text{Flow Key} = (\text{protocol}=50, \text{src}=\text{172.20.0.2:0}, \text{dst}=\text{172.20.0.3:0})$$
   Because inner IP addresses, transport protocols (TCP/UDP/ICMP), and port numbers are fully encrypted within the ESP payload, all packets traversing the direct PC1↔PC2 tunnel share the exact same outer flow identifier.
2. **Feature Contamination:**
   If background traffic (e.g., continuous ping or background file transfer) is introduced while a target workload runs, both streams merge into a single aggregate outer ESP flow in the packet table. The extracted features (`packet_count`, `byte_count`, `mean_inter_arrival_time`, `std_packet_size`) aggregate both activities, corrupting ground truth and invalidating the 1-flow-per-workload contract.
3. **Disentanglement Constraint:**
   Without inner plaintext access or per-workload CHILD_SAs (each with a dedicated SPI), outer ESP traffic multiplexing cannot be separated. Therefore, multiplexed experiments under a single tunnel cannot support isolated-workload classification ground truth.

---

## 9. Operational Boundaries & Production Safeguards

Passing this robustness validation milestone does **not** make the candidate model ready for production deployment. The following operational boundaries remain strictly enforced:

1. **No Production Deployment:**
   - `validated_for_inference = false`
   - `production_eligible = false`
   - `experimental = true`
2. **Controlled Workload Scope Only:**
   The model classifies three specific benign workload generators (`controlled_icmpv4`, `controlled_tcp_marker`, `controlled_http`) operating between two known container endpoints.
3. **No Attack Detection:**
   The model does not detect network intrusions, exfiltration attacks, or malicious VPN tunnels.
4. **No Arbitrary Application Classification:**
   The model cannot distinguish arbitrary real-world Internet protocols (e.g., VoIP, video streaming, SMTP, BitTorrent) traversing an enterprise VPN.
5. **No Encrypted Payload Visibility:**
   Classification relies entirely on outer-ESP packet timing, count, and size distributions. The inner plaintext remains cryptographically secure.

---

## 10. Final Deliverables & Artifact References

- **Machine-Readable Report:** [`vista-ml/reports/phase12_robustness_report.json`](file:///c:/vista/vista-ml/reports/phase12_robustness_report.json)
- **New Campaign Manifest:** [`captures/strongswan/campaigns/d645e930-010c-4f8a-a10a-fe7f22aef309/manifest.json`](file:///c:/vista/captures/strongswan/campaigns/d645e930-010c-4f8a-a10a-fe7f22aef309/manifest.json)
- **Prepared Dataset:** [`captures/strongswan/datasets/d645e930-010c-4f8a-a10a-fe7f22aef309/dataset.parquet`](file:///c:/vista/captures/strongswan/datasets/d645e930-010c-4f8a-a10a-fe7f22aef309/dataset.parquet)
- **Robustness Evaluation Script:** [`vista-ml/scripts/evaluate_robustness_campaign.py`](file:///c:/vista/vista-ml/scripts/evaluate_robustness_campaign.py)
- **Regression Tests:** [`vista-ml/tests/test_phase12_robustness.py`](file:///c:/vista/vista-ml/tests/test_phase12_robustness.py) (5/5 passed)
- **Updated Implementation Gaps:** [`docs/IMPLEMENTATION_GAPS.md`](file:///c:/vista/docs/IMPLEMENTATION_GAPS.md)

---

## Final Verdict

$$\mathbf{ROBUSTNESS\_SUPPORTED\_WITHIN\_TESTED\_SCOPE}$$

The frozen Phase 10 candidate model demonstrates genuine robustness against traffic-generation recipe perturbations within its controlled domain, achieving 96.67% accuracy across 60 new independent observations with substantial distribution shifts. However, operational inference remains blocked pending realistic application diversity and multi-flow tunnel handling.
