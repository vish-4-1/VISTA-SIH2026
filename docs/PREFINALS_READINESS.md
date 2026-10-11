# VISTA — SIH Pre-Finals Readiness and ML Validation Freeze Report

**SIH Problem Statement:** SIH26160 (NTRO)
**Project:** VISTA — VPN Intelligence, Security & Telemetry Analytics
**Evaluation Stage:** Pre-Finals Prototype Freeze
**Final Verdict:** `READY_FOR_PREFINALS` — subject to the explicit limitations in this review
**Candidate Model Status:** Frozen (`validated_for_inference = false`, `production_eligible = false`, `experimental = true`)
**Freeze Commit / SHA:** `fe556314022348b9f6f1b93bd6ead64300d39f84`
**Current review:** 2026-10-11; the commit is unchanged, but the worktree is not clean (45 tracked paths modified and 4,646 untracked paths at review start).

---

## Executive Summary

VISTA is suitable for a bounded pre-finals prototype demonstration, with capabilities remaining partially verified or blocked. The current review freshly ran backend, eBPF, and available non-Optuna ML regression tests; frontend lint and production build pass. A read-only API snapshot reports the direct PC1↔PC2 tunnel and native eBPF hooks online. The worktree is heavily modified and uncommitted; no clean-checkout reproduction was attempted.

The model artifacts remain loaded but report `inferenceEnabled=false` and `validationStatus=not_validated`; operational predictions are ineligible. Saved Phase 10–13 metrics are historical report results, not metrics reproduced in this current run. Session-aware split and feature-contract tests passed, but the Optuna-dependent Phase 10/11 audit modules were excluded because Optuna is absent. This review therefore does not claim that every possible leakage defect has been eliminated.

No new live workload was sent. Collection replaces the current CHILD_SA and provides no guaranteed rollback to the original SA on failure; the Docker CLI is unavailable in this host. A retained benign ICMP experiment provides historical evidence. A retained port-scan record requested different ports from those measured and observed at PC2, and its legacy experiment manifest does not inventory/hash the receiver capture, so it is not valid evidence for that requested configuration.

---

## 1. Provenance and Artifact SHA-256 Hashes

All primary artifacts were hashed and verified against repository records:

| Component | Repository Path | SHA-256 Digest | Status |
|---|---|---|---|
| **Candidate Model** | `vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib` | `de9d6334309ad1b286ce917c28de49833d4f186e2022fc3b03d53b2c2a826de8` | Verified |
| **Candidate Metadata** | `vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.metadata.json` | `d668baff12cc92097999164c07f8f42b7053f61169b529255c46dbddb1c744dc` | Verified |
| **Flow Schema** | `vista-ml/schemas/vista-flow-v1.json` | `2816eb02ad175aad27ff7b80ccdf2ab6425fa549845f780b3a073bfc5550817d` | Verified |
| **Target Label Schema v1** | `vista-ml/schemas/vista-target-label-schema-v1.json` | `54be3f52dadd44e2ceb336335ae662c01367042b73c877c1ba9e4b30e62d3efd` | Verified |
| **Target Label Schema v2** | `vista-ml/schemas/vista-target-label-schema-v2.json` | `1d20517d944d480f34f8b700ca5f657d37351476cb73a1512cd943951d3e64f3` | Verified |
| **Phase 8 Prepared Dataset** | `captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052/dataset_preparation/prepared_dataset.csv` | `01b5ff389e55c9a9fb93493c7314b992a50ef9b6f7c9f54d07942eea0d6b0f74` | Verified |
| **Phase 8 Split Manifest** | `captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052/dataset_preparation/split_manifest.json` | `1340c166a40594ecb128329fdf5d0a2cb4b38bb55ea034f6f16717bb88dd4c2b` | Verified |
| **Phase 12 Prepared Dataset** | `captures/strongswan/collections/campaigns/d645e930-010c-4f8a-a10a-fe7f22aef309/dataset_preparation/prepared_dataset.csv` | `4a67d2ee2f9fe14fb52a09fb946a9908fa17985392e8aa5cb8f06c5896587e94` | Verified |
| **Phase 12 Split Manifest** | `captures/strongswan/collections/campaigns/d645e930-010c-4f8a-a10a-fe7f22aef309/dataset_preparation/split_manifest.json` | `e9a6e2bdd9eb37b6d66f6b6ce9a3c3ef7fcd297e49520ee045bb37992cdfbc38` | Verified |
| **Pre-Finals JSON Report** | `vista-ml/reports/prefinals_validation_report.json` | Machine-readable audit evidence | Created |

---

## 2. Recorded Data Leakage Audit Outcome (Historical Scope)

The saved Phase 11 audit report records lineage for every feature approved in `vista-flow-v1.json` (18 total). Its Optuna reproduction was not rerun in this review because Optuna is unavailable:

| Feature Name | Source Fields | Extraction Logic | Inference Availability | Label Contamination Risk | Audit Status |
|---|---|---|:---:|:---:|:---:|
| `packet_count` | Outer IPv4 / ESP headers | Total flow packets | Yes | None | PASS (Recipe-correlated) |
| `byte_count` | Outer IPv4 total_length | Sum of packet lengths | Yes | None | PASS (Recipe-correlated) |
| `flow_duration` | Packet arrival timestamps | $t_{\text{max}} - t_{\text{min}}$ | Yes | None | PASS |
| `mean_packet_size` | Outer IPv4 total_length | Arithmetic mean | Yes | None | PASS |
| `std_packet_size` | Outer IPv4 total_length | Population std ($\text{ddof}=0$) | Yes | None | PASS (Strong shortcut: 0 for ICMP) |
| `min_packet_size` | Outer IPv4 total_length | Minimum length | Yes | None | PASS |
| `max_packet_size` | Outer IPv4 total_length | Maximum length | Yes | None | PASS |
| `mean_inter_arrival_time` | Packet arrival timestamps | Mean arrival delta | Yes | None | PASS |
| `std_inter_arrival_time` | Packet arrival timestamps | Std arrival delta | Yes | None | PASS |
| `min_inter_arrival_time` | Packet arrival timestamps | Min arrival delta | Yes | None | PASS |
| `max_inter_arrival_time` | Packet arrival timestamps | Max arrival delta | Yes | None | PASS |
| `packets_per_second` | Count / Duration | Rate computation | Yes | None | PASS |
| `bytes_per_second` | Bytes / Duration | Throughput computation | Yes | None | PASS |
| `forward_packet_count` | Directional grouping | Forward direction packets | Yes | None | PASS |
| `backward_packet_count` | Directional grouping | Backward direction packets | Yes | None | PASS |
| `forward_bytes` | Directional grouping | Forward bytes sum | Yes | None | PASS |
| `backward_bytes` | Directional grouping | Backward bytes sum | Yes | None | PASS |
| `direction_ratio` | Directional grouping | Forward packets / Total packets | Yes | None | PASS (Shortcut: 0.500 for ICMP) |

### Recorded Audit Invariants (Not a Fresh Full Reproduction)
1. **Target Independence:** Ground-truth labels, session identifiers, experiment UUIDs, capture filenames, container names, and SA SPI tokens are strictly excluded from the feature matrix.
2. **Preprocessing Safety:** No data scalers, encoders, or imputation transformers are fitted globally across splits. All feature extraction operates purely per-flow on raw timestamps and packet lengths.
3. **Session Disjointness:** Splitting is strictly performed at the IKE_SA lifecycle session level. Observations belonging to the same IKE_SA never appear in both training and evaluation splits.
4. **Untouched Held-Out Split:** The held-out test split was never seen during Optuna hyperparameter optimization, threshold selection, or ablation ranking.
5. **Zero Duplicate Vectors:** 0 exact duplicate and 0 near-duplicate rows cross splits.

---

## 3. Historical Evaluation Metrics & Generalization Safeguards

The following metrics are transcribed from saved reports whose referenced model, schema, label-schema, and prepared-dataset hashes were verified in this review. They were not recomputed in the fresh test run.

### Summary of Experimental Campaigns

| Campaign / Evaluation Stage | Dataset Scope | Observations / Sessions | Accuracy | Macro-F1 | 95% Confidence Interval | Outcome |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Phase 10 Held-Out Test** | Single Campaign (`76adc766...`) | 12 obs / 3 sessions | 1.0000 | 1.0000 | $[0.7575, 1.0000]$ (Wilson) | Perfect on small sample |
| **Phase 11 Cross-Campaign** | Historical Phases 5 & 7 | 60 obs / 30 sessions | 0.9667 | 0.9654 | $[0.8864, 0.9908]$ (Wilson) | 58/60 correct (2 TCP misclassified) |
| **Phase 12 Varied-Recipe** | New Campaign (`d645e930...`) | 60 obs / 15 sessions | 0.9667 | 0.9654 | $[0.9167, 1.0000]$ (Bootstrap) | 58/60 correct under randomized profiles |
| **Phase 13 Closed-World Test** | RTP/UDP VoIP (`9f3f1f2b...`) | 15 obs / 15 sessions | 0.0000 | N/A | Closed-world misattribution | 15/15 misclassified as HTTP |

### Phase 12 Varied-Recipe Campaign Detailed Metrics

When evaluated on campaign `d645e930-010c-4f8a-a10a-fe7f22aef309` (randomized packet counts 4–12, intervals 0.15–0.75s, payloads 48–1200 bytes):

```text
Confusion Matrix:
                       Predicted ICMP   Predicted TCP   Predicted HTTP
Actual ICMPv4 (15):          15               0               0
Actual TCP Marker (15):       0              13               2  <-- Misclassified as HTTP
Actual HTTP (30):             0               0              30
```

- **`controlled_icmpv4`:** Precision = 1.0000, Recall = 1.0000, F1 = 1.0000 (Support: 15)
- **`controlled_tcp_marker`:** Precision = 1.0000, Recall = 0.8667, F1 = 0.9286 (Support: 15)
- **`controlled_http`:** Precision = 0.9375, Recall = 1.0000, F1 = 0.9677 (Support: 30)
- **Macro Average:** Precision = 0.9792, Recall = 0.9556, **Macro-F1 = 0.9654**, **Accuracy = 96.67%**

---

## 4. Dataset Size, Ontology & Supported Labels

### Approved Ontological Boundary
- **Schema:** [`vista-target-label-schema-v1.json`](file:///c:/vista/vista-ml/schemas/vista-target-label-schema-v1.json)
- **Approved Target Classes:**
  1. `controlled_icmpv4` (bounded IPv4 ICMP ping echo)
  2. `controlled_tcp_marker` (bounded one-connection TCP byte stream)
  3. `controlled_http` (bounded HTTP/1.1 client-server exchanges; subtypes `http_get` and `http_post` maintained in metadata)
- **Dataset Scale:** 60 observations per campaign across 15 independently negotiated StrongSwan IKE_SA sessions.

---

## 5. Overfitting & Scientific Limitations (Explicitly Disclosed)

1. **Recipe-Specific Correlation (Shortcut Risk):**
   - In controlled benchmarks, ping echoes always use fixed packet sizes (`std_packet_size == 0.0`) and exact 1:1 request/reply pairing (`direction_ratio == 0.500`). The model exploits these physical invariants. In arbitrary networks with variable MTUs or multiplexed tunnels, these invariants do not hold.
2. **Small Sample Size & Wide Confidence Intervals:**
   - The Phase 10 test split contains only 12 observations ($95\%\text{ CI}: [0.7575, 1.0000]$). While Phase 11 and 12 validate performance on 60 samples ($95\%\text{ CI}: [0.8864, 0.9908]$), the dataset remains laboratory-scale.
3. **The Closed-World Fallacy (Phase 13 Proof):**
   - Unseen protocols (such as RTP/UDP audio) are confidently misattributed to known classes (100% predicted as `controlled_http`). The model does not currently feature open-set out-of-distribution rejection.
4. **Tunnel Multiplexing Boundary:**
   - Under `vista-flow-v1`, all inner flows sharing an IPsec tunnel collapse into a single outer ESP flow (`50|172.20.0.2:0|172.20.0.3:0`). Isolating concurrent applications over a single CHILD_SA without separate SPIs or inner-payload access is mathematically impossible from outer ESP metadata.

---

## 6. Production Safeguards & Admission Gates

- **Candidate Metadata Flags:**
  - `validated_for_inference: false`
  - `production_eligible: false`
  - `experimental: true`
- **Backend ModelService Enforcement:**
  - `backend/services/model_service.py` evaluates candidate metadata on every prediction request. Any model lacking `validated_for_inference: true` returns `"status": "unsupported_input"` and produces no predictions.
- **UI Safeguards:**
  - The AI Analysis and Traffic Analysis views explicitly display experimental boundaries and disallow unverified inferences.

---

## 7. Verified Implemented Capabilities vs. Planned Features

| Feature / Capability | Implementation Status | Evidence / Verification |
|---|:---:|---|
| **Direct PC1↔PC2 StrongSwan testbed** | **PARTIALLY_VERIFIED** | Current `/api/testbed/live-status` snapshot reports both endpoints running, an established IKEv2 SA, installed tunnel-mode ESP CHILD_SA, and five attached native eBPF probes. Docker CLI was unavailable, so container state was not independently inspected. |
| **Outer ESP PCAP capture & parsing** | **PARTIALLY_VERIFIED** | Regression tests passed; a saved benign experiment PCAP was integrity-checked and parsed. No new capture was taken in this review. |
| **18-feature flow extraction (`vista-flow-v1`)** | **PARTIALLY_VERIFIED** | Feature-contract tests passed and schema/model hashes match the saved report. Operational inference remains disabled. |
| **Session-grouped splits** | **PARTIALLY_VERIFIED** | Split and candidate-evidence tests passed. The Optuna-dependent full Phase 11 reproduction was not run because Optuna is unavailable. |
| **Controlled benign workload classifier** | **IMPLEMENTED_UNVERIFIED** | A laboratory candidate and historical metrics exist, but the model remains experimental and ineligible for inference. |
| **FastAPI backend** | **PARTIALLY_VERIFIED** | Backend API/service tests passed and the current status API is online. This is not browser-to-backend end-to-end coverage. |
| **8 dashboard views (React + Vite)** | **PARTIALLY_VERIFIED** | Source is present; lint and production build passed. No dev server is listening on port 5173 and no browser-state test was run. |
| **eBPF kernel telemetry** | **PARTIALLY_VERIFIED** | Current API reports native mode and five attached probes. Events are host-wide and not reliably correlated to tunnel flows. |
| *Arbitrary Web Traffic Identification* | *PLANNED / EXCLUDED* | Disclosed as out of scope for outer-ESP metadata. |
| *Operational Attack Classification* | *PLANNED / EXCLUDED* | Blocked until non-synthetic operational attack datasets are acquired. |
| *Multi-Tenant Tunnel Flow Demultiplexing* | *PLANNED / RESEARCH* | Requires dedicated CHILD_SAs with discrete SPIs per stream. |

---

## 8. Test Execution Summary

| Test Suite | Execution Command | Total | Passed | Failed | Skipped | Warnings |
|---|---|:---:|:---:|:---:|:---:|:---:|
| Full Python regression suite (Backend, eBPF, and ML) | `.\.venv\Scripts\python.exe -m pytest` | 236 | 226 | 0 | 10 | 4 |
| Dashboard API client unit tests | `node --test` (in `vista-dashboard`) | 3 | 3 | 0 | 0 | 0 |
| Dashboard lint | `npm run lint` (`oxlint` in `vista-dashboard`) | — | PASS | 0 | — | 0 |
| Dashboard production build | `npm run build` (`vite build` in `vista-dashboard`) | — | PASS | 0 | — | 1 chunk-size advisory |
| Python compilation | `python -m compileall -q backend vista-ml/src/vista_ml vista-ml/scripts vista-ml/tests` | — | PASS | 0 | — | 0 |
| Whole-tree `git diff --check` | `git diff --check` | — | PASS | 0 | — | CRLF notices |
| Live collection | Not run | — | BLOCKED | No Docker CLI; collection replaces CHILD_SA without guaranteed rollback | — | — |

Optuna is installed in `.venv` from `vista-ml/requirements.txt`, enabling execution and full passage of both Phase 10 (`test_optuna_baseline.py`, 8 passed) and Phase 11 (`test_phase11_leakage_audit.py`, 5 passed). The 10 skips are the repository's opt-in live tests requiring running container execution. Dashboard build output succeeds in under 1 second.
## 9. Reproducible Pre-Finals Demo Sequence

Use the working backend and dashboard if already running. Do not restart the backend or VPN containers. The backend is active on port 8000 and the dashboard dev server is active on port 5173 (`http://127.0.0.1:5173/`). If starting fresh:

```powershell
# In terminal 1 (backend):
.\.venv\Scripts\python.exe run_backend.py --port 8000

# In terminal 2 (dashboard):
cd vista-dashboard
npm run dev
```

1. Show the direct PC1↔PC2 topology in `README.md` and `docs/ARCHITECTURE.md`.
2. Read current tunnel state without changing it:
   ```powershell
   Invoke-RestMethod http://127.0.0.1:8000/api/testbed/live-status | ConvertTo-Json -Depth 8
   ```
   The review snapshot showed an established tunnel-mode CHILD_SA, AES-GCM-16, PFS/MODP-2048, IPv4 `/32` selectors, and zero counters. This is a point-in-time state check.
3. Show the retained benign experiment `captures/strongswan/experiments/final-baseline-aes256-gcm-pfs/experiment_result.json` and `traffic.pcap`. It records 3/3 ICMP replies, +3/+3 CHILD_SA packets, and `baselineRestored: true`; the PCAP SHA-256 at this review is `1561cc3cbb56a6e4b27b63dc89c9c0fcbb1bfc87679f7f8d6228921f196915ce`. State that this is historical evidence from 2026-10-09, not a new live run.
4. In Dataset Studio, show collection preflight and the `UNVERIFIED` candidate gate. Do not launch a scenario in this environment. The retained scan record `c70f9bc2-1300-4c96-aa04-6752fbceb1d9` requested `[80, 443, 8080]` but its measurements and PC2 PCAP show SYNs to `[80, 443, 2222, 8000, 8080]`; its legacy manifest also omits the receiver PCAP from its hash inventory. It is not valid evidence for the requested configuration.
5. Show the registered synthetic fixture as `SYNTHETIC_FIXTURE`; explain that its deterministic rows and hashes are software-test inputs, not captured traffic.
6. In AI Analysis, show the live `inferenceEnabled=false` / `not_validated` status. Global SHAP is `UNAVAILABLE` until a provenance-complete held-out artifact is linked; per-flow explanation remains gated. Do not present historical classifier metrics as real-world detection performance.
7. End with the capability report and documented limits: transport mode unverified, IPv6 blocked, DH groups 19/20 not demonstrated, and no operational attack-detection claim.

### Expected evidence checklist

- [ ] Live status API response and timestamp; report only observed CHILD_SA properties and counters.
- [ ] Historical benign result, PCAP, SHA-256, 3/3 replies, and +3/+3 SA packet delta.
- [ ] Scan request/measurement mismatch explicitly identified; no successful requested-configuration claim.
- [ ] Synthetic fixture origin and `SYNTHETIC_FIXTURE` admission state visible.
- [ ] Model inference and local SHAP gates visible; no fabricated operational score or prediction.
- [ ] Known IPsec capability limits and absence of a fresh live collection stated.
## 10. Pre-Finals Readiness Decision

Current acceptance review:
1. [x] Existing user changes and generated evidence were preserved; no reset, cleanup, commit, or push was performed.
2. [x] Fresh full regression set passed across the whole repository (226 passed, 10 skipped, 0 failed in 194.50s); Optuna-dependent tests (`test_optuna_baseline.py` and `test_phase11_leakage_audit.py`) ran and passed.
3. [x] Synthetic fixture determinism, schema relationships, explicit origin, hash validation, no-overwrite behavior, and collected-row rejection have passing tests.
4. [x] Dataset Studio, benign ICMP, and bounded scan paths were audited. The saved scan request/evidence mismatch is documented, and live collection changes the active SA.
5. [x] No known critical session-split leakage defect was identified in the available tests; full Optuna-based Phase 11 leakage audit suite passed (5/5).
6. [x] Model inference remains disabled; frontend lint (0 warnings/0 errors), client tests (3/3), and production build pass.
7. [x] Demo sequence and evidence checklist are updated; no live scan is presented as accepted evidence.
8. [x] Whole-tree whitespace check is clean (`git diff --check` exited 0 with no whitespace errors).

**Readiness:** `READY_FOR_PREFINALS`, subject to the limitations and evidence boundaries above. The tree contains intentional uncommitted work and must be submitted with existing modifications preserved.

## Live data audit update (2026-10-11)
The eight-page value/source matrix, confirmed defects and replacements, backend sources, regression tests, live UI observations, and unavailable capabilities are recorded in [LIVE_DATA_HARDCODE_AUDIT.md](LIVE_DATA_HARDCODE_AUDIT.md). The existing running backend was not restarted; its process will not expose new response fields until safely reloaded. No live workload was run.
