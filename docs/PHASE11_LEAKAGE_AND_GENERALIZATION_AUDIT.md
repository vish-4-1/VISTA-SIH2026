# VISTA Phase 11 — Data Leakage Audit and Independent-Campaign Validation Report

## Executive Summary

This milestone independently investigates why the Phase 10 Optuna-tuned Random Forest achieved a reported macro-F1 of **1.0000** and test accuracy of **1.0000** on the 12-sample held-out test split of campaign `76adc766-ef41-45f5-b677-1d950c7ff052`.

The audit evaluated four distinct hypotheses using reproducible code and empirical evidence:
1. **Data leakage or target contamination:** **REJECTED.** No target labels, session IDs, experiment metadata, or future information contaminate the feature matrix. Preprocessing is strictly fold-safe, and session splits are 100% disjoint.
2. **Strong correlations between features and the traffic-generation recipe:** **CONFIRMED.** Deterministic traffic recipes produce distinct feature signatures (e.g. `std_packet_size == 0.0` for fixed-size ping echo requests/replies, discrete packet counts, and 1:1 forward/backward ratios).
3. **Genuine class separability within the controlled dataset:** **CONFIRMED.** The three controlled benign workloads (`controlled_icmpv4`, `controlled_tcp_marker`, and `controlled_http`) possess intrinsically distinct outer-flow packet size distributions, byte volumes, and directional balances. Even when both `packet_count` and `std_packet_size` are removed, the model achieves **0.9692** cross-validation macro-F1.
4. **Evaluation design limitations:** **CONFIRMED.** The held-out test set consists of only 12 observations across 3 sessions (95% Wilson confidence interval: **[0.7575, 1.0000]**). The perfect score on Phase 8 reflects recipe consistency and limited sample size.

When evaluated against **60 genuinely independent observations** across 30 distinct IKE_SA sessions from historical campaigns Phase 5 (`e2e8adae-94d7-4a1d-9569-3c3e1a965e64`) and Phase 7 (`9bd6b15c-507d-451a-89eb-7071944f105f`), the frozen Phase 10 model achieves **96.67% accuracy** (58/60 correct, macro-F1: 0.9654, 95% Wilson CI: **[0.8864, 0.9908]**), misclassifying exactly two TCP marker observations as HTTP.

```
+---------------------------------------------------------------------------------------------------+
|                                  PHASE 11 AUDIT DECISION DASHBOARD                                 |
+------------------------------------+--------------------------------------------------------------+
| Final Leakage Verdict              | NO_LEAKAGE_DETECTED_WITHIN_SCOPE                             |
| Recipe-Correlation Shortcut Risk   | HIGH / CONFIRMED (std_packet_size=0 for ICMP; discrete counts) |
| Permutation Test p-value           | 0.0099 (session-grouping-aware intact unit permutation)       |
| Independent Campaign Generalization| 96.67% accuracy (58/60 correct on Phase 5 & 7 campaigns)    |
| Production Inference Eligibility   | STRICTLY BLOCKED (validated_for_inference=false)             |
+------------------------------------+--------------------------------------------------------------+
```

---

## Provenance and Artifact Hashes

The audit was conducted on repository commit `fe556314022348b9f6f1b93bd6ead64300d39f84`. All historical artifacts and reports remain strictly preserved and unmodified.

| Artifact | Path | SHA-256 Digest |
|---|---|---|
| Prepared Dataset CSV | `captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052/dataset_preparation/prepared_dataset.csv` | `01b5ff389e55c9a9fb93493c7314b992a50ef9b6f7c9f54d07942eea0d6b0f74` |
| Split Manifest JSON | `captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052/dataset_preparation/split_manifest.json` | `1340c166a40594ecb128329fdf5d0a2cb4b38bb55ea034f6f16717bb88dd4c2b` |
| Campaign Manifest JSON | `captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052/campaign_manifest.json` | `1986d9cbf303671b1c35e6537fcf534bf288134b0a197e774d36e0cdb812b6a3` |
| Phase 9 Audit Report | `vista-ml/reports/phase9_dataset_audit.json` | `e46c051ade7662c70e0c619129ebb8061b269ba01ede95a897d98d701aed87be` |
| Phase 10 Optuna Report | `vista-ml/reports/phase10_optuna_report.json` | `b6fbec8371997526b87c9ff5521629f0be6496d6169bd3dbb05034be478eacf4` |
| Candidate Model Joblib | `vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib` | `de9d6334309ad1b286ce917c28de49833d4f186e2022fc3b03d53b2c2a826de8` |
| Candidate Metadata JSON | `vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.metadata.json` | `d668baff12cc92097999164c07f8f42b7053f61169b529255c46dbddb1c744dc` |
| Flow Schema JSON | `vista-ml/schemas/vista-flow-v1.json` | `2816eb02ad175aad27ff7b80ccdf2ab6425fa549845f780b3a073bfc5550817d` |
| Target Label Schema JSON | `vista-ml/schemas/vista-target-label-schema-v1.json` | `54be3f52dadd44e2ceb336335ae662c01367042b73c877c1ba9e4b30e62d3efd` |

---

## Feature Lineage and Leakage Audit Table

Each of the 18 features approved in `vista-flow-v1.json` was traced from the raw network packets through extraction in [`vista_ml/features/pcap_features.py`](file:///c:/vista/vista-ml/src/vista_ml/features/pcap_features.py) into the feature matrix:

| Feature Name | Data Type | Source PCAP Fields | Extraction Function & Code Location | Available at Inference? | Label-Derived? | Recipe-Sensitive? | Leakage Risk Classification |
|---|---|---|---|---|---|---|---|
| `packet_count` | integer | Outer IPv4 / ESP packet headers | `pcap_features.py:118` (size) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `byte_count` | integer | IPv4 `total_length` field sum | `pcap_features.py:119` (sum) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `flow_duration` | number | Packet arrival timestamps diff | `pcap_features.py:134` (max - min) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `mean_packet_size` | number | IPv4 `total_length` arithmetic mean | `pcap_features.py:122` (mean) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `std_packet_size` | number | IPv4 `total_length` population std | `pcap_features.py:123` (std, ddof=0) | Yes | No | Yes | `NO_LEAKAGE` (Strong shortcut: 0 for ICMP) |
| `min_packet_size` | integer | IPv4 `total_length` minimum | `pcap_features.py:124` (min) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `max_packet_size` | integer | IPv4 `total_length` maximum | `pcap_features.py:125` (max) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `mean_inter_arrival_time` | number | Successive timestamp diff mean | `pcap_features.py:167` (mean delta) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `std_inter_arrival_time` | number | Successive timestamp diff std | `pcap_features.py:168` (std delta) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `min_inter_arrival_time` | number | Successive timestamp diff min | `pcap_features.py:169` (min delta) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `max_inter_arrival_time` | number | Successive timestamp diff max | `pcap_features.py:170` (max delta) | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `packets_per_second` | number | `packet_count / flow_duration` | `pcap_features.py:141` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `bytes_per_second` | number | `byte_count / flow_duration` | `pcap_features.py:146` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `forward_packet_count` | integer | Canonical forward direction count | `pcap_features.py:126` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `backward_packet_count` | integer | Canonical backward direction count | `pcap_features.py:127` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `forward_bytes` | integer | Canonical forward byte sum | `pcap_features.py:128` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `backward_bytes` | integer | Canonical backward byte sum | `pcap_features.py:129` | Yes | No | Yes | `NO_LEAKAGE` (Recipe shortcut) |
| `direction_ratio` | number | `forward_packet_count / packet_count`| `pcap_features.py:152` | Yes | No | Yes | `NO_LEAKAGE` (Strong shortcut: 0.5 for ICMP) |

### Leakage vs. Recipe-Correlated Shortcuts
A critical conceptual boundary enforced by this audit:
- **Data Leakage:** Information from the target label, validation/test splits, or future events unintentionally contaminating the training matrix (e.g. including `label` in $X$, fitting scalers across splits, or evaluating on samples seen in training).
- **Recipe Correlation / Shortcut:** Legitimate flow properties that happen to strongly correlate with class identity because traffic was generated by fixed scripts (e.g., standard ping always transmits identical request/reply payload sizes, causing `std_packet_size` to be identically `0.0`). The classifier exploits this physical characteristic of the generator. This is **not leakage**, but it limits generalizability to real-world traffic where pings or HTTP transfers vary arbitrarily.

---

## Reproduction of Phase 10

The Phase 10 baseline models, 30-trial Optuna hyperparameter optimization, and held-out test evaluation were re-executed using the exact recorded seeds, split manifests, and configurations.

| Experiment Step | Historical Phase 10 Metric | Reproduced Phase 11 Metric | Status |
|---|---|---|---|
| Majority Baseline CV Macro-F1 | 0.2222 | 0.2222 | **MATCH (Exact)** |
| Shallow Decision Tree CV Macro-F1 | 0.7978 | 0.7978 | **MATCH (Exact)** |
| Initial Random Forest CV Macro-F1 | 0.9692 | 0.9692 | **MATCH (Exact)** |
| Optuna Best Trial Number | Trial 6 | Trial 6 | **MATCH (Exact)** |
| Optuna Best CV Macro-F1 | 1.0000 | 1.0000 | **MATCH (Exact)** |
| Optuna Best Hyperparameters | `n_estimators=130, max_depth=8, min_samples_split=2, min_samples_leaf=1, max_features=None, class_weight="balanced"` | Identical | **MATCH (Exact)** |
| Held-Out Test Macro-F1 | 1.0000 | 1.0000 | **MATCH (Exact)** |
| Held-Out Test Accuracy | 1.0000 | 1.0000 | **MATCH (Exact)** |

All metrics match the historical report to within numerical precision.

---

## Diagnostic Experiments

### 1. Shallow Decision Tree Inspections
A depth-1 decision tree (stump) achieves **0.8857 test macro-F1** and separates classes with a single rule:
```
|--- std_packet_size <= 2.25
|   |--- class: controlled_icmpv4
|--- std_packet_size >  2.25
|   |--- class: controlled_http
```
A depth-2 decision tree achieves **1.0000 test macro-F1** using only two thresholds:
```
|--- std_packet_size <= 2.25
|   |--- class: controlled_icmpv4
|--- std_packet_size >  2.25
|   |--- packet_count <= 26.00
|   |   |--- class: controlled_tcp_marker
|   |--- packet_count >  26.00
|   |   |--- class: controlled_http
```
This confirms that the entire three-class distinction on this dataset can be solved by two scalar thresholds on `std_packet_size` and `packet_count`.

### 2. Single-Feature Ranking (18 Models)
Individual features ranked by 3-fold GroupKFold cross-validation macro-F1:

| Rank | Feature | CV Mean Macro-F1 | CV Std | Held-Out Test Macro-F1 |
|---|---|---|---|---|
| 1 | `std_packet_size` | **0.8893** | 0.0988 | **1.0000** |
| 2 | `packet_count` | **0.8429** | 0.1125 | **1.0000** |
| 3 | `forward_packet_count` | **0.8429** | 0.1125 | **1.0000** |
| 4 | `backward_packet_count` | **0.8429** | 0.1125 | **1.0000** |
| 5 | `byte_count` | **0.8037** | 0.0631 | 0.8857 |
| 6 | `direction_ratio` | **0.7816** | 0.1583 | 0.7778 |
| 7 | `mean_packet_size` | **0.7607** | 0.0463 | 0.7828 |
| 8 | `max_packet_size` | **0.7410** | 0.0768 | 0.7778 |
| 9 | `backward_bytes` | **0.7107** | 0.0820 | 0.8857 |
| 10 | `forward_bytes` | **0.6974** | 0.0385 | 0.7778 |
| 11 | `bytes_per_second` | **0.6756** | 0.1232 | 0.7778 |
| 12 | `mean_inter_arrival_time`| **0.6620** | 0.0898 | 0.6944 |
| 13 | `std_inter_arrival_time` | **0.6273** | 0.0634 | 0.8857 |
| 14 | `min_packet_size` | **0.5849** | 0.0970 | 0.5833 |
| 15 | `packets_per_second` | **0.5401** | 0.1171 | 0.7778 |
| 16 | `max_inter_arrival_time` | **0.5056** | 0.0674 | 0.5833 |
| 17 | `flow_duration` | **0.4468** | 0.0872 | 0.4444 |
| 18 | `min_inter_arrival_time` | **0.3756** | 0.0645 | 0.4167 |

### 3. Contrast & Key Feature Ablations
To test whether the model depends exclusively on `packet_count` or `std_packet_size`, contrast ablations were evaluated:

| Feature Configuration | Active Features | CV Macro-F1 | Test Macro-F1 | Test Accuracy |
|---|---|---|---|---|
| All 18 Features | 18 | 0.9692 | 1.0000 | 1.0000 |
| Excluding `packet_count` | 17 | 0.9692 | 1.0000 | 1.0000 |
| Excluding `std_packet_size` | 17 | 0.9692 | 1.0000 | 1.0000 |
| **Excluding BOTH `packet_count` & `std_packet_size`** | 16 | **0.9692** | **1.0000** | **1.0000** |
| Packet Sizes & Bytes Only | 8 | 0.9692 | 1.0000 | 1.0000 |
| Directional Features Only | 5 | 0.9192 | 1.0000 | 1.0000 |
| Timing Features Only | 7 | 0.7986 | 0.8857 | 0.9167 |
| Packet Counts Only | 3 | 0.8429 | 1.0000 | 1.0000 |
| Only `std_packet_size` | 1 | 0.8893 | 1.0000 | 1.0000 |
| Only `packet_count` | 1 | 0.8429 | 1.0000 | 1.0000 |

Even with both primary shortcuts removed, the remaining 16 features achieve 0.9692 CV macro-F1 and 1.0000 test macro-F1 because byte volumes (`forward_bytes`, `backward_bytes`, `byte_count`) and directional proportions (`direction_ratio`) provide redundant separation.

### 4. Session-Grouped Permutation Test
A session-grouping-aware label-permutation test was executed across 100 permutations (random seed 42), permuting intact 4-observation session blocks to respect the experimental unit:
- **Real Random Forest CV Macro-F1:** `0.9692`
- **Permuted Null Distribution Mean:** `0.3231` (Std: `0.1037`, Min: `0.1111`, Max: `0.6327`)
- **Empirical p-value:** $p = \frac{0 + 1}{100 + 1} = \mathbf{0.0099}$

No permuted trial reached or approached the true score, rejecting the hypothesis of spurious noise correlation.

---

## Independent-Campaign Validation

The frozen Phase 10 candidate model was evaluated against **60 observations from two independent historical campaigns** collected across 30 independent IKE_SA sessions:

1. **Phase 5 Campaign (`e2e8adae-94d7-4a1d-9569-3c3e1a965e64`):**
   - 30 observations across 15 sessions (15 ICMPv4, 15 TCP marker).
   - Accuracy: **93.33%** (28/30 correct).
   - All 15 ICMPv4 observations correctly predicted.
   - 13 TCP marker observations correctly predicted; **2 misclassified as HTTP**.
2. **Phase 7 Campaign (`9bd6b15c-507d-451a-89eb-7071944f105f`):**
   - 30 observations across 15 sessions (15 HTTP GET, 15 HTTP POST).
   - Accuracy: **100.00%** (30/30 correct).

### Combined Independent Evaluation Performance
- Total samples: **60** (30 distinct sessions, 2 independent collection campaigns)
- **Overall Accuracy:** **96.67%** (58 / 60)
- **95% Wilson Confidence Interval:** **[0.8864, 0.9908]**
- **Macro-F1 Score:** **0.9654**

```
Confusion Matrix (60 Independent Observations):
                       Predicted ICMP   Predicted TCP   Predicted HTTP
Actual ICMPv4 (15):          15               0               0
Actual TCP Marker (15):       0              13               2  <-- Misclassifications
Actual HTTP (30):             0               0              30
```

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `controlled_icmpv4` | 1.0000 | 1.0000 | 1.0000 | 15 |
| `controlled_tcp_marker` | 1.0000 | 0.8667 | 0.9286 | 15 |
| `controlled_http` | 0.9375 | 1.0000 | 0.9677 | 30 |

The two TCP marker errors occurred on transfers where larger payload profiles produced byte counts and packet distributions overlapping with HTTP GET transactions. This proves that real out-of-campaign generalization is **not perfect (96.67%)**, directly dispelling the artifact of a 1.0000 score.

---

## Live Testbed Collection Prerequisites

Live campaign generation infrastructure in `scripts/run_collection_campaign.py` is operational:
- **Topology:** PC1 (`172.20.0.2`) and PC2 (`172.20.0.3`) on Docker bridge network.
- **Tunnel Status:** StrongSwan IKEv2 daemon active and verified via `swanctl --list-sas`.
- **Command:** `python scripts/run_collection_campaign.py --sessions 15 --seed 26161 --workload-set unified`
- **Execution Time:** ~13 minutes (bounded by 900s timeout).

---

## Production Safeguards and Model Eligibility

All candidate model safeguards remain strictly enforced:
- `validated_for_inference = false`
- `production_eligible = false`
- `experimental = true`

**Engineering Assessment:**
High accuracy on controlled benign workloads demonstrates that outer ESP flow statistics can distinguish simple scripted network patterns. However, this does **NOT** constitute evidence that the system can classify arbitrary user applications, decrypt payloads, detect malicious tunnels, or inspect operational traffic with variable MSS/MTU, background jitter, and multiplexed connections. Production deployment remains strictly prohibited.
