# VISTA Phase 10 — Baseline ML Training and Optuna Hyperparameter Optimization Report

## Executive Summary

Phase 10 implements a reproducible, leakage-aware exploratory machine learning experiment for VISTA, building directly upon the audited Phase 8 unified workload dataset ([`76adc766-ef41-45f5-b677-1d950c7ff052`](file:///c:/vista/captures/strongswan/collections/campaigns/76adc766-ef41-45f5-b677-1d950c7ff052)) and the Phase 9 baseline eligibility gate report ([`vista-ml/reports/phase9_dataset_audit.json`](file:///c:/vista/vista-ml/reports/phase9_dataset_audit.json)).

### Scope & Strict Operational Boundaries
- **Exploratory Experiment Only:** This phase trains and evaluates experimental candidate models offline. It does **NOT** promote, deploy, or enable any model for production or live backend inference.
- **Inference Eligibility Unchanged:** Model metadata strictly records `validated_for_inference: false` and `production_eligible: false`. Backend `ModelService` remains closed to unapproved candidate models.
- **Target Boundary:** The prediction target is strictly bounded to three controlled benign workloads (`controlled_icmpv4`, `controlled_tcp_marker`, `controlled_http`) through an encrypted StrongSwan IPv4 IPsec tunnel. This phase does **NOT** claim arbitrary application identification, attack detection, or production IPsec protocol classification.
- **Cross-Campaign Generalization Boundary:** `independent_campaign_validation` remains **`BLOCKED`**. Perfect held-out metrics on 12 test observations from three sessions on a single testbed do **NOT** prove generalizability to real-world network deployments.

---

## 1. Dataset Eligibility Gate Enforcement

Before initializing any training or hyperparameter optimization, [`vista-ml/scripts/run_optuna_baseline.py`](file:///c:/vista/vista-ml/scripts/run_optuna_baseline.py) programmatically loaded and validated [`vista-ml/reports/phase9_dataset_audit.json`](file:///c:/vista/vista-ml/reports/phase9_dataset_audit.json) against campaign `76adc766-ef41-45f5-b677-1d950c7ff052`:

| Gate | Required Status | Verified Status | Evidence |
|---|:---:|:---:|---|
| `baseline_eligibility` | `PASS` | **`PASS`** | Authorized exclusively for exploratory baseline experiment. |
| `artifact_integrity` | `PASS` | **`PASS`** | 60/60 raw PCAPs readable with outer ESP/NAT-T frames; SHA-256 hashes match. |
| `ground_truth_integrity` | `PASS` | **`PASS`** | 60/60 endpoint verification records agree (ICMP, TCP payload hash, HTTP 200 OK + body hash). |
| `label_integrity` | `PASS` | **`PASS`** | Canonical labels conform to `vista-target-label-schema-v1.json`. |
| `feature_integrity` | `PASS` | **`PASS`** | 18/18 features in `vista-flow-v1.json` reproduce with 100% parity from outer ESP metadata. |
| `leakage_controls` | `PASS` | **`PASS`** | Zero session, SA identity, or SPI overlap across splits; zero duplicate vectors. |
| `class_coverage` | `PASS` | **`PASS`** | All 3 target classes represented across train, validation, and test splits. |
| `split_validity` | `PASS` | **`PASS`** | Deterministic nested `GroupShuffleSplit` partitioned strictly by verified IKE_SA identity. |
| `independent_campaign_validation` | `BLOCKED` | **`BLOCKED`** | Single campaign, single testbed constraint confirmed. |
| `discrepancies` | `[]` | **`[]`** | Zero unresolved discrepancies. |

Audit report hash recorded: `e46c051ade7662c70e0c619129ebb8061b269ba01ede95a897d98d701aed87be`.

---

## 2. Feature Schema & Inference Boundary

Model inputs were strictly restricted to the 18 approved flow features in [`vista-ml/schemas/vista-flow-v1.json`](file:///c:/vista/vista-ml/schemas/vista-flow-v1.json):
1. `packet_count`
2. `byte_count`
3. `flow_duration`
4. `mean_packet_size`
5. `std_packet_size`
6. `min_packet_size`
7. `max_packet_size`
8. `mean_inter_arrival_time`
9. `std_inter_arrival_time`
10. `min_inter_arrival_time`
11. `max_inter_arrival_time`
12. `packets_per_second`
13. `bytes_per_second`
14. `forward_packet_count`
15. `backward_packet_count`
16. `forward_bytes`
17. `backward_bytes`
18. `direction_ratio`

**Excluded Metadata:** Experiment IDs, session IDs, ground-truth sidecars, capture paths, SHA-256 hashes, timestamps, SA identities, SPIs, and container identifiers were strictly excluded from model feature matrices.

**Domain Boundary:** Extracted features reflect only outer encrypted IPv4 ESP timing and packet lengths. Encrypted inner IP headers, TCP flags, HTTP headers, URLs, and inner plaintext are completely unobservable and are never accessed.

---

## 3. Training Protocol & Non-Optimized Baselines

Validation was performed exclusively on the 9 training sessions (36 observations) using a 3-fold `GroupKFold` grouped by session UUID (`groups=session_id`).
- Each fold contained exactly 6 training sessions (24 observations) and 3 validation sessions (12 observations).
- Zero observations from the same session ever crossed between training and validation within any fold.
- The held-out test split was **completely withheld** from this protocol.

### Baseline Results across Session-Grouped Folds:

| Model | Mean Macro-F1 | Std Macro-F1 | Mean Accuracy | Fold 0 F1 | Fold 1 F1 | Fold 2 F1 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Majority-Class Baseline** (`DummyClassifier`) | **0.2222** | $\pm 0.0000$ | 0.5000 | 0.2222 | 0.2222 | 0.2222 |
| **Interpretable Decision Tree** (`max_depth=2`) | **0.7978** | $\pm 0.1402$ | 0.8611 | 0.6970 | 0.7302 | 0.9663 |
| **Initial Random Forest** (`n_est=100, depth=4`) | **0.9692** | $\pm 0.0435$ | 0.9722 | 0.9077 | 1.0000 | 1.0000 |

### Key Observations:
1. The majority-class baseline achieves 50% accuracy by always predicting `controlled_http` (the most frequent class with 18/36 training samples), but has a poor macro-F1 of $0.2222$ because it fails entirely on ICMP and TCP marker classes.
2. The shallow decision tree (`max_depth=2`) reveals realistic session-to-session variability ($\text{std} = 0.1402$), scoring 0.6970 in Fold 0 and 0.9663 in Fold 2, proving that grouping by genuine IKE_SA sessions tests real cross-session behavior.
3. The initial Random Forest achieves a strong mean macro-F1 of $0.9692$, with Fold 0 having a minor confusion between TCP marker and HTTP.

---

## 4. Leakage-Aware Optuna Hyperparameter Optimization

Optuna was configured with a deterministic `TPESampler(seed=42)` to optimize mean session-grouped validation macro-F1 over 30 trials using the 9 training sessions.

### Search Space & Hyperparameters:
- `n_estimators`: $[20, 200]$ with step 10
- `max_depth`: $[2, 8]$
- `min_samples_split`: $[2, 10]$
- `min_samples_leaf`: $[1, 5]$
- `max_features`: `["sqrt", "log2", None]`
- `class_weight`: `[None, "balanced"]`

### Optimization Results:
- **Best Trial:** Trial 6
- **Best Validation Macro-F1:** **1.0000** (mean across all 3 session folds; std = 0.0000)
- **Best Hyperparameters:**
  ```json
  {
    "n_estimators": 130,
    "max_depth": 8,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "max_features": null,
    "class_weight": "balanced"
  }
  ```

### Selected Trials History:

| Trial | `n_estimators` | `max_depth` | `min_samples_split` | `min_samples_leaf` | `max_features` | `class_weight` | Mean Macro-F1 | Std Macro-F1 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 0 | 90 | 8 | 8 | 4 | `sqrt` | None | 0.9692 | $\pm 0.0435$ |
| 1 | 30 | 8 | 3 | 2 | `sqrt` | `balanced` | 0.9692 | $\pm 0.0435$ |
| 2 | 190 | 6 | 4 | 2 | `sqrt` | None | 0.9692 | $\pm 0.0435$ |
| 3 | 120 | 6 | 5 | 1 | `sqrt` | `balanced` | 0.9692 | $\pm 0.0435$ |
| 4 | 40 | 6 | 3 | 4 | `log2` | `balanced` | 0.9692 | $\pm 0.0435$ |
| 5 | 160 | 3 | 7 | 4 | `sqrt` | `balanced` | 0.9077 | $\pm 0.0653$ |
| **6** | **130** | **8** | **2** | **1** | **None** | **`balanced`** | **1.0000** | **$\pm 0.0000$** |
| 7 | 120 | 4 | 7 | 3 | None | None | 0.9692 | $\pm 0.0435$ |
| 8 | 150 | 8 | 3 | 5 | None | None | 0.9692 | $\pm 0.0435$ |
| 9 | 170 | 2 | 9 | 5 | `sqrt` | `balanced` | 0.7770 | $\pm 0.1706$ |
| 14 | 140 | 8 | 2 | 1 | None | `balanced` | 1.0000 | $\pm 0.0000$ |
| 20 | 140 | 8 | 2 | 1 | None | `balanced` | 1.0000 | $\pm 0.0000$ |

---

## 5. Mandatory Feature-Shortcut & Ablation Analysis

Ablation analysis was executed on the same session-grouped validation folds on the 9 training sessions.

### Single-Feature Diagnostic Performance:

| Feature Tested | Mean Macro-F1 | Std Macro-F1 | Mean Accuracy | Primary Diagnostic Finding |
|---|:---:|:---:|:---:|---|
| **`std_packet_size`** | **0.8893** | $\pm 0.0988$ | 0.9167 | ICMP pings have uniform size ($\text{std}=0.0$), perfectly separating ICMP from TCP and HTTP. |
| **`packet_count`** | **0.8429** | $\pm 0.1125$ | 0.8889 | Discrete sample counts (ICMP: 6..14, TCP: 12..34, HTTP: 21..74) partially separate classes. |
| **`forward_packet_count`** | **0.8169** | $\pm 0.0764$ | 0.8611 | Correlated with `packet_count`. |
| **`mean_inter_arrival_time`** | **0.8108** | $\pm 0.0563$ | 0.8611 | Ping rate spacing differs from TCP streaming bursts and HTTP request pacing. |
| **`min_inter_arrival_time`** | **0.8026** | $\pm 0.1440$ | 0.8333 | TCP and HTTP generate sub-millisecond local ACKs, unlike ICMP ping intervals. |
| **`max_packet_size`** | **0.7941** | $\pm 0.0758$ | 0.8333 | TCP marker and HTTP POST payloads exceed standard ping payloads. |
| **`mean_packet_size`** | **0.7819** | $\pm 0.0774$ | 0.8333 | Significant overlap between classes, but distinct central tendencies. |
| **`packets_per_second`** | **0.7685** | $\pm 0.0131$ | 0.8056 | HTTP transaction rate is higher than spaced ICMP echoes. |
| **`direction_ratio`** | **0.7108** | $\pm 0.0784$ | 0.7778 | ICMP is strictly 1:1 forward/backward; TCP/HTTP have asymmetric request/response ratios. |
| **`backward_packet_count`** | **0.7042** | $\pm 0.1328$ | 0.7778 | Correlated with forward packet counts. |
| **`max_inter_arrival_time`** | **0.6634** | $\pm 0.1913$ | 0.7500 | Correlated with inter-request pauses. |
| **`backward_bytes`** | **0.6552** | $\pm 0.0589$ | 0.7500 | Reflects response body payload sizes. |
| **`min_packet_size`** | **0.5722** | $\pm 0.0393$ | 0.6944 | Smallest packets are TCP ACKs (108 bytes outer ESP). |
| **`flow_duration`** | **0.5231** | $\pm 0.1054$ | 0.6111 | Continuous overlap across classes prevents single-feature separation. |
| **`byte_count`** | **0.5147** | $\pm 0.0458$ | 0.6111 | Broad continuous overlap across all three classes. |
| **`std_inter_arrival_time`** | **0.4908** | $\pm 0.1874$ | 0.6111 | High variance within classes. |
| **`forward_bytes`** | **0.4672** | $\pm 0.0889$ | 0.5833 | Overlapping forward payload bytes. |
| **`bytes_per_second`** | **0.4551** | $\pm 0.1844$ | 0.5556 | High overlap; insufficient for standalone discrimination. |

### Leave-One-Feature-Out (LOFO) Random Forest Performance:
- Excluding `packet_count`: Mean Macro-F1 = **0.9692** ($\pm 0.0435$).
- Dropping any individual feature from the full set leaves Random Forest mean macro-F1 between **0.9286** and **1.0000**.
- Timing-only feature group (7 features): Mean Macro-F1 = **0.7986** ($\pm 0.0617$).
- Packet-size and byte-count group (10 features): Mean Macro-F1 = **0.8192** ($\pm 0.0875$).

### Diagnostic Takeaways:
1. `packet_count` is **not the sole driver** of performance: removing it completely maintains a 0.9692 macro-F1.
2. The high performance is driven by redundant multidimensional physical attributes:
   - ICMP ping echoes have fixed sizes (`std_packet_size == 0.0`) and symmetric directionality (`direction_ratio == 0.5`).
   - TCP marker flows have streaming ACKs and distinct packet-size distributions.
   - HTTP transactions have asymmetric request/response payloads, varying packet counts, and rapid inter-arrival timing.
3. Because these properties reflect the controlled testbed recipes rather than arbitrary in-the-wild web traffic, the model must **NOT** be claimed as a general web traffic identifier.

---

## 6. Final Held-Out Test Evaluation

The selected Optuna configuration was fitted on all 9 training sessions (36 observations) and evaluated **once** on the held-out test split (3 sessions, 12 observations: `139363bc-4b47-4a7c-b353-8d5005abec82`, `72215fee-164b-4e7f-ae42-65eaf209d234`, `9ec1c7f5-5fdf-4ec4-8117-a28d110eb0cf`).

### Performance Comparison on Held-Out Test Split:

| Model Evaluated | Test Accuracy | Test Macro Precision | Test Macro Recall | Test Macro-F1 |
|---|:---:|:---:|:---:|:---:|
| **Majority-Class Baseline** | 0.5000 | 0.1667 | 0.3333 | 0.2222 |
| **Interpretable Decision Tree** (`max_depth=2`) | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Initial Random Forest** (`n_est=100, depth=4`) | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Best Optuna-Tuned Random Forest** | **1.0000** | **1.0000** | **1.0000** | **1.0000** |

### Tuned Random Forest Confusion Matrix ($3 \times 3$):
```
                       Predicted: ICMP   Predicted: TCP   Predicted: HTTP
Actual: ICMPv4               3                0                0
Actual: TCP Marker           0                3                0
Actual: HTTP                 0                0                6
```

### Per-Class Test Metrics:
- **`controlled_icmpv4`:** Precision: 1.0000, Recall: 1.0000, F1: 1.0000 (Support: 3)
- **`controlled_tcp_marker`:** Precision: 1.0000, Recall: 1.0000, F1: 1.0000 (Support: 3)
- **`controlled_http`:** Precision: 1.0000, Recall: 1.0000, F1: 1.0000 (Support: 6)

### Sample-Level Held-Out Predictions Log:

| Observation ID | Session ID | Ground Truth Label | Predicted Label | Correct? |
|---|---|---|---|:---:|
| `0b50b7b3-768d-4bed-9845-0d2f25bfc1f3` | `139363bc...` | `controlled_http` | `controlled_http` | Yes |
| `28df5c77-3a02-4853-8e43-0aa7823cbd08` | `139363bc...` | `controlled_tcp_marker` | `controlled_tcp_marker` | Yes |
| `50dd2566-3ff8-48c7-a227-d6446ab3c973` | `139363bc...` | `controlled_http` | `controlled_http` | Yes |
| `bf54f3f7-7ded-435e-8759-564dcbee82b5` | `139363bc...` | `controlled_icmpv4` | `controlled_icmpv4` | Yes |
| `08d5667b-ed6e-4c5f-a460-612036b3ff85` | `72215fee...` | `controlled_tcp_marker` | `controlled_tcp_marker` | Yes |
| `548d1faf-69a7-42b5-8562-2387976e0db0` | `72215fee...` | `controlled_icmpv4` | `controlled_icmpv4` | Yes |
| `91ec67e2-1776-4df5-9b30-b65ac8f4a5a2` | `72215fee...` | `controlled_http` | `controlled_http` | Yes |
| `c2a830aa-0437-4545-9ec5-b99ea4951616` | `72215fee...` | `controlled_http` | `controlled_http` | Yes |
| `3c660c3b-3651-44e0-875d-4ea81cf6fd5e` | `9ec1c7f5...` | `controlled_tcp_marker` | `controlled_tcp_marker` | Yes |
| `bbe6f775-5ea1-4aa1-bb96-8f34ba3d3ea9` | `9ec1c7f5...` | `controlled_http` | `controlled_http` | Yes |
| `e54946ac-fa8f-4604-83b5-e0781fa74ca1` | `9ec1c7f5...` | `controlled_icmpv4` | `controlled_icmpv4` | Yes |
| `fa07f6c3-0d58-481b-b221-81d3c819386c` | `9ec1c7f5...` | `controlled_http` | `controlled_http` | Yes |

### Critical Statistical Limitation & Uncertainty Disclaimer:
> [!WARNING]
> **High Statistical Uncertainty on Small Test Sample:**
> The held-out test split contains **only 12 observations from 3 sessions** collected on a single testbed.
> While 12/12 correct predictions confirm that the trained model generalizes across sessions within this specific testbed campaign, the score has substantial statistical variance (Wilson 95% confidence interval for 12/12 is $[0.758, 1.000]$).
> This score must **NOT** be presented as evidence of generalizable performance in operational enterprise networks.

---

## 7. Model Persistence & Metadata Compliance

The experimental candidate model was serialized to:
- Model artifact: [`vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib`](file:///c:/vista/vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib)
- Metadata sidecar: [`vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.metadata.json`](file:///c:/vista/vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.metadata.json)

Metadata sidecar contents:
```json
{
  "model_id": "phase10-rf-20261010T082308Z-6b8eb840",
  "task": "controlled_benign_workload_classification",
  "task_boundary": "Exploratory candidate model only. Excludes arbitrary applications, attacks, and IPsec classification.",
  "feature_schema_version": "vista-flow-v1",
  "target_label_schema_version": "vista-target-label-schema-v1",
  "campaign_id": "76adc766-ef41-45f5-b677-1d950c7ff052",
  "phase9_audit_report_hash": "e46c051ade7662c70e0c619129ebb8061b269ba01ede95a897d98d701aed87be",
  "validated_for_inference": false,
  "production_eligible": false,
  "experimental": true,
  "trained_at": "2026-10-10T08:23:08.242455+00:00",
  "training_sample_count": 36,
  "training_session_count": 9,
  "test_sample_count": 12,
  "test_session_count": 3,
  "hyperparameters": {
    "n_estimators": 130,
    "max_depth": 8,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "max_features": null,
    "class_weight": "balanced"
  },
  "validation_mean_macro_f1": 1.0,
  "test_macro_f1": 1.0,
  "classes": [
    "controlled_icmpv4",
    "controlled_tcp_marker",
    "controlled_http"
  ]
}
```

---

## 8. Summary of Completion Criteria

| Criterion | Implementation | Status |
|---|---|:---:|
| **Eligibility Gate** | Validated Phase 9 audit report; confirmed all 7 integrity gates pass; verified independent campaign is BLOCKED. | **MET** |
| **Feature Boundary** | Strictly 18 `vista-flow-v1` outer ESP features; all metadata excluded; zero encrypted inner payload inspection. | **MET** |
| **Non-Optimized Baselines** | Majority-class, shallow decision tree, and initial RF evaluated on identical 3-fold session-grouped CV. | **MET** |
| **Optuna Optimization** | 30 trials with TPE sampler (seed 42) maximizing session-grouped macro-F1 on training sessions only. | **MET** |
| **Shortcut Analysis** | Evaluated packet count alone, 18 single features, 18 LOFO models, timing-only, and size-only feature groups. | **MET** |
| **Held-Out Evaluation** | Fitted on all 9 training sessions and evaluated once on the 3 held-out test sessions; reported per-class metrics and confusion matrix. | **MET** |
| **Uncertainty Disclosed** | Explicitly stated high variance of 12-sample test split; no claim of general operational deployment readiness. | **MET** |
| **Model Non-Production** | Saved under candidate directory; marked `validated_for_inference: false` and `production_eligible: false`. | **MET** |
