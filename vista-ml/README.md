# VISTA ML

VISTA is a VPN intelligence, security, and telemetry analytics project focused on encrypted IPsec traffic analysis without decrypting payloads. This repository implements the ML experimentation pipeline that ingests synthetic development data, public benchmark datasets, and future StrongSwan-generated PCAP/eBPF datasets into a common canonical data model.

> The current sample dataset is synthetic and is used only to validate the ML pipeline. It must not be represented as measured IPsec performance.

## 1. Objective

The ML system is designed to learn from encrypted traffic behavior, supporting:

- Task A: encrypted traffic behaviour classification
- Task B: cryptographic configuration inference
- Task C: behavioural anomaly detection

The system is intentionally modular so that public datasets such as UNB ISCXVPN2016 and future StrongSwan captures can be integrated through data adapters and feature engineering stages.

## 2. Architecture

Dataset
  ↓
Adapter
  ↓
VISTA canonical schema
  ↓
Feature engineering
  ↓
Experiment-aware split
  ↓
Model training
  ↓
Evaluation + SHAP

The project is organized into data, feature, dataset generation, model, evaluation, and explainability components. It avoids unnecessary infrastructure and remains CPU-friendly for laptop development.

## 3. Dataset schema

Each row represents one flow/session. Required metadata includes:

- experiment_id
- scenario_id
- flow_id
- timestamp_start
- timestamp_end
- traffic_type
- attack_type
- label
- ipsec_mode
- ike_version
- cipher
- integrity_algorithm
- dh_group
- pfs_enabled

The canonical feature groups are:

- NETWORK_BASIC: packet_count, byte_count, flow_duration
- PACKET_SIZE: mean_packet_size, std_packet_size, min_packet_size, max_packet_size
- TIMING: mean_inter_arrival_time, std_inter_arrival_time, min_inter_arrival_time, max_inter_arrival_time
- RATE: packets_per_second, bytes_per_second
- DIRECTION: forward_packet_count, backward_packet_count, forward_bytes, backward_bytes, direction_ratio
- EBPF: ebpf_event_count, socket_event_count, process_event_count, network_event_count, unique_process_count

## 4. Feature groups and config

Feature groups are selected in [config.yaml](config.yaml). The code supports toggling group membership while keeping the schema extensible for future eBPF features.

## 5. Synthetic dataset limitations

This project includes a synthetic sample dataset only for pipeline validation. It is not a real dataset and must never be used to claim real-world IPsec performance. It is intentionally reproducible and lightweight.

To generate the canonical synthetic testbed-validation dataset and run Random Forest, XGBoost, Isolation Forest, and SHAP through an experiment-group holdout, run:

```powershell
python scripts/run_testbed_synthetic_validation.py
```

The command writes a schema/provenance dataset card beside the Parquet file under `data/processed/testbed_validation`, and reports/models under `reports/testbed_synthetic_validation` and `models/testbed_synthetic_validation`. Features, labels, and eBPF-shaped columns are generated, not collected; resulting metrics are pipeline checks only.

The generator deliberately samples numeric network/eBPF profiles conditional on the synthetic label, so very high scores are expected and are not estimates of SIH task performance. IPsec configuration metadata is independently sampled and must not be treated as an inference result. Train/test partitions are grouped by experiment to prevent experiment overlap, but this does not make label-conditioned synthetic features representative of real captures.

## 6. Public dataset integration strategy

The repository supports integration of public benchmark datasets before StrongSwan data becomes available. The priority public dataset is UNB ISCXVPN2016 / CIC VPN-nonVPN.

Public datasets are adapted through the adapter layer in [src/vista_ml/data/adapters](src/vista_ml/data/adapters), which maps source-specific fields into the VISTA canonical schema when possible. Real eBPF features remain absent when the source dataset does not provide them.

## 7. PCAP pipeline

The PCAP feature extraction interface is implemented in [src/vista_ml/features/pcap_features.py](src/vista_ml/features/pcap_features.py). It operates on packet-level CSV/JSON/Parquet inputs and aggregates them into flow-level features such as packet counts, byte totals, flow duration, and inter-arrival statistics.

For real packet capture files, the adapter or ingestion step should emit packet-level rows with columns such as:

- timestamp
- packet_length
- src_ip
- dst_ip
- src_port
- dst_port
- protocol
- flow_id

The code does not inspect encrypted payload contents.

## 8. eBPF pipeline

The eBPF interface is implemented in [src/vista_ml/features/ebpf_features.py](src/vista_ml/features/ebpf_features.py). It loads event records from CSV/JSON/Parquet and aggregates them into per-flow statistics. It tolerates missing optional fields and leaves eBPF metrics NULL/absent when the dataset has no telemetry.

## 9. Correlation

The correlation layer is implemented in [src/vista_ml/features/fusion.py](src/vista_ml/features/fusion.py). It aligns PCAP and eBPF data using flow context and a configurable temporal correlation window, defaulting to 100 ms. If exact 5-tuple keys are not available, the code uses the strongest available identifier and marks the limitation in the pipeline.

## 10. Leakage-aware splitting

Random flow-level train/test splitting is dangerous because flows from the same experiment/session can leak across partitions and artificially inflate scores. The project uses experiment-aware splitting via `GroupShuffleSplit` and checks that no `experiment_id` appears in both train and test sets.

## 11. Models

The project implements:

- Random Forest for baseline supervised classification
- XGBoost for the primary supervised model
- Isolation Forest for anomaly detection

These are implemented in [src/vista_ml/models](src/vista_ml/models).

## 12. SHAP

SHAP support is implemented in [src/vista_ml/explainability/shap_analysis.py](src/vista_ml/explainability/shap_analysis.py). It produces global feature importance summaries, bee swarm plots, bar plots, and an individual explanation JSON summary.

## 13. Evaluation

The evaluation module in [src/vista_ml/evaluation](src/vista_ml/evaluation) computes metrics for classification and anomaly tasks, saves confusion matrices, and writes machine-readable summaries.

## 14. How to run

From the project root:

```bash
python scripts/generate_sample_dataset.py
python scripts/validate_dataset.py
python scripts/train_baseline.py
python scripts/train_xgboost.py
python scripts/train_anomaly.py
python scripts/evaluate_models.py
python scripts/run_shap.py
pytest -q
```

## 15. Replacing synthetic data with real VISTA data

To integrate real data, place the source dataset in `data/raw` and add or update the relevant adapter under `src/vista_ml/data/adapters`. Then update the configuration under `configs/datasets` and rerun the appropriate training/evaluation scripts.

The canonical internal format is:

Dataset
  ↓
Adapter
  ↓
VISTA canonical schema
  ↓
Feature engineering
  ↓
ML

## 16. Future StrongSwan integration

The script [scripts/train_testbed_normal.py](scripts/train_testbed_normal.py) captures independent benign ICMP and TCP-marker sessions on the gateway's outer interface, filters encrypted ESP, derives outer packet size/timing/direction features, and trains RF/XGBoost with a whole-session holdout. Run it from the ML project root with:

```powershell
python scripts/train_testbed_normal.py --repetitions 10
```

The script uses only the direct `pc1` and `pc2` StrongSwan containers; it captures ESP on `pc1` while generating ICMP and TCP-marker traffic to `pc2`. No gateway, protected server, forwarding, or SNAT is involved. Captures, processed features, models, and reports are stored under `../captures/strongswan/normal`, `data/processed/strongswan`, `models/strongswan_testbed_normal`, and `reports/strongswan_testbed_normal` respectively. The current run varies benign ICMP/TCP workloads but uses only the default direct-tunnel configuration (IKEv2 AES-CBC-256/HMAC-SHA2-256 with MODP-2048; ESP AES-256-GCM with MODP-2048; tunnel mode). It collects no eBPF or attack traffic and cannot train configuration inference; its scores validate traffic-type capture/model plumbing only. Attack and crypto-inference claims require multiple controlled configurations, endpoint-ground-truth SA records, and separately held-out configuration/session groups.

The separate [scripts/train_testbed_ike_dh.py](scripts/train_testbed_ike_dh.py) runner collects fresh IKE_SA_INIT handshakes for MODP-2048, MODP-3072, and ECP-256 while holding other proposals constant. It verifies each target against the negotiated SA, restores the original StrongSwan configuration, and trains RF/XGBoost using only packet-size/timing features. Run it with `python scripts/train_testbed_ike_dh.py --repetitions 20 --test-size 0.25`. The report cites [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296) (IKEv2 exchanges and transform negotiation), [RFC 4301](https://www.rfc-editor.org/rfc/rfc4301) (IPsec architecture and modes), [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303) (ESP), and the [strongSwan `swanctl.conf` reference](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html). This validates only DH-group classification in IKE_SA_INIT; protocol-aware parsing of the visible KE/SA fields is the deterministic baseline, and the ML score must not be generalized to cipher, PFS, mode, attacks, or unseen deployments.

## 17. Public benchmark differentiation

The project explicitly distinguishes:

- A. Public benchmark performance
- B. Synthetic development performance
- C. VISTA-generated StrongSwan performance
- D. Final PCAP + eBPF performance

Metrics from one class of dataset must not be mixed with another class.

## 18. ISCXVPN2016 benchmark requirement

### Public Dataset Validation

The ISCXVPN2016 experiment is a public-dataset validation of flow-level VPN/application classification, not the final VISTA attack-detection result. The current run used 18,758 rows, 23 source features, and a stratified 80/20 row split. The source does not provide capture/session identifiers, so scores may be optimistic and should be treated as exploratory.

| Task | Random Forest accuracy / macro-F1 | XGBoost accuracy / macro-F1 |
| --- | --- | --- |
| 14-class application/VPN label | 85.26% / 81.87% | 87.23% / 84.14% |
| VPN vs non-VPN | 92.16% / 92.13% | 92.70% / 92.67% |

The dataset labels application categories and VPN status. It has no attack labels or IPsec configuration ground truth. These results therefore do not demonstrate DoS, port-scan, brute-force, C2, or exfiltration detection, nor cipher/AES, DH-group, PFS, or tunnel-mode inference. The dataset and source limitations are recorded in `reports/iscxvpn2016/dataset_summary.json`.

SIH-specific security claims require a separate labeled StrongSwan testbed dataset linking controlled IPsec configurations and attack scenarios to captured PCAP/eBPF telemetry. Keep those results separate from both this public benchmark and the synthetic development dataset.
