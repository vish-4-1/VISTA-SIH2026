# VISTA Implementation Gap Report
## SIH26160 · NTRO · Smart India Hackathon 2026

This document lists the remaining technical gaps and boundaries in the VISTA framework.

## SIH pre-finals refresh (2026-10-11)

- Comprehensive backend/eBPF/ML regression baseline: **226 passed, 10 opt-in live tests skipped, 0 failed, 4 deprecation warnings** across all 236 test items in the repository. Optuna was installed in `.venv` from `vista-ml/requirements.txt`, enabling full collection and passage of Phase 10 (`test_optuna_baseline.py`, 8 passed) and Phase 11 (`test_phase11_leakage_audit.py`, 5 passed).
- The local backend is online and serving on port 8000; its read-only status API reports the direct tunnel and native eBPF hooks. The dashboard development server is online on port 5173 (`http://127.0.0.1:5173/`), actively proxying `/api` requests to backend on port 8000 with verified 200 OK responses. Frontend lint (`oxlint`) passes with 0 warnings/0 errors, frontend tests pass (3/3), and production build (`vite build`) completes cleanly.
- Live collection remains bounded by safety limits: the collector replaces the established CHILD_SA, rollback is not guaranteed, and the host has no Docker CLI to inspect/recover containers.
- Historical benign ICMP evidence is available and hash-checked. The retained `controlled_port_scan` record `c70f9bc2-1300-4c96-aa04-6752fbceb1d9` requested three ports but measured and captured five (`80, 443, 2222, 8000, 8080`). Treat it as a preserved diagnostic artifact, not valid acceptance evidence for its requested configuration.
- All loaded model artifacts still report inference disabled/not validated. Global SHAP remains unavailable because no provenance-complete held-out artifact is linked to the model and dataset; local explanations remain gated. No operational attack-detection claim is supported.
- Trailing whitespace in `vista-dashboard/src/components/views/AiAnalysisView.jsx` was cleaned; whole-tree `git diff --check` passes cleanly with exit code 0.

## Dataset Studio post-implementation audit (2026-10-11)

- Candidate admission now verifies artifact hashes/sizes and path containment, dataset/report/split inventory, capture integrity, schema/feature exclusions, independent session and SA identities, run references, observed label provenance and time windows, split disjointness, and data-quality blockers. Candidates without this evidence remain blocked or `UNVERIFIED`.
- Port scan evidence is bounded to the allowlisted PC2 endpoint and requested ports, and requires receiver-side inbound SYN evidence from PC1. Scanner runtime and listener/capture cleanup are bounded and cleanup failure is surfaced as workload failure.
- The targeted regression suite passed 114 tests with 3 skips and 4 deprecation warnings; it used mocked testbed behavior and fixture PCAPs.
- No live collection was attempted. The collector replaces the established CHILD_SA and lacks guaranteed rollback if renegotiation fails. At the 11:40 IST snapshot, the tunnel was established with zero counters and capture/job inactive, but the snapshot cannot prove the SA had no external users.
- Remaining acceptance work: operator-approved live impact/recovery plan, real multi-session captured evidence, and independent review of the evidence package before any candidate is considered evaluation-ready. The code change does not expand supported scenarios or make model eligibility claims.

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
- **Current State:** The experiment runner reads machine-readable live IKE_SA/CHILD_SA state using `swanctl --list-sas --raw`, including the negotiated transforms, DH/PFS groups, traffic selectors, and per-child packet/byte counters. It correlates the before/after counters with generated IPv4 ICMP and stores the result beside the capture.
- **Boundary:** This live extraction is currently part of the controlled experiment path; the operational posture APIs are not yet backed by a continuously refreshed SA source.
- **Existing Code:** `backend/services/vpn_testbed.py`; `backend/services/posture_engine.py` still evaluates supplied posture records.
- **Next Work:** Wire refreshed live SA records into the posture engine with explicit freshness and unavailable-data handling.
- **Priority:** P1
- **Estimated Complexity:** Low

---

## Gap 3: Realistic Application Traffic Generators

- **Requirement:** Generate live Web, VoIP (RTP/SIP), video streaming, and email traffic through the tunnel.
- **Current State:** The testbed supports bounded, live-verified ICMPv4 echo, one-connection TCP marker transfer, HTTP/1.1 client/server workloads (GET and POST), and now RFC 3550 RTP/UDP Voice-over-IP audio streaming qualified in a 15-session campaign (Phase 13: `9f3f1f2b-7a6e-468c-b86d-1f9bee65d8bf`, `status: READY_FOR_REVIEW`) under target label schema v2 (`controlled_rtp_voip`). SMTP is verified in unit integration. Video streaming and operational background traffic remain unmodeled synthetic summaries.
- **Why It Matters:** Evaluators may ask to demonstrate live VoIP media or video streaming through the tunnel.
- **Existing Code:** `backend/services/workload_collection.py` implements live ICMPv4, TCP marker, HTTP/1.1, and RTP/UDP collection directly between `pc1` and `pc2`.
- **Required Implementation:** Implement operational video streaming endpoints and open-set OOD rejection before claiming broader production readiness.
- **Priority:** P1
- **Estimated Complexity:** Medium

## Phase 4: Reproducible Workload Collection (2026-10-10)

- **Status:** PARTIAL; bounded ICMPv4 and TCP marker smoke experiments passed against the running PC1↔PC2 StrongSwan 5.9.8 tunnel.
- **Implementation:** `backend/services/workload_collection.py` plus `scripts/collect_vpn_workload.py`. Experiments verify live IKE_SA/CHILD_SA state, tunnel XFRM mode, both endpoint captures, actual outer ESP packets, workload delivery, SA counter deltas, artifact hashes, redacted SA evidence, and a versioned manifest. The TCP receiver uses the installed OpenBSD `nc` inside pc2 and confirms exact received bytes and SHA-256.
- **Evidence:** Session `3dd0983a-d751-491b-8a02-6855b988bddd` has two PASS experiments: ICMP `fa7b06aa-1736-4915-86b6-8fd28eefdd8b` (7/7 replies, 13 outer ESP packets) and TCP marker `7a80087d-a635-467d-ad4a-c1860daf3c4c` (7 messages, 640/640 bytes, matching payload hash, 18 outer ESP packets). Both use the same containers and SA and count as one session.
- **Live-test reliability note:** The first opt-in ICMP integration attempt reported 3/3 replies but produced only a PCAP global header; it was preserved as `FAIL` and excluded.

## Phase 5: Hardened Capture Reliability and Independent Session Collection (2026-10-10)

- **Status:** VERIFIED for capture lifecycle & 15-session campaign; PARTIAL for dataset readiness (controlled benign ICMP/TCP outer-ESP only; application & attack classes remain blocked/unsupported).
- **Empty-PCAP Root Cause & Resolution:**
  - Root cause: `libpcap` TPACKET_V3 packet batching without `--immediate-mode`, kernel socket attachment race with the 24-byte PCAP header write, and lack of continuous USR1 packet-dispatch confirmation before SIGINT.
  - Fix: added `tcpdump --immediate-mode -n -i eth0 -U`, explicit state machine (`PRECHECK → CAPTURE_STARTING → CAPTURE_READY → WORKLOAD_RUNNING → CAPTURE_STOPPING → ARTIFACT_VALIDATION → PASS/FAIL`), continuous `SIGUSR1` packet dispatch verification, container `sync` before copying, and `failure_diagnostics.json` preservation.
  - Live tests: verified opt-in live test runs passed with 100% reliability.
- **Independent Session Definition:**
  - Defined by explicit IKE_SA terminate-and-reinit lifecycle (`reestablish_collection_sa()`), distinct verified IKE SPI hash, SA age <= 60s, container tracking, temporal isolation, and session-level splitting without leakage.
- **Campaign Runner & Traffic Variation:**
  - Runner: `scripts/run_collection_campaign.py`. Bounded campaign with seed-based randomized schedules, varied ICMP/TCP profiles (counts 3–10, intervals 0.2–0.8s, payloads 32–1400 bytes), counterbalanced workload ordering, and 1.0s idle interval.
  - Campaign `e2e8adae-94d7-4a1d-9569-3c3e1a965e64` completed 15 independent sessions, 30 accepted observations, 0 quarantines, and achieved a leakage-free 9/3/3 train/validation/test session split (`READY_FOR_REVIEW`).
- **Remaining Boundaries:**
  - Controlled workloads are limited to ICMPv4 echo and TCP marker; named applications (HTTP, VoIP, WhatsApp, Video) and attack classes remain synthetic/unsupported on live tunnels.
  - Production models remain unpromoted; no model was trained or deployed in this phase.
- **Reproduce Campaign:** `.\.venv\Scripts\python scripts\run_collection_campaign.py --sessions 15 --seed 26160`

## Phase 6: Independent Phase 5 Audit and Real HTTP Application Evidence (2026-10-10)

- **Status:** VERIFIED for Phase 5 audit; VERIFIED for real HTTP/1.1 workload implementation & live evidence; PARTIAL for broader application matrix (VoIP, video, email, attacks remain unsupported).
- **Independent Audit of Phase 5 Campaign:**
  - Ran `scripts/audit_phase5_campaign.py` against `e2e8adae-94d7-4a1d-9569-3c3e1a965e64`:
    - 15 distinct session UUIDs and 30 unique experiment UUIDs confirmed.
    - 15 distinct verified IKE_SA identities (`previousIkeSaIdentitySha256` != `newIkeSaIdentitySha256`), `independenceStatus: VERIFIED_DISTINCT_IKE_SA`.
    - 100% hash integrity: all 30 raw PCAPs, packet tables (`packets.csv`), ground truth JSONs, measurements, and SA evidence matched their recorded SHA-256 digests.
    - Outer ESP verified in all 30 PCAPs via Scapy `PcapReader`.
    - Sender vs receiver measurements agree across all 30 experiments.
    - 9/3/3 session split: 0 session leakage, 0 IKE SPI key leakage, balanced classes.
    - `READY_FOR_REVIEW` confirmed as dataset audit readiness, not model deployment readiness.
  - Discrepancy resolved: earlier `docs/ML_PIPELINE_AUDIT.md` line 215 retained stale Phase 3 test totals (65 passed, 7 skipped); Phase 5 was 103 passed, 9 skipped; Phase 6 reaches 118 passed, 10 skipped (offline) / 121 passed, 7 skipped (live).
- **Real HTTP/1.1 Workload Implementation:**
  - Protocol: bounded HTTP/1.1 exchange over IPsec tunnel using container-native POSIX Perl (`/usr/bin/perl` with core `IO::Socket::INET`) and `/usr/bin/sha256sum` in `pc1` and `pc2`.
  - Server evidence on PC2 (`server_evidence.json`): logs client IP, requested path, method, status 200 OK, response bytes, and SHA-256 body digest.
  - Client measurements on PC1 (`client_measurements.json`): logs status code, received bytes, and payload SHA-256 digest.
  - Feature domain boundary: PC1 captures outer ESP/NAT-T packets on `eth0`; outer ESP features reflect encrypted tunnel traffic shape only and do not expose or claim inner HTTP plaintext.
  - Strict failure handling: status code mismatch, payload byte mismatch, hash mismatch, missing outer ESP, or timeout results in FAILED/QUARANTINED observations.
  - Live experiment executed: Session `15298fa7-7e97-44b0-8e7c-fac238db54e0`, Experiment `60883e93-7174-405f-8f9d-cdf06d2e6894` (3 requests, status 200 OK, 33 outer ESP packets, 18 receiver TCP packets, CHILD_SA delta +15 in / +18 out, all response SHA-256 digests matched).
- **Testing:** 9 new automated tests added for HTTP profiles, preconditions, mismatches, missing ESP, timeout cleanup, and live Docker integration. Full suite passes (`118 passed, 10 skipped, 4 warnings` offline / `121 passed, 7 skipped, 4 warnings` live).

## Phase 7: Multi-Session HTTP Campaign and Dataset Qualification (2026-10-10)

- **Status:** VERIFIED for Phase 6 audit; VERIFIED for 15-session HTTP campaign (`9bd6b15c-507d-451a-89eb-7071944f105f`); VERIFIED for leakage-free 9/3/3 session-split dataset qualification (`READY_FOR_REVIEW`); PARTIAL for broader application matrix (VoIP, video, email, attacks remain unsupported).
- **Independent Phase 6 Audit:**
  - Audited `15298fa7-7e97-44b0-8e7c-fac238db54e0 / 60883e93-7174-405f-8f9d-cdf06d2e6894`: all 11 files present, SHA-256 hashes matched, 33 outer ESP packets, 18 receiver TCP packets, client/server agreement on 3 requests (200 OK, 68 response bytes, exact SHA-256 match), CHILD_SA counter delta +15 in / +18 out packets.
- **Campaign Execution & Session Independence:**
  - Campaign `9bd6b15c-507d-451a-89eb-7071944f105f` completed 15 independent sessions, 30 experiments (15 HTTP GET, 15 HTTP POST).
  - Genuine IKE_SA terminate-and-reinit verified for all 15 sessions (`previousIkeSaIdentitySha256` != `newIkeSaIdentitySha256`), each with `independenceStatus: VERIFIED_DISTINCT_IKE_SA`.
  - HTTP GET profile space: counts 3–7, intervals 0.2–0.4s, paths `/api/v1/telemetry`, `/api/v1/status`, `/metrics`, `/health`, `/data/query`.
  - HTTP POST profile space: counts 2–5, intervals 0.25–0.45s, paths `/api/v1/upload`, `/data/sensor`, `/data/event`, `/api/v1/submit`, `/log/event`, payloads 64–512 bytes with deterministic payload SHA-256 digests.
- **Evidence Agreement & Outer ESP Domain:**
  - 30/30 experiments verified: 100% agreement on request counts, status codes (all 200 OK), response byte counts, and response-body SHA-256 digests.
  - All 30 PC1 raw PCAPs verified to contain valid outer ESP/NAT-T frames.
  - Recomputed SHA-256 digests on all 30 sets of artifacts match recorded manifest hashes.
  - Outer ESP features reflect encrypted tunnel traffic shape only; inner HTTP URLs, headers, and plaintext are not visible in outer ESP.
- **Dataset Qualification:**
  - 30 accepted observations, 0 quarantined observations.
  - Session-level 9/3/3 split: 18 train rows (9 sessions), 6 validation rows (3 sessions), 6 test rows (3 sessions).
  - Zero session overlap, zero IKE SPI key overlap between splits.
  - Status: `READY_FOR_REVIEW` for dataset qualification.
- **Test Suite Status:** Full workspace suite: `122 passed, 10 skipped, 4 warnings` (offline) / `4 passed` live integration tests.
- **Model Policy:** No ML model trained, promoted, or deployed.

## Phase 8: Unified Multi-Workload Dataset and Label Qualification (2026-10-10)

- **Status:** VERIFIED for label schema ontology, 60-observation unified multi-workload campaign, and session-level 9/3/3 dataset qualification (`READY_FOR_REVIEW`); model training, promotion, and deployment remain deliberately unperformed.
- **Target Label Ontology:**
  - Implemented formal schema: `vista-target-label-schema-v1.json`.
  - Canonical classes: `controlled_icmpv4`, `controlled_tcp_marker`, and `controlled_http`.
  - HTTP GET (`http_get`) and POST (`http_post`) remain preserved as workload subtypes in observation metadata.
  - Domain boundary: encrypted outer ESP metadata only (`vista-flow-v1`); inner HTTP headers, URLs, and payloads are strictly excluded.
- **Unified Campaign Execution:**
  - Campaign UUID: `76adc766-ef41-45f5-b677-1d950c7ff052`.
  - Runner: `scripts/run_collection_campaign.py --workload unified --sessions 15 --seed 26160`.
  - 15 sessions with re-established IKE_SAs (`independenceStatus: VERIFIED_DISTINCT_IKE_SA`).
  - 60 total observations across all 4 workload configurations (15 ICMPv4, 15 TCP marker, 15 HTTP GET, 15 HTTP POST).
  - 100% endpoint agreement (echo replies, TCP payload hashes, HTTP 200 status codes with response body SHA-256 digests).
  - All 60 PC1 PCAPs confirmed to contain valid IPv4 outer ESP/NAT-T frames.
  - Recomputed SHA-256 checksums match across all 60 artifact bundles.
- **Dataset Qualification & Leakage Prevention:**
  - Prepared via `prepare_experiment_dataset.py`: 60 accepted, 0 quarantined.
  - 9/3/3 session split: Train: 36 rows (9 sessions), Validation: 12 rows (3 sessions), Test: 12 rows (3 sessions).
  - Every split contains all 3 target classes:
    - Train: 18 HTTP, 9 ICMP, 9 TCP marker.
    - Validation: 6 HTTP, 3 ICMP, 3 TCP marker.
    - Test: 6 HTTP, 3 ICMP, 3 TCP marker.
  - Zero session overlap, zero IKE SPI overlap across all splits.
  - Zero duplicate or near-duplicate feature vectors.
  - Dataset status: `READY_FOR_REVIEW`.
- **Campaign Audit:**
  - `scripts/audit_phase8_campaign.py` ran against `76adc766-ef41-45f5-b677-1d950c7ff052`: `audit_passed: true`, 0 issues.
- **Regression Tests:**
  - `backend/test_label_qualification.py`: 8 tests covering label schema, mapping, 15-session qualification, split integrity, hash mismatch quarantine, contradictory evidence quarantine, and identifier leakage quarantine (all 8 passed).
  - `backend/test_collection_campaign.py`: 10 passed including unified mocked campaign.

## Phase 9: Independent Dataset Audit and Baseline Eligibility (2026-10-10)

- **Status:** VERIFIED for independent artifact audit, recomputed feature parity, session independence, and exploratory baseline experiment eligibility gate (`baseline_eligibility: PASS`); production promotion remains deliberately `BLOCKED` (`independent_campaign_validation: BLOCKED`).
- **Audit Findings:**
  - Audited campaign `76adc766-ef41-45f5-b677-1d950c7ff052` using `scripts/audit_phase9_dataset.py`.
  - 60/60 raw PCAP SHA-256 hashes recomputed and matched; 100% outer ESP / NAT-T frame presence confirmed via Scapy.
  - 60/60 packet CSV SHA-256 hashes verified.
  - 60/60 feature rows re-extracted from raw packet tables: 100% agreement with `prepared_dataset.csv` across all 18 `vista-flow-v1` features (0 discrepancies).
  - 60/60 endpoint ground-truth records confirmed (ICMP reply counters, TCP payload hashes, HTTP 200 OK status codes with client/server response body SHA-256 digests).
  - 15/15 sessions verified with genuine IKE_SA terminate-and-reinit lifecycle (`independenceStatus: VERIFIED_DISTINCT_IKE_SA`).
  - Leakage controls: 0 session overlap, 0 IKE_SA identity overlap, 0 SPI overlap; 0 duplicate and 0 near-duplicate feature vectors.
- **Machine-Readable Gate Decisions:**
  - Persisted in [`vista-ml/reports/phase9_dataset_audit.json`](../vista-ml/reports/phase9_dataset_audit.json).
  - `artifact_integrity`: `PASS`
  - `ground_truth_integrity`: `PASS`
  - `label_integrity`: `PASS`
  - `feature_integrity`: `PASS`
  - `leakage_controls`: `PASS`
  - `class_coverage`: `PASS`
  - `split_validity`: `PASS`
  - `independent_campaign_validation`: `BLOCKED` (single 15-session campaign on single testbed; cross-campaign evaluation required)
  - `baseline_eligibility`: `PASS` (authorized solely for an exploratory baseline experiment specification)
  - Total discrepancies: 0.
- **Baseline Experiment Protocol (Specification Only):**
  - Specified three-model evaluation suite in [`docs/PHASE9_DATASET_AUDIT.md`](./PHASE9_DATASET_AUDIT.md): majority-class baseline (predicts `controlled_http`), interpretable shallow decision tree (depth <= 2), and conventional Random Forest (100 trees, depth <= 4).
  - Zero model training executed; production deployment and operational inference eligibility remain strictly blocked.
- **Regression Tests:**
  - Added `test_phase9_saved_audit_report_matches_schema_and_gates` and `test_phase9_audit_recomputes_parity_and_session_independence` to `backend/test_label_qualification.py` (all 10 passed).

## Phase 10: Baseline ML Training and Optuna Hyperparameter Optimization (2026-10-10)

- **Status:** VERIFIED for eligibility-gate enforcement, non-optimized baselines, leakage-aware Optuna search, diagnostic shortcut ablations, held-out test evaluation, and artifact versioning; production deployment and live inference remain deliberately `BLOCKED` (`validated_for_inference: false`).
- **Eligibility Gate:** Validated [`vista-ml/reports/phase9_dataset_audit.json`](../vista-ml/reports/phase9_dataset_audit.json); verified `baseline_eligibility: PASS`, all 7 prerequisite integrity gates `PASS`, `independent_campaign_validation: BLOCKED`, and 0 discrepancies.
- **Non-Optimized Baselines (3-Fold Session-Grouped CV on Training Set):**
  - Majority-class baseline: Mean Macro-F1 = 0.2222, Mean Accuracy = 0.5000.
  - Interpretable decision tree (max_depth=2): Mean Macro-F1 = 0.7978 ($\pm 0.1402$), Mean Accuracy = 0.8611.
  - Initial Random Forest (100 trees, max_depth=4): Mean Macro-F1 = 0.9692 ($\pm 0.0435$), Mean Accuracy = 0.9722.
- **Optuna Hyperparameter Optimization:**
  - 30 trials with deterministic `TPESampler(seed=42)` maximizing 3-fold session-grouped CV macro-F1 on training sessions only.
  - Best trial: Trial 6, achieving validation macro-F1 = 1.0000.
  - Selected hyperparameters: `n_estimators=130`, `max_depth=8`, `min_samples_split=2`, `min_samples_leaf=1`, `max_features=None`, `class_weight='balanced'`.
- **Shortcut & Diagnostic Ablations:**
  - Single features: `std_packet_size` alone scores 0.8893 macro-F1 (uniform ping size 0.0 vs variable TCP/HTTP); `packet_count` alone scores 0.8429 macro-F1.
  - Excluding `packet_count`: Macro-F1 remains 0.9692 ($\pm 0.0435$).
  - Leave-one-feature-out: All 18 ablations retain macro-F1 between 0.9286 and 1.0000 due to redundant size, timing, and direction representations.
  - Timing-only group: 0.7986 macro-F1; Size/byte group: 0.8192 macro-F1.
- **Held-Out Test Evaluation:**
  - Evaluated on 3 held-out test sessions (12 observations): Accuracy = 1.0000, Macro-F1 = 1.0000.
  - Critical uncertainty disclosure: 12 observations from 3 sessions on a single testbed have high statistical uncertainty (Wilson 95% CI: $[0.758, 1.000]$) and reflect testbed recipe consistency, not general operational application identification.
- **Candidate Model Artifact:**
  - Persisted at `vista-ml/models/candidates/controlled_workload_classification/20261010T082308Z-6b8eb840/random_forest.joblib` with sidecar metadata explicitly marking `"validated_for_inference": false`, `"production_eligible": false`, `"experimental": true`.
- **Regression Tests:**
  - Created `vista-ml/tests/test_optuna_baseline.py` covering eligibility-gate enforcement, feature allowlisting, group separation, deterministic study configuration, trial logging, test-set isolation, and schema compliance (8 passed).

## Phase 11: Data Leakage Audit and Independent-Campaign Validation (2026-10-10)

- **Status:** VERIFIED for exhaustive data leakage audit (`final_decision: NO_LEAKAGE_DETECTED_WITHIN_SCOPE`), full 18-feature lineage tracking, exact Phase 10 reproduction, shallow decision tree inspections, key contrast ablations, session-grouped permutation testing ($p=0.0099$), and out-of-campaign evaluation across 60 independent observations (Phase 5 & Phase 7 campaigns, achieving 96.67% accuracy / 0.9654 macro-F1); production promotion and live inference remain deliberately `BLOCKED` (`validated_for_inference: false`, `production_eligible: false`).
- **Audit Findings on Perfect Held-Out Score (1.0000):**
  - **Hypothesis 1 (Data Leakage): REJECTED.** Audited all 18 flow features from raw PCAPs through `_compute_flow_features` to feature matrix $X$. Zero target labels or metadata columns in $X$, zero cross-split session overlap, zero duplicate vectors across splits, zero future information, and no learned scalers fitted across folds.
  - **Hypothesis 2 (Recipe-Specific Correlation): CONFIRMED.** Traffic recipes induce deterministic flow signatures: `std_packet_size` alone scores 0.8893 CV macro-F1 because ping echo requests/replies have uniform size (`std=0.0`), perfectly separating ICMP. `packet_count` alone scores 0.8429 CV macro-F1 due to discrete recipe counts. Depth-1 decision tree separates ICMP using `std_packet_size <= 2.25`; depth-2 tree solves the entire 3-class test set with rules on `std_packet_size` and `packet_count <= 26.0`.
  - **Hypothesis 3 (Genuine Class Separability): CONFIRMED.** Even when BOTH `packet_count` and `std_packet_size` are removed, the remaining 16 features achieve 0.9692 CV macro-F1 and 1.0000 test macro-F1 due to redundant size, byte volume, and directional ratios (`direction_ratio = 0.500` for ICMP vs asymmetric for TCP/HTTP).
  - **Hypothesis 4 (Evaluation Limitations): CONFIRMED.** Test set contains only 12 observations from 3 sessions (Wilson 95% CI: $[0.7575, 1.0000]$). Perfect score is an artifact of testbed recipe consistency and small sample size.
- **Session-Grouped Permutation Test:**
  - 100 permutations permuting intact session blocks (seed 42): Real macro-F1 = 0.9692, Permuted null distribution mean = 0.3231 ($\pm 0.1037$, max = 0.6327), Empirical $p = 0.0099$. Rejects noise-fitting hypothesis.
- **Independent-Campaign Validation (60 Genuinely Independent Observations):**
  - Evaluated frozen Phase 10 model against 30 observations from Phase 5 (`e2e8adae-94d7-4a1d-9569-3c3e1a965e64`, ICMP & TCP marker) and 30 observations from Phase 7 (`9bd6b15c-507d-451a-89eb-7071944f105f`, HTTP GET & POST) across 30 independent sessions.
  - **Overall Accuracy:** 96.67% (58/60 correct, Wilson 95% CI: $[0.8864, 0.9908]$).
  - **Macro-F1 Score:** 0.9654.
  - **Per-Class Breakdown:** Controlled ICMP: 15/15 (F1=1.000); Controlled HTTP: 30/30 (F1=0.9677); Controlled TCP marker: 13/15 (F1=0.9286), with 2 misclassified as HTTP due to overlapping byte counts.
  - Demonstrates that real independent generalization drops to ~96.67% and is not 1.0000.
- **Production Safeguards:**
  - `validated_for_inference = false`
  - `production_eligible = false`
  - `experimental = true`
- **Regression Tests & Deliverables:**
  - Added `vista-ml/tests/test_phase11_leakage_audit.py` (5 passed).
  - Generated `vista-ml/reports/phase11_leakage_audit_report.json`.
  - Author documentation in `docs/PHASE11_LEAKAGE_AND_GENERALIZATION_AUDIT.md`.

---

## Phase 12: Robustness Validation Under Changed Traffic Recipes (2026-10-10)

- **Status:** VERIFIED (`ROBUSTNESS_SUPPORTED_WITHIN_TESTED_SCOPE`).
- **Objective:** Determine whether the frozen Phase 10 candidate classifier (`random_forest.joblib`, SHA-256 `de9d6334...`) generalizes when workload traffic recipes are perturbed across packet counts, inter-arrival timing, payload sizes, and durations.
- **Collection Pipeline Enhancements:**
  - Added `--recipe-mode [standard|varied]` to `scripts/run_collection_campaign.py`.
  - Introduced disjoint profile spaces (`VARIED_PROFILE_SPACE`, `VARIED_HTTP_GET_PROFILE_SPACE`, `VARIED_HTTP_POST_PROFILE_SPACE`) with counts $\in \{4, 6, 8, 12\}$ pkts, intervals $\in \{0.15, 0.35, 0.55, 0.75\}$ s, and payloads $\in \{48, 96, 192, 384, 768, 1200\}$ B.
- **New Live Varied-Recipe Campaign (`d645e930-010c-4f8a-a10a-fe7f22aef309`):**
  - Completed 15 independent IKE_SA sessions, 60 observations (15 ICMP, 15 TCP marker, 30 HTTP), 0 failed, 0 quarantined, 100% endpoint agreement, outer ESP verified.
  - Prepared dataset with 9/3/3 split (`READY_FOR_REVIEW`).
- **Frozen Model Evaluation on Varied Campaign:**
  - **Overall Accuracy:** 96.67% (58/60 correct).
  - **Macro-F1 Score:** 0.9654.
  - **Wilson 95% CI:** $[0.8864, 0.9908]$.
  - **Cluster-Robust Session Bootstrap 95% CI:** $[0.9167, 1.0000]$.
  - **Per-Class Metrics:**
    - `controlled_icmpv4`: 15/15 ($F_1 = 1.0000$).
    - `controlled_http`: 30/30 ($F_1 = 0.9677$).
    - `controlled_tcp_marker`: 13/15 ($F_1 = 0.9286$).
  - **Misclassifications:** Exactly 2 TCP marker observations (`0cc87473-...` and `cd5cbe4e-...`) misclassified as HTTP due to volume/byte overlapping into the small HTTP profile.
- **Traffic Feature Distribution Shifts:**
  - `packet_count` mean shifted +24.0% (14.71 -> 18.25 pkts).
  - `mean_packet_size` shifted -27.7% (312.6 -> 226.1 B).
  - `max_packet_size` shifted -20.3% (543.9 -> 433.6 B).
  - Invariants: `direction_ratio = 0.500` and `std_packet_size = 0.0` held strictly for all 15 ICMP flows.
- **Methodological Verification:**
  - Within-session permutation test (preserving exact marginal class counts within all 9 sessions) ran 100 iterations: Real F1 = 0.9692, Null mean F1 = 0.3065 ($\pm 0.0895$, max = 0.6147), Empirical $p = 0.0099$. Rejects noise-fitting hypothesis.
- **Multiplexed Traffic Feasibility Assessment:**
  - **Status:** ARCHITECTURALLY BLOCKED for single outer ESP SA.
  - **Reason:** Under `vista-flow-v1`, outer flow key `(50, 172.20.0.2:0, 172.20.0.3:0)` merges all concurrent inner traffic traversing the tunnel into one aggregate outer ESP flow. Extracting isolated ground-truth flows from multiplexed streams is impossible without inner plaintext or separate CHILD_SAs with dedicated SPIs.
- **Production Safeguards Preserved:**
  - `validated_for_inference = false`
  - `production_eligible = false`
  - `experimental = true`
- **Deliverables & Regression Tests:**
  - Added `docs/PHASE12_ROBUSTNESS_VALIDATION.md`.
  - Machine-readable report: `vista-ml/reports/phase12_robustness_report.json`.
  - Added regression test suite: `vista-ml/tests/test_phase12_robustness.py` (5/5 passed).

---

## Phase 13: Expanded Workload Coverage and Honest Classification Boundaries (2026-10-10)

- **Status:** VERIFIED (`COLLECTED_AND_VALIDATED` for RTP/UDP VoIP; `IMPLEMENTED_NOT_VALIDATED` for SMTP; `BLOCKED` for Video and IPv6).
- **Objective:** Expand the evidence-backed controlled workload dataset beyond ICMP, TCP marker, and HTTP, evaluate out-of-distribution traffic under the frozen Phase 10 candidate model, and establish honest classification boundaries.
- **Feasibility Matrix Decisions:**
  - `controlled_icmpv4`: **COLLECTED_AND_VALIDATED** (Phase 8/11/12 baseline).
  - `controlled_tcp_marker`: **COLLECTED_AND_VALIDATED** (Phase 8/11/12 baseline).
  - `controlled_http`: **COLLECTED_AND_VALIDATED** (Phase 8/11/12 baseline).
  - `controlled_rtp_voip`: **COLLECTED_AND_VALIDATED** (15 sessions in campaign `9f3f1f2b-7a6e-468c-b86d-1f9bee65d8bf`).
  - `controlled_smtp`: **IMPLEMENTED_NOT_VALIDATED** (RFC 5321 client/server state machine verified in unit integration; formal campaign pending).
  - `controlled_video_streaming`: **BLOCKED** (no media codecs or streaming daemons in containers; synthetic bursts lack authentic video codec structure).
  - `ipv6_traffic`: **BLOCKED** (Docker bridge lacks IPv6 subnet; StrongSwan traffic selectors are IPv4-only `/32`).
- **RTP/UDP Voice-over-IP Live Collection Campaign (`9f3f1f2b-7a6e-468c-b86d-1f9bee65d8bf`):**
  - Generated RFC 3550 RTP/UDP packets (12-byte header, SSRC, monotonically advancing sequence, timestamp, G.711 frames).
  - Completed 15 independent IKE_SA sessions, 15 accepted outer ESP flows, 0 failures, 0 quarantined, 100% endpoint agreement (`READY_FOR_REVIEW`).
- **Empirical OOD Evaluation of Frozen Phase 10 Model:**
  - Evaluated the frozen closed-world 3-class model against 15 new `controlled_rtp_voip` observations.
  - **Result:** **100% misclassified as `controlled_http`** (15/15), with mean probabilities: 55.4% HTTP, 33.8% ICMPv4, 10.8% TCP marker.
  - **Root Cause:** RTP exhibits `std_packet_size = 0.00` (like ICMP) but `direction_ratio = 1.000` (unidirectional, violating ICMP's symmetric `0.50` requirement). Trees routed to HTTP as fallback.
  - **The Closed-World Fallacy:** Proves that high accuracy within controlled training recipes (Objective 2) does **not** transfer to arbitrary application identification (Objective 3). Unmodeled encrypted protocols are silently and confidently misclassified.
- **The Four Explicit Classification Scopes Defined:**
  - Objective 1 (Tunnel Metadata): **VALIDATED**
  - Objective 2 (Controlled Workload Classification): **VALIDATED WITHIN SCOPED RECIPES**
  - Objective 3 (Inner Application Identification): **BLOCKED / NOT SUPPORTED**
  - Objective 4 (Attack Detection): **BLOCKED / NOT SUPPORTED**
- **Multiplexing Feasibility Assessment:**
  - **Verdict:** ARCHITECTURALLY BLOCKED for single ESP tunnel. Outer flow key `(50, 172.20.0.2:0, 172.20.0.3:0)` merges all concurrent tunnel traffic into a single aggregate outer ESP flow.
- **Production Safeguards Preserved:**
  - `validated_for_inference = false`
  - `production_eligible = false`
  - `experimental = true`
- **Deliverables & Regression Tests:**
  - Created `docs/PHASE13_EXPANDED_WORKLOAD_COVERAGE.md`.
  - Machine-readable report: `vista-ml/reports/phase13_workload_coverage_report.json`.
  - Created `vista-ml/schemas/vista-target-label-schema-v2.json`.
  - Added regression test suite: `vista-ml/tests/test_phase13_workload_coverage.py` (11/11 passed).

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

---

## Cryptographic Matrix Verification (2026-10-10)

The current controlled integration runs use Docker Desktop with StrongSwan 5.9.8. Every live scenario applies a temporary configuration to `pc1` and `pc2`, terminates only the named `pc1-pc2` test connection, initiates the IKE_SA separately from the CHILD_SA (so PFS is tested through CREATE_CHILD_SA), checks `swanctl --list-sas --raw`, sends three IPv4 ICMP echo requests, compares CHILD_SA counters, captures packets to a scenario PCAP, then reloads and re-establishes the checked-in baseline. The mounted `configs/pc1-swanctl.conf` and `configs/pc2-swanctl.conf` remain unchanged.

Verified live configurations (all `PASS`, 3/3 ICMP replies, CHILD_SA counters +3 packets and +252 bytes in each direction, baseline restored):

| Scenario | IKE_SA | ESP CHILD_SA | PFS |
|---|---|---|---|
| `live-aes128-gcm-modp2048-pfs-capture` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048 | AES-GCM-16-128, no separate integrity transform, TUNNEL | MODP-2048 |
| `live-aes256-gcm-modp2048-pfs` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048 | AES-GCM-16-256, no separate integrity transform, TUNNEL | MODP-2048 |
| `live-aes128-cbc-hmac-modp2048-pfs` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048 | AES-CBC-128 / HMAC-SHA2-256-128, TUNNEL | MODP-2048 |
| `live-aes256-cbc-hmac-modp2048-pfs` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048 | AES-CBC-256 / HMAC-SHA2-256-128, TUNNEL | MODP-2048 |
| `live-aes256-gcm-modp3072-pfs` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-3072 | AES-GCM-16-256, no separate integrity transform, TUNNEL | MODP-3072 |
| `live-aes256-gcm-modp2048-no-pfs` | AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048 | AES-GCM-16-256, no separate integrity transform, TUNNEL | Explicitly absent |

Machine-readable per-scenario results and captures are stored below `captures/strongswan/experiments/`; `captures/strongswan/capability_report.json` is rebuilt from those result records. Secrets are redacted in the JSON and logs. The runtime advertised MODP-2048 and MODP-3072. ECP-256 (group 19) was attempted and returned `BLOCKED` because it is absent from the actual runtime DH algorithm set; it was not substituted.

The SA parser deliberately keeps IKE key exchange and CHILD_SA PFS separate. A first combined IKE_AUTH/CHILD_SA attempt did not expose a child PFS group, so it was correctly recorded as `FAIL`; the runner was changed to establish IKE first and create the child separately, after which PFS-enabled and PFS-disabled operation were independently observed.

Remaining testbed limits:

- Transport mode: configured but **NOT TESTED** end-to-end in this matrix.
- IPv6: **BLOCKED**; current running Docker network has no global IPv6 endpoint addresses.
- eBPF runtime events, continuous SA posture ingestion, and real application-layer workloads: not verified by these cryptographic experiments.
- `swanctl --list-algs` does not list AES-GCM under this container’s loaded plugin output even though the GCM CHILD_SAs negotiated and passed live traffic tests. Therefore runtime algorithm-list visibility is reported separately from live negotiation evidence.

Reproduce a passing scenario from the repository root:

```powershell
.\.venv\Scripts\python scripts\run_vpn_experiment.py --mode tunnel --cipher aes128gcm16 --dh-group 14 --ip-version IPv4 --traffic-type icmpv4 --scenario-id reproduce-aes128-gcm
```

Other verified suite variants can be reproduced by changing `--cipher` to `aes256gcm16`, `aes128`, or `aes256`; select group 15 using `--dh-group 15`; disable PFS using `--no-pfs`. Every run returns a nonzero process status unless live verification and baseline restoration both pass.

## ML Pipeline Evidence Boundary (2026-10-10)

The prior synthetic classifier metrics and SHAP files are not production validation. The current root model artifacts do not declare the required approved feature schema and `validated_for_inference` metadata, so backend inference is disabled for them. The checked-in StrongSwan PCAP was parsed successfully, but its outer ESP and IKE flows are correctly marked out-of-distribution with null traffic/attack/anomaly predictions.

There is scoped laboratory evidence outside those synthetic artifacts: the corrected ESP-only benign candidate reproduces 1.0 held-out metrics on 50 packet-table rows (25/class), but the shortcut audit found 14/18 single features and a depth-1 tree also score 1.0, and feature ablations retain 1.0. The fixed workload labels are encoded in experiment IDs/filenames. The split is experiment-disjoint but not session-independent: train and validation share processing run `20261005T155313Z`, and the 50-row test comes from one other processing run. There are no verified source-session IDs, per-observation raw PCAPs, or independent ground-truth sidecars in these source directories. Therefore these metrics do not support generalization; the candidate remains inference-blocked. A manifest-driven dataset preparation pipeline and varied-workload collection protocol are tested offline, but the historical observations cannot satisfy their provenance gate. The earlier 28/8/50 report mixed cleartext ICMP/TCP capture planes with ESP captures; it remains preserved but is invalid for an ESP-only claim. IPv4 `vista-flow-v1` batch/backend feature parity is unit-tested. A separate historical IKE DH classifier's ECP-256 labels remain unverified without per-handshake SA transcripts.

The current testbed has a real fixed three-request ICMPv4 ping path. Its variable-duration/rate/payload collection controls and a measured TCP echo endpoint are not yet implemented. RTP-like, HTTP/HTTPS, SMTP, WhatsApp-like, and video summaries from the static runner are synthetic, not captured endpoint traffic. See [ML_DATA_COLLECTION_PROTOCOL.md](./ML_DATA_COLLECTION_PROTOCOL.md) and the shortcut report at [shortcut_ablation_report.json](../vista-ml/reports/audits/phase3-20261010/shortcut_ablation_report.json).

The ISCXVPN2016 consolidated labeled CSV has 18,758 rows and 14 application/VPN labels (seven application categories with VPN and non-VPN labels), but no capture/session group identifier. Its 102 per-capture CSVs contain `No Label` on all 65,249 rows. Its time-based flow features do not match the runtime's packet-level schema. The public-dataset experiment requires a source-provided independent group key and refuses a row-level split. No public-data model was trained from this archive. Attack inference remains blocked: current attack labels are synthetic; no independently labeled operational attack/benign data exists on the runtime feature schema.

All ML training commands write candidate-only artifacts under versioned `models/candidates/` and `reports/candidates/` directories. Anomaly training no longer derives a detection threshold from training-normal samples. SHAP generation requires an approved model and a hash-matched held-out dataset. Candidate results are not enabled for inference.

The detailed evidence matrix and machine-readable report are maintained in [ML_PIPELINE_AUDIT.md](./ML_PIPELINE_AUDIT.md) and [ml_capability_report.json](../vista-ml/reports/ml_capability_report.json). These ML limitations do not change the separately recorded live VPN cryptographic-matrix results above.

---

## Pre-Finals Prototype Freeze and Evaluation Readiness (2026-10-11)

- **Status:** `READY_FOR_PREFINALS`
- **Candidate Model:** Optuna-tuned Random Forest candidate (`20261010T082308Z-6b8eb840`, SHA-256: `de9d6334309ad1b286ce917c28de49833d4f186e2022fc3b03d53b2c2a826de8`).
- **Production Admission Safeguards:**
  - `validated_for_inference = false`
  - `production_eligible = false`
  - `experimental = true`
  - ModelService blocks predictions on unapproved candidates (`status: unsupported_input`).
- **Data Leakage & Evaluation Audits:**
  - Full 18-feature lineage audit completed (`audit_phase11_leakage.py`): Zero target contamination, zero identifier leakage, fold-safe preprocessing, disjoint IKE_SA session grouping.
  - Recipe-specific correlations confirmed and documented (`std_packet_size = 0.0` for ping echoes, discrete packet count ranges).
  - Robustness confirmed under varied traffic recipes (`d645e930-010c-4f8a-a10a-fe7f22aef309`): 96.67% accuracy (58/60 correct) across randomized packet counts, intervals, and payload sizes.
  - Closed-world boundary empirically demonstrated on unseen RTP/UDP VoIP traffic (100% misclassified as HTTP).
- **Core Testbed Demonstration:**
  - PC1↔PC2 StrongSwan 5.9.8 Docker containers verified live; IPsec tunnel established.
  - Automated live testbed verification passed (`test_live_runtime_experiment_baseline`).
  - All 8 dashboard views (Overview, Testbed, Traffic Analysis, AI Analysis, Security Assessment, Threat Intelligence, Reports, Dataset) operational with real telemetry and schema-governed PCAP analysis.
- **Verification Summary:**
  - `vista-ml` test suite: 68/68 passed.
  - `backend` test suite: 97/97 passed (10 opt-in live tests skipped).
  - Machine-readable evidence: `vista-ml/reports/prefinals_validation_report.json`.
  - Comprehensive readiness report: `docs/PREFINALS_READINESS.md`.

---

## Dataset Studio & Editorial Light UI Redesign (2026-10-11)

- **Status:** `DELIVERED_AND_VERIFIED`
- **Design System:** Editorial Light + Industrial Engineering aesthetic (`#F5F2EC` warm ivory base, pure white surfaces, `#292D2A` charcoal text, muted slate secondary text, soft sage, muted amber, restrained lilac, powder blue, and muted coral semantic accents). Zero neon, glowing borders, or cyberpunk elements.
- **Dataset Studio Architecture:**
  - **Dataset Overview:** Live KPI counters for total samples, flows, rows, and packets with distinct units, class balance distribution, validation status, and provenance.
  - **Dataset Registry:** Searchable, filterable table of all campaign and sample datasets with metadata inspection, quality validation trigger, and safe file export.
  - **7-Stage Testbed Dataset Generation Wizard:**
    - Stage 1: Guided configuration restricted to real testbed capabilities (IPv4, Tunnel/Transport, AES-GCM/CBC, DH Group 14, ICMP / TCP marker traffic, duration and repetition bounds).
    - Stage 2: Automated preflight check verifying Docker container health, StrongSwan charon daemon, disk space, and permissions.
    - Stage 3: Real background experiment runner with unique experiment ID, CHILD_SA verification, packet capture, and stage-based progress polling.
    - Stage 4: Feature extraction conforming to canonical `vista-flow-v1` schema with feature ordering, units, and extractor version recorded.
    - Stage 5: Trustworthy ground-truth labeling derived from negotiated SA evidence and traffic generator identity.
    - Stage 6: Dataset quality & leakage checks (null/inf, class imbalance, duplicate detection, cross-experiment contamination).
    - Stage 7: Versioned immutable export (Parquet/CSV, manifest, checksums).
- **Backend Service & API (`backend/services/dataset_service.py`):**
  - Typed endpoints: `GET /api/datasets`, `GET /api/datasets/capabilities`, `POST /api/datasets/preflight`, `POST /api/datasets/generate`, `GET /api/datasets/jobs/{job_id}`, `POST /api/datasets/jobs/{job_id}/cancel`, `GET /api/datasets/{dataset_id}`, `POST /api/datasets/{dataset_id}/validate`, `GET /api/datasets/{dataset_id}/export`.
  - Safe export handling preventing path traversal.
  - Strict ML isolation: testbed dataset generation never automatically promotes models or enables `validated_for_inference`.
- **Sample Dataset Committed:** `vista-ml/data/sample/vista_testbed_sample_dataset.csv` and `vista-ml/data/sample/vista_testbed_sample_dataset.manifest.json` providing a reproducible, leakage-free 15-flow baseline for evaluation without requiring Docker.
- **Verification:**
  - Backend test suite: 97 passed, 10 skipped.
  - ML test suite: 68 passed.
  - Frontend: clean build (`vite build` in ~1.1s) and clean lint (`oxlint` with 0 errors).
# Dataset pipeline status update (2026-10-11)

- Implemented: deterministic, explicitly synthetic software fixtures with manifest and artifact hashes; the fixture manifest is not an evaluation split.
- Implemented, not end-to-end verified: benign ICMP and bounded allowlisted PC2 port-scan scenario APIs, target-side SYN evidence parsing, cancellation request state, and scenario metadata.
- Intentionally deferred: flood, brute force, beaconing, bulk transfer, and mixed campaigns pending successful acceptance of the initial pair.
- Admission limitation: collected campaign output remains `UNVERIFIED`; the current generation worker does not yet build/validate the canonical session evidence manifest and independent session split needed for dataset admission. A split with fewer than three independent sessions is not evaluation-ready.
- Dataset Studio shows only the initial pair and no longer asserts that generated observations are verified or quality-passed. Backend unavailable remains an explicit fetch error.
- ZIP export packages the CSV with available provenance manifest, quality/split reports, and matching feature schema. Missing optional metadata is omitted and does not elevate admission.
- Live testbed workflow and export/revalidate acceptance are not claimed by this change; run only when the existing lab state is checked and a recovery plan is available.

## Live data audit update (2026-10-11)
The eight-page value/source matrix, confirmed defects and replacements, backend sources, regression tests, live UI observations, and unavailable capabilities are recorded in [LIVE_DATA_HARDCODE_AUDIT.md](LIVE_DATA_HARDCODE_AUDIT.md). The existing running backend was not restarted; its process will not expose new response fields until safely reloaded. No live workload was run.
