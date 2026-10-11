# SIH26160 Requirements and Evidence Matrix

**Problem:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
**Organization:** National Technical Research Organisation (NTRO)
**Audit date:** 2026-10-11

## Status definitions

- `VERIFIED` — the specific claim has matching runtime or artifact evidence.
- `PARTIALLY_VERIFIED` — one or more variants are verified, with scope limits listed.
- `IMPLEMENTED_UNVERIFIED` — implementation/configuration exists but the required experiment has not been evidenced.
- `CONFIGURATION_VALIDATED` — schema or preflight validation passed; this does not prove negotiation or operation.
- `BLOCKED` — the capability is gated or cannot be claimed with the available evidence.
- `NOT_IMPLEMENTED` — no implementation is present.
- `NOT_APPLICABLE` — the requirement does not apply to this system.

Status applies to the exact scope in the “Requirement” column. An implementation, configuration, screenshot, or unit test alone is not runtime verification.

## A. VPN testbed generation

| Requirement | Implementation and source of truth | Evidence and test procedure | Status | Remaining work |
|---|---|---|---|---|
| Direct PC1 ↔ PC2 tunnel mode | `topology/docker-compose.yml`; `backend/services/vpn_testbed.py` | `captures/strongswan/capability_report.json` records `tunnel_mode=PASS`; current `GET /api/testbed/live-status` at 2026-10-11 10:54 IST reported IKEv2 ESTABLISHED and ESP CHILD_SA INSTALLED, mode `TUNNEL`, selectors `172.20.0.2/32` ↔ `172.20.0.3/32`. | `VERIFIED` | Repeat from a clean startup for each demo and retain the experiment manifest and artifact hashes. |
| Transport mode | Validator and parameter path exist; there is no successful transport profile in the live testbed. | Capability report records `transport mode=NOT TESTED`; `GET /api/testbed/profiles` is now labeled `IMPLEMENTED_UNVERIFIED`. | `IMPLEMENTED_UNVERIFIED` | Build an actual transport config, negotiate it, verify installed XFRM state and endpoint traffic, then retain artifacts. |
| AES-128-GCM and AES-256-GCM | Proposal generation and runtime SA parser in `backend/services/vpn_testbed.py`. | Capability report records `aes128gcm=PASS` and `aes256gcm=PASS`; each passing experiment requires negotiated SA and traffic/capture evidence. | `VERIFIED` | Re-run after StrongSwan/runtime upgrades. |
| AES-128-CBC + HMAC and AES-256-CBC + HMAC | CBC proposal generation and negotiated-SA checks in `backend/services/vpn_testbed.py`. | Capability report records both CBC/HMAC variants as `PASS`; see its experiment records and referenced PCAPs. | `VERIFIED` | Re-run after StrongSwan/runtime upgrades. |
| Multiple Diffie–Hellman groups | Runtime proposal and SA parsing supports group reporting. | MODP-2048/group 14 and MODP-3072/group 15 have passing experiment records. ECP-256/group 19 is recorded as blocked/unavailable; group 20 is not demonstrated. | `PARTIALLY_VERIFIED` | Add and retain successful ECP experiments if the runtime supports them; otherwise keep unavailable. |
| PFS enabled and disabled | CHILD_SA DH group is checked by the testbed runner. | Capability report records passing PFS-on and PFS-off experiments; the current live status reports PFS enabled with group 14. | `VERIFIED` | Repeat both variants in the reproducible matrix. |
| IPv4 communication | Direct IPv4 bridge and workload runner. | Current live status reports the two direct endpoint addresses and installed CHILD_SA; prior experiment records include endpoint traffic and packet captures. | `VERIFIED` | Preserve current experiment artifact references in demo output. |
| IPv6 communication | PCAP parser recognizes IPv6 frames; Compose network has no global IPv6 subnet. | Capability report records IPv6 as blocked; `GET /api/datasets/capabilities` reports IPv6 unsupported because the bridge lacks a global IPv6 subnet. | `BLOCKED` | Configure a dual-stack testbed and run a real IPv6 negotiation and workload. |
| ICMP, TCP marker, HTTP, and RTP/VoIP workloads | `backend/services/workload_collection.py`; controlled traffic paths run between PC1 and PC2. | Collection manifests and dataset registry include ICMP, TCP marker, HTTP, and RTP/VoIP sessions. Phase 13 evidence is in `docs/PHASE13_EXPANDED_WORKLOAD_COVERAGE.md`. | `VERIFIED` | Repeat required profiles against a clean tunnel and preserve endpoint-side ground truth. |
| Email, WhatsApp-like, and video-streaming workloads | No validated live generators for these profiles. Synthetic labels and UI/catalog names are not execution evidence. | `GET /api/datasets/capabilities` does not offer these as executed generators; previous phase reports mark these recipes unverified or synthetic. | `NOT_IMPLEMENTED` | Implement endpoint generators and capture receiver-side ground truth before claiming them. |

## B. Traffic capture and parsing

| Requirement | Implementation and source of truth | Evidence and test procedure | Status | Remaining work |
|---|---|---|---|---|
| Testbed PCAP collection | `backend/services/workload_collection.py`, `scripts/collect_vpn_workload.py`; output under `captures/strongswan/collections/`. | Collection records retain PCAP, manifest, negotiated SA, ground truth, and SHA-256 fields; tests check capture closure and hashes. | `VERIFIED` | Keep large runtime artifacts outside source-control unless an artifact is a deliberately versioned fixture. |
| IKE negotiation evidence | StrongSwan `swanctl --list-sas --raw` parsing and PCAP IKE header decoding in `backend/services/vpn_testbed.py` and `backend/services/pcap_analyzer.py`. | Current live API reports IKEv2 and negotiated proposals; IKEv2 packets are present in the repository capture set. | `VERIFIED` for IKEv2 | IKEv1 parsing exists but lacks a live negotiation experiment. |
| ESP packet evidence | Scapy parser and endpoint capture workflows; outer ESP is retained as protocol metadata. | `captures/strongswan/capability_report.json` includes PCAP capture evidence; parser and collection tests cover ESP/NAT-T handling. | `VERIFIED` | Preserve capture provenance when exporting or presenting analysis. |
| AH | No AH experiment or validated parser path is present. | No runtime or artifact evidence found. | `NOT_IMPLEMENTED` | Keep optional and explicitly unsupported until tested. |
| Empty/malformed PCAP, IPv4/IPv6, direction, flow grouping, timestamps, lengths | `backend/services/pcap_analyzer.py`; canonical packet features in `vista-ml/src/vista_ml/features/pcap_features.py`. | Backend/ML contract tests cover supported parsing and feature consistency; IPv6 testbed transport remains blocked independently. | `PARTIALLY_VERIFIED` | Add malformed and empty PCAP end-to-end API checks in the final integration matrix. |
| Capture provenance | Collection and dataset services store experiment/session identifiers, hashes, label provenance, and validation outcomes where available. | Collection manifests and dataset inspection/export responses expose the evidence fields; some older/sample datasets have incomplete provenance. | `PARTIALLY_VERIFIED` | Quarantine legacy rows with missing or inconsistent source evidence. |

## C. Protocol identification and ML

| Requirement | Implementation and source of truth | Evidence and test procedure | Status | Remaining work |
|---|---|---|---|---|
| IPsec/IKE/ESP protocol and IKE version | `backend/services/pcap_analyzer.py` decodes ESP and IKE headers on UDP 500/4500; `/api/testbed/live-status` reads live StrongSwan state. | Parser tests and current live IKEv2/ESP SA observation. | `VERIFIED` for IKEv2/ESP | Add live IKEv1 evidence if that version is claimed operationally. |
| Tunnel/transport mode | The live testbed API reports negotiated CHILD_SA mode; offline ESP alone does not reveal it. | Current runtime reports `TUNNEL`; transport experiment is explicitly not tested. | `PARTIALLY_VERIFIED` | Execute a transport-mode experiment before claiming support. |
| Encryption, integrity, DH, PFS, and SA characteristics | These are sourced from live StrongSwan SA state, not inferred from encrypted payloads. | Current live observation: IKE AES-CBC-256/HMAC-SHA2-256-128/PRF-SHA2-256/MODP-2048; ESP AES-GCM-16-256/TUNNEL; selectors and PFS group 14. | `VERIFIED` for the observed session | Add lifetime/replay fields from authoritative runtime state before assessing them. |
| Encrypted inner-application identification | Controlled outer-ESP flow experiments and candidate models exist; model-service eligibility checks fail closed. | `/api/status` reports loaded classifiers with `inferenceEnabled=false` and `validationStatus=not_validated`; current source dataset is synthetic VISTA testbed data. | `BLOCKED` for operational predictions | Acquire independently sourced, session-separated labeled data; validate out-of-distribution handling; admit a model only through the existing gate. |
| AI confidence interpretation | Model outputs may expose uncalibrated classifier scores; no calibrated confidence is established. | `/api/status` reports uncalibrated probability support in metadata but no eligible inference model; `aiConfidence` is null. | `BLOCKED` | Do not present scores as calibrated probability or confidence without calibration evidence. |
| SHAP global/local explanations | SHAP service and UI gate candidate explanations by model eligibility, schema, and provenance. | AI view suppresses the old global table because evaluation status is `NOT_VALIDATED`; local flow selection requires a returned uploaded capture flow and remains gated. Regression tests cover unavailable global artifacts and local safeguards. | `PARTIALLY_VERIFIED` | Produce a provenance-complete held-out SHAP artifact and demonstrate an eligible model with a real associated prediction before claiming operational explanations. |

## D. Security assessment

| Requirement | Implementation and source of truth | Evidence and test procedure | Status | Remaining work |
|---|---|---|---|---|
| Cryptographic strength and configuration compliance | `backend/services/posture_engine.py` applies rules to explicit session parameters; live SA is available from the testbed route. | Current `/api/status` reports no operational audit source and null posture values; the Security Assessment UI shows “No operational audit data.” | `IMPLEMENTED_UNVERIFIED` operationally | Connect fresh negotiated SA and installed kernel state to the assessment record; retain rule inputs and rationale. |
| SA parameters and key lifetime | Live SA parser returns selected parameters and a remaining lifetime field; no operational lifetime compliance calculation is currently sourced into posture records. | Current runtime reports SA negotiation; no live audit record with assessed lifetime is available. | `IMPLEMENTED_UNVERIFIED` | Verify configured and observed lifetimes against standards, including stale/unavailable behavior. |
| Replay protection | XFRM can expose anti-replay state, but current posture endpoint does not use a validated live replay assessment. | No assessed operational replay field or finding in the current API response. | `IMPLEMENTED_UNVERIFIED` | Read authoritative kernel state and test replay protection enabled/disabled behavior safely. |
| Forward Secrecy | Current live API reports PFS and CHILD_SA group for the active tunnel; the assessment page does not yet score the live session. | Current live session reports PFS enabled and group 14; PFS on/off experiments are recorded separately. | `PARTIALLY_VERIFIED` | Integrate the observation into an auditable posture record and assess PFS-off cases. |
| Metadata exposure | PCAP/eBPF show packet sizes, timing, direction, SPI, and process observations; these do not reveal encrypted payload content. | Live collector and parser fields are displayed; no validated numeric metadata risk formula is active. | `PARTIALLY_VERIFIED` | Document observed fields and any exposure score formula before showing a score. |
| Risk score and severity rationale | Operational posture score and audit counts are nullable when there is no operational audit source. | `/api/status` reports `securityScore=null`; Security Assessment UI renders unavailable data rather than a score. | `BLOCKED` operational score | Document a formula with evidence inputs, severity mapping, and limits before computing a score. |
| Confirmed threat findings and MITRE matrix | SOC maps repository dataset labels to techniques and labels them synthetic/unobserved. | Threat view explicitly identifies records as synthetic scenario labels, not observed attacks. | `PARTIALLY_VERIFIED` | Only map eligible predictions or verified findings to operational incidents; preserve evidence reference and uncertainty. |

## E. Dashboard and deliverables

| Requirement | Implementation and source of truth | Evidence and test procedure | Status | Remaining work |
|---|---|---|---|---|
| Eight-view interactive dashboard | React/Vite routes in `vista-dashboard/src/App.jsx`; API client in `src/utils/apiClient.js`. | Browser review exercised Overview, Testbed, Traffic Analysis, AI Analysis, Security Assessment, Threat Intelligence, Reports, and Dataset against the running local stack. Vite production build succeeds. | `PARTIALLY_VERIFIED` | Add automated browser coverage at desktop and narrow widths, plus loading/error/stale/empty/blocked assertions for each view. |
| Live runtime status and eBPF telemetry | `/api/testbed/live-status`, `/api/ebpf/status`, `/api/ebpf/events`; native CO-RE collector. | At 2026-10-11 10:54 IST: backend `ONLINE`; current tunnel `ESTABLISHED`; collector `RUNNING`, five probes `ATTACHED`, ring drop count 0. CHILD_SA counters were idle (0 packets/bytes). Recent event rows included socket-send observations; they are not correlated to a specific flow. | `VERIFIED` for collector/tunnel status; `PARTIALLY_VERIFIED` for workload correlation | Keep collector health separate from workload evidence and report event loss/freshness and correlation limits. |
| Dataset Studio and provenance | Dataset routes in `backend/main.py`, `backend/services/dataset_service.py`; manifests and exports under `captures/strongswan/collections/`. | Runtime registry returned 11 datasets (9 campaigns, 2 representative samples), 239 rows total; records include `VALIDATED`, `READY_FOR_REVIEW`, and `BLOCKED`. These are not all evaluation-ready. | `PARTIALLY_VERIFIED` | Preserve hashes/session IDs through export and verify campaign independence/class coverage before defined evaluation. |
| Technical and executive reports | `POST /api/reports/generate`; Reports view downloads Markdown. | UI generated a technical report from repository records; response identified a synthetic repository source and left operational posture unavailable. Executive option exists but was not exercised in this audit. | `PARTIALLY_VERIFIED` | Verify both report types against actual evidence IDs/hashes; PDF rendering is not implemented. |
| Training/testing dataset and benchmark | `DATASET/`, `vista-ml/`, campaign manifests and phase audit reports. | Existing leakage, shortcut, and varied-recipe reports document synthetic and recipe-specific limits; public ISCX archive lacks a reliable session group key. | `PARTIALLY_VERIFIED` | No generalization or attack-detection claim until independent datasets satisfy the evaluation contract. |
| Reproducible demonstration and technical documentation | Root README, architecture, implementation gaps, phase reports, and scripts. | Demo startup and evidence commands are documented in `docs/DEMO_RUNBOOK.md`; this audit did not run a fresh full experiment to avoid disturbing the already-running testbed. | `PARTIALLY_VERIFIED` | Execute the runbook from a clean environment and record exact results. |

## Current runtime snapshot and boundaries

- `GET /api/testbed/live-status` at 2026-10-11 10:54:57 +05:30 reported `ONLINE`, a direct IKEv2 tunnel `ESTABLISHED`, ESP CHILD_SA `INSTALLED`, mode `TUNNEL`, AES-GCM-16 with a 256-bit key, PFS/MODP-2048, and 0 CHILD_SA packets/bytes at that observation.
- `GET /api/ebpf/status` reported `NATIVE_KERNEL_EBPF`, five attached probes, and zero ring-buffer drops. A large ring event count is collector history, not flow volume or proof that one workload generated those events.
- `GET /api/status` reported loaded model artifacts but `inferenceEnabled=false`; operational security score and AI confidence were null. The current dataset source was identified as a synthetic repository dataset.
- `captures/strongswan/capability_report.json` is a cumulative experiment report. Use each experiment's own status/artifact references; do not treat advertised matrix options as passing evidence.

## Evidence sources

- Runtime routes: `GET /api/status`, `/api/testbed/live-status`, `/api/ebpf/status`, `/api/datasets`, `/api/datasets/capabilities`.
- Testbed artifacts: `captures/strongswan/capability_report.json` and per-experiment manifest/result/PCAP files under `captures/strongswan/experiments/`.
- Dataset provenance: collection manifests, session records, negotiated SA records, ground-truth files, validation reports, and PCAPs under `captures/strongswan/collections/`.
- ML methodology: `docs/ML_PIPELINE_AUDIT.md`, `docs/PHASE11_LEAKAGE_AND_GENERALIZATION_AUDIT.md`, `docs/PHASE12_ROBUSTNESS_VALIDATION.md`, `docs/PHASE13_EXPANDED_WORKLOAD_COVERAGE.md`.
- Code and tests: `backend/services/`, `backend/test_*.py`, `vista-ml/src/vista_ml/`, and `vista-ml/tests/`.
# Dataset generation implementation scope (2026-10-11)

## Post-implementation verification (2026-10-11)

The targeted regression set passed **114 tests, skipped 3, failed 0**, with four dependency deprecation warnings. It verifies fail-closed candidate admission, artifact integrity, schema/provenance/split gates, scan parameter propagation and receiver-side evidence, and bounded cleanup. Tests are mocked/fixture-based and do not count as live dataset acceptance.

The read-only live snapshot around 11:40 IST found an established `pc1-pc2` CHILD_SA with zero counters and no active capture/job. No live collection was run because its preflighted collector path terminates and re-establishes that SA, without guaranteed restoration of the original SA on failure. Keep live collection acceptance blocked until an operator confirms the impact and recovery procedure and independently reviews real captured artifacts.

## Prefinals readiness refresh (2026-10-11 11:55 IST)

Fresh backend/eBPF/available-ML regression baseline: **208 passed, 10 opt-in live skips, 4 warnings**. Optuna-dependent Phase 10/11 tests were not run because Optuna is absent. Dashboard lint and production build pass; no browser-state tests are configured, and port 5173 was not listening. The current read-only status endpoint reports the tunnel established and CHILD_SA installed with zero counters; all model inference gates remain disabled. The current API reports five native eBPF probes, but event history is not correlated to individual tunnel traffic.

Historical benign ICMP evidence exists (`final-baseline-aes256-gcm-pfs`, 3/3 replies, +3/+3 SA packet counters, baseline restored; 2026-10-09). The historical port-scan record requested `[80, 443, 8080]` but its measured and captured ports include `[2222, 8000]`; it is not acceptance evidence for the requested run. No new live workload was sent because collection replaces the established SA without guaranteed rollback, and the Docker CLI is unavailable on this host.

Dataset Studio currently exposes the benign ICMP control and bounded `PORT_SCAN` behavior only. The scan target is fixed to allowlisted PC2 (`172.20.0.3`); it records the execution window and requires target-side PCAP evidence. `FLOOD`, `BRUTE_FORCE`, `BEACONING`, and `LARGE_TRANSFER` remain deferred until scenario-specific end-to-end acceptance passes. A behavior label is not intent attribution.

Collected candidates are kept `UNVERIFIED` until independent evidence/provenance, schema, ground truth, class coverage, and leakage requirements are actually established. A one-session run cannot support a session-disjoint evaluation split. Synthetic fixtures carry explicit synthetic origin and are limited to software testing.

## Live data audit update (2026-10-11)
The eight-page value/source matrix, confirmed defects and replacements, backend sources, regression tests, live UI observations, and unavailable capabilities are recorded in [LIVE_DATA_HARDCODE_AUDIT.md](LIVE_DATA_HARDCODE_AUDIT.md). The existing running backend was not restarted; its process will not expose new response fields until safely reloaded. No live workload was run.
