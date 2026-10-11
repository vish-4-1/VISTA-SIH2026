# Data provenance and interpretation

## Sources

| Data | Source / location | Interpretation |
|---|---|---|
| PCAP analysis | User-provided capture parsed by backend Scapy services; selected frontend fallback parsers | Extracted packet and flow metadata. Encrypted payload is not decrypted. A capture label is not ground truth unless independently established. |
| Testbed state | StrongSwan `pc1` and `pc2`, Linux XFRM, and backend testbed APIs | Runtime evidence for observed configuration and counters. Idle counters do not demonstrate workload coverage. |
| eBPF events | `vista-ebpf-monitor` kernel collector | Native host-kernel events, including socket process metadata and XFRM observations. Current events do not reliably map to individual flows. |
| Registered datasets | Dataset registry API and repository records | Registry row counts include sample and campaign entries with mixed readiness/validation states. A row count is not validated operational flow count. |
| ML artifacts and metrics | `vista-ml/` and checked-in root artifacts | Models use synthetic VISTA development data. No provenance-complete held-out SHAP artifact is currently available; the previous in-memory value table was removed. Global values do not establish real-world performance or explain a capture. |
| Threat and security views | API services, checked-in seed/demo records, and user analyses | Treat synthetic or unverified findings as demonstrations/records, not confirmed incidents or live cryptographic audits. |

## Audit snapshot

On 2026-10-11, `/api/status` reported a live backend but `securityScore` and `aiConfidence` were null; model artifacts were not eligible for inference. The dataset registry returned 11 entries and 239 aggregate rows across mixed statuses. The testbed API exposed two tunnel profiles with capability evidence and one transport profile that is implemented but unverified. These are observations from one run and may change.

The capability report at `captures/strongswan/capability_report.json` identifies tested, blocked, and not-tested combinations. Evidence files under `captures/strongswan/experiments/` and `captures/strongswan/collections/` should be interpreted with that report; their presence alone does not establish successful coverage.

## Reporting rules

- Preserve the distinction between registered, captured, validated, and evaluation-ready data.
- Label predictions as model outputs, not confirmed threats.
- Label synthetic fixtures and demonstration records as synthetic.
- Do not describe socket ring-buffer records as correlated VPN flows or traffic volume.
- Do not derive a security score or compliance result when the API has no validated assessment data.

## Dataset Studio scenario evidence

### Post-implementation audit update (2026-10-11)

Candidate admission now validates the evidence itself rather than accepting the presence of provenance fields: artifact size and SHA-256, repository-contained paths, dataset/report/split inventory, closed PCAP integrity, schema and target/identifier exclusion, at least three independent session records, session/experiment references, observed label provenance bounded by capture windows, and disjoint session and IKE-identity partitions. Any missing or inconsistent evidence leaves the candidate blocked or `UNVERIFIED`. This gate has unit coverage; no freshly collected live candidate was admitted during this audit.

The port scan collector consumes top-level job parameters, applies bounded scanner deadlines, and requires inbound PC1-to-PC2 SYNs for requested ports in an integrity-checked PC2 receiver capture. Capture and listener cleanup now verify process exit and fail the workload if cleanup cannot be confirmed. Regression coverage uses mocked Docker responses and fixture PCAPs only.

At approximately 2026-10-11 11:40 IST, the read-only testbed status snapshot showed an established tunnel-mode CHILD_SA with zero packet/byte counters and no active capture/job. The eBPF event count was host-wide and could not be attributed to this tunnel. No live workload was run because the collection path first terminates and replaces the established SA; that operation has no guaranteed rollback to the original SA.

### SIH pre-finals evidence review (2026-10-11 11:55 IST)

The current read-only `/api/testbed/live-status` response at `2026-10-11T06:25:42Z` reports the endpoints online, IKEv2 established, tunnel-mode ESP CHILD_SA installed with AES-GCM-16/256 and PFS MODP-2048, selectors `172.20.0.2/32` ↔ `172.20.0.3/32`, zero packet/byte counters, and inactive capture/no job. The API reports five attached native eBPF probes; event history is host-wide and must not be represented as tunnel attribution. `/api/status` reports all model artifacts loaded but inference disabled and not validated. `/api/ml/metrics` reports `evaluationProvenance.status=NOT_VALIDATED`; global SHAP and per-flow explanation values are therefore suppressed/gated.

The retained benign experiment `captures/strongswan/experiments/final-baseline-aes256-gcm-pfs/experiment_result.json` records a historical 3/3 ICMP exchange, +3/+3 CHILD_SA packet counters, and baseline restoration on 2026-10-09. Its six-packet PCAP passed the closed-PCAP check; SHA-256 is `1561cc3cbb56a6e4b27b63dc89c9c0fcbb1bfc87679f7f8d6228921f196915ce`.

Two identical-seed fixture CLI runs in external temporary directories produced the same six-row CSV SHA-256 (`01f2944219267218b42142ec96c533feb567245533a3a939f1b95d9b50f12b48`). Manifest hashes differed because `createdAt` records wall-clock artifact creation; each manifest's own artifact hash validation passed in the regression suite. These fixtures are software tests, not capture evidence.

The retained port-scan result `c70f9bc2-1300-4c96-aa04-6752fbceb1d9` is not valid evidence for its requested configuration. `collection_result.json` records requested ports `[80, 443, 8080]`, but `workload_measurements.json` and the integrity-checked PC2 receiver capture show five probes/SYNs to `[80, 443, 2222, 8000, 8080]`. Its legacy experiment manifest also fails to inventory/hash the PC2 receiver capture. Preserve this artifact as historical diagnostic evidence; do not treat its `PASS` status as acceptance for the requested run. Current regression tests cover propagation and exact receiver evidence after the fix, but those mocked tests are not live acceptance.

No new live collection was attempted in this review. The collector terminates and replaces the established CHILD_SA and has no guaranteed rollback to the original SA on failure; the local host also has no Docker CLI. These conditions block safe re-verification here.

The implemented acceptance pair is `benign_icmp_control_v1` and `port_scan_v1`. Port probes are restricted to the PC2 lab allowlist at `172.20.0.3`; labels describe an observed time window and do not prove malicious intent. The scan collector parses the PC2 receiver PCAP for inbound TCP SYN destination ports. A configured run without matching receiver-side packets is a failure, not an observed scan. The outer ESP capture cannot establish the inner application or attribute an encrypted aggregate flow to a specific behavior. eBPF remains a separate observation layer unless a defensible correlation key is available.

New collection candidates are `UNVERIFIED` until artifact inventory and hashes, ground-truth provenance, schema, labels, and independent-session split evidence pass validation. Existing sample records with no declared origin are registered as `unknown` / `UNVERIFIED`. Synthetic software fixtures have explicit `synthetic_fixture` origin and `SYNTHETIC_FIXTURE` status; they are never captured-traffic or evaluation evidence and are not mixed with collected records.

Dataset Studio routes: `GET /api/datasets/scenarios`, `GET /api/datasets/scenarios/{id}`, `POST /api/datasets/scenarios/{id}/validate`, and `POST /api/datasets/scenarios/{id}/runs`. Run requests require `confirmedIsolatedLab: true`. Run status, log events, and artifact references are available from the returned job and `GET /api/datasets/scenario-runs/{job_id}`. Cancellation enters `CANCELLING`; the bounded collector must clean up before terminal cancellation.

## Live data audit update (2026-10-11)
The eight-page value/source matrix, confirmed defects and replacements, backend sources, regression tests, live UI observations, and unavailable capabilities are recorded in [LIVE_DATA_HARDCODE_AUDIT.md](LIVE_DATA_HARDCODE_AUDIT.md). The existing running backend was not restarted; its process will not expose new response fields until safely reloaded. No live workload was run.
