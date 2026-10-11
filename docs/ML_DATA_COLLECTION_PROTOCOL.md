# VISTA ML Data Collection Protocol

## Readiness

The first live collection increment now passes against the running PC1↔PC2
StrongSwan tunnel: bounded ICMPv4 echo and one-connection TCP marker transfer.
The ICMP generator records requested profiles separately from sender counters;
the TCP marker receiver independently verifies byte count and payload SHA-256.
Both runs verify the negotiated SA, installed XFRM tunnel mode, actual outer
ESP in the PC1 `eth0` PCAP, endpoint captures, artifact hashes, and manifest
admission. The live evidence is recorded below and in each collection result.

This is a smoke-tested collector, not a training-ready dataset. The verified
matrix currently contains one collection session with two observations (one
ICMPv4 experiment and one TCP marker experiment). Dataset preparation admitted
both records but correctly blocked a session-disjoint 60/20/20 split because
15 independent sessions are required. The two workloads reused the same live
IKE/CHILD SA and Docker containers; they are not evidence of 15 statistically
independent sessions.

The opt-in live tests also exercised failure handling. An initial ICMP attempt
received all 3 requested replies but produced only a 24-byte PCAP header, so
the collector persisted a `FAIL` rather than admitting the observation. The
failed record is retained at
`captures/strongswan/collections/75be973c-d0bd-4095-b3c2-dfe0cf2c43f5/da6793b9-a638-4591-b053-e3436bc238e9/collection_result.json`.

In Phase 5, the root cause of this empty-PCAP failure was isolated and resolved:
1. `tcpdump` with `libpcap` TPACKET_V3 kernel ring buffers buffered packets unless `--immediate-mode` was passed.
2. `tcpdump` wrote the 24-byte PCAP file header synchronously on open before the kernel packet socket / BPF filter were attached to the interface.
3. The capture lifecycle lacked continuous USR1 packet-dispatch verification and container filesystem `sync` prior to artifact retrieval.

The collector was hardened with:
- `tcpdump --immediate-mode -n -i eth0 -U` ensuring immediate kernel delivery and packet-buffered file flushing.
- An explicit capture lifecycle: `PRECHECK → CAPTURE_STARTING → CAPTURE_READY → WORKLOAD_RUNNING → CAPTURE_STOPPING → ARTIFACT_VALIDATION → PASS/FAIL`.
- Continuous `SIGUSR1` packet-dispatch polling in `_wait_for_capture_dispatch` verifying dispatched packets before sending `SIGINT`.
- Container filesystem `sync` before artifact retrieval.
- Preservation of tcpdump logs and structured `failure_diagnostics.json` on error.
- Full regression tests covering early exit, delayed readiness, empty PCAP, missing ESP, nonzero exit, and failure diagnostics.

Using this hardened lifecycle, the reproducible campaign runner (`scripts/run_collection_campaign.py`)
collected 15 genuinely independent sessions (`captures/strongswan/collections/campaigns/e2e8adae-94d7-4a1d-9569-3c3e1a965e64`),
each with a distinct verified IKE_SA identity after terminate-and-reinit. The dataset preparation
script admitted all 30 observations (15 ICMPv4, 15 TCP marker) with 0 quarantines and generated
a clean, leakage-free 9/3/3 session-split dataset report (`READY_FOR_REVIEW`).

In Phase 6, the collector was expanded to support a real, bounded HTTP/1.1 workload over the
existing IPsec tunnel without requiring container image modifications. Using container-native POSIX
Perl (`/usr/bin/perl` with core `IO::Socket::INET` and `select`) and `/usr/bin/sha256sum`, PC2 acts as
a real HTTP/1.1 server on `172.20.0.3:8080` while PC1 executes client HTTP/1.1 requests. The server
independently writes `server_evidence.json` with requested path, method, client IP, response status code,
response byte count, and response body SHA-256 digest. PC1 records `client_measurements.json` with
status codes, received bytes, and payload SHA-256 digests. Both sides must agree on status (200 OK),
bytes, and SHA-256 digests, and outer ESP packets must be captured on PC1 `eth0`.

In Phase 7, the HTTP workload collector was extended into a reproducible multi-session collection
campaign using the enhanced campaign runner (`scripts/run_collection_campaign.py --workload-set http`).
The campaign executed 15 independent sessions (`captures/strongswan/collections/campaigns/9bd6b15c-507d-451a-89eb-7071944f105f`),
each re-establishing a distinct verified IKE_SA identity and CHILD_SA tunnel before collection.
Two bounded HTTP/1.1 workloads were executed per session across parameterized profile spaces:
- `HTTP_GET_PROFILE_SPACE`: request counts 3–7, intervals 0.2–0.4s, varied paths (`/api/v1/telemetry`, `/api/v1/status`, `/metrics`, `/health`, `/data/query`).
- `HTTP_POST_PROFILE_SPACE`: request counts 2–5, intervals 0.25–0.45s, varied paths (`/api/v1/upload`, `/data/sensor`, `/data/event`, `/api/v1/submit`, `/log/event`), payload sizes 64–512 bytes with deterministic payload SHA-256 digests.
Across all 30 experiments (15 GET, 15 POST), all client and server measurements agreed on 200 OK status codes,
response byte counts, and response-body SHA-256 digests. The dataset preparation pipeline admitted all 30
observations with 0 quarantines and established a leakage-free 9/3/3 session split (18 train / 6 validation / 6 test rows)
marked `READY_FOR_REVIEW`. No models were trained or promoted, and outer ESP metadata features do not expose
inner HTTP plaintext, URLs, or headers.

In Phase 8, a unified multi-workload dataset campaign was executed to combine all three independently verified
workloads (ICMPv4 echo, controlled TCP marker, and HTTP/1.1 GET/POST) under a formal target label ontology:
- **Target Label Ontology:** Versioned as [`vista-target-label-schema-v1.json`](../vista-ml/schemas/vista-target-label-schema-v1.json),
  defining 3 mutually exclusive canonical target classes: `controlled_icmpv4`, `controlled_tcp_marker`, and `controlled_http`.
  HTTP GET and POST are retained as metadata workload subtypes (`http_get`, `http_post`) rather than fragmented classes,
  preserving class semantic coherence while capturing workload parameter diversity.
- **Unified Campaign Execution:** Campaign `76adc766-ef41-45f5-b677-1d950c7ff052` was executed with 15 genuinely independent
  IKE_SA sessions (`--workload-set unified --sessions 15 --seed 26160`). Every session re-established a fresh IKE_SA lifecycle
  and executed all 4 workloads: ICMPv4, TCP marker, HTTP GET, and HTTP POST (in randomized, counterbalanced orders with bounded variations).
- **Full Class Coverage:** The campaign produced 60 observations (15 ICMPv4, 15 TCP marker, 15 HTTP GET, 15 HTTP POST;
  yielding 15 `controlled_icmpv4`, 15 `controlled_tcp_marker`, and 30 `controlled_http`).
- **Endpoint Ground Truth & ESP Verification:** All 60 observations achieved 100% endpoint agreement (ICMP echo reply matching,
  TCP payload hash agreement, HTTP 200 OK status codes with client/server SHA-256 agreement), non-zero outer ESP captures
  on PC1 `eth0`, and valid artifact SHA-256 checksums across all manifests, PCAPs, CSVs, and SA evidence records.
- **Leakage-Safe Session Split Qualification:** The dataset preparation engine validated all 60 observations with 0 quarantines
  and generated a leakage-free 9/3/3 session split (`READY_FOR_REVIEW`):
  - Train: 9 sessions, 36 observations (18 HTTP, 9 ICMP, 9 TCP marker)
  - Validation: 3 sessions, 12 observations (6 HTTP, 3 ICMP, 3 TCP marker)
  - Test: 3 sessions, 12 observations (6 HTTP, 3 ICMP, 3 TCP marker)
  - Overlap: 0 sessions, 0 IKE SA identities, and 0 SPIs shared across any split boundaries.
  - Duplicate Vectors: 0 exact duplicate and 0 near-duplicate feature vectors.
- **Strict Boundary:** The outer ESP feature extractor (`vista-flow-v1`) extracts only 18 bidirectional traffic shape features
  from IPv4 ESP packets. No inner payload, URLs, HTTP headers, experiment IDs, or metadata are accessible or used.
  Model training and promotion remain explicitly disclaimed in Phase 8.

The static VPN experiment runner still emits synthetic fixed summaries for RTP-like, SMTP,
WhatsApp-like, and video workloads. Those are not traffic observations and must not enter a dataset.
They remain unsupported for this collection flow.

The machine-readable plan is
[`strongswan-collection-plan-v1.json`](../vista-ml/schemas/strongswan-collection-plan-v1.json).
It proposes a controlled-workload recognition experiment from **outer IPv4 ESP
metadata**. It does not claim to identify the encrypted inner application.
Labels describe the controlled workload selected and observed at the endpoints,
not an application identity inferred from encrypted packet features.

## Capture and ground-truth protocol

1. Start a collection session and retain its UUIDv4 session record. It binds the
   session ID to actual container IDs, image IDs/references, endpoint addresses,
   StrongSwan version, repository revision, and worktree-dirty flag. A new ID is
   not by itself proof of an independent testbed restart; record genuinely
   independent collection campaigns and do not treat repeats on one SA as
   independent validation.
2. Allocate random/opaque UUIDv4 experiment IDs before selecting a workload.
   Never include the target label in IDs, directory names, capture names, or
   split keys. Reusing a session ID appends another experiment without
   overwriting prior evidence.
3. Validate the tunnel and the actual negotiated IKE_SA/CHILD_SA before the
   workload. Save redacted machine-readable SA output and effective
   configuration. A successful command alone is not tunnel evidence.
4. Capture `pc1` and `pc2` on `eth0`; the PC1 raw capture contains the observed
   outer ESP packets and may also contain inner workload packets. The derived
   packet table deliberately contains only IPv4 ESP/NAT-T ESP packets, so its
   feature domain is outer-tunnel metadata rather than decrypted ICMP/TCP/HTTP.
   Capture start/end times, interface, capture point and IP version are
   recorded. Closed raw captures are hashed and validated before parsing; the
   CSV is supplemental and never replaces the raw PCAP.
5. Establish ground truth from a separate endpoint/workload record:
   - For ICMP, compare ping transmitted/received counters with the PC2 receiver-side
     echo-request capture. The PC2 capture point sees requests but not necessarily
     its own post-XFRM reply; successful client replies and CHILD_SA counters
     provide the return-path evidence.
   - For TCP marker traffic, compare sender bytes and deterministic payload hash
     with the independently saved and hashed PC2 receiver payload.
   - For HTTP traffic, verify pre-installed tunnel SA, compare requested vs observed
     request counts, verify HTTP status codes (200 OK), verify received byte counts
     against server response bytes, and verify client payload SHA-256 digests against
     server-side access evidence (`server_evidence.json`).
   Labels are recorded separately and are not inferred from packet counts, feature values,
   filenames, or model predictions. Any status mismatch, hash mismatch, missing ESP, or timeout
   is recorded as a failed/quarantined observation, never admitted as successful application traffic.
6. Write an experiment manifest using
   [`strongswan-experiment-manifest-v2.schema.json`](../vista-ml/schemas/strongswan-experiment-manifest-v2.schema.json).
   The v1 schema remains supported for historical records. The v2 preparation
   pipeline verifies raw-PCAP structure/protocol, packet-table/ground-truth/
   measurement/session/SA hashes, the explicit label record, and exact
   `vista-flow-v1` feature extraction. Missing, unverified, malformed,
   unsupported, or duplicate records are quarantined with reasons.
7. Freeze session assignments before inspecting feature or label distributions.
   Split only on `session_id`. Require adequate independent session counts and
   every target class in each split. If the fixed split cannot satisfy this,
   stop and collect more sessions; do not keep retrying seeds.
8. Each collection run writes a new session-level manifest snapshot containing
   all successful ESP-domain records from that session and runs the preparation
   validator. Snapshots and report directories are unique and immutable. Keep
   raw PCAPs and input manifests; the report includes hashes, class/session
   counts, feature ranges, missingness, duplicates, blockers, and exclusions.

## Planned varied workload matrix

The verified workloads are controlled ICMPv4 echo, controlled TCP marker
transfer, and controlled HTTP/1.1 request/response exchange.
The TCP marker is a raw local TCP stream, not an echo protocol or named application.
The HTTP workload is a bounded HTTP/1.1 client/server transaction with independent
status and content hash verification. All support an explicit sequence of bounded
profiles with count, inter-message interval, and payload/request configuration.
Collection profiles must be varied and balanced across sessions. The initial smoke
sessions validate mechanics only and are not suitable model training evidence.

The target study remains fifteen independent collection sessions with six
captures of each workload per session. A pre-registered balanced-incomplete
schedule should cover multiple durations, target rates and payload sizes;
include an idle/background control where measurable; record schedule seeds and
actual endpoint counters; and counterbalance class order. The split must hold
out entire sessions (9/3/3 sessions), with represented classes in every
split.

Do not add VoIP, messaging, email, video, IPv6, attacks, or anomaly
labels until the corresponding endpoint workload, capture path, independent
ground truth, and counters are implemented and verified. The current synthetic
workload summaries cannot serve as training examples.

## Feature contract and data boundary

Use the ordered feature list in
[`vista-flow-v1.json`](../vista-ml/schemas/vista-flow-v1.json): packet count
(packets), byte count (IPv4 network-layer bytes), duration (seconds), mean and
population standard deviation of packet size (bytes), minimum and maximum
packet size (bytes), mean/std/min/max inter-arrival time (seconds), packet and
byte rates (per second), forward/backward packet counts, forward/backward byte
counts, and forward packet fraction. The current extractor aggregates all
packets for one bidirectional protocol-family/endpoint key across the uploaded
capture; there is no idle timeout. Forward is the lexicographically first
endpoint. Length includes the IPv4 network-layer header but excludes link
framing. Missing timestamps/lengths are rejected; single-packet IAT and
zero-duration rates remain undefined. Identifiers, timestamps, target labels,
workload configuration, SA parameters, and capture paths are metadata, never
model inputs. IPv6 and ESP/IKE inference are not qualified by this contract.

Outer ESP packet metadata reflects encrypted tunnel traffic shape only. It does
not reveal inner application protocol or prove a named application generated
the packets. Report observations separately from any model prediction.

## Readiness gates

- **Benign controlled-workload model:** remain experimental until session-level
  train/validation/test splits, varied and balanced workload parameters, enough
  independent sessions, and per-class metrics/error analysis are available.
- **Application classification:** blocked until real application endpoints,
  application-level ground truth, and a justified capture domain are collected.
- **Attack detection:** blocked until isolated-lab benign controls and attacks
  have independently verified family, time interval, target tuple, tool/config,
  capture/campaign grouping, and session-disjoint test evidence.
- **Anomaly detection:** blocked until a separately collected and independently
  representative normal dataset supports threshold calibration and false-alarm
  reporting.
- **Runtime inference:** the experimental outer-ESP candidate remains blocked.
  Preserve the backend's explicit out-of-distribution/insufficient-data results.
