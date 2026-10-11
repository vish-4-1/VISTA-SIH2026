#!/usr/bin/env python3
"""Independent Audit Script for VISTA Phase 6 HTTP Experiment.

Verifies:
1. All persisted Phase 6 HTTP experiment artifacts exist and are readable.
2. Recomputed SHA-256 digests match recorded hashes in collection_result and experiment_manifest.
3. PCAPs are readable, valid, and contain expected outer ESP/NAT-T (PC1) and TCP (PC2) packets.
4. Client measurements and server evidence agree on counts, paths, status codes, byte counts, and body SHA-256 digests.
5. SA evidence and CHILD_SA counter deltas support the claimed exchange.
6. Derived packet table (packets.csv) matches outer ESP packets.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.ipsec import ESP
from scapy.utils import PcapReader


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_phase6_experiment(exp_dir: Path) -> dict[str, Any]:
    results: dict[str, Any] = {"checks": {}, "issues": []}

    required_files = [
        "pc1_outer_http.pcap",
        "pc2_receiver_http.pcap",
        "packets.csv",
        "server_evidence.json",
        "workload_measurements.json",
        "ground_truth.json",
        "negotiated_sa.json",
        "collection_result.json",
        "experiment_manifest.json",
        "client_measurements.json",
        "session_record.json",
    ]

    # 1. Existence and readability
    for fname in required_files:
        fpath = exp_dir / fname
        if not fpath.exists():
            results["issues"].append(f"Missing file: {fname}")
        elif fpath.stat().st_size == 0:
            results["issues"].append(f"Empty file: {fname}")

    results["checks"]["all_required_files_exist"] = len(results["issues"]) == 0

    col_res_path = exp_dir / "collection_result.json"
    col_res = json.loads(col_res_path.read_text(encoding="utf-8"))
    exp_manifest_path = exp_dir / "experiment_manifest.json"
    exp_manifest = json.loads(exp_manifest_path.read_text(encoding="utf-8"))

    # 2. Recompute and verify SHA-256 hashes
    recomputed_hashes = {}
    for fname in required_files:
        fpath = exp_dir / fname
        if fpath.exists():
            recomputed_hashes[fname] = sha256_file(fpath)

    results["checks"]["recomputed_hashes"] = recomputed_hashes

    # Compare against collection_result.json hashes
    recorded_hashes = col_res.get("artifactHashes", {})
    results["checks"]["recorded_hashes_matched"] = True
    for fname, rec_hash in recorded_hashes.items():
        if fname in recomputed_hashes:
            if recomputed_hashes[fname] != rec_hash:
                results["issues"].append(
                    f"Hash mismatch in collection_result for {fname}: "
                    f"expected {rec_hash}, recomputed {recomputed_hashes[fname]}"
                )
                results["checks"]["recorded_hashes_matched"] = False

    # Compare against manifest hashes
    manifest_obs = exp_manifest.get("observations", [{}])[0]
    m_capture_hash = manifest_obs.get("capture", {}).get("sha256")
    m_raw_hash = manifest_obs.get("capture", {}).get("raw_pcap_sha256")
    m_truth_hash = manifest_obs.get("ground_truth", {}).get("record_sha256")
    m_meas_hash = manifest_obs.get("workload", {}).get("measurement_sha256")
    m_sa_hash = manifest_obs.get("vpn", {}).get("negotiated_sa_evidence_sha256")

    if recomputed_hashes.get("packets.csv") != m_capture_hash:
        results["issues"].append("Manifest capture.sha256 mismatch")
    if recomputed_hashes.get("pc1_outer_http.pcap") != m_raw_hash:
        results["issues"].append("Manifest capture.raw_pcap_sha256 mismatch")
    if recomputed_hashes.get("ground_truth.json") != m_truth_hash:
        results["issues"].append("Manifest ground_truth.record_sha256 mismatch")
    if recomputed_hashes.get("workload_measurements.json") != m_meas_hash:
        results["issues"].append("Manifest workload.measurement_sha256 mismatch")
    if recomputed_hashes.get("negotiated_sa.json") != m_sa_hash:
        results["issues"].append("Manifest vpn.negotiated_sa_evidence_sha256 mismatch")

    # 3. PCAP readability and packet protocol verification
    pc1_pcap = exp_dir / "pc1_outer_http.pcap"
    pc1_pkts = 0
    pc1_esp_pkts = 0
    for pkt in PcapReader(str(pc1_pcap)):
        pc1_pkts += 1
        if IP in pkt and (int(pkt[IP].proto) == 50 or ESP in pkt):
            pc1_esp_pkts += 1
        elif UDP in pkt and int(pkt[UDP].dport) == 4500:
            payload = bytes(pkt[UDP].payload)
            if payload and payload[:4] != b"\x00\x00\x00\x00":
                pc1_esp_pkts += 1

    results["checks"]["pc1_total_packets"] = pc1_pkts
    results["checks"]["pc1_outer_esp_packets"] = pc1_esp_pkts
    if pc1_esp_pkts <= 0:
        results["issues"].append("No outer ESP packets found in pc1_outer_http.pcap")

    pc2_pcap = exp_dir / "pc2_receiver_http.pcap"
    pc2_pkts = 0
    pc2_tcp_pkts = 0
    for pkt in PcapReader(str(pc2_pcap)):
        pc2_pkts += 1
        if IP in pkt and TCP in pkt:
            pc2_tcp_pkts += 1

    results["checks"]["pc2_total_packets"] = pc2_pkts
    results["checks"]["pc2_tcp_packets"] = pc2_tcp_pkts
    if pc2_tcp_pkts <= 0:
        results["issues"].append("No TCP packets found in pc2_receiver_http.pcap")

    # 4. Client and Server evidence agreement
    server_ev = json.loads((exp_dir / "server_evidence.json").read_text(encoding="utf-8"))
    workload_meas = json.loads((exp_dir / "workload_measurements.json").read_text(encoding="utf-8"))
    client_meas = json.loads((exp_dir / "client_measurements.json").read_text(encoding="utf-8"))

    s_reqs = server_ev.get("requests", [])
    c_reqs = client_meas.get("requests", [])

    results["checks"]["server_request_count"] = len(s_reqs)
    results["checks"]["client_request_count"] = len(c_reqs)

    if len(s_reqs) != len(c_reqs) or len(s_reqs) == 0:
        results["issues"].append(
            f"Request count mismatch: server saw {len(s_reqs)}, client saw {len(c_reqs)}"
        )
    else:
        for idx, (s_r, c_r) in enumerate(zip(s_reqs, c_reqs)):
            if s_r.get("path") != c_r.get("path"):
                results["issues"].append(f"Request {idx} path mismatch: {s_r.get('path')} vs {c_r.get('path')}")
            s_status = s_r.get("responseStatus")
            c_status = c_r.get("statusCode")
            if s_status != 200 or c_status != 200:
                results["issues"].append(f"Request {idx} non-200 status: {s_status} / {c_status}")
            s_bytes = s_r.get("responseBytes")
            c_bytes = c_r.get("responseBytes")
            if s_bytes != c_bytes:
                results["issues"].append(
                    f"Request {idx} bytes mismatch: server {s_bytes}, client {c_bytes}"
                )
            s_sha = s_r.get("responseSha256")
            c_sha = c_r.get("responseSha256")
            if s_sha != c_sha or not s_sha:
                results["issues"].append(
                    f"Request {idx} body SHA-256 mismatch: server {s_sha}, client {c_sha}"
                )

    results["checks"]["endpoint_evidence_agrees"] = len([
        issue for issue in results["issues"] if "Request" in issue
    ]) == 0

    # 5. SA Evidence & Counter Deltas
    sa_before = col_res.get("negotiatedSaBefore", {}).get("pc1", {}).get("child", {})
    sa_after = col_res.get("negotiatedSaAfter", {}).get("pc1", {}).get("child", {})
    in_delta = sa_after.get("packetsIn", 0) - sa_before.get("packetsIn", 0)
    out_delta = sa_after.get("packetsOut", 0) - sa_before.get("packetsOut", 0)
    bytes_in_delta = sa_after.get("bytesIn", 0) - sa_before.get("bytesIn", 0)
    bytes_out_delta = sa_after.get("bytesOut", 0) - sa_before.get("bytesOut", 0)

    results["checks"]["child_sa_counter_deltas"] = {
        "inboundPackets": in_delta,
        "outboundPackets": out_delta,
        "inboundBytes": bytes_in_delta,
        "outboundBytes": bytes_out_delta,
    }

    if in_delta <= 0 or out_delta <= 0:
        results["issues"].append(f"SA counter deltas invalid: in={in_delta}, out={out_delta}")

    # 6. Packet table (packets.csv)
    packet_lines = (exp_dir / "packets.csv").read_text(encoding="utf-8").strip().splitlines()
    results["checks"]["packets_csv_rows"] = len(packet_lines) - 1  # exclude header
    if len(packet_lines) - 1 != pc1_esp_pkts:
        results["issues"].append(
            f"packets.csv row count ({len(packet_lines)-1}) does not match outer ESP count ({pc1_esp_pkts})"
        )

    results["checks"]["total_issues"] = len(results["issues"])
    results["checks"]["audit_passed"] = len(results["issues"]) == 0
    return results


if __name__ == "__main__":
    exp_dir = Path("captures/strongswan/collections/15298fa7-7e97-44b0-8e7c-fac238db54e0/60883e93-7174-405f-8f9d-cdf06d2e6894")
    res = audit_phase6_experiment(exp_dir)
    print(json.dumps(res, indent=2))
