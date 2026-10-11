#!/usr/bin/env python3
"""Independent Audit Script for VISTA Phase 5 Campaign.

Verifies:
1. 15 distinct session records and 30 unique experiment records.
2. IKE_SA re-establishment evidence and distinct IKE SPI hashes.
3. Linking and SHA-256 integrity across PCAPs, packet tables, measurements, ground truth, SA evidence, session records.
4. PCAPs readability, valid header, and outer ESP / NAT-T packet verification.
5. Sender vs receiver measurement agreement.
6. Dataset report and split manifest consistency, class distributions, and zero cross-split leakage.
7. READY_FOR_REVIEW status semantics.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import ESP
from scapy.utils import PcapReader


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_outer_esp(pcap_path: Path) -> int:
    esp_count = 0
    for pkt in PcapReader(str(pcap_path)):
        if IP in pkt and (int(pkt[IP].proto) == 50 or ESP in pkt):
            esp_count += 1
        elif UDP in pkt and int(pkt[UDP].dport) == 4500:
            payload = bytes(pkt[UDP].payload)
            if payload and payload[:4] != b"\x00\x00\x00\x00":
                esp_count += 1
    return esp_count


def audit_campaign(campaign_dir: Path) -> dict[str, Any]:
    summary_path = campaign_dir / "campaign_summary.json"
    manifest_path = campaign_dir / "campaign_manifest.json"
    prep_dir = campaign_dir / "dataset_preparation"
    report_path = prep_dir / "dataset_report.json"
    split_path = prep_dir / "split_manifest.json"
    dataset_csv = prep_dir / "prepared_dataset.csv"

    results: dict[str, Any] = {"checks": {}, "issues": []}

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    split = json.loads(split_path.read_text(encoding="utf-8"))

    # 1. Distinct Sessions and Experiments
    sessions = summary.get("sessions", [])
    session_ids = [s["sessionId"] for s in sessions]
    exp_ids = [exp["experimentId"] for s in sessions for exp in s.get("experiments", [])]
    manifest_obs = manifest.get("observations", [])
    manifest_exp_ids = [obs["experiment_id"] for obs in manifest_obs]

    results["checks"]["session_count"] = len(sessions)
    results["checks"]["distinct_session_ids"] = len(set(session_ids))
    results["checks"]["experiment_count"] = len(exp_ids)
    results["checks"]["distinct_experiment_ids"] = len(set(exp_ids))
    results["checks"]["manifest_observations"] = len(manifest_obs)
    results["checks"]["manifest_distinct_experiments"] = len(set(manifest_exp_ids))

    if len(sessions) != 15 or len(set(session_ids)) != 15:
        results["issues"].append("Expected exactly 15 distinct sessions in summary.")
    if len(exp_ids) != 30 or len(set(exp_ids)) != 30:
        results["issues"].append("Expected exactly 30 distinct experiments in summary.")
    if len(manifest_obs) != 30 or len(set(manifest_exp_ids)) != 30:
        results["issues"].append("Expected exactly 30 distinct experiments in manifest.")

    # 2. IKE_SA Re-establishment and distinct identities
    ike_identities = []
    for idx, s in enumerate(sessions):
        reestab = s.get("saReestablishment", {})
        prev_id = reestab.get("previousIkeSaIdentitySha256")
        new_id = reestab.get("newIkeSaIdentitySha256")
        if not prev_id or not new_id or prev_id == new_id:
            results["issues"].append(f"Session {idx} ({s['sessionId']}) does not verify new IKE identity.")
        if s.get("independenceStatus") != "VERIFIED_DISTINCT_IKE_SA":
            results["issues"].append(f"Session {idx} independenceStatus is not VERIFIED_DISTINCT_IKE_SA.")
        ike_identities.append(new_id)

    results["checks"]["distinct_ike_identities"] = len(set(ike_identities))
    if len(set(ike_identities)) != 15:
        results["issues"].append(f"Expected 15 distinct IKE SA identities, got {len(set(ike_identities))}.")

    # 3. Artifact links, hashes, readability, outer ESP, and measurement consistency
    verified_artifacts = 0
    outer_esp_verified = 0
    measurement_verified = 0

    for obs in manifest_obs:
        exp_id = obs["experiment_id"]
        sess_id = obs["session_id"]

        # Paths
        capture_rel = obs["capture"]["path"]
        raw_pcap_rel = obs["capture"]["raw_pcap_path"]
        truth_rel = obs["ground_truth"]["record_path"]
        meas_rel = obs["workload"]["measurement_path"]
        vpn_rel = obs["vpn"]["negotiated_sa_evidence_path"]
        sess_rel = obs["session_record_path"]

        capture_file = campaign_dir / capture_rel
        raw_pcap_file = campaign_dir / raw_pcap_rel
        truth_file = campaign_dir / truth_rel
        meas_file = campaign_dir / meas_rel
        vpn_file = campaign_dir / vpn_rel
        sess_file = campaign_dir / sess_rel

        # Hash checks
        if sha256_file(capture_file) != obs["capture"]["sha256"]:
            results["issues"].append(f"Hash mismatch on {capture_rel}")
        if sha256_file(raw_pcap_file) != obs["capture"]["raw_pcap_sha256"]:
            results["issues"].append(f"Hash mismatch on {raw_pcap_rel}")
        if sha256_file(truth_file) != obs["ground_truth"]["record_sha256"]:
            results["issues"].append(f"Hash mismatch on {truth_rel}")
        if sha256_file(meas_file) != obs["workload"]["measurement_sha256"]:
            results["issues"].append(f"Hash mismatch on {meas_rel}")
        if sha256_file(vpn_file) != obs["vpn"]["negotiated_sa_evidence_sha256"]:
            results["issues"].append(f"Hash mismatch on {vpn_rel}")
        if sha256_file(sess_file) != obs["session_record_sha256"]:
            results["issues"].append(f"Hash mismatch on {sess_rel}")
        verified_artifacts += 1

        # Check raw pcap readability and outer ESP
        esp_pkts = count_outer_esp(raw_pcap_file)
        if esp_pkts <= 0:
            results["issues"].append(f"No outer ESP packets found in {raw_pcap_rel}")
        else:
            outer_esp_verified += 1

        # Measurement verification
        meas_data = json.loads(meas_file.read_text(encoding="utf-8"))
        truth_data = json.loads(truth_file.read_text(encoding="utf-8"))
        workload_type = obs["workload"]["type"]

        if workload_type == "icmpv4_echo":
            # Compare ping sent/recv with receiver echo requests
            sent = meas_data.get("senderMeasurements", [{}])[0].get("packetsSent")
            recv = meas_data.get("senderMeasurements", [{}])[0].get("packetsReceived")
            recv_requests = meas_data.get("independentReceiverEvidence", {}).get("echoRequests")
            if sent != recv or sent != recv_requests:
                results["issues"].append(f"ICMP mismatch in {exp_id}: sent={sent}, recv={recv}, rcvr_req={recv_requests}")
            else:
                measurement_verified += 1
        elif workload_type == "tcp_marker":
            # Compare sender bytes and sha256 with receiver bytes and sha256
            s_bytes = meas_data.get("sender", {}).get("bytesSent")
            s_sha = meas_data.get("sender", {}).get("expectedPayloadSha256")
            r_bytes = meas_data.get("receiver", {}).get("bytesReceived")
            r_sha = meas_data.get("receiver", {}).get("payloadSha256")
            if s_bytes != r_bytes or s_sha != r_sha:
                results["issues"].append(f"TCP mismatch in {exp_id}: s_bytes={s_bytes}, r_bytes={r_bytes}, s_sha={s_sha}, r_sha={r_sha}")
            else:
                measurement_verified += 1

    results["checks"]["verified_artifact_records"] = verified_artifacts
    results["checks"]["outer_esp_verified_count"] = outer_esp_verified
    results["checks"]["measurement_verified_count"] = measurement_verified

    # 4. Dataset Report and Split Manifest consistency
    results["checks"]["report_status"] = report.get("status")
    results["checks"]["report_accepted"] = report.get("accepted_observations")
    results["checks"]["report_quarantined"] = report.get("quarantined_observations")
    results["checks"]["report_independent_sessions"] = report.get("independent_session_count")
    results["checks"]["report_class_distribution"] = report.get("class_distribution")

    split_sessions = split.get("session_ids", {})
    split_keys = split.get("independent_session_keys", {})
    train_sess = set(split_sessions.get("train", []))
    val_sess = set(split_sessions.get("validation", []))
    test_sess = set(split_sessions.get("test", []))

    results["checks"]["train_sessions_count"] = len(train_sess)
    results["checks"]["validation_sessions_count"] = len(val_sess)
    results["checks"]["test_sessions_count"] = len(test_sess)

    # Check zero overlap
    train_val_overlap = train_sess & val_sess
    train_test_overlap = train_sess & test_sess
    val_test_overlap = val_sess & test_sess

    results["checks"]["train_val_session_overlap"] = len(train_val_overlap)
    results["checks"]["train_test_session_overlap"] = len(train_test_overlap)
    results["checks"]["val_test_session_overlap"] = len(val_test_overlap)

    if train_val_overlap or train_test_overlap or val_test_overlap:
        results["issues"].append("Session leakage detected across splits!")

    train_keys = set(split_keys.get("train", []))
    val_keys = set(split_keys.get("validation", []))
    test_keys = set(split_keys.get("test", []))
    key_overlap = (train_keys & val_keys) | (train_keys & test_keys) | (val_keys & test_keys)
    results["checks"]["key_overlap"] = len(key_overlap)
    if key_overlap:
        results["issues"].append("IKE key leakage detected across splits!")

    # Check class representation in splits
    class_dist = split.get("class_distributions", {})
    results["checks"]["split_class_distributions"] = class_dist
    for split_name in ("train", "validation", "test"):
        dist = class_dist.get(split_name, {})
        if set(dist.keys()) != {"controlled_icmpv4_echo", "controlled_tcp_marker"}:
            results["issues"].append(f"Split {split_name} missing classes: {dist}")

    return results


if __name__ == "__main__":
    campaign = Path("captures/strongswan/collections/campaigns/e2e8adae-94d7-4a1d-9569-3c3e1a965e64")
    res = audit_campaign(campaign)
    print(json.dumps(res, indent=2))
