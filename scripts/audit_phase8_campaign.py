#!/usr/bin/env python3
"""
Phase 8 Campaign Audit Tool for VISTA.
Verifies unified multi-workload dataset campaign artifacts, 15 independent sessions,
60 observations (15 ICMP, 15 TCP marker, 30 HTTP), artifact SHA-256 hashes,
outer ESP frames, endpoint ground-truth agreement, class distribution,
and leakage-free 9/3/3 session split (READY_FOR_REVIEW).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import ESP
from scapy.utils import PcapReader

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGNS_ROOT = ROOT / "captures" / "strongswan" / "collections" / "campaigns"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_outer_esp(pcap_path: Path) -> int:
    count = 0
    for packet in PcapReader(str(pcap_path)):
        if IP in packet and (int(packet[IP].proto) == 50 or ESP in packet):
            count += 1
        elif UDP in packet and int(packet[UDP].dport) == 4500:
            payload = bytes(packet[UDP].payload)
            if payload and payload[:4] != b"\x00\x00\x00\x00":
                count += 1
    return count


def audit_campaign(campaign_dir: Path) -> dict[str, Any]:
    issues: list[str] = []
    checks: dict[str, Any] = {
        "campaign_id": campaign_dir.name,
    }

    summary_path = campaign_dir / "campaign_summary.json"
    manifest_path = campaign_dir / "campaign_manifest.json"
    prep_dir = campaign_dir / "dataset_preparation"
    report_path = prep_dir / "dataset_report.json"
    split_path = prep_dir / "split_manifest.json"

    if not summary_path.is_file():
        issues.append("campaign_summary_missing")
        return {"checks": checks, "issues": issues, "audit_passed": False}
    if not manifest_path.is_file():
        issues.append("campaign_manifest_missing")
        return {"checks": checks, "issues": issues, "audit_passed": False}

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    checks["workload_set"] = summary.get("workloadSet")
    sessions = summary.get("sessions", [])
    checks["session_count"] = len(sessions)

    session_ids = [s.get("sessionId") for s in sessions]
    distinct_session_ids = set(session_ids)
    checks["distinct_session_ids"] = len(distinct_session_ids)
    if len(distinct_session_ids) != 15:
        issues.append(f"expected_15_distinct_sessions_found_{len(distinct_session_ids)}")

    experiment_ids = []
    for s in sessions:
        for exp in s.get("experiments", []):
            experiment_ids.append(exp.get("experimentId"))
    checks["experiment_count"] = len(experiment_ids)
    checks["distinct_experiment_ids"] = len(set(experiment_ids))
    if len(experiment_ids) != 60:
        issues.append(f"expected_60_experiments_found_{len(experiment_ids)}")
    if len(set(experiment_ids)) != len(experiment_ids):
        issues.append("duplicate_experiment_ids_in_summary")

    observations = manifest.get("observations", [])
    checks["manifest_observations"] = len(observations)
    manifest_exp_ids = [o.get("experiment_id") for o in observations]
    checks["manifest_distinct_experiments"] = len(set(manifest_exp_ids))
    if len(observations) != 60:
        issues.append(f"manifest_expected_60_observations_found_{len(observations)}")

    # Check distinct IKE_SA identities
    ike_identities = set()
    for s in sessions:
        if s.get("independenceStatus") != "VERIFIED_DISTINCT_IKE_SA":
            issues.append(f"session_{s.get('sessionId')}_not_VERIFIED_DISTINCT_IKE_SA")
        reest = s.get("saReestablishment", s.get("reestablishment", {}))
        ident = reest.get("newIkeSaIdentitySha256", reest.get("ikeSaIdentitySha256"))
        if ident:
            ike_identities.add(ident)
        if reest.get("previousIkeSaIdentitySha256") == ident:
            issues.append(f"session_{s.get('sessionId')}_prior_identity_matches_new_identity")
    checks["distinct_ike_identities"] = len(ike_identities)
    if len(ike_identities) != 15:
        issues.append(f"expected_15_distinct_ike_identities_found_{len(ike_identities)}")


    # Check observation artifacts, hashes, ESP frames, and agreement
    hash_verified_count = 0
    outer_esp_verified_count = 0
    agreement_verified_count = 0
    target_class_counts: dict[str, int] = {}

    for obs_idx, obs in enumerate(observations):
        exp_id = obs["experiment_id"]
        sess_id = obs["session_id"]
        exp_dir = campaign_dir / "artifacts" / sess_id / exp_id

        # Verify session record
        sess_rec_path = campaign_dir / obs["session_record_path"]
        if not sess_rec_path.is_file() or sha256_file(sess_rec_path) != obs["session_record_sha256"]:
            issues.append(f"obs_{exp_id}_session_record_hash_mismatch")

        # Verify packet table
        cap = obs["capture"]
        pkt_path = campaign_dir / cap["path"]
        if not pkt_path.is_file() or sha256_file(pkt_path) != cap["sha256"]:
            issues.append(f"obs_{exp_id}_packet_table_hash_mismatch")

        # Verify raw PCAP
        raw_pcap_path = campaign_dir / cap["raw_pcap_path"]
        if not raw_pcap_path.is_file() or sha256_file(raw_pcap_path) != cap["raw_pcap_sha256"]:
            issues.append(f"obs_{exp_id}_raw_pcap_hash_mismatch")
        else:
            esp_count = count_outer_esp(raw_pcap_path)
            if esp_count > 0:
                outer_esp_verified_count += 1
            else:
                issues.append(f"obs_{exp_id}_pc1_pcap_has_zero_outer_esp")

        # Verify ground truth
        gt = obs["ground_truth"]
        gt_path = campaign_dir / gt["record_path"]
        if not gt_path.is_file() or sha256_file(gt_path) != gt["record_sha256"]:
            issues.append(f"obs_{exp_id}_ground_truth_hash_mismatch")
        else:
            gt_data = json.loads(gt_path.read_text(encoding="utf-8"))
            label = gt["label"]
            target_class_counts[label] = target_class_counts.get(label, 0) + 1
            if gt_data.get("label") != label:
                issues.append(f"obs_{exp_id}_ground_truth_label_mismatch")

            # Check endpoint agreements
            if label == "controlled_icmpv4":
                if gt_data.get("senderPacketsSent") != gt_data.get("senderPacketsReceived"):
                    issues.append(f"obs_{exp_id}_icmp_sent_recv_mismatch")
                if gt_data.get("receiverEchoRequests") != gt_data.get("requestedPackets"):
                    issues.append(f"obs_{exp_id}_icmp_receiver_requests_mismatch")
                agreement_verified_count += 1
            elif label == "controlled_tcp_marker":
                if gt_data.get("bytesSent") != gt_data.get("bytesReceived"):
                    issues.append(f"obs_{exp_id}_tcp_bytes_mismatch")
                if gt_data.get("senderPayloadSha256") != gt_data.get("receiverPayloadSha256"):
                    issues.append(f"obs_{exp_id}_tcp_sha_mismatch")
                agreement_verified_count += 1
            elif label == "controlled_http":
                meas_path = exp_dir / "workload_measurements.json"
                meas_data = json.loads(meas_path.read_text(encoding="utf-8")) if meas_path.is_file() else {}
                srv_evidence_path = exp_dir / "server_evidence.json"
                if not srv_evidence_path.is_file():
                    srv_evidence_path = ROOT / "captures" / "strongswan" / "collections" / sess_id / exp_id / "server_evidence.json"
                if not srv_evidence_path.is_file():
                    issues.append(f"obs_{exp_id}_server_evidence_missing")
                else:
                    if sha256_file(srv_evidence_path) != gt_data.get("serverEvidenceSha256"):
                        issues.append(f"obs_{exp_id}_server_evidence_hash_mismatch")
                    srv_data = json.loads(srv_evidence_path.read_text(encoding="utf-8"))
                    reqs_req = gt_data.get("requestsRequested", 0)
                    cli_results = meas_data.get("senderMeasurements", {})
                    if cli_results.get("totalRequestsSent") != reqs_req or srv_data.get("totalRequestsReceived") != reqs_req:
                        issues.append(f"obs_{exp_id}_http_requests_mismatch")
                    cli_reqs = cli_results.get("requests", [])
                    srv_reqs = srv_data.get("requests", [])
                    hashes_match = all(
                        c.get("responseSha256") == s.get("responseSha256") and c.get("statusCode") == 200
                        for c, s in zip(cli_reqs, srv_reqs)
                    )
                    if not hashes_match:
                        issues.append(f"obs_{exp_id}_http_hash_or_status_mismatch")
                    agreement_verified_count += 1

        # Verify workload measurement
        wl = obs["workload"]
        wl_meas_path = campaign_dir / wl["measurement_path"]
        if not wl_meas_path.is_file() or sha256_file(wl_meas_path) != wl["measurement_sha256"]:
            issues.append(f"obs_{exp_id}_workload_measurement_hash_mismatch")

        # Verify negotiated SA
        vpn = obs["vpn"]
        sa_path = campaign_dir / vpn["negotiated_sa_evidence_path"]
        if not sa_path.is_file() or sha256_file(sa_path) != vpn["negotiated_sa_evidence_sha256"]:
            issues.append(f"obs_{exp_id}_negotiated_sa_hash_mismatch")

        hash_verified_count += 1

    checks["verified_artifact_records"] = hash_verified_count
    checks["outer_esp_verified_count"] = outer_esp_verified_count
    checks["agreement_verified_count"] = agreement_verified_count
    checks["target_class_counts"] = target_class_counts

    expected_classes = {
        "controlled_icmpv4": 15,
        "controlled_tcp_marker": 15,
        "controlled_http": 30,
    }
    if target_class_counts != expected_classes:
        issues.append(f"target_class_counts_mismatch: observed {target_class_counts}, expected {expected_classes}")

    # Check dataset report and split manifest
    if not report_path.is_file():
        issues.append("dataset_report_missing")
    else:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        checks["report_status"] = report.get("status")
        checks["report_accepted"] = report.get("accepted_observations")
        checks["report_quarantined"] = report.get("quarantined_observations")
        checks["report_independent_sessions"] = report.get("independent_session_count")
        checks["report_class_distribution"] = report.get("class_distribution")

        if report.get("status") != "READY_FOR_REVIEW":
            issues.append(f"report_status_not_READY_FOR_REVIEW: {report.get('status')}")
        if report.get("accepted_observations") != 60:
            issues.append(f"expected_60_accepted_observations: {report.get('accepted_observations')}")
        if report.get("quarantined_observations") != 0:
            issues.append(f"quarantined_observations_nonzero: {report.get('quarantined_observations')}")

    if not split_path.is_file():
        issues.append("split_manifest_missing")
    else:
        split = json.loads(split_path.read_text(encoding="utf-8"))
        sess_ids = split.get("session_ids", {})
        train_s = set(sess_ids.get("train", []))
        val_s = set(sess_ids.get("validation", []))
        test_s = set(sess_ids.get("test", []))

        checks["train_sessions_count"] = len(train_s)
        checks["validation_sessions_count"] = len(val_s)
        checks["test_sessions_count"] = len(test_s)
        checks["train_val_session_overlap"] = len(train_s & val_s)
        checks["train_test_session_overlap"] = len(train_s & test_s)
        checks["val_test_session_overlap"] = len(val_s & test_s)

        if len(train_s) != 9 or len(val_s) != 3 or len(test_s) != 3:
            issues.append(f"unexpected_session_split_sizes: train={len(train_s)}, val={len(val_s)}, test={len(test_s)}")
        if train_s & val_s or train_s & test_s or val_s & test_s:
            issues.append("session_leakage_detected_across_splits")

        checks["split_row_counts"] = split.get("row_counts", {})
        checks["split_class_distributions"] = split.get("class_distributions", {})

        # Verify all 3 classes exist in each split
        for split_name in ("train", "validation", "test"):
            dist = split.get("class_distributions", {}).get(split_name, {})
            if set(dist.keys()) != {"controlled_icmpv4", "controlled_tcp_marker", "controlled_http"}:
                issues.append(f"split_{split_name}_missing_target_classes: {dist}")

    checks["total_issues"] = len(issues)
    checks["audit_passed"] = len(issues) == 0

    return {
        "checks": checks,
        "issues": issues,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Phase 8 unified multi-workload campaign.")
    parser.add_argument("--campaign-id", help="Campaign UUIDv4 to audit. If omitted, uses latest.")
    args = parser.parse_args()

    if args.campaign_id:
        campaign_dir = CAMPAIGNS_ROOT / args.campaign_id
    else:
        candidates = sorted(
            [d for d in CAMPAIGNS_ROOT.iterdir() if d.is_dir() and (d / "campaign_manifest.json").is_file()],
            key=lambda d: d.stat().st_mtime,
        )
        if not candidates:
            # Look for most recently modified directory
            candidates = sorted(
                [d for d in CAMPAIGNS_ROOT.iterdir() if d.is_dir()],
                key=lambda d: d.stat().st_mtime,
            )
        campaign_dir = candidates[-1]

    print(f"Auditing campaign: {campaign_dir}")
    result = audit_campaign(campaign_dir)
    print(json.dumps(result, indent=2))
    if not result["checks"].get("audit_passed"):
        sys.exit(1)


if __name__ == "__main__":
    main()
