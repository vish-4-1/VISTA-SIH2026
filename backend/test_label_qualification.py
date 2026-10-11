from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any

import pandas as pd
import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vista-ml" / "scripts"))

import run_collection_campaign as campaign  # noqa: E402
from backend.services import workload_collection  # noqa: E402
from prepare_experiment_dataset import (  # noqa: E402
    prepare_dataset,
    validate_manifest_shape,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_target_label_schema_json_is_valid():
    """Verify vista-target-label-schema-v1.json defines the 3 target classes and boundary."""
    schema_path = ROOT / "vista-ml" / "schemas" / "vista-target-label-schema-v1.json"
    assert schema_path.is_file()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["schema_version"] == "vista-target-label-schema-v1"
    assert "Outer ESP" in schema["domain_boundary"]

    # Verify 3 canonical target classes
    targets = schema["target_classes"]
    assert set(targets.keys()) == {
        "controlled_icmpv4",
        "controlled_tcp_marker",
        "controlled_http",
    }
    assert "icmpv4_echo" in targets["controlled_icmpv4"]["allowed_subtypes"]
    assert "tcp_marker" in targets["controlled_tcp_marker"]["allowed_subtypes"]
    assert set(targets["controlled_http"]["allowed_subtypes"]) == {"http_get", "http_post"}

    # Verify mapping
    mapping = schema["workload_subtype_mapping"]
    assert mapping["icmpv4_echo"] == "controlled_icmpv4"
    assert mapping["tcp_marker"] == "controlled_tcp_marker"
    assert mapping["http_get"] == "controlled_http"
    assert mapping["http_post"] == "controlled_http"


def test_workload_dispatch_applies_correct_target_labels():
    """Verify dispatch applies canonical target labels and workload subtypes."""
    configs: dict[str, dict[str, Any]] = {}

    def mock_icmp(c):
        configs["icmpv4"] = dict(c)
        return {"status": "PASS"}

    def mock_tcp(c):
        configs["tcp_marker"] = dict(c)
        return {"status": "PASS"}

    def mock_http(c):
        configs[c.get("workloadSubtype", "http")] = dict(c)
        return {"status": "PASS"}

    orig_icmp = campaign.collector.collect_icmp_workload
    orig_tcp = campaign.collector.collect_tcp_marker_workload
    orig_http = campaign.collector.collect_http_workload
    try:
        campaign.collector.collect_icmp_workload = mock_icmp
        campaign.collector.collect_tcp_marker_workload = mock_tcp
        campaign.collector.collect_http_workload = mock_http

        campaign._dispatch_workload("icmpv4", {})
        campaign._dispatch_workload("tcp_marker", {})
        campaign._dispatch_workload("http_get", {})
        campaign._dispatch_workload("http_post", {})

        assert configs["icmpv4"]["targetLabel"] == "controlled_icmpv4"
        assert configs["icmpv4"]["workloadSubtype"] == "icmpv4_echo"
        assert configs["icmpv4"]["labelSchemaVersion"] == "vista-target-label-schema-v1"

        assert configs["tcp_marker"]["targetLabel"] == "controlled_tcp_marker"
        assert configs["tcp_marker"]["workloadSubtype"] == "tcp_marker"
        assert configs["tcp_marker"]["labelSchemaVersion"] == "vista-target-label-schema-v1"

        assert configs["http_get"]["targetLabel"] == "controlled_http"
        assert configs["http_get"]["workloadSubtype"] == "http_get"
        assert configs["http_get"]["labelSchemaVersion"] == "vista-target-label-schema-v1"

        assert configs["http_post"]["targetLabel"] == "controlled_http"
        assert configs["http_post"]["workloadSubtype"] == "http_post"
        assert configs["http_post"]["labelSchemaVersion"] == "vista-target-label-schema-v1"
    finally:
        campaign.collector.collect_icmp_workload = orig_icmp
        campaign.collector.collect_tcp_marker_workload = orig_tcp
        campaign.collector.collect_http_workload = orig_http


def test_unified_schedule_contains_all_workloads_in_every_session():
    """Verify unified schedule includes icmpv4, tcp_marker, http_get, and http_post."""
    sched = campaign.make_campaign_schedule(15, 26160, workload_set="unified")
    assert len(sched) == 15
    for plan in sched:
        assert set(plan["workloadOrder"]) == {"icmpv4", "tcp_marker", "http_get", "http_post"}
        assert set(plan["profiles"]) == {"icmpv4", "tcp_marker", "http_get", "http_post"}
        assert plan["profiles"]["http_get"]["method"] == "GET"
        assert plan["profiles"]["http_post"]["method"] == "POST"


def _build_multiworkload_fixture(
    tmp_path: Path, *, sessions: int = 15, corrupt_field: str | None = None
) -> Path:
    """Build a synthetic 15-session multi-workload dataset with ICMP, TCP, HTTP GET, and HTTP POST."""
    observations = []
    workload_configs = [
        ("controlled_icmpv4", "icmpv4_echo", 64, 84),
        ("controlled_tcp_marker", "tcp_marker", 128, 140),
        ("controlled_http", "http_get", 256, 320),
        ("controlled_http", "http_post", 512, 600),
    ]

    for session_idx in range(sessions):
        session_id = str(uuid.uuid4())
        experiment_ids = [str(uuid.uuid4()) for _ in range(len(workload_configs))]
        sa_identity = hashlib.sha256(f"test-sa-{session_idx}".encode("ascii")).hexdigest()
        prev_identity = hashlib.sha256(f"test-prev-sa-{session_idx}".encode("ascii")).hexdigest()
        started = pd.Timestamp("2026-10-10T06:00:00Z") + pd.Timedelta(seconds=session_idx * 120)

        session_record_path = tmp_path / f"session-{session_idx:02d}.json"
        session_record = {
            "sessionId": session_id,
            "sessionIdSource": "unit test verified session UUID",
            "sessionStartedAt": started.isoformat(),
            "sessionObservedThroughAt": (started + pd.Timedelta(seconds=60)).isoformat(),
            "experimentIds": experiment_ids,
            "containerIds": {"pc1": f"pc1-c{session_idx}", "pc2": f"pc2-c{session_idx}"},
            "vpnLifecycle": {
                "ikeSaIdentitySha256": sa_identity,
                "ikeSaAgeSeconds": 1,
                "reestablishment": {
                    "independenceStatus": "VERIFIED_DISTINCT_IKE_SA",
                    "previousIkeSaIdentitySha256": prev_identity,
                    "ikeSaIdentitySha256": sa_identity,
                    "reestablishedAt": (started - pd.Timedelta(seconds=1)).isoformat(),
                },
            },
        }
        session_record_path.write_text(json.dumps(session_record), encoding="utf-8")

        for w_idx, (label, subtype, fwd_len, bwd_len) in enumerate(workload_configs):
            exp_id = experiment_ids[w_idx]
            exp_start = started + pd.Timedelta(seconds=w_idx * 15)

            # Packet CSV
            packet_path = tmp_path / f"{exp_id}-packets.csv"
            pd.DataFrame([
                {
                    "timestamp": exp_start.isoformat(),
                    "packet_length": fwd_len + session_idx,
                    "protocol": "ESP",
                    "flow_id": f"ESP|{sa_identity[:8]}|fwd",
                    "direction": "forward",
                },
                {
                    "timestamp": (exp_start + pd.Timedelta(seconds=1)).isoformat(),
                    "packet_length": bwd_len + session_idx,
                    "protocol": "ESP",
                    "flow_id": f"ESP|{sa_identity[:8]}|fwd",
                    "direction": "backward",
                },
            ]).to_csv(packet_path, index=False)

            # Raw PCAP
            raw_pcap_path = tmp_path / f"{exp_id}.pcap"
            wrpcap(
                str(raw_pcap_path),
                [
                    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                    / IP(src="172.20.0.2", dst="172.20.0.3", proto=50)
                    / bytes([w_idx + 1]) * (fwd_len - 34),
                    Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                    / IP(src="172.20.0.3", dst="172.20.0.2", proto=50)
                    / bytes([w_idx + 2]) * (bwd_len - 34),
                ],
            )

            # Ground truth record
            gt_path = tmp_path / f"{exp_id}-gt.json"
            gt_record = {
                "label": label,
                "labelSchemaVersion": "vista-target-label-schema-v1",
                "workloadSubtype": subtype,
                "experimentId": exp_id,
                "sessionId": session_id,
            }
            gt_path.write_text(json.dumps(gt_record), encoding="utf-8")

            # Measurement record
            meas_path = tmp_path / f"{exp_id}-meas.json"
            meas_path.write_text(
                json.dumps({"experimentId": exp_id, "sessionId": session_id}),
                encoding="utf-8",
            )

            # SA record
            sa_path = tmp_path / f"{exp_id}-sa.json"
            sa_path.write_text(
                json.dumps({"ikeSaIdentitySha256": sa_identity}),
                encoding="utf-8",
            )

            obs = {
                "experiment_id": exp_id,
                "session_id": session_id,
                "session_record_path": session_record_path.name,
                "session_record_sha256": _sha(session_record_path),
                "capture": {
                    "path": packet_path.name,
                    "format": "packet_table_csv",
                    "sha256": _sha(packet_path),
                    "started_at": exp_start.isoformat(),
                    "completed_at": (exp_start + pd.Timedelta(seconds=2)).isoformat(),
                    "interface": "eth0",
                    "capture_point": "outer",
                    "ip_version": 4,
                    "protocol_family": "ESP",
                    "raw_pcap_path": raw_pcap_path.name,
                    "raw_pcap_format": "pcap",
                    "raw_pcap_sha256": _sha(raw_pcap_path),
                    "raw_pcap_size_bytes": raw_pcap_path.stat().st_size,
                },
                "ground_truth": {
                    "label": label,
                    "label_schema_version": "vista-target-label-schema-v1",
                    "workload_subtype": subtype,
                    "record_path": gt_path.name,
                    "record_sha256": _sha(gt_path),
                    "record_field": "label",
                    "method": "independent synthetic testbench record",
                    "independently_verified": True,
                },
                "workload": {
                    "type": "http_traffic" if "http" in subtype else ("icmpv4_echo" if "icmp" in subtype else "tcp_marker"),
                    "subtype": subtype,
                    "configuration": {"param": session_idx + w_idx},
                    "measurement_path": meas_path.name,
                    "measurement_sha256": _sha(meas_path),
                },
                "vpn": {
                    "requested_configuration": {"mode": "tunnel"},
                    "effective_configuration": {"mode": "tunnel"},
                    "negotiated_sa_evidence_path": sa_path.name,
                    "negotiated_sa_evidence_sha256": _sha(sa_path),
                },
                "data_quality": {"status": "accepted", "reasons": []},
            }

            if corrupt_field == "unsupported_label" and session_idx == 0 and w_idx == 0:
                obs["ground_truth"]["label"] = "malicious_covert_channel"
                gt_path.write_text(json.dumps({**gt_record, "label": "malicious_covert_channel"}), encoding="utf-8")
                obs["ground_truth"]["record_sha256"] = _sha(gt_path)
            elif corrupt_field == "contradictory_evidence" and session_idx == 0 and w_idx == 0:
                # ground truth file has different label than manifest
                gt_path.write_text(json.dumps({**gt_record, "label": "different_label"}), encoding="utf-8")
                obs["ground_truth"]["record_sha256"] = _sha(gt_path)
            elif corrupt_field == "raw_pcap_hash_mismatch" and session_idx == 0 and w_idx == 0:
                obs["capture"]["raw_pcap_sha256"] = "f" * 64
            elif corrupt_field == "csv_hash_mismatch" and session_idx == 0 and w_idx == 0:
                obs["capture"]["sha256"] = "e" * 64

            observations.append(obs)

    manifest = {
        "manifest_version": "vista-strongswan-experiment-v2",
        "dataset_id": f"fixture-unified-{sessions}s",
        "feature_schema_version": "vista-flow-v1",
        "extractor_version": "vista-ml-pcap-features-v1",
        "observations": observations,
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def test_unified_15_session_multiworkload_dataset_qualification(tmp_path: Path):
    """Verify 15-session 3-class dataset achieves READY_FOR_REVIEW with 9/3/3 split and 0 leakage."""
    manifest_path = _build_multiworkload_fixture(tmp_path, sessions=15)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert validate_manifest_shape(manifest) == []

    output_dir = tmp_path / "prepared_unified"
    report = prepare_dataset(manifest_path, output_dir, seed=26160)

    assert report["status"] == "READY_FOR_REVIEW"
    assert report["accepted_observations"] == 60  # 15 sessions * 4 workloads
    assert report["quarantined_observations"] == 0
    assert report["independent_session_count"] == 15

    # Check 3 target classes distribution
    class_dist = report["class_distribution"]
    assert class_dist["controlled_icmpv4"] == 15
    assert class_dist["controlled_tcp_marker"] == 15
    assert class_dist["controlled_http"] == 30  # 15 GET + 15 POST

    # Verify split integrity: 9 train, 3 val, 3 test
    split = report["split_manifest"]
    session_splits = split["session_ids"]
    assert len(session_splits["train"]) == 9
    assert len(session_splits["validation"]) == 3
    assert len(session_splits["test"]) == 3

    # Zero leakage across session sets
    assert not (set(session_splits["train"]) & set(session_splits["validation"]))
    assert not (set(session_splits["train"]) & set(session_splits["test"]))
    assert not (set(session_splits["validation"]) & set(session_splits["test"]))

    # Zero leakage across IKE SA identities
    ike_splits = split["independent_session_keys"]
    assert not (set(ike_splits["train"]) & set(ike_splits["validation"]))
    assert not (set(ike_splits["train"]) & set(ike_splits["test"]))
    assert not (set(ike_splits["validation"]) & set(ike_splits["test"]))

    # Verify all 3 classes are represented in train, validation, and test splits
    split_classes = split["class_distributions"]
    for split_name in ("train", "validation", "test"):
        assert set(split_classes[split_name].keys()) == {
            "controlled_icmpv4",
            "controlled_tcp_marker",
            "controlled_http",
        }
        # In 9/3/3 split: train has 9 of each (18 http), val has 3 of each (6 http), test has 3 of each (6 http)
        assert split_classes[split_name]["controlled_icmpv4"] > 0
        assert split_classes[split_name]["controlled_tcp_marker"] > 0
        assert split_classes[split_name]["controlled_http"] > 0


def test_contradictory_endpoint_evidence_is_quarantined(tmp_path: Path):
    """Verify mismatched ground-truth record is quarantined."""
    manifest_path = _build_multiworkload_fixture(
        tmp_path, sessions=15, corrupt_field="contradictory_evidence"
    )
    output_dir = tmp_path / "prepared_contradiction"
    report = prepare_dataset(manifest_path, output_dir, seed=26160)

    assert report["quarantined_observations"] == 1
    reasons = report["exclusions"][0]["reasons"]
    assert "ground_truth_record_does_not_support_manifest_label" in reasons


def test_raw_pcap_hash_mismatch_is_quarantined(tmp_path: Path):
    """Verify raw PCAP SHA-256 mismatch is quarantined."""
    manifest_path = _build_multiworkload_fixture(
        tmp_path, sessions=15, corrupt_field="raw_pcap_hash_mismatch"
    )
    output_dir = tmp_path / "prepared_pcap_mismatch"
    report = prepare_dataset(manifest_path, output_dir, seed=26160)

    assert report["quarantined_observations"] == 1
    reasons = report["exclusions"][0]["reasons"]
    assert "raw_pcap_sha256_mismatch" in reasons


def test_packet_csv_hash_mismatch_is_quarantined(tmp_path: Path):
    """Verify packet CSV SHA-256 mismatch is quarantined."""
    manifest_path = _build_multiworkload_fixture(
        tmp_path, sessions=15, corrupt_field="csv_hash_mismatch"
    )
    output_dir = tmp_path / "prepared_csv_mismatch"
    report = prepare_dataset(manifest_path, output_dir, seed=26160)

    assert report["quarantined_observations"] == 1
    reasons = report["exclusions"][0]["reasons"]
    assert "capture_sha256_mismatch" in reasons


def test_leakage_via_identifier_containing_label_is_quarantined(tmp_path: Path):
    """Verify an observation whose experiment ID or capture path leaks the label is quarantined."""
    manifest_path = _build_multiworkload_fixture(tmp_path, sessions=15)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Leak label into capture path
    leaked_path = tmp_path / "controlled_http_leak.csv"
    orig_path = tmp_path / manifest["observations"][2]["capture"]["path"]
    leaked_path.write_bytes(orig_path.read_bytes())
    manifest["observations"][2]["capture"]["path"] = leaked_path.name
    manifest["observations"][2]["capture"]["sha256"] = _sha(leaked_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    output_dir = tmp_path / "prepared_leak"
    report = prepare_dataset(manifest_path, output_dir, seed=26160)

    assert report["quarantined_observations"] >= 1
    matching = [
        e for e in report["exclusions"]
        if "identifier_or_filename_contains_target_label" in e["reasons"]
    ]
    assert len(matching) == 1


def test_phase9_saved_audit_report_matches_schema_and_gates():
    """Verify vista-ml/reports/phase9_dataset_audit.json has all 9 gates and expected statuses."""
    report_path = ROOT / "vista-ml" / "reports" / "phase9_dataset_audit.json"
    assert report_path.is_file(), f"Missing audit report: {report_path}"
    audit = json.loads(report_path.read_text(encoding="utf-8"))

    assert audit["audited_campaign_id"] == "76adc766-ef41-45f5-b677-1d950c7ff052"
    assert audit["discrepancies"] == []
    assert audit["overall_eligibility_status"] == "PASS"

    gates = audit["gates"]
    assert gates["artifact_integrity"]["status"] == "PASS"
    assert gates["ground_truth_integrity"]["status"] == "PASS"
    assert gates["label_integrity"]["status"] == "PASS"
    assert gates["feature_integrity"]["status"] == "PASS"
    assert gates["leakage_controls"]["status"] == "PASS"
    assert gates["class_coverage"]["status"] == "PASS"
    assert gates["split_validity"]["status"] == "PASS"
    assert gates["independent_campaign_validation"]["status"] == "BLOCKED"
    assert gates["baseline_eligibility"]["status"] == "PASS"

    assert "Model promotion, production deployment, and operational inference remain BLOCKED" in audit["scope_boundary"]
    assert audit["dataset_metrics"]["total_observations"] == 60
    assert audit["dataset_metrics"]["independent_sessions"] == 15
    assert audit["dataset_metrics"]["duplicate_vectors_count"] == 0
    assert audit["dataset_metrics"]["near_duplicate_vectors_count"] == 0
    assert audit["recomputed_evidence"]["re_extracted_feature_matches"] == 60


def test_phase9_audit_recomputes_parity_and_session_independence():
    """Execute live recomputation audit of Phase 8 campaign artifacts."""
    from audit_phase9_dataset import audit_phase9

    audit = audit_phase9("76adc766-ef41-45f5-b677-1d950c7ff052")
    assert audit["discrepancies"] == []
    assert audit["overall_eligibility_status"] == "PASS"

    gates = audit["gates"]
    for gate_name in [
        "artifact_integrity",
        "ground_truth_integrity",
        "label_integrity",
        "feature_integrity",
        "leakage_controls",
        "class_coverage",
        "split_validity",
        "baseline_eligibility",
    ]:
        assert gates[gate_name]["status"] == "PASS"
    assert gates["independent_campaign_validation"]["status"] == "BLOCKED"

    # Recomputed evidence
    evidence = audit["recomputed_evidence"]
    assert evidence["verified_raw_pcaps"] == 60
    assert evidence["verified_packet_csvs"] == 60
    assert evidence["verified_outer_esp_pcaps"] == 60
    assert evidence["re_extracted_feature_matches"] == 60
    assert evidence["verified_ground_truth_records"] == 60
    assert evidence["verified_session_records"] == 60
    assert evidence["verified_endpoint_agreements"] == 60

    # Dataset metrics
    metrics = audit["dataset_metrics"]
    assert metrics["total_observations"] == 60
    assert metrics["independent_sessions"] == 15
    assert metrics["distinct_ike_identities"] == 15
    assert metrics["duplicate_vectors_count"] == 0
    assert metrics["near_duplicate_vectors_count"] == 0
