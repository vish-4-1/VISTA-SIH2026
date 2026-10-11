from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

import pandas as pd
import pytest
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_experiment_dataset import (  # noqa: E402
    _duplicate_flags,
    prepare_dataset,
    validate_manifest_shape,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(tmp_path: Path, *, sessions: int = 15) -> Path:
    observations = []
    for session_index in range(sessions):
        session_id = str(uuid.uuid4())
        experiment_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        sa_identity = hashlib.sha256(
            f"fixture-sa-{session_index}".encode("ascii")
        ).hexdigest()
        previous_identity = hashlib.sha256(
            f"fixture-prior-sa-{session_index}".encode("ascii")
        ).hexdigest()
        session_started = pd.Timestamp("2026-01-01T00:00:00Z") + pd.Timedelta(
            seconds=session_index * 100
        )
        reestablished_at = session_started - pd.Timedelta(seconds=1)
        session_record_path = tmp_path / f"session-{session_index:02d}.json"
        session_record = {
            "sessionId": session_id,
            "sessionIdSource": "test fixture independently generated session UUID",
            "sessionStartedAt": session_started.isoformat(),
            "sessionObservedThroughAt": (
                session_started + pd.Timedelta(seconds=20)
            ).isoformat(),
            "experimentIds": experiment_ids,
            "containerIds": {"pc1": "fixture-pc1", "pc2": "fixture-pc2"},
            "vpnLifecycle": {
                "ikeSaIdentitySha256": sa_identity,
                "ikeSaAgeSeconds": 2,
                "reestablishment": {
                    "independenceStatus": "VERIFIED_DISTINCT_IKE_SA",
                    "previousIkeSaIdentitySha256": previous_identity,
                    "ikeSaIdentitySha256": sa_identity,
                    "reestablishedAt": reestablished_at.isoformat(),
                },
            },
        }
        session_record_path.write_text(
            json.dumps(session_record), encoding="utf-8"
        )
        for label_index, label in enumerate(("CLASS_A", "CLASS_B")):
            experiment_id = experiment_ids[label_index]
            packet_path = tmp_path / f"{experiment_id}.csv"
            start = session_started + pd.Timedelta(seconds=label_index * 10)
            pd.DataFrame(
                [
                    {
                        "timestamp": start.isoformat(),
                        "packet_length": 100 + session_index + label_index,
                        "protocol": "ESP",
                        "flow_id": f"ESP|a{session_index}|b",
                        "direction": "forward",
                    },
                    {
                        "timestamp": (start + pd.Timedelta(seconds=1 + session_index / 10)).isoformat(),
                        "packet_length": 200 + session_index + label_index,
                        "protocol": "ESP",
                        "flow_id": f"ESP|a{session_index}|b",
                        "direction": "backward",
                    },
                ]
            ).to_csv(packet_path, index=False)

            label_path = tmp_path / f"{experiment_id}-truth.json"
            label_path.write_text(json.dumps({"verified_label": label}), encoding="utf-8")
            sa_path = tmp_path / f"{experiment_id}-sa.json"
            sa_path.write_text(json.dumps({"ike_sa": "redacted", "child_sa": "redacted"}), encoding="utf-8")
            raw_capture_path = tmp_path / f"{experiment_id}.pcap"
            wrpcap(
                str(raw_capture_path),
                [
                    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
                        src="192.0.2.1", dst="192.0.2.2", proto=50
                    ) / bytes([session_index + label_index + 1]) * 16,
                    Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(
                        src="192.0.2.2", dst="192.0.2.1", proto=50
                    ) / bytes([session_index + label_index + 2]) * 16,
                ],
            )
            measurement_path = tmp_path / f"{experiment_id}-measurement.json"
            measurement_path.write_text(
                json.dumps({
                    "experimentId": experiment_id,
                    "sessionId": session_id,
                }),
                encoding="utf-8",
            )
            observations.append(
                {
                    "experiment_id": experiment_id,
                    "session_id": session_id,
                    "session_record_path": session_record_path.name,
                    "session_record_sha256": _sha(session_record_path),
                    "capture": {
                        "path": packet_path.name,
                        "format": "packet_table_csv",
                        "sha256": _sha(packet_path),
                        "started_at": start.isoformat(),
                        "completed_at": (start + pd.Timedelta(seconds=1)).isoformat(),
                        "interface": "eth0",
                        "capture_point": "outer",
                        "ip_version": 4,
                        "protocol_family": "ESP",
                        "raw_pcap_path": raw_capture_path.name,
                        "raw_pcap_format": "pcap",
                        "raw_pcap_sha256": _sha(raw_capture_path),
                        "raw_pcap_size_bytes": raw_capture_path.stat().st_size,
                    },
                    "ground_truth": {
                        "label": label,
                        "record_path": label_path.name,
                        "record_sha256": _sha(label_path),
                        "record_field": "verified_label",
                        "method": "test-fixture endpoint record",
                        "independently_verified": True,
                    },
                    "workload": {
                        "type": "icmpv4_echo",
                        "configuration": {"duration_seconds": session_index + 1},
                        "measurement_path": measurement_path.name,
                        "measurement_sha256": _sha(measurement_path),
                    },
                    "vpn": {
                        "requested_configuration": {"mode": "tunnel"},
                        "effective_configuration": {"mode": "tunnel"},
                        "negotiated_sa_evidence_path": sa_path.name,
                        "negotiated_sa_evidence_sha256": _sha(sa_path),
                    },
                    "data_quality": {"status": "accepted", "reasons": []},
                }
            )
    manifest = {
        "manifest_version": "vista-strongswan-experiment-v2",
        "dataset_id": "fixture-dataset",
        "feature_schema_version": "vista-flow-v1",
        "extractor_version": "fixture-extractor-v1",
        "observations": observations,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def test_manifest_schema_and_preparation_are_session_grouped_and_reproducible(
    tmp_path: Path,
) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert validate_manifest_shape(manifest) == []

    first = prepare_dataset(manifest_path, tmp_path / "prepared-a", seed=23)
    second = prepare_dataset(manifest_path, tmp_path / "prepared-b", seed=23)
    assert first["status"] == "READY_FOR_REVIEW"
    assert first["accepted_observations"] == 30
    assert first["quarantined_observations"] == 0
    assert first["independent_session_count"] == 15
    assert first["prepared_dataset_sha256"] == second["prepared_dataset_sha256"]
    assert first["split_manifest"] == second["split_manifest"]
    assert first["feature_target_separation"]["target_column"] == "label"
    features = first["feature_target_separation"]["model_features"]
    dataset = pd.read_csv(tmp_path / "prepared-a" / "prepared_dataset.csv")
    assert set(features).isdisjoint({"label", "experiment_id", "session_id", "capture_path"})
    assert list(dataset.columns) == [
        "experiment_id", "session_id", "label", "capture_path", "capture_sha256", *features
    ]
    splits = first["split_manifest"]["session_ids"]
    assert not set(splits["train"]) & set(splits["validation"])
    assert not set(splits["train"]) & set(splits["test"])
    assert not set(splits["validation"]) & set(splits["test"])


def test_bad_capture_hash_is_quarantined_with_reason(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][0]["capture"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert report["quarantined_observations"] == 1
    assert "capture_sha256_mismatch" in report["exclusions"][0]["reasons"]


def test_manifest_paths_cannot_escape_the_manifest_directory(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][0]["capture"]["path"] = "..\\outside.csv"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert any(
        "invalid_manifest_path" in reason
        for reason in report["exclusions"][0]["reasons"]
    )


def test_label_must_match_hashed_ground_truth_record(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][0]["ground_truth"]["label"] = "UNSUPPORTED_LABEL"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert "ground_truth_record_does_not_support_manifest_label" in report["exclusions"][0]["reasons"]


def test_unsupported_ipv6_capture_is_quarantined_for_ipv4_schema(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][0]["capture"]["ip_version"] = 6
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert "unsupported_ip_version_for_vista_flow_v1" in report["exclusions"][0]["reasons"]


def test_malformed_packet_table_is_quarantined(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    observation = manifest["observations"][0]
    packet_path = tmp_path / observation["capture"]["path"]
    packets = pd.read_csv(packet_path).drop(columns=["timestamp"])
    packets.to_csv(packet_path, index=False)
    observation["capture"]["sha256"] = _sha(packet_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert any(
        reason.startswith("packet_table_or_feature_extraction_error:")
        for reason in report["exclusions"][0]["reasons"]
    )


def test_malformed_observation_is_quarantined_instead_of_using_row_split(
    tmp_path: Path,
) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["observations"][0]["capture"]["protocol_family"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert report["quarantined_observations"] == 1
    assert any(
        reason.startswith("manifest_schema:missing_capture_fields")
        for reason in report["exclusions"][0]["reasons"]
    )


def test_duplicate_experiment_identifiers_are_quarantined(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][1]["experiment_id"] = manifest["observations"][0]["experiment_id"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    matching = [
        item for item in report["exclusions"]
        if "duplicate_experiment_id" in item["reasons"]
    ]
    assert len(matching) == 2


def test_labels_are_taken_from_ground_truth_record_and_not_identifier(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    observation = manifest["observations"][0]
    leaked_path = tmp_path / "class_a-capture.csv"
    leaked_path.write_bytes((tmp_path / observation["capture"]["path"]).read_bytes())
    observation["capture"]["path"] = leaked_path.name
    observation["capture"]["sha256"] = _sha(leaked_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert any(
        "identifier_or_filename_contains_target_label" in item["reasons"]
        for item in report["exclusions"]
    )


def test_duplicate_capture_hash_and_feature_vectors_are_quarantined() -> None:
    rows = [
        {
            "experiment_id": "one",
            "capture_sha256": "same",
            "packet_count": 2.0,
            "byte_count": 200.0,
        },
        {
            "experiment_id": "two",
            "capture_sha256": "different",
            "packet_count": 2.0,
            "byte_count": 200.0,
        },
        {
            "experiment_id": "three",
            "capture_sha256": "same",
            "packet_count": 3.0,
            "byte_count": 300.0,
        },
    ]
    quarantine, pairs = _duplicate_flags(rows, ["packet_count", "byte_count"])
    assert "duplicate_capture_hash_group:one,three" in quarantine["one"]
    assert "duplicate_feature_vector_with:one" in quarantine["two"]
    assert "duplicate_capture_hash_group:one,three" in quarantine["three"]
    assert {pair["kind"] for pair in pairs} == {"exact"}


def test_near_duplicate_features_are_reported_and_quarantined() -> None:
    rows = [
        {
            "experiment_id": "one",
            "capture_sha256": "first",
            "packet_count": 2.0,
            "byte_count": 200.0,
        },
        {
            "experiment_id": "two",
            "capture_sha256": "second",
            "packet_count": 2.0,
            "byte_count": 200.0001,
        },
    ]
    quarantine, pairs = _duplicate_flags(rows, ["packet_count", "byte_count"])
    assert "near_duplicate_feature_vector_with:one" in quarantine["two"]
    assert pairs == [{
        "left": "one",
        "right": "two",
        "kind": "near",
        "relative_tolerance": 1e-6,
    }]


def test_too_few_sessions_are_blocked_without_row_split(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path, sessions=3)
    report = prepare_dataset(manifest_path, tmp_path / "prepared")
    assert report["status"] == "BLOCKED"
    assert "At least 15 independently verified IKE_SA session lifecycles" in report["blocker"]
    assert not (tmp_path / "prepared" / "prepared_dataset.csv").exists()


def test_manifest_secret_fields_are_rejected(tmp_path: Path) -> None:
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["observations"][0]["vpn"]["requested_configuration"]["psk"] = "never log"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="prohibited secret/credential field"):
        prepare_dataset(manifest_path, tmp_path / "prepared")


def test_existing_manifest_rejects_missing_record_fields() -> None:
    with pytest.raises(ValueError, match="dataset_id must be a non-empty string"):
        validate_manifest_shape({"manifest_version": "vista-strongswan-experiment-v1"})


def test_v2_manifest_migration_verifies_raw_pcap_and_session_artifacts(
    tmp_path: Path,
) -> None:
    manifest_path = _manifest(tmp_path, sessions=1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["manifest_version"] = "vista-strongswan-experiment-v2"
    session_id = str(uuid.uuid4())
    session_record = tmp_path / "session.json"
    for observation in manifest["observations"]:
        observation["experiment_id"] = str(uuid.uuid4())
        observation["session_id"] = session_id
        observation["session_record_path"] = session_record.name
        capture = observation["capture"]
        packet_path = tmp_path / capture["path"]
        packets = pd.read_csv(packet_path)
        packets["protocol"] = "ESP"
        packets["protocol_family"] = "ESP"
        packets.to_csv(packet_path, index=False)
        capture["protocol_family"] = "ESP"
        capture["sha256"] = _sha(packet_path)
        capture["completed_at"] = capture["started_at"]
        raw_path = tmp_path / f"{observation['experiment_id']}.pcap"
        wrpcap(
            str(raw_path),
            [
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src="192.0.2.1", dst="192.0.2.2", proto=50) / bytes(8),
                Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                / IP(src="192.0.2.2", dst="192.0.2.1", proto=50) / bytes(8),
            ],
        )
        capture["raw_pcap_path"] = raw_path.name
        capture["raw_pcap_format"] = "pcap"
        capture["raw_pcap_sha256"] = _sha(raw_path)
        capture["raw_pcap_size_bytes"] = raw_path.stat().st_size
        measurement_path = tmp_path / f"{observation['experiment_id']}-measurement.json"
        measurement_path.write_text(
            json.dumps({
                "experimentId": observation["experiment_id"],
                "sessionId": observation["session_id"],
            }),
            encoding="utf-8",
        )
        observation["workload"]["type"] = "icmpv4_echo"
        observation["workload"]["measurement_path"] = measurement_path.name
        observation["workload"]["measurement_sha256"] = _sha(measurement_path)
    experiment_ids = [item["experiment_id"] for item in manifest["observations"]]
    sa_identity = hashlib.sha256(b"migration-fixture-new-sa").hexdigest()
    previous_identity = hashlib.sha256(b"migration-fixture-prior-sa").hexdigest()
    started_at = pd.Timestamp(manifest["observations"][0]["capture"]["started_at"])
    reestablished_at = started_at - pd.Timedelta(seconds=1)
    session_record.write_text(
        json.dumps({
            "sessionId": session_id,
            "sessionIdSource": "test fixture with observed SA lifecycle",
            "sessionStartedAt": started_at.isoformat(),
            "sessionObservedThroughAt": (
                started_at + pd.Timedelta(seconds=30)
            ).isoformat(),
            "experimentIds": experiment_ids,
            "containerIds": {"pc1": "fixture-pc1", "pc2": "fixture-pc2"},
            "vpnLifecycle": {
                "ikeSaIdentitySha256": sa_identity,
                "ikeSaAgeSeconds": 2,
                "reestablishment": {
                    "independenceStatus": "VERIFIED_DISTINCT_IKE_SA",
                    "previousIkeSaIdentitySha256": previous_identity,
                    "ikeSaIdentitySha256": sa_identity,
                    "reestablishedAt": reestablished_at.isoformat(),
                },
            },
        }),
        encoding="utf-8",
    )
    for observation in manifest["observations"]:
        observation["session_record_sha256"] = _sha(session_record)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    report = prepare_dataset(manifest_path, tmp_path / "v2-prepared")
    assert report["manifest_schema"].endswith("strongswan-experiment-manifest-v2.schema.json")
    assert report["accepted_observations"] == 2
    assert report["quarantined_observations"] == 0
    assert report["independent_session_count"] == 1
    assert report["status"] == "BLOCKED"
    assert "At least 15 independently verified IKE_SA session lifecycles" in report["blocker"]
