"""
Automated Security, Safety Limits, Ground-Truth Qualification, and Leakage Tests
for VISTA Controlled Attack Dataset Generation (SIH26160 / NTRO).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from backend.main import app
from backend.services.attack_workloads import (
    SAFE_SCAN_PORTS,
    SYNTHETIC_USER_ALLOWLIST,
    WorkloadCollectionError,
    validate_auth_failure_config,
    validate_bulk_transfer_config,
    validate_connection_burst_config,
    validate_periodic_beacon_config,
    validate_port_scan_config,
)
from backend.services.dataset_service import dataset_service
from backend.services.model_service import model_service


@pytest.fixture
def client():
    return TestClient(app)


# --------------------------------------------------------------------------
# 1. Scenario Safety Limits and Allowlisting
# --------------------------------------------------------------------------

def test_port_scan_safety_allowlist():
    # Valid allowlisted ports
    valid = validate_port_scan_config({"ports": [80, 443, 8080], "interval_seconds": 0.25})
    assert valid["ports"] == [80, 443, 8080]
    assert valid["interval_seconds"] == 0.25

    # Target ports alias
    valid_alias = validate_port_scan_config({"target_ports": [80, 9000]})
    assert valid_alias["ports"] == [80, 9000]

    # Non-allowlisted external port (e.g., SMB 445, RDP 3389)
    with pytest.raises(ValueError, match="not in the safe testbed allowlist"):
        validate_port_scan_config({"ports": [80, 445]})

    with pytest.raises(ValueError, match="not in the safe testbed allowlist"):
        validate_port_scan_config({"ports": [3389]})

    # Excessive port count (> 10)
    with pytest.raises(ValueError, match="At most 10 ports"):
        validate_port_scan_config({"ports": list(range(1, 15))})

    # Fast probe rate violation (< 50ms)
    with pytest.raises(ValueError, match="interval_seconds must be in"):
        validate_port_scan_config({"ports": [80], "interval_seconds": 0.01})

    with pytest.raises(ValueError, match="allowlisted lab endpoint"):
        validate_port_scan_config({"target": "8.8.8.8", "ports": [80]})
    with pytest.raises(ValueError, match="duplicates"):
        validate_port_scan_config({"ports": [80, 80]})
    with pytest.raises(ValueError, match="timeout_seconds"):
        validate_port_scan_config({"ports": [80], "timeout_seconds": 30})
    with pytest.raises(ValueError, match="non-empty"):
        validate_port_scan_config({"ports": []})
    with pytest.raises(ValueError, match="finite numbers"):
        validate_port_scan_config({"ports": [80], "interval_seconds": True})
    with pytest.raises(ValueError, match="must agree"):
        validate_port_scan_config({"ports": [80], "target_ports": [443]})
    with pytest.raises(ValueError, match="must agree"):
        validate_port_scan_config({"target": "172.20.0.99", "target_ipv4": "172.20.0.3", "ports": [80]})


def test_pc2_scan_evidence_is_parsed_from_capture_not_synthesized(tmp_path):
    from scapy.all import IP, TCP, wrpcap
    from backend.services.attack_workloads import _inspect_pc2_receiver_capture

    pcap_path = tmp_path / "pc2_scan.pcap"
    csv_path = tmp_path / "pc2_scan.csv"
    packets = [
        IP(src="172.20.0.2", dst="172.20.0.3") / TCP(sport=41000, dport=80, flags="S"),
        IP(src="172.20.0.2", dst="172.20.0.3") / TCP(sport=41001, dport=443, flags="S"),
        IP(src="172.20.0.3", dst="172.20.0.2") / TCP(sport=443, dport=41001, flags="SA"),
    ]
    wrpcap(str(pcap_path), packets)

    result = _inspect_pc2_receiver_capture(
        pcap_path, csv_path, "tcp", expected_ports=[80, 443]
    )
    assert result["packets"] == 3
    assert result["inboundSynPackets"] == 2
    assert result["targetSynPorts"] == [80, 443]
    assert result["sha256"]
    assert csv_path.is_file()

    empty_path = tmp_path / "empty.pcap"
    wrpcap(str(empty_path), [])
    with pytest.raises(WorkloadCollectionError, match="no readable packets"):
        _inspect_pc2_receiver_capture(empty_path, tmp_path / "empty.csv", "tcp")

    # Unrelated PC1 SYNs or other senders cannot prove the requested destination port.
    with pytest.raises(WorkloadCollectionError, match=r"requested ports \[22\]"):
        _inspect_pc2_receiver_capture(pcap_path, tmp_path / "unrelated.csv", "tcp", expected_ports=[22])

    missing_path = tmp_path / "missing.pcap"
    with pytest.raises(WorkloadCollectionError, match="capture is missing"):
        _inspect_pc2_receiver_capture(missing_path, tmp_path / "missing.csv", "tcp")

    truncated_path = tmp_path / "truncated.pcap"
    truncated_path.write_bytes(pcap_path.read_bytes()[:-3])
    with pytest.raises(WorkloadCollectionError, match="truncated"):
        _inspect_pc2_receiver_capture(truncated_path, tmp_path / "truncated.csv", "tcp")


def test_scan_collector_uses_top_level_job_parameters_without_network(tmp_path, monkeypatch):
    import backend.services.attack_workloads as attack_workloads

    seen = []
    original_validator = attack_workloads.validate_port_scan_config
    monkeypatch.setattr(attack_workloads, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(
        attack_workloads, "validate_port_scan_config",
        lambda config: (seen.append(dict(config)) or original_validator(config)),
    )
    monkeypatch.setattr(
        attack_workloads, "_verify_tunnel_baseline",
        lambda _record: (_ for _ in ()).throw(WorkloadCollectionError("mocked; no live testbed")),
    )
    result = attack_workloads.collect_port_scan_workload({
        "target_ports": [443], "probe_delay_seconds": 0.4, "timeout_seconds": 0.6,
    })
    assert result["status"] == "BLOCKED"
    assert seen == [{"target_ports": [443], "probe_delay_seconds": 0.4, "timeout_seconds": 0.6}]


def test_connection_burst_safety_bounds():
    # Valid burst (unprivileged port [1024, 65535])
    valid = validate_connection_burst_config({"connection_count": 15, "interval_seconds": 0.05, "port": 40050})
    assert valid["connection_count"] == 15
    assert valid["port"] == 40050

    # Excessive burst count (> 50)
    with pytest.raises(ValueError, match="connection_count must be in"):
        validate_connection_burst_config({"connection_count": 100})

    # Privileged port violation (< 1024)
    with pytest.raises(ValueError, match="port must be an unprivileged port"):
        validate_connection_burst_config({"port": 80})


def test_periodic_beacon_safety_bounds():
    # Valid beacon
    valid = validate_periodic_beacon_config({"pulse_count": 8, "interval_seconds": 0.25, "payload_bytes": 32, "port": 40060})
    assert valid["pulse_count"] == 8
    assert valid["payload_bytes"] == 32

    # Excessive pulse count (> 50)
    with pytest.raises(ValueError, match="pulse_count must be in"):
        validate_periodic_beacon_config({"pulse_count": 100})

    # Excessive payload size (> 256 bytes)
    with pytest.raises(ValueError, match="payload_bytes must be in"):
        validate_periodic_beacon_config({"payload_bytes": 2048})

    # Invalid port range (< 1024)
    with pytest.raises(ValueError, match="port must be in"):
        validate_periodic_beacon_config({"port": 80})


def test_bulk_transfer_safety_bounds():
    # Valid bounded transfer
    valid = validate_bulk_transfer_config({"total_bytes": 65536, "chunk_size": 1400, "port": 40070})
    assert valid["total_bytes"] == 65536
    assert valid["chunk_size"] == 1400

    # Excessive volume (> 1024 KB = 1MB)
    with pytest.raises(ValueError, match="total_bytes must be in"):
        validate_bulk_transfer_config({"total_bytes": 10485760})

    # Chunk size larger than MTU constraint (1400 bytes)
    with pytest.raises(ValueError, match="chunk_size must be in"):
        validate_bulk_transfer_config({"chunk_size": 2000})


def test_auth_failure_synthetic_user_bounds():
    # Valid synthetic nonces
    valid = validate_auth_failure_config({
        "attempt_count": 5,
        "interval_seconds": 0.3,
        "port": 40080,
        "synthetic_usernames": ["sim_user_1", "sim_user_2"]
    })
    assert valid["attempt_count"] == 5
    assert "sim_user_1" in valid["synthetic_usernames"]

    # Forbidden real user or password guessing
    with pytest.raises(ValueError, match="only allowlisted synthetic nonces permitted"):
        validate_auth_failure_config({"synthetic_usernames": ["root", "admin"]})

    with pytest.raises(ValueError, match="only allowlisted synthetic nonces permitted"):
        validate_auth_failure_config({"synthetic_usernames": ["real_user"]})

    # Attempt count violation (> 20)
    with pytest.raises(ValueError, match="attempt_count must be in"):
        validate_auth_failure_config({"attempt_count": 100})


# --------------------------------------------------------------------------
# 2. Preflight API Safety Checks & Unsupported Scenario Rejection
# --------------------------------------------------------------------------

def test_preflight_blocks_unsafe_attack_parameters(client):
    # Port scan with forbidden port 3389
    res = client.post("/api/datasets/preflight", json={
        "trafficType": "controlled_port_scan",
        "parameters": {"target_ports": [3389, 80]}
    })
    assert res.status_code == 200
    data = res.json()
    assert data["canProceed"] is False
    assert data["status"] == "BLOCKED"
    safety_check = next((c for c in data["checks"] if "Controlled Scenario Safety" in c["name"]), None)
    assert safety_check is not None
    assert safety_check["passed"] is False

    # Valid port scan passes
    res_valid = client.post("/api/datasets/preflight", json={
        "trafficType": "controlled_port_scan",
        "parameters": {"target_ports": [80, 443]}
    })
    assert res_valid.status_code == 200
    assert res_valid.json()["canProceed"] is True

    # Destructive attack traffic is completely rejected by policy
    res_destructive = client.post("/api/datasets/preflight", json={
        "trafficType": "destructive_attack_traffic"
    })
    assert res_destructive.status_code == 200
    assert res_destructive.json()["canProceed"] is False


# --------------------------------------------------------------------------
# 3. Ground Truth Qualification & Provenance Integrity
# --------------------------------------------------------------------------

def test_ground_truth_and_manifest_hash_integrity():
    sample_csv = Path("vista-ml/data/sample/vista_attack_sample_dataset.csv")
    sample_manifest = Path("vista-ml/data/sample/vista_attack_sample_dataset.manifest.json")

    assert sample_csv.exists()
    assert sample_manifest.exists()

    # Recompute SHA-256 and assert exact integrity
    computed_sha = hashlib.sha256(sample_csv.read_bytes()).hexdigest()
    manifest_data = json.loads(sample_manifest.read_text(encoding="utf-8"))
    assert manifest_data["sha256"] == computed_sha

    # Verify ground truth schema and labels
    assert manifest_data["targetLabelSchemaVersion"] == "vista-target-label-schema-v1"
    assert manifest_data["classDistribution"]["controlled_suspicious"] == 10
    assert "controlled_port_scan" in manifest_data["workloadSubtypes"]


def test_session_disjoint_splits_guarantee_zero_leakage():
    sample_manifest = Path("vista-ml/data/sample/vista_attack_sample_dataset.manifest.json")
    manifest_data = json.loads(sample_manifest.read_text(encoding="utf-8"))
    split = manifest_data["split"]

    train_sess = set(split["train_sessions"])
    val_sess = set(split["val_sessions"])
    test_sess = set(split["test_sessions"])

    # Assert strictly disjoint session partitions
    assert len(train_sess.intersection(val_sess)) == 0
    assert len(train_sess.intersection(test_sess)) == 0
    assert len(val_sess.intersection(test_sess)) == 0
    assert split["overlap_sessions"] == 0


def test_no_target_proxy_leakage_in_features():
    sample_csv = Path("vista-ml/data/sample/vista_attack_sample_dataset.csv")
    lines = sample_csv.read_text(encoding="utf-8").strip().splitlines()
    header = lines[0].split(",")

    # Feature columns must not encode labels, dates, or file paths
    forbidden_features = {"label", "target", "attack", "is_attack", "malware", "ground_truth"}
    feature_cols = [c for c in header if c not in {"flow_id", "session_id", "experiment_id", "label", "workload_type"}]

    for col in feature_cols:
        assert col.lower() not in forbidden_features
        # Must be valid numeric flow statistics
        assert any(term in col for term in ["packet", "byte", "duration", "inter_arrival", "ratio", "size"])


# --------------------------------------------------------------------------
# 4. Export Path Safety
# --------------------------------------------------------------------------

def test_export_path_traversal_safety():
    # Attempt directory traversal attack in export_dataset_file
    with pytest.raises(ValueError):
        dataset_service.export_dataset_file("../../windows/system32/cmd.exe")

    with pytest.raises(ValueError):
        dataset_service.export_dataset_file("non_existent_dataset_12345")


# --------------------------------------------------------------------------
# 5. Fail-Closed Model Inference Safeguard
# --------------------------------------------------------------------------

def test_fail_closed_model_inference_preserved():
    # Model service gating must remain closed
    info = model_service.get_info()
    classifier_info = info["models"]["traffic_classifier"]
    assert classifier_info["inferenceEnabled"] is False

    # Inference attempts must fail-closed with status unsupported_input and null predictions
    import pandas as pd
    cols = model_service._feature_columns(model_service.traffic_model, model_service.traffic_metadata)
    sample_df = pd.DataFrame([{col: 10.0 for col in cols}])
    preds = model_service.predict_traffic(sample_df)
    assert len(preds) == 1
    assert preds[0]["status"] == "unsupported_input"
    assert preds[0]["predictedClass"] is None
    assert preds[0]["source"] == "model_validation_gate"

    # Attack dataset validation must NOT automatically promote the model
    quality_report = dataset_service.validate_dataset_quality("ds-sample-vista_attack_sample_dataset")
    assert quality_report["qualityStatus"] == "BLOCKED"
    assert quality_report["originType"] == "unknown"
    assert "manifest_origin_type_not_testbed_collected" in quality_report["evidenceBlockers"]

    # Status must still be fail-closed
    post_info = model_service.get_info()
    assert post_info["models"]["traffic_classifier"]["inferenceEnabled"] is False
