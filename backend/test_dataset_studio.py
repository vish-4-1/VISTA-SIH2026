from __future__ import annotations

import pytest
import zipfile
import io
from starlette.testclient import TestClient

from backend.main import app
from backend.services.dataset_service import dataset_service
import backend.services.dataset_service as dataset_service_module


@pytest.fixture
def client():
    return TestClient(app)


def test_list_datasets_returns_registered_datasets(client):
    res = client.get("/api/datasets")
    assert res.status_code == 200
    data = res.json()
    assert "datasets" in data
    assert data["total"] >= 1
    sample_ds = next((d for d in data["datasets"] if "sample" in d["id"]), None)
    assert sample_ds is not None
    assert sample_ds["unit"] == "bidirectional_flows"
    assert sample_ds["featureSchema"] == "vista-flow-v1"
    assert sample_ds["status"] == "UNVERIFIED"
    assert sample_ds["originType"] == "unknown"


def test_legacy_attack_sample_is_explicitly_unverified(client):
    response = client.get("/api/datasets")
    assert response.status_code == 200
    attack_sample = next(
        item for item in response.json()["datasets"]
        if item["id"] == "ds-sample-vista_attack_sample_dataset"
    )
    assert attack_sample["originType"] == "unknown"
    assert attack_sample["provenanceStatus"] == "incomplete"
    assert attack_sample["status"] == "UNVERIFIED"

    details = client.get(f"/api/datasets/{attack_sample['id']}")
    assert details.status_code == 200
    manifest = details.json()["datasetManifest"]
    assert manifest["originType"] == "unknown"
    assert manifest["admissionStatus"] == "UNVERIFIED"
    assert manifest["verificationLimitations"]


def test_get_dataset_capabilities(client):
    res = client.get("/api/datasets/capabilities")
    assert res.status_code == 200
    caps = res.json()
    assert "testbedActive" in caps
    assert any(c["value"] == "aes256gcm16" and c["supported"] for c in caps["supportedCiphers"])
    assert any(g["value"] == 14 and g["supported"] for g in caps["supportedDhGroups"])
    assert any(g["value"] == 19 and not g["supported"] for g in caps["supportedDhGroups"])
    assert any(t["value"] == "icmpv4" and t["supported"] for t in caps["supportedTrafficGenerators"])
    assert any(t["value"] == "video_streaming" and not t["supported"] for t in caps["supportedTrafficGenerators"])


def test_preflight_check_blocks_unsupported_params(client):
    # Valid config
    res_valid = client.post("/api/datasets/preflight", json={"sessions": 2, "trafficType": "icmpv4", "cipher": "aes256gcm16"})
    assert res_valid.status_code == 200
    assert res_valid.json()["canProceed"] is True

    # Unsupported IPv6
    res_ipv6 = client.post("/api/datasets/preflight", json={"ipVersion": "IPv6", "trafficType": "icmpv4"})
    assert res_ipv6.status_code == 200
    assert res_ipv6.json()["canProceed"] is False

    # Unsupported DH group 19
    res_dh = client.post("/api/datasets/preflight", json={"dhGroup": 19, "trafficType": "icmpv4"})
    assert res_dh.status_code == 200
    assert res_dh.json()["canProceed"] is False

    # Unsupported video traffic
    res_traffic = client.post("/api/datasets/preflight", json={"trafficType": "video_streaming"})
    assert res_traffic.status_code == 200
    assert res_traffic.json()["canProceed"] is False


def test_get_dataset_details_and_validation(client):
    res_list = client.get("/api/datasets")
    dataset_id = res_list.json()["datasets"][0]["id"]

    res_det = client.get(f"/api/datasets/{dataset_id}")
    assert res_det.status_code == 200
    det = res_det.json()
    assert det["id"] == dataset_id
    assert "columns" in det
    assert "sampleRows" in det

    res_val = client.post(f"/api/datasets/{dataset_id}/validate")
    assert res_val.status_code == 200
    val = res_val.json()
    assert val["datasetId"] == dataset_id
    assert "leakageCheck" in val
    assert val["qualityStatus"] in {"BLOCKED", "FAILED", "SYNTHETIC_FIXTURE"}


def test_export_dataset_safeguards(client):
    res_list = client.get("/api/datasets")
    dataset_id = res_list.json()["datasets"][0]["id"]

    res_export = client.get(f"/api/datasets/{dataset_id}/export?format=csv")
    assert res_export.status_code == 200
    assert "text/csv" in res_export.headers.get("content-type", "") or "application/octet-stream" in res_export.headers.get("content-type", "")

    package = client.get(f"/api/datasets/{dataset_id}/export?format=zip")
    assert package.status_code == 200
    assert package.content[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        assert "dataset.csv" in archive.namelist()
        assert "dataset_manifest.json" in archive.namelist()

    # Non-existent dataset
    res_404 = client.get("/api/datasets/ds-nonexistent-12345/export")
    assert res_404.status_code == 404


def test_job_cancel_not_active_returns_400(client):
    res = client.post("/api/datasets/jobs/job-nonexistent/cancel")
    assert res.status_code == 400


def test_scenario_catalogue_contains_only_acceptance_pair(client):
    response = client.get("/api/datasets/scenarios")
    assert response.status_code == 200
    scenarios = response.json()["scenarios"]
    assert {scenario["id"] for scenario in scenarios} == {"benign_icmp_control_v1", "port_scan_v1"}


def test_scenario_validation_rejects_external_target_and_unsupported_scenario(client):
    external = client.post("/api/datasets/scenarios/port_scan_v1/validate", json={
        "parameters": {"target": "1.1.1.1", "ports": [80]},
    })
    assert external.status_code == 400
    malformed = client.post("/api/datasets/scenarios/port_scan_v1/validate", json={
        "parameters": {"ports": [80, 65536], "interval_seconds": 0.001},
    })
    assert malformed.status_code == 400
    deferred = client.post("/api/datasets/scenarios/flood_v1/validate", json={"parameters": {}})
    assert deferred.status_code == 400


def test_scenario_run_requires_explicit_isolated_lab_confirmation(client, monkeypatch):
    monkeypatch.setattr(dataset_service, "run_preflight_check", lambda config: {
        "canProceed": True, "checks": [],
    })
    response = client.post("/api/datasets/scenarios/benign_icmp_control_v1/runs", json={
        "parameters": {}, "confirmedIsolatedLab": False,
    })
    assert response.status_code == 400


def test_legacy_generation_endpoint_also_requires_lab_confirmation(client):
    response = client.post("/api/datasets/generate", json={
        "trafficType": "icmpv4", "sessions": 1,
    })
    assert response.status_code == 400


def test_collected_candidate_admission_rejects_presence_only_manifest_and_split_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset_service_module, "ROOT_DIR", tmp_path)
    feature_keys = [
        "packet_count", "byte_count", "flow_duration", "mean_packet_size", "std_packet_size",
        "min_packet_size", "max_packet_size", "mean_inter_arrival_time", "std_inter_arrival_time",
        "min_inter_arrival_time", "max_inter_arrival_time", "packets_per_second", "bytes_per_second",
        "forward_packet_count", "backward_packet_count", "forward_bytes", "backward_bytes", "direction_ratio",
    ]
    manifest = {
        "originType": "testbed_collected",
        "execution": {"state": "EXECUTED", "result": "PASS", "observationState": "OBSERVED"},
        "artifacts": [],
        "featureSchemaVersion": "vista-flow-v1",
        "featureColumns": feature_keys,
        "sessionRecords": [],
        "labelEvidence": [{"sessionId": "s1", "experimentId": "e1", "label": "PORT_SCAN", "granularity": "time_window", "executionState": "EXECUTED", "observationState": "OBSERVED", "groundTruthSource": "endpoint"}],
    }
    details = {
        "datasetManifest": manifest,
        "manifestPath": "manifest.json",
        "dataPath": "prepared.csv",
        "qualityReport": {"status": "PASS", "accepted_count": 1, "missing_values_count": 0, "duplicate_rows_count": 0},
        "splitManifest": {
            "session_ids": {"train": ["s1"], "validation": ["s1"], "test": []},
            "independent_session_keys": {"train": ["sa1"], "validation": ["sa1"], "test": []},
        },
    }
    blockers = dataset_service_module._collected_candidate_blockers(
        details, [{"session_id": "s1", "experiment_id": "e1", "label": "PORT_SCAN", "label_granularity": "time_window"}], feature_keys,
    )
    assert "artifact_hash_inventory_missing" in blockers
    assert "session_split_overlap" in blockers
    assert "independent_sa_split_overlap" in blockers
    assert "insufficient_independent_session_records" in blockers


def test_collected_admission_detects_artifact_hash_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset_service_module, "ROOT_DIR", tmp_path)
    data_path = tmp_path / "prepared.csv"
    data_path.write_text("label,session_id,experiment_id\nPORT_SCAN,s1,e1\n", encoding="utf-8")
    details = {
        "manifestPath": "manifest.json",
        "dataPath": "prepared.csv",
        "datasetManifest": {"artifacts": [{
            "path": "prepared.csv", "sizeBytes": data_path.stat().st_size,
            "sha256": "0" * 64, "sourceRunId": "e1", "createdAt": "2026-10-11T00:00:00Z",
        }]},
    }
    feature_keys = ["packet_count"]
    blockers = dataset_service_module._collected_candidate_blockers(details, [], feature_keys)
    assert "artifact_integrity_mismatch:0" in blockers


def test_package_export_retry_is_unique_and_manifest_traversal_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset_service_module, "ROOT_DIR", tmp_path)
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    monkeypatch.setattr(dataset_service_module, "EXPORTS_DIR", export_dir)
    data = tmp_path / "dataset.csv"
    data.write_text("label\nunknown\n", encoding="utf-8")
    details = {"id": "ds-test", "version": "1.0", "dataPath": "dataset.csv", "manifestPath": None, "featureSchema": None}
    monkeypatch.setattr(dataset_service, "get_dataset_details", lambda _dataset_id: details)
    first = dataset_service.export_dataset_file("ds-test", "zip")
    second = dataset_service.export_dataset_file("ds-test", "zip")
    assert first != second and first.is_file() and second.is_file()

    details["manifestPath"] = "..\\outside.json"
    with pytest.raises(ValueError, match="manifest path escapes"):
        dataset_service.export_dataset_file("ds-test", "zip")


def test_cancel_marks_running_job_cancelling_without_claiming_terminal_state():
    from backend.services.dataset_service import GENERATION_JOBS
    job_id = "job-test-cancel-hardening"
    GENERATION_JOBS[job_id] = {"status": "RUNNING", "cancelRequested": False, "logEvents": []}
    try:
        assert dataset_service.cancel_job(job_id)
        assert GENERATION_JOBS[job_id]["cancelRequested"] is True
        assert GENERATION_JOBS[job_id]["status"] == "CANCELLING"
    finally:
        GENERATION_JOBS.pop(job_id, None)


def test_active_job_lock_prevents_concurrent_run_dispatch(monkeypatch):
    from backend.services.dataset_service import GENERATION_JOBS
    monkeypatch.setattr(dataset_service, "run_preflight_check", lambda _config: {"canProceed": True, "checks": []})
    monkeypatch.setattr(dataset_service_module.threading.Thread, "start", lambda _thread: None)
    first = dataset_service.start_generation_job({"trafficType": "icmpv4", "sessions": 1, "confirmedIsolatedLab": True})
    try:
        assert first["scenarioId"] == "benign_icmp_control_v1"
        with pytest.raises(ValueError, match="already using the testbed"):
            dataset_service.start_generation_job({"trafficType": "icmpv4", "sessions": 1, "confirmedIsolatedLab": True})
    finally:
        GENERATION_JOBS.pop(first["jobId"], None)


def test_worker_start_failure_marks_job_failed_and_releases_lock(monkeypatch):
    from backend.services.dataset_service import GENERATION_JOBS
    monkeypatch.setattr(dataset_service, "run_preflight_check", lambda _config: {"canProceed": True, "checks": []})
    monkeypatch.setattr(dataset_service_module.threading.Thread, "start", lambda _thread: (_ for _ in ()).throw(RuntimeError("thread denied")))
    with pytest.raises(RuntimeError, match="thread denied"):
        dataset_service.start_generation_job({"trafficType": "icmpv4", "sessions": 1, "confirmedIsolatedLab": True})
    failed = [job for job in GENERATION_JOBS.values() if job["status"] == "FAILED" and any("thread denied" in error for error in job["errors"])]
    assert len(failed) == 1
    failed_id = failed[0]["jobId"]
    second_id = None
    try:
        monkeypatch.setattr(dataset_service_module.threading.Thread, "start", lambda _thread: None)
        second = dataset_service.start_generation_job({"trafficType": "icmpv4", "sessions": 1, "confirmedIsolatedLab": True})
        second_id = second["jobId"]
        assert second["status"] == "RUNNING"
    finally:
        GENERATION_JOBS.pop(failed_id, None)
        if second_id:
            GENERATION_JOBS.pop(second_id, None)
