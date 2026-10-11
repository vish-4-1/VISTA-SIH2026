from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_collection_campaign as campaign  # noqa: E402
from backend.services import workload_collection


def test_campaign_schedule_is_seeded_varied_and_class_balanced():
    first = campaign.make_campaign_schedule(15, 91)
    second = campaign.make_campaign_schedule(15, 91)
    assert first == second
    assert len(first) == 15
    assert all(set(item["profiles"]) == {"icmpv4", "tcp_marker"} for item in first)
    assert all(set(item["workloadOrder"]) == {"icmpv4", "tcp_marker"} for item in first)
    assert len({
        tuple(sorted(
            (name, tuple(profile.items()))
            for name, profile in item["profiles"].items()
        ))
        for item in first
    }) == 15
    assert len({item["profiles"]["icmpv4"]["payload_bytes"] for item in first}) > 1
    assert len({item["profiles"]["tcp_marker"]["interval_seconds"] for item in first}) > 1


@pytest.mark.parametrize("count", [0, 16])
def test_campaign_session_count_is_strictly_bounded(count):
    with pytest.raises(ValueError, match="sessions must be"):
        campaign.make_campaign_schedule(count, 1)


def test_campaign_rerun_uses_unique_persistent_directory(monkeypatch, tmp_path):
    campaign_id = str(uuid.uuid4())
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(campaign, "_preflight", lambda: {})
    monkeypatch.setattr(campaign.collector, "reestablish_collection_sa", lambda: {
        "previousIkeSaIdentitySha256": "0" * 64,
        "newIkeSaIdentitySha256": "1" * 64,
        "reestablishedAt": "2026-10-10T00:00:00+00:00",
    })
    monkeypatch.setattr(
        campaign.collector,
        "collect_icmp_workload",
        lambda _configuration: {"status": "PASS", "artifactDirectory": ""},
    )
    monkeypatch.setattr(
        campaign.collector,
        "collect_tcp_marker_workload",
        lambda _configuration: {"status": "PASS", "artifactDirectory": ""},
    )
    monkeypatch.setattr(campaign, "_collect_observations", lambda *_args: None)

    result = campaign.run_campaign(1, 1, campaign_id=campaign_id, max_runtime_seconds=60)
    assert result["status"] == "PASS"
    assert result["completedSessions"] == 1
    assert result["independentlyVerifiedSessions"] == 1
    assert Path(result["summaryPath"]).is_file()
    with pytest.raises(FileExistsError):
        campaign.run_campaign(
            1, 1, campaign_id=campaign_id, max_runtime_seconds=60
        )


def test_session_context_requires_new_fresh_sa_and_recent_timestamp():
    identity = {
        "ikeSaIdentitySha256": "a" * 64,
        "ikeSaAgeSeconds": 3,
    }
    result = workload_collection._validate_session_context(
        {
            "previousIkeSaIdentitySha256": "b" * 64,
            "reestablishedAt": "2026-10-10T00:00:00+00:00",
        },
        identity,
        "2026-10-10T00:00:05+00:00",
    )
    assert result["independenceStatus"] == "VERIFIED_DISTINCT_IKE_SA"
    assert result["ikeSaIdentitySha256"] == "a" * 64
    with pytest.raises(workload_collection.WorkloadCollectionError, match="identity did not change"):
        workload_collection._validate_session_context(
            {
                "previousIkeSaIdentitySha256": "a" * 64,
                "reestablishedAt": "2026-10-10T00:00:00+00:00",
            },
            identity,
            "2026-10-10T00:00:05+00:00",
        )


def test_campaign_handles_failed_experiment_cleanly(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(campaign, "_preflight", lambda: {})
    monkeypatch.setattr(campaign.collector, "reestablish_collection_sa", lambda: {
        "previousIkeSaIdentitySha256": "0" * 64,
        "newIkeSaIdentitySha256": "1" * 64,
        "reestablishedAt": "2026-10-10T00:00:00+00:00",
    })
    monkeypatch.setattr(
        campaign.collector,
        "collect_icmp_workload",
        lambda _configuration: {"status": "PASS", "artifactDirectory": ""},
    )
    monkeypatch.setattr(
        campaign.collector,
        "collect_tcp_marker_workload",
        lambda _configuration: {"status": "FAIL", "errors": ["simulated packet drop"], "artifactDirectory": ""},
    )
    monkeypatch.setattr(campaign, "_collect_observations", lambda *_args: None)

    result = campaign.run_campaign(1, 1, max_runtime_seconds=60)
    assert result["status"] == "PARTIAL"
    assert result["completedSessions"] == 0
    assert result["failedSessions"] == 1
    assert result["independentlyVerifiedSessions"] == 0
    assert result["sessions"][0]["status"] == "FAIL"


def test_campaign_stops_gracefully_on_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(campaign, "_preflight", lambda: {})
    ticks = iter([0, 70, 75, 80])
    monkeypatch.setattr(campaign.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(campaign, "_collect_observations", lambda *_args: None)

    result = campaign.run_campaign(2, 1, max_runtime_seconds=60)
    assert result["status"] == "PARTIAL"
    assert "campaign_runtime_deadline_reached" in result["errors"]


def test_http_campaign_schedule_is_seeded_and_varied():
    sched = campaign.make_campaign_schedule(15, 26160, workload_set="http")
    assert len(sched) == 15
    for plan in sched:
        assert set(plan["workloadOrder"]) == {"http_get", "http_post"}
        assert set(plan["profiles"]) == {"http_get", "http_post"}
        assert plan["profiles"]["http_get"]["method"] == "GET"
        assert plan["profiles"]["http_post"]["method"] == "POST"
        assert plan["profiles"]["http_get"]["expected_status"] == 200
        assert plan["profiles"]["http_post"]["expected_status"] == 200
    # Verify variations in counts, paths, intervals
    get_paths = {p["profiles"]["http_get"]["path"] for p in sched}
    post_payloads = {p["profiles"]["http_post"]["payload_bytes"] for p in sched}
    assert len(get_paths) > 1
    assert len(post_payloads) > 1


def test_http_campaign_run_mocked(monkeypatch, tmp_path):
    campaign_id = str(uuid.uuid4())
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(campaign, "_preflight", lambda: {})
    monkeypatch.setattr(campaign.collector, "reestablish_collection_sa", lambda: {
        "previousIkeSaIdentitySha256": "0" * 64,
        "newIkeSaIdentitySha256": "1" * 64,
        "reestablishedAt": "2026-10-10T00:00:00+00:00",
    })
    http_calls = []

    def mock_http(conf):
        http_calls.append(conf)
        return {"status": "PASS", "artifactDirectory": str(tmp_path)}

    monkeypatch.setattr(campaign.collector, "collect_http_workload", mock_http)
    monkeypatch.setattr(campaign, "_collect_observations", lambda *_args: None)

    result = campaign.run_campaign(
        2, 42, campaign_id=campaign_id, max_runtime_seconds=60, workload_set="http"
    )
    assert result["status"] == "PASS"
    assert result["completedSessions"] == 2
    assert result["independentlyVerifiedSessions"] == 2
    assert len(http_calls) == 4  # 2 sessions * 2 workloads (http_get, http_post)
    assert Path(result["summaryPath"]).is_file()


def test_unified_campaign_run_mocked(monkeypatch, tmp_path):
    campaign_id = str(uuid.uuid4())
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path)
    monkeypatch.setattr(campaign, "_preflight", lambda: {})
    monkeypatch.setattr(campaign.collector, "reestablish_collection_sa", lambda: {
        "previousIkeSaIdentitySha256": "0" * 64,
        "newIkeSaIdentitySha256": "1" * 64,
        "reestablishedAt": "2026-10-10T00:00:00+00:00",
    })
    dispatched = []

    def mock_icmp(conf):
        dispatched.append(("icmpv4", conf))
        return {"status": "PASS", "artifactDirectory": str(tmp_path)}

    def mock_tcp(conf):
        dispatched.append(("tcp_marker", conf))
        return {"status": "PASS", "artifactDirectory": str(tmp_path)}

    def mock_http(conf):
        dispatched.append((conf.get("workloadSubtype", "http"), conf))
        return {"status": "PASS", "artifactDirectory": str(tmp_path)}

    monkeypatch.setattr(campaign.collector, "collect_icmp_workload", mock_icmp)
    monkeypatch.setattr(campaign.collector, "collect_tcp_marker_workload", mock_tcp)
    monkeypatch.setattr(campaign.collector, "collect_http_workload", mock_http)
    monkeypatch.setattr(campaign, "_collect_observations", lambda *_args: None)

    result = campaign.run_campaign(
        2, 26160, campaign_id=campaign_id, max_runtime_seconds=60, workload_set="unified"
    )
    assert result["status"] == "PASS"
    assert result["completedSessions"] == 2
    assert result["independentlyVerifiedSessions"] == 2
    assert len(dispatched) == 8  # 2 sessions * 4 workloads (icmp, tcp, http_get, http_post)
    kinds = [item[0] for item in dispatched]
    assert kinds.count("icmpv4") == 2
    assert kinds.count("tcp_marker") == 2
    assert kinds.count("http_get") == 2
    assert kinds.count("http_post") == 2
    assert Path(result["summaryPath"]).is_file()
