from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet import UDP
from scapy.utils import wrpcap

from backend.services import workload_collection


def test_icmp_profile_validation_accepts_reproducible_sequence():
    profiles = [
        {"count": 3, "interval_seconds": 0.2, "payload_bytes": 32},
        {"count": 5, "interval_seconds": 0.5, "payload_bytes": 256},
    ]
    assert workload_collection.validate_icmp_profiles(profiles) == [
        {"count": 3, "interval_seconds": 0.2, "payload_bytes": 32},
        {"count": 5, "interval_seconds": 0.5, "payload_bytes": 256},
    ]


@pytest.mark.parametrize(
    "profile",
    [
        {"count": 0, "interval_seconds": 0.2, "payload_bytes": 32},
        {"count": 2, "interval_seconds": 0.01, "payload_bytes": 32},
        {"count": 2, "interval_seconds": 0.2, "payload_bytes": 1401},
        {"count": True, "interval_seconds": 0.2, "payload_bytes": 32},
        {"count": 2, "interval_seconds": 0.2, "payload_bytes": 32, "shell": "; id"},
    ],
)
def test_icmp_profile_validation_rejects_unsafe_or_ambiguous_parameters(profile):
    with pytest.raises(ValueError):
        workload_collection.validate_icmp_profiles([profile])


def test_ping_uses_argument_array_and_observed_sender_counters(monkeypatch):
    calls = []

    def fake_run(*args, timeout=15):
        calls.append((args, timeout))
        return subprocess.CompletedProcess(
            args, 0, "5 packets transmitted, 5 received, 0% packet loss\n", ""
        )

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    measured = workload_collection._run_ping({
        "count": 5,
        "interval_seconds": 0.2,
        "payload_bytes": 256,
    })
    assert measured["packetsSent"] == 5
    assert measured["packetsReceived"] == 5
    assert measured["exitCode"] == 0
    assert calls[0][0] == (
        "exec", "pc1", "ping", "-n", "-c", "5", "-W", "1",
        "-s", "256", "-i", "0.2", "172.20.0.3",
    )
    assert calls[0][1] < 20


def test_capture_packet_table_uses_real_ipv4_icmp_metadata(tmp_path):
    pcap_path = tmp_path / "capture.pcap"
    csv_path = tmp_path / "packets.csv"
    wrpcap(
        str(pcap_path),
        [
            IP(src="172.20.0.2", dst="172.20.0.3") / ICMP(type=8) / bytes(32),
            IP(src="172.20.0.3", dst="172.20.0.2") / ICMP(type=0) / bytes(32),
        ],
    )
    result = workload_collection._generate_packet_table(pcap_path, csv_path, "ICMP")
    assert result == {
        "echoRequests": 1,
        "echoReplies": 1,
        "icmpPackets": 2,
        "tcpPackets": 0,
        "udpPackets": 0,
        "espPackets": 0,
        "ipv4Bytes": 120,
    }
    table = csv_path.read_text(encoding="utf-8")
    assert "172.20.0.2" in table
    assert "172.20.0.3" in table
    assert "ICMP" in table


def test_capture_packet_table_extracts_outer_esp_only(tmp_path):
    pcap_path = tmp_path / "outer.pcap"
    csv_path = tmp_path / "outer.csv"
    wrpcap(
        str(pcap_path),
        [
            IP(src="172.20.0.2", dst="172.20.0.3", proto=50) / bytes(16),
            IP(src="172.20.0.3", dst="172.20.0.2", proto=50) / bytes(16),
            IP(src="172.20.0.2", dst="172.20.0.3") / ICMP(type=8) / bytes(32),
        ],
    )
    result = workload_collection._generate_packet_table(pcap_path, csv_path, "ESP")
    assert result["espPackets"] == 2
    assert result["icmpPackets"] == 0
    assert result["ipv4Bytes"] == 72
    table = csv_path.read_text(encoding="utf-8")
    assert table.count(",ESP,ESP,") == 2
    assert "ICMP" not in table


def test_closed_capture_requires_readable_packet_records(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(bytes(24))
    with pytest.raises(workload_collection.WorkloadCollectionError, match="unreadable or truncated"):
        workload_collection._validate_closed_pcap(empty)

    truncated = tmp_path / "truncated.pcap"
    wrpcap(str(truncated), [IP(src="192.0.2.1", dst="192.0.2.2", proto=50) / bytes(16)])
    truncated.write_bytes(truncated.read_bytes()[:-2])
    with pytest.raises(workload_collection.WorkloadCollectionError, match="unreadable or truncated"):
        workload_collection._validate_closed_pcap(truncated)


def test_closed_capture_rejects_zero_packet_files_even_with_valid_header(tmp_path):
    empty = tmp_path / "empty-valid-header.pcap"
    wrpcap(str(empty), [])
    with pytest.raises(workload_collection.WorkloadCollectionError, match="no readable packets"):
        workload_collection._validate_closed_pcap(empty)


def test_capture_readiness_waits_for_listening_process_and_header(monkeypatch):
    observations = {"log": 0}

    def fake_run(*args, timeout=15):
        if args[:3] == ("exec", "pc1", "sh") and args[-2] == "-c":
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            observations["log"] += 1
            text = "tcpdump: listening on eth0" if observations["log"] > 1 else ""
            return subprocess.CompletedProcess(args, 0, text, "")
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[-3:] == ("sh", "-c", "kill -0 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("-c", "/tmp/vista-token.pcap") and args[-3] == "wc":
            return subprocess.CompletedProcess(args, 0, "24 /tmp/vista-token.pcap\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    workload_collection._start_capture("pc1", "token")
    assert observations["log"] > 1


def test_capture_start_rejects_tcpdump_early_exit(monkeypatch):
    def fake_run(*args, timeout=15):
        if args[:3] == ("exec", "pc1", "sh") and args[-2] == "-c":
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            return subprocess.CompletedProcess(args, 0, "tcpdump: permission denied\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 1, "", "missing")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    with pytest.raises(workload_collection.WorkloadCollectionError, match="exited before capture readiness"):
        workload_collection._start_capture("pc1", "token")


def test_capture_stop_waits_for_exit_and_validates_transferred_artifact(
    monkeypatch, tmp_path
):
    destination = tmp_path / "capture.pcap"
    wrpcap(
        str(destination),
        [IP(src="192.0.2.1", dst="192.0.2.2", proto=50) / bytes(16)],
    )
    calls = []

    def fake_run(*args, timeout=15):
        calls.append(args)
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-3:] == ("sh", "-c", "kill -INT 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 0, "0\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            return subprocess.CompletedProcess(args, 0, "2 packets captured\n", "")
        if args[-5:] == (
            "exec", "pc1", "rm", "-f",
            "/tmp/vista-token.pcap",
        ):
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(
        workload_collection.vpn_testbed, "_docker_path", lambda: "docker"
    )

    def copy_capture(args, **_kwargs):
        assert args == ["docker", "cp", "pc1:/tmp/vista-token.pcap", str(destination)]
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", copy_capture)
    result = workload_collection._stop_capture("pc1", "token", destination)
    assert result["packetCount"] == 1
    assert result["exitCode"] == 0
    assert any(call[-3:] == ("sh", "-c", "kill -INT 321") for call in calls)


def test_capture_cleanup_force_kills_orphan_when_graceful_signal_times_out(monkeypatch):
    alive = True
    calls = []
    ticks = iter([0.0, 0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.1, 5.2])

    def fake_run(*args, timeout=15):
        nonlocal alive
        calls.append(args)
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[-3:] == ("kill", "-0", "321"):
            return subprocess.CompletedProcess(args, 0 if alive else 1, "", "")
        if args[-3:] == ("kill", "-KILL", "321"):
            alive = False
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    workload_collection._cleanup_capture("pc1", "token")
    assert not alive
    assert any(call[-3:] == ("kill", "-KILL", "321") for call in calls)


@pytest.mark.parametrize(
    ("exit_result", "copy_result", "error"),
    [
        ("1\n", None, "exited with status 1"),
        ("0\n", 1, "Retrieving completed pc1 PCAP failed"),
    ],
)
def test_capture_stop_reports_nonzero_exit_and_transfer_failure(
    monkeypatch, tmp_path, exit_result, copy_result, error
):
    def fake_run(*args, timeout=15):
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 0, exit_result, "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            return subprocess.CompletedProcess(
                args, 0, "1 packets captured, 1 packets received by filter\n", ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(
        workload_collection.vpn_testbed, "_docker_path", lambda: "docker"
    )
    monkeypatch.setattr(
        workload_collection.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, copy_result or 0, "", "copy failed" if copy_result else ""
        ),
    )
    with pytest.raises(workload_collection.WorkloadCollectionError, match=error):
        workload_collection._stop_capture(
            "pc1", "token", tmp_path / "capture.pcap"
        )


def test_capture_stop_times_out_without_claiming_artifact_completion(
    monkeypatch, tmp_path
):
    ticks = iter([0, 0, 16, 32])
    monkeypatch.setattr(workload_collection.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        workload_collection, "_wait_for_capture_dispatch", lambda *_args: 1
    )

    def fake_run(*args, timeout=15):
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    with pytest.raises(workload_collection.WorkloadCollectionError, match="did not exit and flush"):
        workload_collection._stop_capture(
            "pc1", "token", tmp_path / "capture.pcap"
        )


def test_capture_cleanup_after_workload_exception_signals_process(monkeypatch):
    calls = []

    def fake_run(*args, timeout=15):
        calls.append(args)
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 0, "0\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    workload_collection._cleanup_capture("pc1", "token")
    assert any(call[-3:] == ("kill", "-INT", "321") for call in calls)


def test_capture_flush_barrier_waits_for_dispatched_packet_count(monkeypatch):
    log_reads = 0

    def fake_run(*args, timeout=15):
        nonlocal log_reads
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-3:] == ("sh", "-c", "kill -USR1 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            log_reads += 1
            output = (
                "tcpdump: listening on eth0\n"
                if log_reads == 1
                else "tcpdump: 3 packets captured, 3 packets received by filter\n"
            )
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[-3:] == ("sh", "-c", "kill -0 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    assert workload_collection._wait_for_capture_dispatch("pc1", "token") == 3


def test_capture_flush_barrier_fails_when_process_exits_without_dispatch(
    monkeypatch,
):
    def fake_run(*args, timeout=15):
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-3:] == ("sh", "-c", "kill -USR1 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            return subprocess.CompletedProcess(
                args, 0, "0 packets captured, 3 packets received by filter\n", ""
            )
        if args[-3:] == ("sh", "-c", "kill -0 321"):
            return subprocess.CompletedProcess(args, 1, "", "")
        raise AssertionError(args)

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    with pytest.raises(workload_collection.WorkloadCollectionError, match="exited before dispatching"):
        workload_collection._wait_for_capture_dispatch("pc1", "token")


def test_outer_esp_evidence_required_for_esp_packet_table(tmp_path):
    pcap_path = tmp_path / "icmp-only.pcap"
    wrpcap(
        str(pcap_path),
        [IP(src="172.20.0.2", dst="172.20.0.3") / ICMP(type=8) / bytes(32)],
    )
    with pytest.raises(workload_collection.WorkloadCollectionError, match="no readable IPv4 ESP"):
        workload_collection._generate_packet_table(
            pcap_path, tmp_path / "packets.csv", "ESP"
        )


def test_nat_t_esp_is_recognized_as_outer_esp(tmp_path):
    pcap_path = tmp_path / "natt.pcap"
    wrpcap(
        str(pcap_path),
        [
            IP(src="172.20.0.2", dst="172.20.0.3")
            / UDP(sport=4500, dport=4500)
            / bytes.fromhex("0102030400000001")
        ],
    )
    packet_count = workload_collection._validate_closed_pcap(pcap_path)
    result = workload_collection._generate_packet_table(
        pcap_path, tmp_path / "packets.csv", "ESP"
    )
    assert packet_count == 1
    assert result["espPackets"] == 1


def test_live_precondition_failure_is_recorded_not_reported_as_success(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")

    def failed_inspect(_container):
        raise workload_collection.WorkloadCollectionError("endpoint is unavailable")

    monkeypatch.setattr(workload_collection, "_inspect_container", failed_inspect)
    result = workload_collection.collect_icmp_workload({
        "profiles": [{"count": 2, "interval_seconds": 0.2, "payload_bytes": 32}],
    })
    assert result["status"] == "BLOCKED"
    assert result["errors"] == ["endpoint is unavailable"]
    saved = json.loads(
        (
            tmp_path / "collections" / result["sessionId"]
            / result["experimentId"] / "collection_result.json"
        ).read_text()
    )
    assert saved["status"] == "BLOCKED"


def test_collection_ids_must_be_distinct_uuid4(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    identifier = str(uuid.uuid4())
    with pytest.raises(ValueError, match="distinct"):
        workload_collection.collect_icmp_workload({
            "profiles": [{"count": 2, "interval_seconds": 0.2, "payload_bytes": 32}],
            "experimentId": identifier,
            "sessionId": identifier,
        })


def test_tcp_sender_uses_argument_array_and_hashes_exact_payload(monkeypatch):
    instances = []

    class RecordingPipe:
        def __init__(self):
            self.chunks = []

        def write(self, value):
            self.chunks.append(value)
            return len(value)

        def flush(self):
            pass

        def close(self):
            pass

        def getvalue(self):
            return b"".join(self.chunks)

    class FakeProcess:
        def __init__(self, args, **_kwargs):
            self.args = args
            self.stdin = RecordingPipe()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = 0
            instances.append(self)

        def wait(self, timeout=None):
            return self.returncode

        def poll(self):
            return self.returncode

    monkeypatch.setattr(workload_collection.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    profile = {"count": 3, "interval_seconds": 0.1, "payload_bytes": 40}
    first = workload_collection._send_tcp_markers([profile], 44000)
    payload = instances[0].stdin.getvalue()
    second = workload_collection._send_tcp_markers([profile], 44001)
    assert instances[0].args[-3:] == ["-N", "172.20.0.3", "44000"]
    assert first["bytesSent"] == 120
    assert first["expectedPayloadSha256"] == second["expectedPayloadSha256"]
    assert first["expectedPayloadSha256"] == hashlib.sha256(payload).hexdigest()


def test_tcp_precondition_failure_is_recorded_not_reported_as_success(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")

    def failed_inspect(_container):
        raise workload_collection.WorkloadCollectionError("TCP endpoint prerequisite unavailable")

    monkeypatch.setattr(workload_collection, "_inspect_container", failed_inspect)
    result = workload_collection.collect_tcp_marker_workload({
        "profiles": [{"count": 2, "interval_seconds": 0.2, "payload_bytes": 32}],
    })
    assert result["status"] == "BLOCKED"
    assert result["errors"] == ["TCP endpoint prerequisite unavailable"]


@pytest.mark.skipif(
    os.environ.get("VISTA_LIVE_COLLECTION", "0") != "1",
    reason="Live Docker/StrongSwan workload collection is opt-in.",
)
def test_live_icmp_collection_requires_sa_capture_and_receiver_evidence():
    result = workload_collection.collect_icmp_workload({
        "profiles": [{"count": 3, "interval_seconds": 0.2, "payload_bytes": 64}],
    })
    assert result["status"] == "PASS", result
    assert result["observedWorkload"]["packetsReceived"] == 3
    assert result["observedWorkload"]["pc1CapturedEspPackets"] > 0
    assert result["captureCompletion"]["pc1"]["packetsDispatchedBeforeStop"] > 0
    assert result["datasetPreparation"]["currentObservationAdmission"] == "QUARANTINED"
    assert result["datasetPreparation"]["status"] == "BLOCKED"


@pytest.mark.skipif(
    os.environ.get("VISTA_LIVE_COLLECTION", "0") != "1",
    reason="Live Docker/StrongSwan workload collection is opt-in.",
)
def test_live_tcp_collection_requires_matching_receiver_bytes_and_outer_esp():
    result = workload_collection.collect_tcp_marker_workload({
        "profiles": [{"count": 3, "interval_seconds": 0.2, "payload_bytes": 32}],
    })
    assert result["status"] == "PASS", result
    assert result["observedWorkload"]["bytesReceived"] == 96
    assert result["observedWorkload"]["pc1CapturedEspPackets"] > 0
    assert result["captureCompletion"]["pc1"]["packetsDispatchedBeforeStop"] > 0
    assert result["datasetPreparation"]["currentObservationAdmission"] == "QUARANTINED"
    assert result["datasetPreparation"]["status"] == "BLOCKED"


def test_capture_command_includes_immediate_mode(monkeypatch):
    captured_commands = []

    def fake_run(*args, timeout=15):
        if args[:3] == ("exec", "pc1", "sh") and args[-2] == "-c":
            captured_commands.append(args[-1])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            return subprocess.CompletedProcess(args, 0, "tcpdump: listening on eth0\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "12345\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[-3:] == ("sh", "-c", "kill -0 12345"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("-c", "/tmp/vista-token.pcap") and args[-3] == "wc":
            return subprocess.CompletedProcess(args, 0, "24 /tmp/vista-token.pcap\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    workload_collection._start_capture("pc1", "token", "icmp")
    assert any("--immediate-mode" in cmd for cmd in captured_commands)


def test_capture_start_delayed_readiness(monkeypatch):
    calls = {"log": 0, "pcap": 0}

    def fake_run(*args, timeout=15):
        if args[:3] == ("exec", "pc1", "sh") and args[-2] == "-c":
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            calls["log"] += 1
            text = "tcpdump: listening on eth0\n" if calls["log"] >= 3 else ""
            return subprocess.CompletedProcess(args, 0, text, "")
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "4567\n", "")
        if args[-2:] == ("cat", "/tmp/vista-token.exit"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[-3:] == ("sh", "-c", "kill -0 4567"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("-c", "/tmp/vista-token.pcap") and args[-3] == "wc":
            calls["pcap"] += 1
            size = "24 /tmp/vista-token.pcap\n" if calls["pcap"] >= 3 else "0 /tmp/vista-token.pcap\n"
            return subprocess.CompletedProcess(args, 0, size, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    workload_collection._start_capture("pc1", "token", "icmp")
    assert calls["log"] >= 3
    assert calls["pcap"] >= 3


def test_capture_flush_barrier_re_signals_usr1_until_dispatch(monkeypatch):
    log_reads = 0
    signals = []

    def fake_run(*args, timeout=15):
        nonlocal log_reads
        if args[-2:] == ("cat", "/tmp/vista-token.pid"):
            return subprocess.CompletedProcess(args, 0, "321\n", "")
        if args[-3:] == ("sh", "-c", "kill -USR1 321"):
            signals.append("USR1")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[-2:] == ("cat", "/tmp/vista-token.log"):
            log_reads += 1
            if log_reads < 3:
                output = "tcpdump: listening on eth0\ntcpdump: 0 packets captured\n"
            else:
                output = "tcpdump: listening on eth0\ntcpdump: 0 packets captured\ntcpdump: 5 packets captured\n"
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[-3:] == ("sh", "-c", "kill -0 321"):
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection, "_run_docker", fake_run)
    monkeypatch.setattr(workload_collection.time, "sleep", lambda _seconds: None)
    dispatched = workload_collection._wait_for_capture_dispatch("pc1", "token")
    assert dispatched == 5
    assert len(signals) >= 2


def test_failure_diagnostics_preserved_on_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")

    def failing_inspect(_container):
        raise workload_collection.WorkloadCollectionError("simulated endpoint failure")

    monkeypatch.setattr(workload_collection, "_inspect_container", failing_inspect)
    result = workload_collection.collect_icmp_workload({
        "profiles": [{"count": 2, "interval_seconds": 0.2, "payload_bytes": 32}],
    })
    assert result["status"] == "BLOCKED"
    assert result["failureStage"] == "PRECHECK"
    experiment_dir = Path(result["artifactDirectory"])
    diag_file = experiment_dir / "failure_diagnostics.json"
    assert diag_file.is_file()
    diag = json.loads(diag_file.read_text(encoding="utf-8"))
    assert diag["status"] == "BLOCKED"
    assert diag["failureStage"] == "PRECHECK"
    assert "simulated endpoint failure" in diag["errors"][0]


def test_http_profile_validation_accepts_valid_profiles():
    profiles = [
        {"count": 3, "interval_seconds": 0.2, "path": "/api/v1", "method": "GET", "payload_bytes": 0, "expected_status": 200},
        {"count": 2, "interval_seconds": 0.5, "path": "/submit", "method": "POST", "payload_bytes": 64, "expected_status": 200},
    ]
    assert workload_collection.validate_http_profiles(profiles) == [
        {"count": 3, "interval_seconds": 0.2, "path": "/api/v1", "method": "GET", "payload_bytes": 0, "expected_status": 200},
        {"count": 2, "interval_seconds": 0.5, "path": "/submit", "method": "POST", "payload_bytes": 64, "expected_status": 200},
    ]


@pytest.mark.parametrize(
    "profile",
    [
        {"count": 0, "interval_seconds": 0.2, "path": "/"},
        {"count": 2, "interval_seconds": 0.01, "path": "/"},
        {"count": 2, "interval_seconds": 0.2, "path": "../etc/passwd"},
        {"count": 2, "interval_seconds": 0.2, "path": "no-slash"},
        {"count": 2, "interval_seconds": 0.2, "path": "/", "method": "DELETE"},
        {"count": 2, "interval_seconds": 0.2, "path": "/", "payload_bytes": 1401},
        {"count": True, "interval_seconds": 0.2, "path": "/"},
        {"count": 2, "interval_seconds": 0.2, "path": "/", "unexpected": 123},
    ],
)
def test_http_profile_validation_rejects_unsafe_or_ambiguous_parameters(profile):
    with pytest.raises(ValueError):
        workload_collection.validate_http_profiles([profile])


def test_http_precondition_failure_is_recorded_not_reported_as_success(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")

    def failed_inspect(_container):
        raise workload_collection.WorkloadCollectionError("HTTP endpoint prerequisite unavailable")

    monkeypatch.setattr(workload_collection, "_inspect_container", failed_inspect)
    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 2, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "BLOCKED"
    assert result["failureStage"] == "PRECHECK"
    assert result["errors"] == ["HTTP endpoint prerequisite unavailable"]
    diag_file = Path(result["artifactDirectory"]) / "failure_diagnostics.json"
    assert diag_file.is_file()


def _mock_sa_for_container(container: str):
    local = workload_collection.ENDPOINTS[container]
    remote = workload_collection.ENDPOINTS["pc2" if container == "pc1" else "pc1"]
    return {
        "established": True,
        "ike": {},
        "child": {
            "state": "INSTALLED",
            "mode": "TUNNEL",
            "localTrafficSelector": f"{local}/32",
            "remoteTrafficSelector": f"{remote}/32",
            "packetsIn": 10,
            "packetsOut": 10,
            "bytesIn": 1000,
            "bytesOut": 1000,
        },
        "pfs": True,
        "raw": "initiator-spi=12345678 responder-spi=87654321 established=10 list-sa event { pc1-pc2 }",
    }


def _mock_require_success(res, op):
    if "StrongSwan" in op:
        return "5.9.8"
    if "XFRM" in op:
        return "src 172.20.0.2 dst 172.20.0.3 proto esp mode tunnel"
    if "PID" in op:
        return "1234"
    return "ok"


def test_http_workload_rejects_status_code_mismatch_or_non_200(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))


    monkeypatch.setattr(
        workload_collection,
        "_run_http_client",
        lambda *args, **kwargs: {
            "totalRequestsSent": 1,
            "totalBytesSent": 100,
            "totalBytesReceived": 200,
            "requests": [{
                "index": 0, "path": "/test", "method": "GET",
                "statusCode": 500, "statusLine": "HTTP/1.1 500 Internal Server Error",
                "responseBytes": 50, "responseSha256": "fakehash", "durationSeconds": 0.01,
            }],
        },
    )

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 1,
                "serverPort": 45000,
                "requests": [{
                    "index": 0, "method": "GET", "path": "/test", "clientIp": "172.20.0.2",
                    "requestBodyBytes": 0, "responseStatus": 500, "responseBytes": 50,
                    "responseSha256": "fakehash", "timestamp": 1000,
                }],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)
    monkeypatch.setattr(workload_collection, "_stop_capture", lambda *args, **kwargs: {"packetCount": 5})
    monkeypatch.setattr(workload_collection, "_generate_packet_table", lambda p, c, proto: {"espPackets": 5, "tcpPackets": 5})
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 5)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 1, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "FAIL"
    assert any("non-200 status code: 500" in err for err in result["errors"])


def test_http_workload_rejects_hash_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))

    monkeypatch.setattr(
        workload_collection,
        "_run_http_client",
        lambda *args, **kwargs: {
            "totalRequestsSent": 1,
            "totalBytesSent": 100,
            "totalBytesReceived": 200,
            "requests": [{
                "index": 0, "path": "/test", "method": "GET",
                "statusCode": 200, "statusLine": "HTTP/1.1 200 OK",
                "responseBytes": 50, "responseSha256": "hash_aaa", "durationSeconds": 0.01,
            }],
        },
    )

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 1,
                "serverPort": 45000,
                "requests": [{
                    "index": 0, "method": "GET", "path": "/test", "clientIp": "172.20.0.2",
                    "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 50,
                    "responseSha256": "hash_bbb", "timestamp": 1000,
                }],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)
    monkeypatch.setattr(workload_collection, "_stop_capture", lambda *args, **kwargs: {"packetCount": 5})
    monkeypatch.setattr(workload_collection, "_generate_packet_table", lambda p, c, proto: {"espPackets": 5, "tcpPackets": 5})
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 5)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 1, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "FAIL"
    assert any("payload hash mismatch" in err for err in result["errors"])


def test_http_workload_rejects_missing_outer_esp(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))

    monkeypatch.setattr(
        workload_collection,
        "_run_http_client",
        lambda *args, **kwargs: {
            "totalRequestsSent": 1,
            "totalBytesSent": 100,
            "totalBytesReceived": 200,
            "requests": [{
                "index": 0, "path": "/test", "method": "GET",
                "statusCode": 200, "statusLine": "HTTP/1.1 200 OK",
                "responseBytes": 50, "responseSha256": "hash_match", "durationSeconds": 0.01,
            }],
        },
    )

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 1,
                "serverPort": 45000,
                "requests": [{
                    "index": 0, "method": "GET", "path": "/test", "clientIp": "172.20.0.2",
                    "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 50,
                    "responseSha256": "hash_match", "timestamp": 1000,
                }],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)
    monkeypatch.setattr(workload_collection, "_stop_capture", lambda *args, **kwargs: {"packetCount": 5})
    monkeypatch.setattr(workload_collection, "_generate_packet_table", lambda p, c, proto: {"espPackets": 0, "tcpPackets": 5})
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 0)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 1, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "FAIL"
    assert any("does not verify outer ESP packets" in err for err in result["errors"])


def test_http_workload_rejects_request_count_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))
    monkeypatch.setattr(
        workload_collection,
        "_run_http_client",
        lambda *args, **kwargs: {
            "totalRequestsSent": 2,
            "totalBytesSent": 100,
            "totalBytesReceived": 200,
            "requests": [
                {"index": 0, "path": "/test", "method": "GET", "statusCode": 200, "responseBytes": 50, "responseSha256": "h1"},
                {"index": 1, "path": "/test", "method": "GET", "statusCode": 200, "responseBytes": 50, "responseSha256": "h2"},
            ],
        },
    )

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 1,
                "serverPort": 45000,
                "requests": [{"index": 0, "method": "GET", "path": "/test", "clientIp": "172.20.0.2", "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 50, "responseSha256": "h1", "timestamp": 1000}],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)
    monkeypatch.setattr(workload_collection, "_stop_capture", lambda *args, **kwargs: {"packetCount": 10})
    monkeypatch.setattr(workload_collection, "_generate_packet_table", lambda p, c, proto: {"espPackets": 5, "tcpPackets": 5})
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 5)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 2, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "FAIL"
    assert any("Server received 1 requests; expected 2" in err for err in result["errors"])


def test_http_workload_rejects_byte_count_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))
    monkeypatch.setattr(
        workload_collection,
        "_run_http_client",
        lambda *args, **kwargs: {
            "totalRequestsSent": 1,
            "totalBytesSent": 100,
            "totalBytesReceived": 200,
            "requests": [
                {"index": 0, "path": "/test", "method": "GET", "statusCode": 200, "responseBytes": 50, "responseSha256": "h1"},
            ],
        },
    )

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 1,
                "serverPort": 45000,
                "requests": [{"index": 0, "method": "GET", "path": "/test", "clientIp": "172.20.0.2", "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 60, "responseSha256": "h1", "timestamp": 1000}],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)
    monkeypatch.setattr(workload_collection, "_stop_capture", lambda *args, **kwargs: {"packetCount": 10})
    monkeypatch.setattr(workload_collection, "_generate_packet_table", lambda p, c, proto: {"espPackets": 5, "tcpPackets": 5})
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 5)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 1, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "FAIL"
    assert any("response byte count mismatch" in err for err in result["errors"])


def test_http_workload_timeout_handling_and_cleanup(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(workload_collection, "_inspect_container", lambda _c: {"running": True})
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})
    monkeypatch.setattr(workload_collection, "_read_live_sa", _mock_sa_for_container)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)


    def failing_server(*args, **kwargs):
        raise workload_collection.WorkloadCollectionError("HTTP server did not reach readiness within timeout.")

    monkeypatch.setattr(workload_collection, "_start_http_server", failing_server)
    cleaned_containers = []
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda container, token: cleaned_containers.append(container))

    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 1, "interval_seconds": 0.2, "path": "/test"}],
    })
    assert result["status"] == "BLOCKED"
    assert result["failureStage"] == "CAPTURE_READY"
    assert "HTTP server did not reach readiness within timeout." in result["errors"][0]
    assert "pc1" in cleaned_containers and "pc2" in cleaned_containers


def test_http_workload_success_with_matching_sender_receiver_and_outer_esp(monkeypatch, tmp_path):
    monkeypatch.setattr(workload_collection, "COLLECTION_ROOT", tmp_path / "collections")
    monkeypatch.setattr(
        workload_collection,
        "_inspect_container",
        lambda c: {
            "containerId": f"cid_{c}",
            "imageId": f"img_{c}",
            "imageName": f"name_{c}",
            "ipv4Address": workload_collection.ENDPOINTS[c],
        },
    )
    monkeypatch.setattr(workload_collection, "_require_success", _mock_require_success)
    monkeypatch.setattr(workload_collection, "_run_docker", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "swanctl 5.9.8\nmode tunnel\n", ""))
    monkeypatch.setattr(workload_collection, "_source_provenance", lambda: {"repositoryRevision": "abc", "worktreeDirty": False})

    sa_call_count = 0
    def mock_sa_before_after(container):
        nonlocal sa_call_count
        base = _mock_sa_for_container(container)
        sa_call_count += 1
        if sa_call_count > 2:
            base["child"]["packetsIn"] += 10
            base["child"]["packetsOut"] += 10
            base["child"]["bytesIn"] += 500
            base["child"]["bytesOut"] += 500
        return base

    monkeypatch.setattr(workload_collection, "_read_live_sa", mock_sa_before_after)
    monkeypatch.setattr(workload_collection, "_start_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_collection, "_start_http_server", lambda *args, **kwargs: ("/tmp/mock-srv", "1234"))

    client_data = {
        "totalRequestsSent": 2,
        "totalBytesSent": 200,
        "totalBytesReceived": 400,
        "requests": [
            {
                "index": 0, "path": "/test1", "method": "GET",
                "statusCode": 200, "statusLine": "HTTP/1.1 200 OK",
                "responseBytes": 50, "responseSha256": "hash_match_1", "durationSeconds": 0.01,
            },
            {
                "index": 1, "path": "/test2", "method": "GET",
                "statusCode": 200, "statusLine": "HTTP/1.1 200 OK",
                "responseBytes": 50, "responseSha256": "hash_match_2", "durationSeconds": 0.01,
            },
        ],
    }
    monkeypatch.setattr(workload_collection, "_run_http_client", lambda *args, **kwargs: client_data)

    def mock_run_server_evidence(args, **kwargs):
        if "cp" in args:
            dest = Path(args[-1])
            dest.write_text(json.dumps({
                "totalRequestsReceived": 2,
                "serverPort": 45000,
                "requests": [
                    {
                        "index": 0, "method": "GET", "path": "/test1", "clientIp": "172.20.0.2",
                        "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 50,
                        "responseSha256": "hash_match_1", "timestamp": 1000,
                    },
                    {
                        "index": 1, "method": "GET", "path": "/test2", "clientIp": "172.20.0.2",
                        "requestBodyBytes": 0, "responseStatus": 200, "responseBytes": 50,
                        "responseSha256": "hash_match_2", "timestamp": 1001,
                    },
                ],
            }), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(workload_collection.subprocess, "run", mock_run_server_evidence)

    def mock_stop_capture(container, token, destination, **kwargs):
        destination.write_bytes(b"mock_pcap_bytes")
        return {"packetCount": 10}

    monkeypatch.setattr(workload_collection, "_stop_capture", mock_stop_capture)

    def mock_generate_packet_table(p, c, proto):
        c.write_text("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,protocol_family,packet_length\n")
        return {"espPackets": 10, "tcpPackets": 10, "icmpPackets": 0, "echoRequests": 0, "echoReplies": 0, "ipv4Bytes": 800}

    monkeypatch.setattr(workload_collection, "_generate_packet_table", mock_generate_packet_table)
    monkeypatch.setattr(workload_collection, "_count_pc1_esp", lambda _p: 10)
    monkeypatch.setattr(workload_collection, "_cleanup_capture", lambda *args, **kwargs: None)


    def mock_dataset_validation(experiment_dir, session_id, manifest_path):
        report = {
            "status": "READY_FOR_REVIEW",
            "accepted_observations": 1,
            "quarantined_observations": 0,
            "independent_session_count": 1,
            "blocker": None,
            "exclusions": [],
        }
        report_file = experiment_dir.parent / "dataset_report.json"
        report_file.write_text(json.dumps(report), encoding="utf-8")
        manifest_file = experiment_dir.parent / "session_manifest.json"
        manifest_file.write_text(json.dumps({}), encoding="utf-8")
        return manifest_file, report_file, report

    monkeypatch.setattr(workload_collection, "_run_session_dataset_validation", mock_dataset_validation)

    result = workload_collection.collect_http_workload({
        "profiles": [
            {"count": 1, "interval_seconds": 0.2, "path": "/test1"},
            {"count": 1, "interval_seconds": 0.2, "path": "/test2"},
        ],
    })
    assert result["status"] == "PASS"
    assert result["observedWorkload"]["requestsSent"] == 2
    assert result["observedWorkload"]["requestsReceivedByServer"] == 2
    assert result["observedWorkload"]["pc1CapturedEspPackets"] == 10
    assert result["observedWorkload"]["pc2CapturedTcpPackets"] == 10
    assert result["observedWorkload"]["saCounterDelta"]["packetsIn"] == 10
    assert result["observedWorkload"]["saCounterDelta"]["packetsOut"] == 10
    assert result["datasetPreparation"]["currentObservationAdmission"] == "ACCEPTED"
    assert Path(result["artifacts"]["serverEvidence"]).is_file()
    assert Path(result["artifacts"]["clientMeasurements"]).is_file()
    assert Path(result["artifacts"]["groundTruth"]).is_file()
    assert Path(result["artifacts"]["manifest"]).is_file()


@pytest.mark.skipif(

    os.environ.get("VISTA_LIVE_COLLECTION", "0") != "1",
    reason="Live Docker/StrongSwan workload collection is opt-in.",
)
def test_live_http_collection_requires_matching_responses_and_outer_esp():
    result = workload_collection.collect_http_workload({
        "profiles": [{"count": 3, "interval_seconds": 0.2, "path": "/api/v1", "method": "GET"}],
    })
    assert result["status"] == "PASS", result
    assert result["observedWorkload"]["requestsSent"] == 3
    assert result["observedWorkload"]["requestsReceivedByServer"] == 3
    assert result["observedWorkload"]["pc1CapturedEspPackets"] > 0
    assert result["observedWorkload"]["pc2CapturedTcpPackets"] > 0
    assert result["observedWorkload"]["saCounterDelta"]["packetsIn"] > 0
    assert result["observedWorkload"]["saCounterDelta"]["packetsOut"] > 0
    assert result["captureCompletion"]["pc1"]["packetsDispatchedBeforeStop"] > 0
    assert result["datasetPreparation"]["currentObservationAdmission"] == "QUARANTINED"
    assert result["datasetPreparation"]["status"] == "BLOCKED"
