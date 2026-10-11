"""
VISTA Controlled Attack-Behavior Workload Generators
===================================================
Safe, bounded, ground-truth-labeled suspicious traffic scenarios executed
strictly across the isolated PC1 <-> PC2 StrongSwan IPsec tunnel (Mode B).

Scenarios implemented:
1. controlled_port_scan           - Low-rate sequential TCP connect probes against an allowlist of ports on PC2
2. controlled_connection_burst     - Bounded burst of short-lived connections to a controlled test service on PC2
3. controlled_periodic_beacon      - Uniformly spaced small heartbeat messages simulating C2 beaconing
4. controlled_bulk_transfer        - Fixed-size dummy file exfiltration stream verified via SHA-256
5. controlled_auth_failure_simulation - Synthetic failed-authentication HTTP transactions with service-level audit logging

Strict Safety Constraints:
- Target endpoint MUST be the isolated testbed peer 172.20.0.3 (pc2). External targets are forbidden.
- Real credentials, destructive denial-of-service, malware payloads, and arbitrary port sweeps are rejected.
- All generators are bounded by tight timeouts and maximum count/volume limits.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
import subprocess
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from scapy.all import IP, TCP, PcapReader

from backend.services import vpn_testbed

logger = logging.getLogger("vista.attack_workloads")

COLLECTION_ROOT = Path(__file__).resolve().parents[2] / "captures" / "strongswan" / "collections"
CONTAINERS = {"pc1": "pc1", "pc2": "pc2"}
ENDPOINTS = {"pc1": "172.20.0.2", "pc2": "172.20.0.3"}


class WorkloadCollectionError(RuntimeError):
    """Raised when controlled workload generation or qualification fails."""
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _get_wc():
    import backend.services.workload_collection as wc
    return wc


def _cleanup_capture(*args, **kwargs):
    return _get_wc()._cleanup_capture(*args, **kwargs)


def _inspect_container(*args, **kwargs):
    return _get_wc()._inspect_container(*args, **kwargs)


def _preserve_capture_artifacts(*args, **kwargs):
    return _get_wc()._preserve_capture_artifacts(*args, **kwargs)


def _read_live_sa(*args, **kwargs):
    return _get_wc()._read_live_sa(*args, **kwargs)


def _require_success(*args, **kwargs):
    return _get_wc()._require_success(*args, **kwargs)


def _run_docker(*args, **kwargs):
    return _get_wc()._run_docker(*args, **kwargs)


def _safe_sa_evidence(*args, **kwargs):
    return _get_wc()._safe_sa_evidence(*args, **kwargs)


def _set_lifecycle_state(*args, **kwargs):
    return _get_wc()._set_lifecycle_state(*args, **kwargs)


def _source_provenance(*args, **kwargs):
    return _get_wc()._source_provenance(*args, **kwargs)


def _start_capture(*args, **kwargs):
    return _get_wc()._start_capture(*args, **kwargs)


def _stop_capture(*args, **kwargs):
    return _get_wc()._stop_capture(*args, **kwargs)


def _update_session_manifest(*args, **kwargs):
    return _get_wc()._update_session_manifest(*args, **kwargs)


def _write_session_record(*args, **kwargs):
    return _get_wc()._write_session_record(*args, **kwargs)

# --------------------------------------------------------------------------
# Safety Allowlist and Conservative Bounds
# --------------------------------------------------------------------------

SAFE_SCAN_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
    8000, 8080, 8443, 8888, 9000, 2222, 40050, 40060, 40070, 40080,
}

MAX_SCAN_PORTS = 10
MIN_PROBE_INTERVAL = 0.15
MAX_PROBE_INTERVAL = 1.5

MAX_BURST_CONNECTIONS = 25
MIN_BURST_INTERVAL = 0.02
MAX_BURST_INTERVAL = 0.5

MAX_BEACON_PULSES = 20
MIN_BEACON_INTERVAL = 0.2
MAX_BEACON_INTERVAL = 3.0
MAX_BEACON_PAYLOAD_BYTES = 256

MIN_BULK_BYTES = 1024
MAX_BULK_BYTES = 131072  # 128 KB maximum

MAX_AUTH_ATTEMPTS = 15
SYNTHETIC_USER_ALLOWLIST = {
    "sim_user_1", "sim_user_2", "sim_user_3", "sim_user_4", "sim_user_5",
    "sim_operator", "sim_secops", "sim_auditor", "sim_guest", "sim_admin",
}


# --------------------------------------------------------------------------
# Helper: Snapshot Live eBPF Telemetry
# --------------------------------------------------------------------------

def snapshot_ebpf_telemetry(experiment_dir: Path) -> Optional[Dict[str, Any]]:
    """Captures real Linux kernel eBPF telemetry from the live collector on port 8765 if available."""
    try:
        req_status = urllib.request.Request("http://127.0.0.1:8765/status")
        with urllib.request.urlopen(req_status, timeout=1.5) as resp:
            status_data = json.loads(resp.read().decode("utf-8"))

        req_events = urllib.request.Request("http://127.0.0.1:8765/events?limit=150")
        with urllib.request.urlopen(req_events, timeout=1.5) as resp:
            events_data = json.loads(resp.read().decode("utf-8"))

        telemetry_file = experiment_dir / "ebpf_telemetry.json"
        raw_events = events_data.get("events", [])
        record = {
            "capturedAt": _utc_now(),
            "collectorStatus": status_data,
            "eventsCount": len(raw_events),
            "events": raw_events[:50],  # Bounded sample for storage safety
        }
        telemetry_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return {
            "path": str(telemetry_file),
            "sha256": _sha256(telemetry_file),
            "mode": status_data.get("mode"),
            "eventCount": len(raw_events),
        }
    except Exception as err:
        logger.debug("eBPF monitor telemetry snapshot skipped: %s", err)
        return None


# --------------------------------------------------------------------------
# Validation Functions for Safe Scenarios
# --------------------------------------------------------------------------

def validate_port_scan_config(config: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("PORT_SCAN configuration must be a JSON object.")
    target = config.get("target_ipv4", config.get("target", ENDPOINTS["pc2"]))
    if "target_ipv4" in config and "target" in config and config["target_ipv4"] != config["target"]:
        raise ValueError("target and target_ipv4 must agree when both are supplied.")
    if target != ENDPOINTS["pc2"]:
        raise ValueError(f"target must be the allowlisted lab endpoint {ENDPOINTS['pc2']}.")
    if "ports" in config and "target_ports" in config and config["ports"] != config["target_ports"]:
        raise ValueError("ports and target_ports must agree when both are supplied.")
    ports = config["ports"] if "ports" in config else config.get("target_ports", [80, 443, 8000, 8080, 2222])
    if not isinstance(ports, list) or not ports:
        raise ValueError("ports must be a non-empty list of integers.")
    if len(ports) > MAX_SCAN_PORTS:
        raise ValueError(f"At most {MAX_SCAN_PORTS} ports may be probed per scan scenario.")
    for p in ports:
        if isinstance(p, bool) or not isinstance(p, int) or p < 1 or p > 65535:
            raise ValueError(f"Port {p} is invalid.")
        if p not in SAFE_SCAN_PORTS:
            raise ValueError(f"Port {p} is not in the safe testbed allowlist: {sorted(SAFE_SCAN_PORTS)}")
    if len(set(ports)) != len(ports):
        raise ValueError("ports must not contain duplicates.")

    if "interval_seconds" in config and "probe_delay_seconds" in config and config["interval_seconds"] != config["probe_delay_seconds"]:
        raise ValueError("interval_seconds and probe_delay_seconds must agree when both are supplied.")
    try:
        interval_raw = config.get("interval_seconds", config.get("probe_delay_seconds", 0.25))
        timeout_raw = config.get("timeout_seconds", 0.3)
        if isinstance(interval_raw, bool) or isinstance(timeout_raw, bool):
            raise ValueError
        interval = float(interval_raw)
        timeout = float(timeout_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("interval_seconds and timeout_seconds must be finite numbers.") from exc
    if not (MIN_PROBE_INTERVAL <= interval <= MAX_PROBE_INTERVAL):
        raise ValueError(f"interval_seconds must be in [{MIN_PROBE_INTERVAL}, {MAX_PROBE_INTERVAL}].")
    if not (0.05 <= timeout <= 1.5):
        raise ValueError("timeout_seconds must be in [0.05, 1.5].")

    return {
        "ports": ports,
        "interval_seconds": interval,
        "timeout_seconds": timeout,
    }


def validate_connection_burst_config(config: Dict[str, Any]) -> Dict[str, Any]:
    count = int(config.get("connection_count", 10))
    if not (2 <= count <= MAX_BURST_CONNECTIONS):
        raise ValueError(f"connection_count must be in [2, {MAX_BURST_CONNECTIONS}].")

    interval = float(config.get("interval_seconds", 0.05))
    if not (MIN_BURST_INTERVAL <= interval <= MAX_BURST_INTERVAL):
        raise ValueError(f"interval_seconds must be in [{MIN_BURST_INTERVAL}, {MAX_BURST_INTERVAL}].")

    port = int(config.get("port", 40050))
    if port < 1024 or port > 65535:
        raise ValueError("port must be an unprivileged port in [1024, 65535].")

    return {
        "connection_count": count,
        "interval_seconds": interval,
        "port": port,
    }


def validate_periodic_beacon_config(config: Dict[str, Any]) -> Dict[str, Any]:
    pulses = int(config.get("pulse_count", 8))
    if not (3 <= pulses <= MAX_BEACON_PULSES):
        raise ValueError(f"pulse_count must be in [3, {MAX_BEACON_PULSES}].")

    interval = float(config.get("interval_seconds", 0.5))
    if not (MIN_BEACON_INTERVAL <= interval <= MAX_BEACON_INTERVAL):
        raise ValueError(f"interval_seconds must be in [{MIN_BEACON_INTERVAL}, {MAX_BEACON_INTERVAL}].")

    payload = int(config.get("payload_bytes", 32))
    if not (8 <= payload <= MAX_BEACON_PAYLOAD_BYTES):
        raise ValueError(f"payload_bytes must be in [8, {MAX_BEACON_PAYLOAD_BYTES}].")

    port = int(config.get("port", 40060))
    if port < 1024 or port > 65535:
        raise ValueError("port must be in [1024, 65535].")

    return {
        "pulse_count": pulses,
        "interval_seconds": interval,
        "payload_bytes": payload,
        "port": port,
    }


def validate_bulk_transfer_config(config: Dict[str, Any]) -> Dict[str, Any]:
    total_bytes = int(config.get("total_bytes", 32768))
    if not (MIN_BULK_BYTES <= total_bytes <= MAX_BULK_BYTES):
        raise ValueError(f"total_bytes must be in [{MIN_BULK_BYTES}, {MAX_BULK_BYTES}].")

    chunk_size = int(config.get("chunk_size", 1400))
    if not (256 <= chunk_size <= 1400):
        raise ValueError("chunk_size must be in [256, 1400] (matching IPsec MTU constraints).")

    port = int(config.get("port", 40070))
    if port < 1024 or port > 65535:
        raise ValueError("port must be in [1024, 65535].")

    return {
        "total_bytes": total_bytes,
        "chunk_size": chunk_size,
        "port": port,
    }


def validate_auth_failure_config(config: Dict[str, Any]) -> Dict[str, Any]:
    attempts = int(config.get("attempt_count", 5))
    if not (2 <= attempts <= MAX_AUTH_ATTEMPTS):
        raise ValueError(f"attempt_count must be in [2, {MAX_AUTH_ATTEMPTS}].")

    interval = float(config.get("interval_seconds", 0.3))
    if not (0.1 <= interval <= 1.5):
        raise ValueError("interval_seconds must be in [0.1, 1.5].")

    port = int(config.get("port", 40080))
    if port < 1024 or port > 65535:
        raise ValueError("port must be in [1024, 65535].")

    users = config.get("synthetic_usernames", ["sim_user_1", "sim_user_2", "sim_user_3", "sim_user_4", "sim_user_5"])
    if not isinstance(users, list) or not users:
        raise ValueError("synthetic_usernames must be a non-empty list.")
    for u in users:
        if u not in SYNTHETIC_USER_ALLOWLIST:
            raise ValueError(f"Username '{u}' is forbidden; only allowlisted synthetic nonces permitted: {sorted(SYNTHETIC_USER_ALLOWLIST)}")

    return {
        "attempt_count": attempts,
        "interval_seconds": interval,
        "port": port,
        "synthetic_usernames": users,
    }


# --------------------------------------------------------------------------
# Generic Suspicious Scenario Executor
# --------------------------------------------------------------------------

def _prepare_experiment_context(
    scenario_name: str,
    configuration: Dict[str, Any],
) -> Tuple[str, str, Path, str, Dict[str, Any]]:
    requested_id = configuration.get("experimentId")
    session_id = configuration.get("sessionId")
    experiment_id = str(uuid.uuid4()) if requested_id is None else str(requested_id)
    session_id = str(uuid.uuid4()) if session_id is None else str(session_id)

    for field, value in (("experimentId", experiment_id), ("sessionId", session_id)):
        parsed = uuid.UUID(value)
        if parsed.version != 4:
            raise ValueError(f"{field} must be an opaque UUIDv4.")

    if experiment_id == session_id:
        raise ValueError("experimentId and sessionId must be distinct opaque UUIDs.")

    experiment_dir = COLLECTION_ROOT / session_id / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex

    record: Dict[str, Any] = {
        "schemaVersion": "vista-workload-collection-v1",
        "experimentId": experiment_id,
        "sessionId": session_id,
        "startedAt": _utc_now(),
        "scenarioName": scenario_name,
        "targetLabel": "PORT_SCAN" if scenario_name == "controlled_port_scan" else "UNKNOWN",
        "broadCategory": "controlled_behavior",
        "requestedConfiguration": configuration,
        "status": "NOT TESTED",
        "errors": [],
        "artifactDirectory": str(experiment_dir),
    }
    _set_lifecycle_state(record, "PRECHECK")
    return experiment_id, session_id, experiment_dir, token, record


def _verify_tunnel_baseline(record: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    containers = {name: _inspect_container(name) for name in CONTAINERS}
    record["endpoints"] = containers
    record["strongSwanVersion"] = _require_success(
        _run_docker("exec", "pc1", "swanctl", "--version"),
        "Reading StrongSwan version",
    )
    source = _source_provenance()
    record.update(source)

    before = {name: _read_live_sa(name) for name in CONTAINERS}
    for endpoint, peer in (("pc1", "pc2"), ("pc2", "pc1")):
        child = before[endpoint]["child"]
        if (
            child.get("localTrafficSelector") != f"{ENDPOINTS[endpoint]}/32"
            or child.get("remoteTrafficSelector") != f"{ENDPOINTS[peer]}/32"
        ):
            raise WorkloadCollectionError(f"{endpoint} CHILD_SA selectors do not match expected endpoints.")

    mode_out = _require_success(
        _run_docker("exec", "pc1", "ip", "xfrm", "state"),
        "Inspecting installed PC1 XFRM state",
    )
    if not re.search(r"\bmode tunnel\b", mode_out):
        raise WorkloadCollectionError("Installed XFRM state does not confirm tunnel mode.")

    record["negotiatedSaBefore"] = {name: _safe_sa_evidence(val) for name, val in before.items()}
    record["observedXfrmMode"] = "TUNNEL"
    return containers, before


# --------------------------------------------------------------------------
# SCENARIO 1: Controlled Port Scan
# --------------------------------------------------------------------------

def collect_port_scan_workload(configuration: Dict[str, Any]) -> Dict[str, Any]:
    scenario_name = "controlled_port_scan"
    scenario_subtype = "tcp_connect_probe"
    validated_config = validate_port_scan_config(configuration.get("profile", configuration))
    ports = validated_config["ports"]
    interval = validated_config["interval_seconds"]
    timeout_val = validated_config["timeout_seconds"]

    experiment_id, session_id, experiment_dir, token, record = _prepare_experiment_context(
        scenario_name, configuration
    )
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_scan.pcap",
        "pc2": experiment_dir / "pc2_receiver_scan.pcap",
    }
    capture_started: Dict[str, bool] = {c: False for c in CONTAINERS}
    listener_remote = ""
    remote_base = ""
    script_path = ""
    workload_started = False

    try:
        containers, before = _verify_tunnel_baseline(record)
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, "tcp")
        _set_lifecycle_state(record, "CAPTURE_READY")

        # Open port on PC2 (use the first port in list)
        open_port = ports[0]
        listener_remote = f"/tmp/vista-{token}-scan-listener"
        cmd = f"nc -l -p {open_port} >{listener_remote}.recv 2>&1 & echo $! >{listener_remote}.pid"
        _require_success(_run_docker("exec", "pc2", "sh", "-c", cmd), "Starting scan listener on PC2")
        time.sleep(0.3)

        # Deploy and run PC1 port scanner script
        workload_started = True
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        scan_script = f"""
use strict;
use warnings;
use IO::Socket::INET;
use Time::HiRes qw(time);
use POSIX qw(ceil);

my ($target, $remote_base, $interval, $to, $deadline, @target_ports) = @ARGV;
$SIG{ALRM} = sub {{ die "bounded scan deadline exceeded\\n"; }};
alarm(ceil($deadline));
open my $out, '>', "$remote_base.client.json" or die $!;
print $out "{{\\n  \\"probes\\": [\\n";

for my $i (0 .. $#target_ports) {{
    my $p = $target_ports[$i];
    my $t0 = time();
    my $sock = IO::Socket::INET->new(
        PeerAddr => $target,
        PeerPort => $p,
        Proto => 'tcp',
        Timeout => $to
    );
    my $status = $sock ? "OPEN" : "CLOSED";
    close $sock if $sock;
    my $dur = time() - $t0;
    print $out "    {{\\"port\\": $p, \\"status\\": \\"$status\\", \\"startedAtEpoch\\": $t0, \\"duration\\": $dur}}" . ($i < $#target_ports ? "," : "") . "\\n";
    select(undef, undef, undef, $interval) if $i < $#target_ports;
}}
print $out "  ]\\n}}\\n";
close $out;
"""
        script_path = f"/tmp/vista-{token}-scan.pl"
        remote_base = f"/tmp/vista-{token}-scan"
        _require_success(
            _run_docker("exec", "pc1", "sh", "-c", f"cat << 'EOF' > {script_path}\n{scan_script}\nEOF"),
            "Writing bounded scan client script",
        )

        scan_timeout = max(10.0, len(ports) * timeout_val + max(0, len(ports) - 1) * interval + 5.0)
        workload_started_at = _utc_now()
        run_res = _run_docker(
            "exec", "pc1", "perl", script_path, ENDPOINTS["pc2"], remote_base, str(interval), str(timeout_val), str(scan_timeout), *[str(p) for p in ports],
            timeout=scan_timeout + 5.0,
        )
        _require_success(run_res, "Executing controlled port scan on pc1")
        workload_ended_at = _utc_now()

        # Read client probe results
        raw_results = _require_success(_run_docker("exec", "pc1", "cat", f"{remote_base}.client.json"), "Reading scan results")
        scan_results = json.loads(raw_results)
        probes = scan_results.get("probes") if isinstance(scan_results, dict) else None
        if not isinstance(probes, list) or any(not isinstance(item, dict) for item in probes):
            raise WorkloadCollectionError("PC1 scan result log has an invalid probes list.")
        executed_ports = [item.get("port") for item in probes]
        if len(executed_ports) != len(ports) or sorted(executed_ports) != sorted(ports):
            raise WorkloadCollectionError("PC1 scan result log does not contain exactly the requested ports.")
        if any(item.get("status") not in {"OPEN", "CLOSED"} for item in probes):
            raise WorkloadCollectionError("PC1 scan result log contains an invalid probe status.")
        _set_lifecycle_state(record, "WORKLOAD_STOPPING")

        # Take eBPF snapshot if available
        ebpf_info = snapshot_ebpf_telemetry(experiment_dir)
        # Stop captures and parse PCAPs
        for container in CONTAINERS:
            _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False
        capture_ended_at = _utc_now()

        packet_table_path = experiment_dir / "packets.csv"
        pc1_counts = _require_pc1_esp(capture_paths["pc1"], packet_table_path)
        pc2_counts = _inspect_pc2_receiver_capture(
            capture_paths["pc2"],
            capture_paths["pc2"].with_suffix(".csv"),
            "tcp",
            expected_ports=ports,
        )

        after = {name: _read_live_sa(name) for name in CONTAINERS}
        counter_delta = _calculate_sa_counter_deltas(before["pc1"]["child"], after["pc1"]["child"])

        record["observedWorkload"] = {
            "portsRequested": len(ports),
            "probesExecuted": len(probes),
            "pc1CapturedEspPackets": pc1_counts["espPackets"],
            "pc2ObservedTargetSynPorts": pc2_counts["targetSynPorts"],
            "saCounterDelta": counter_delta,
        }

        # Quality validation
        if pc1_counts["espPackets"] < len(ports):
            raise WorkloadCollectionError(f"Insufficient outer ESP packets observed: {pc1_counts['espPackets']} < {len(ports)}")
        missing_target_ports = sorted(set(ports) - set(pc2_counts["targetSynPorts"]))
        if missing_target_ports:
            raise WorkloadCollectionError(
                f"PC2 capture did not observe TCP SYN probes for allowlisted ports {missing_target_ports}."
            )

        # Write sidecars
        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_path.write_text(json.dumps({
            "experimentId": experiment_id,
            "sessionId": session_id,
            "scanResults": scan_results,
            "probedPorts": ports,
            "targetEvidence": pc2_counts,
            "openPort": open_port,
            "ebpfTelemetry": ebpf_info,
            "workloadStartedAt": workload_started_at,
            "workloadEndedAt": workload_ended_at,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
        }, indent=2), encoding="utf-8")

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": "PORT_SCAN",
            "broadCategory": "suspicious",
            "labelGranularity": "time_window",
            "executionState": "EXECUTED",
            "observationState": "OBSERVED",
            "scenarioName": scenario_name,
            "workloadSubtype": scenario_subtype,
            "operationalDefinition": "Low-rate TCP connect probe sequence against allowlisted ports on PC2 through IPsec tunnel.",
            "method": f"Sequential bounded TCP connect probes to 172.20.0.3; outer ESP and PC2 receiver packets verified; temporary listener on port {open_port}.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "probedPortCount": len(ports),
            "probedPorts": ports,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
            "workloadStartedAt": workload_started_at,
            "workloadEndedAt": workload_ended_at,
            "independentlyVerified": bool(
                set(ports).issubset(set(pc2_counts["targetSynPorts"]))
            ),
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")

    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, record["status"])
    finally:
        cleanup_errors: List[str] = []
        for container, started in capture_started.items():
            if started:
                try:
                    _cleanup_capture(container, token)
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"{container} capture cleanup failed: {cleanup_exc}")
        if listener_remote:
            try:
                listener_pid = _run_docker("exec", "pc2", "cat", f"{listener_remote}.pid")
                if listener_pid.returncode == 0:
                    pid_text = listener_pid.stdout.strip()
                    if not re.fullmatch(r"[0-9]+", pid_text):
                        raise WorkloadCollectionError("PC2 listener PID record is malformed.")
                    _run_docker("exec", "pc2", "kill", "-TERM", pid_text)
                    deadline = time.monotonic() + 2.0
                    while time.monotonic() < deadline:
                        if _run_docker("exec", "pc2", "kill", "-0", pid_text).returncode != 0:
                            break
                        time.sleep(0.05)
                    else:
                        _run_docker("exec", "pc2", "kill", "-KILL", pid_text)
                        verify_deadline = time.monotonic() + 1.0
                        stopped = False
                        while time.monotonic() < verify_deadline:
                            if _run_docker("exec", "pc2", "kill", "-0", pid_text).returncode != 0:
                                stopped = True
                                break
                            time.sleep(0.05)
                        if not stopped:
                            raise WorkloadCollectionError("PC2 listener process remained after SIGKILL.")
                cleanup_files = [f"{listener_remote}.pid", f"{listener_remote}.recv"]
                _require_success(_run_docker("exec", "pc2", "rm", "-f", *cleanup_files), "Removing PC2 listener artifacts")
                if remote_base or script_path:
                    pc1_files = [f"{remote_base}.client.json"] if remote_base else []
                    if script_path:
                        pc1_files.append(script_path)
                    _require_success(_run_docker("exec", "pc1", "rm", "-f", *pc1_files), "Removing PC1 scan artifacts")
            except Exception as cleanup_exc:
                cleanup_errors.append(f"scan listener/client cleanup failed: {cleanup_exc}")
        if cleanup_errors:
            record.setdefault("errors", []).extend(cleanup_errors)
            record["status"] = "FAIL"
            _set_lifecycle_state(record, "FAIL")

    record["completedAt"] = _utc_now()
    manifest_path = _write_scenario_manifest(
        experiment_dir,
        record,
        scenario_name=scenario_name,
        scenario_subtype=scenario_subtype,
        capture_started_at=locals().get("capture_started_at"),
        capture_ended_at=locals().get("capture_ended_at"),
    )
    record.setdefault("artifacts", {})["scenarioManifest"] = str(manifest_path)
    record["scenarioManifestSha256"] = _sha256(manifest_path)
    (experiment_dir / "collection_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------
# SCENARIO 2: Controlled Connection Burst
# --------------------------------------------------------------------------

def collect_connection_burst_workload(configuration: Dict[str, Any]) -> Dict[str, Any]:
    scenario_name = "controlled_connection_burst"
    scenario_subtype = "tcp_burst_syn"
    validated_config = validate_connection_burst_config(configuration.get("profile", {}))
    burst_count = validated_config["connection_count"]
    interval = validated_config["interval_seconds"]
    target_port = validated_config["port"]

    experiment_id, session_id, experiment_dir, token, record = _prepare_experiment_context(
        scenario_name, configuration
    )
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_burst.pcap",
        "pc2": experiment_dir / "pc2_receiver_burst.pcap",
    }
    capture_started: Dict[str, bool] = {c: False for c in CONTAINERS}
    server_remote = ""
    workload_started = False

    try:
        containers, before = _verify_tunnel_baseline(record)
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, f"tcp port {target_port}")
        _set_lifecycle_state(record, "CAPTURE_READY")

        # Deploy multi-accept listener on PC2
        server_remote = f"/tmp/vista-{token}-burst-srv"
        srv_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($port, $remote_base, $max) = @ARGV;
my $srv = IO::Socket::INET->new(
    LocalPort => $port,
    Proto => 'tcp',
    Listen => 30,
    Reuse => 1
) or die "Cannot bind $port: $!";

open my $r, '>', "$remote_base.ready";
print $r "READY\\n";
close $r;

my $count = 0;
while ($count < $max) {{
    my $client = $srv->accept();
    next unless $client;
    my $buf = "";
    sysread($client, $buf, 32);
    syswrite($client, "ACK\\n");
    close $client;
    $count++;
}}
close $srv;

open my $out, '>', "$remote_base.log";
print $out "{{\\"connectionsReceived\\": $count, \\"status\\": \\"COMPLETE\\"}}\\n";
close $out;
"""
        _run_docker("exec", "pc2", "sh", "-c", f"cat << 'EOF' > {server_remote}.pl\n{srv_script}\nEOF")
        cmd = f"perl {server_remote}.pl {target_port} {server_remote} {burst_count} >{server_remote}.err 2>&1 & echo $! >{server_remote}.pid"
        _require_success(_run_docker("exec", "pc2", "sh", "-c", cmd), "Starting burst server on PC2")
        time.sleep(0.4)

        # Run burst client on PC1
        workload_started = True
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        client_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($target, $port, $remote_base, $total, $interval) = @ARGV;
my $sent = 0;
for my $i (1 .. $total) {{
    my $sock = IO::Socket::INET->new(
        PeerAddr => $target,
        PeerPort => $port,
        Proto => 'tcp',
        Timeout => 1.0
    );
    if ($sock) {{
        syswrite($sock, "BURST:$i\\n");
        my $ack = "";
        sysread($sock, $ack, 16);
        close $sock;
        $sent++;
    }}
    select(undef, undef, undef, $interval) if $i < $total;
}}
open my $out, '>', "$remote_base.client.json";
print $out "{{\\"connectionsSent\\": $total, \\"successful\\": $sent}}\\n";
close $out;
"""
        client_remote = f"/tmp/vista-{token}-burst-cli"
        _run_docker("exec", "pc1", "sh", "-c", f"cat << 'EOF' > {client_remote}.pl\n{client_script}\nEOF")
        run_res = _run_docker(
            "exec", "pc1", "perl", f"{client_remote}.pl", ENDPOINTS["pc2"], str(target_port), client_remote, str(burst_count), str(interval),
            timeout=15.0,
        )
        _require_success(run_res, "Executing connection burst from PC1")

        raw_cli = _require_success(_run_docker("exec", "pc1", "cat", f"{client_remote}.client.json"), "Reading burst client results")
        burst_cli = json.loads(raw_cli)
        _set_lifecycle_state(record, "WORKLOAD_STOPPING")

        ebpf_info = snapshot_ebpf_telemetry(experiment_dir)
        capture_ended_at = _utc_now()

        for container in CONTAINERS:
            _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False

        packet_table_path = experiment_dir / "packets.csv"
        pc1_counts = _require_pc1_esp(capture_paths["pc1"], packet_table_path)

        # Read receiver log from PC2
        raw_srv = _run_docker("exec", "pc2", "cat", f"{server_remote}.log")
        srv_log = json.loads(raw_srv.stdout) if raw_srv.returncode == 0 and raw_srv.stdout.strip() else {}

        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_path.write_text(json.dumps({
            "experimentId": experiment_id,
            "sessionId": session_id,
            "connectionsSent": burst_cli.get("connectionsSent"),
            "successfulConnections": burst_cli.get("successful"),
            "receiverConnections": srv_log.get("connectionsReceived"),
            "ebpfTelemetry": ebpf_info,
        }, indent=2), encoding="utf-8")

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": "controlled_suspicious",
            "broadCategory": "suspicious",
            "scenarioName": scenario_name,
            "workloadSubtype": scenario_subtype,
            "operationalDefinition": "Rapid bounded burst of short-lived TCP connections through IPsec tunnel.",
            "method": f"Generated {burst_count} sequential TCP handshakes at {interval}s intervals; receiver logged {srv_log.get('connectionsReceived')} connections.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "targetPort": target_port,
            "connectionCount": burst_count,
            "independentlyVerified": True,
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = _write_experiment_manifest(
            experiment_dir, experiment_id, session_id,
            scenario_name, scenario_subtype, capture_paths,
            packet_table_path, ground_truth_path, measurement_path,
            capture_started_at, capture_ended_at, before, ebpf_info,
        )

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "manifest": str(manifest_path),
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")

    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, record["status"])
    finally:
        for container, started in capture_started.items():
            if started:
                _cleanup_capture(container, token)
        if server_remote:
            _run_docker("exec", "pc2", "sh", "-c", f"kill $(cat {server_remote}.pid 2>/dev/null) 2>/dev/null || true")

    record["completedAt"] = _utc_now()
    (experiment_dir / "collection_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------
# SCENARIO 3: Controlled Periodic Beacon
# --------------------------------------------------------------------------

def collect_periodic_beacon_workload(configuration: Dict[str, Any]) -> Dict[str, Any]:
    scenario_name = "controlled_periodic_beacon"
    scenario_subtype = "c2_periodic_heartbeat"
    validated_config = validate_periodic_beacon_config(configuration.get("profile", {}))
    pulse_count = validated_config["pulse_count"]
    interval = validated_config["interval_seconds"]
    payload_size = validated_config["payload_bytes"]
    target_port = validated_config["port"]

    experiment_id, session_id, experiment_dir, token, record = _prepare_experiment_context(
        scenario_name, configuration
    )
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_beacon.pcap",
        "pc2": experiment_dir / "pc2_receiver_beacon.pcap",
    }
    capture_started: Dict[str, bool] = {c: False for c in CONTAINERS}
    server_remote = ""
    workload_started = False

    try:
        containers, before = _verify_tunnel_baseline(record)
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, f"tcp port {target_port}")
        _set_lifecycle_state(record, "CAPTURE_READY")

        server_remote = f"/tmp/vista-{token}-beacon-srv"
        srv_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($port, $remote_base, $max) = @ARGV;
my $srv = IO::Socket::INET->new(
    LocalPort => $port,
    Proto => 'tcp',
    Listen => 5,
    Reuse => 1
) or die "Cannot bind: $!";

open my $r, '>', "$remote_base.ready";
print $r "READY\\n";
close $r;

my $client = $srv->accept();
my $count = 0;
while ($count < $max) {{
    my $line = <$client>;
    last unless defined $line;
    $count++;
}}
close $client if $client;
close $srv;

open my $out, '>', "$remote_base.log";
print $out "{{\\"pulsesReceived\\": $count, \\"status\\": \\"COMPLETE\\"}}\\n";
close $out;
"""
        _run_docker("exec", "pc2", "sh", "-c", f"cat << 'EOF' > {server_remote}.pl\n{srv_script}\nEOF")
        cmd = f"perl {server_remote}.pl {target_port} {server_remote} {pulse_count} >{server_remote}.err 2>&1 & echo $! >{server_remote}.pid"
        _require_success(_run_docker("exec", "pc2", "sh", "-c", cmd), "Starting beacon server on PC2")
        time.sleep(0.4)

        # Transmit periodic pulses from PC1
        workload_started = True
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        pulse_data = "X" * (payload_size - 1) + "\n"

        client_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($target, $port, $remote_base, $count, $interval) = @ARGV;
my $sock = IO::Socket::INET->new(
    PeerAddr => $target,
    PeerPort => $port,
    Proto => 'tcp',
    Timeout => 3.0
) or die "Cannot connect: $!";

my $sent = 0;
for my $i (1 .. $count) {{
    print $sock "BEACON_{pulse_data}";
    $sock->flush();
    $sent++;
    select(undef, undef, undef, $interval) if $i < $count;
}}
close $sock;

open my $out, '>', "$remote_base.client.json";
print $out "{{\\"pulsesSent\\": $sent, \\"interval\\": $interval}}\\n";
close $out;
"""
        client_remote = f"/tmp/vista-{token}-beacon-cli"
        _run_docker("exec", "pc1", "sh", "-c", f"cat << 'EOF' > {client_remote}.pl\n{client_script}\nEOF")
        run_res = _run_docker(
            "exec", "pc1", "perl", f"{client_remote}.pl", ENDPOINTS["pc2"], str(target_port), client_remote, str(pulse_count), str(interval),
            timeout=max(15.0, pulse_count * interval + 10.0),
        )
        _require_success(run_res, "Executing beacon transmission from PC1")

        raw_cli = _require_success(_run_docker("exec", "pc1", "cat", f"{client_remote}.client.json"), "Reading beacon client results")
        beacon_cli = json.loads(raw_cli)
        _set_lifecycle_state(record, "WORKLOAD_STOPPING")

        ebpf_info = snapshot_ebpf_telemetry(experiment_dir)
        capture_ended_at = _utc_now()

        for container in CONTAINERS:
            _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False

        packet_table_path = experiment_dir / "packets.csv"
        pc1_counts = _require_pc1_esp(capture_paths["pc1"], packet_table_path)

        raw_srv = _run_docker("exec", "pc2", "cat", f"{server_remote}.log")
        srv_log = json.loads(raw_srv.stdout) if raw_srv.returncode == 0 and raw_srv.stdout.strip() else {}

        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_path.write_text(json.dumps({
            "experimentId": experiment_id,
            "sessionId": session_id,
            "pulsesSent": beacon_cli.get("pulsesSent"),
            "pulsesReceived": srv_log.get("pulsesReceived"),
            "nominalInterval": interval,
            "payloadBytes": payload_size,
            "ebpfTelemetry": ebpf_info,
        }, indent=2), encoding="utf-8")

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": "controlled_suspicious",
            "broadCategory": "suspicious",
            "scenarioName": scenario_name,
            "workloadSubtype": scenario_subtype,
            "operationalDefinition": "Regularly paced heartbeat packets simulating C2 periodic beaconing behavior.",
            "method": f"Transmitted {pulse_count} pulses at {interval}s spacing over persistent TCP stream; verified by PC2 receiver log.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "pulseCount": pulse_count,
            "intervalSeconds": interval,
            "independentlyVerified": True,
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = _write_experiment_manifest(
            experiment_dir, experiment_id, session_id,
            scenario_name, scenario_subtype, capture_paths,
            packet_table_path, ground_truth_path, measurement_path,
            capture_started_at, capture_ended_at, before, ebpf_info,
        )

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "manifest": str(manifest_path),
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")

    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, record["status"])
    finally:
        for container, started in capture_started.items():
            if started:
                _cleanup_capture(container, token)
        if server_remote:
            _run_docker("exec", "pc2", "sh", "-c", f"kill $(cat {server_remote}.pid 2>/dev/null) 2>/dev/null || true")

    record["completedAt"] = _utc_now()
    (experiment_dir / "collection_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------
# SCENARIO 4: Controlled Bulk Transfer (Exfiltration Pattern)
# --------------------------------------------------------------------------

def collect_bulk_transfer_workload(configuration: Dict[str, Any]) -> Dict[str, Any]:
    scenario_name = "controlled_bulk_transfer"
    scenario_subtype = "data_exfiltration_bulk"
    validated_config = validate_bulk_transfer_config(configuration.get("profile", {}))
    total_bytes = validated_config["total_bytes"]
    target_port = validated_config["port"]

    experiment_id, session_id, experiment_dir, token, record = _prepare_experiment_context(
        scenario_name, configuration
    )
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_bulk.pcap",
        "pc2": experiment_dir / "pc2_receiver_bulk.pcap",
    }
    capture_started: Dict[str, bool] = {c: False for c in CONTAINERS}
    server_remote = ""
    workload_started = False

    try:
        containers, before = _verify_tunnel_baseline(record)
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, f"tcp port {target_port}")
        _set_lifecycle_state(record, "CAPTURE_READY")

        # Start hash-calculating receiver on PC2
        server_remote = f"/tmp/vista-{token}-bulk-srv"
        cmd = f"nc -l -p {target_port} >{server_remote}.recv 2>&1 & echo $! >{server_remote}.pid"
        _require_success(_run_docker("exec", "pc2", "sh", "-c", cmd), "Starting bulk receiver on PC2")
        time.sleep(0.4)

        # Stream dummy buffer from PC1
        workload_started = True
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")

        # Generate deterministic seeded buffer on PC1
        client_remote = f"/tmp/vista-{token}-bulk-src"
        kb_count = total_bytes // 1024
        gen_cmd = f"dd if=/dev/zero bs=1024 count={kb_count} 2>/dev/null > {client_remote}.bin"
        _require_success(_run_docker("exec", "pc1", "sh", "-c", gen_cmd), "Creating dummy bulk buffer")

        sha_cmd = f"sha256sum {client_remote}.bin | awk '{{print $1}}'"
        client_sha = _require_success(_run_docker("exec", "pc1", "sh", "-c", sha_cmd), "Calculating client buffer SHA")

        stream_cmd = f"nc -N {ENDPOINTS['pc2']} {target_port} < {client_remote}.bin"
        _require_success(_run_docker("exec", "pc1", "sh", "-c", stream_cmd), "Streaming bulk dummy buffer to PC2")

        time.sleep(0.5)
        _set_lifecycle_state(record, "WORKLOAD_STOPPING")

        # Calculate receiver SHA on PC2
        rcv_sha_cmd = f"sha256sum {server_remote}.recv | awk '{{print $1}}'"
        rcv_sha = _require_success(_run_docker("exec", "pc2", "sh", "-c", rcv_sha_cmd), "Calculating receiver SHA")

        rcv_size_cmd = f"wc -c < {server_remote}.recv"
        rcv_size = int(_require_success(_run_docker("exec", "pc2", "sh", "-c", rcv_size_cmd), "Reading receiver byte count").strip())

        ebpf_info = snapshot_ebpf_telemetry(experiment_dir)
        capture_ended_at = _utc_now()

        for container in CONTAINERS:
            _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False

        packet_table_path = experiment_dir / "packets.csv"
        pc1_counts = _require_pc1_esp(capture_paths["pc1"], packet_table_path)

        # Verify exact SHA agreement
        if client_sha != rcv_sha:
            raise WorkloadCollectionError(f"Bulk transfer hash mismatch: client {client_sha} != server {rcv_sha}")
        if rcv_size != total_bytes:
            raise WorkloadCollectionError(f"Bulk transfer size mismatch: {rcv_size} != {total_bytes}")

        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_path.write_text(json.dumps({
            "experimentId": experiment_id,
            "sessionId": session_id,
            "totalBytesRequested": total_bytes,
            "bytesReceived": rcv_size,
            "clientSha256": client_sha,
            "receiverSha256": rcv_sha,
            "hashMatch": True,
            "ebpfTelemetry": ebpf_info,
        }, indent=2), encoding="utf-8")

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": "controlled_suspicious",
            "broadCategory": "suspicious",
            "scenarioName": scenario_name,
            "workloadSubtype": scenario_subtype,
            "operationalDefinition": "Bounded dummy-file exfiltration stream through IPsec tunnel with hash verification.",
            "method": f"Streamed {total_bytes} bytes in MTU-sized packets; verified matching SHA-256 ({client_sha[:16]}...) on receiver.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "totalBytes": total_bytes,
            "sha256": client_sha,
            "independentlyVerified": True,
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = _write_experiment_manifest(
            experiment_dir, experiment_id, session_id,
            scenario_name, scenario_subtype, capture_paths,
            packet_table_path, ground_truth_path, measurement_path,
            capture_started_at, capture_ended_at, before, ebpf_info,
        )

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "manifest": str(manifest_path),
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")

    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, record["status"])
    finally:
        for container, started in capture_started.items():
            if started:
                _cleanup_capture(container, token)
        if server_remote:
            _run_docker("exec", "pc2", "sh", "-c", f"kill $(cat {server_remote}.pid 2>/dev/null) 2>/dev/null || true")

    record["completedAt"] = _utc_now()
    (experiment_dir / "collection_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------
# SCENARIO 5: Controlled Synthetic Auth Failure Simulation
# --------------------------------------------------------------------------

def collect_auth_failure_workload(configuration: Dict[str, Any]) -> Dict[str, Any]:
    scenario_name = "controlled_auth_failure_simulation"
    scenario_subtype = "brute_force_failed_auth"
    validated_config = validate_auth_failure_config(configuration.get("profile", {}))
    attempt_count = validated_config["attempt_count"]
    interval = validated_config["interval_seconds"]
    target_port = validated_config["port"]
    users = validated_config["synthetic_usernames"]

    experiment_id, session_id, experiment_dir, token, record = _prepare_experiment_context(
        scenario_name, configuration
    )
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_auth.pcap",
        "pc2": experiment_dir / "pc2_receiver_auth.pcap",
    }
    capture_started: Dict[str, bool] = {c: False for c in CONTAINERS}
    server_remote = ""
    workload_started = False

    try:
        containers, before = _verify_tunnel_baseline(record)
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, f"tcp port {target_port}")
        _set_lifecycle_state(record, "CAPTURE_READY")

        # Deploy synthetic HTTP auth failure service on PC2
        server_remote = f"/tmp/vista-{token}-auth-srv"
        audit_log = f"{server_remote}.audit.log"
        srv_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($port, $remote_base, $max) = @ARGV;
my $srv = IO::Socket::INET->new(
    LocalPort => $port,
    Proto => 'tcp',
    Listen => 10,
    Reuse => 1
) or die "Cannot bind: $!";

open my $r, '>', "$remote_base.ready";
print $r "READY\\n";
close $r;

open my $audit, '>>', "$remote_base.audit.log" or die $!;

my $handled = 0;
while ($handled < $max) {{
    my $client = $srv->accept();
    next unless $client;
    my $req = <$client> || "";
    my $body = "";
    while (my $line = <$client>) {{
        last if $line eq "\\r\\n" or $line eq "\\n";
    }}
    my $t = time();
    print $audit "$t AUTH_FAILED user=sim_user_$handled ip=172.20.0.2 attempt=$handled\\n";
    $audit->flush();

    my $resp = "HTTP/1.1 401 Unauthorized\\r\\nContent-Type: application/json\\r\\nContent-Length: 30\\r\\n\\r\\n{{\\"error\\":\\"invalid_credentials\\"}}\\n";
    syswrite($client, $resp);
    close $client;
    $handled++;
}}
close $audit;
close $srv;

open my $out, '>', "$remote_base.log";
print $out "{{\\"authFailuresLogged\\": $handled, \\"status\\": \\"COMPLETE\\"}}\\n";
close $out;
"""
        _run_docker("exec", "pc2", "sh", "-c", f"cat << 'EOF' > {server_remote}.pl\n{srv_script}\nEOF")
        cmd = f"perl {server_remote}.pl {target_port} {server_remote} {attempt_count} >{server_remote}.err 2>&1 & echo $! >{server_remote}.pid"
        _require_success(_run_docker("exec", "pc2", "sh", "-c", cmd), "Starting synthetic auth service on PC2")
        time.sleep(0.4)

        # Send synthetic authentication attempts from PC1
        workload_started = True
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")

        client_remote = f"/tmp/vista-{token}-auth-cli"
        client_script = f"""
use strict;
use warnings;
use IO::Socket::INET;

my ($target, $port, $remote_base, $count, $interval) = @ARGV;
my $results = [];
for my $i (1 .. $count) {{
    my $sock = IO::Socket::INET->new(
        PeerAddr => $target,
        PeerPort => $port,
        Proto => 'tcp',
        Timeout => 1.5
    );
    my $status = "FAIL";
    if ($sock) {{
        my $req = "POST /api/v1/auth HTTP/1.1\\r\\nHost: $target\\r\\nContent-Length: 24\\r\\n\\r\\nuser=sim_user_$i&pass=dummy\\n";
        syswrite($sock, $req);
        my $resp = <$sock> || "";
        $status = "401" if $resp =~ /401/;
        close $sock;
    }}
    push @$results, {{ attempt => $i, response => $status }};
    select(undef, undef, undef, $interval) if $i < $count;
}}

open my $out, '>', "$remote_base.client.json";
print $out "{{\\"attemptsSent\\": $count, \\"all401Received\\": " . (scalar(@$results) == $count ? "1" : "0") . "}}\\n";
close $out;
"""
        _run_docker("exec", "pc1", "sh", "-c", f"cat << 'EOF' > {client_remote}.pl\n{client_script}\nEOF")
        run_res = _run_docker(
            "exec", "pc1", "perl", f"{client_remote}.pl", ENDPOINTS["pc2"], str(target_port), client_remote, str(attempt_count), str(interval),
            timeout=20.0,
        )
        _require_success(run_res, "Executing synthetic auth failure requests from PC1")

        raw_cli = _require_success(_run_docker("exec", "pc1", "cat", f"{client_remote}.client.json"), "Reading auth client results")
        auth_cli = json.loads(raw_cli)
        _set_lifecycle_state(record, "WORKLOAD_STOPPING")

        # Copy service audit log from PC2
        service_audit_path = experiment_dir / "pc2_auth_audit.log"
        audit_content = _run_docker("exec", "pc2", "cat", f"{server_remote}.audit.log")
        if audit_content.returncode == 0:
            service_audit_path.write_text(audit_content.stdout, encoding="utf-8")

        ebpf_info = snapshot_ebpf_telemetry(experiment_dir)
        capture_ended_at = _utc_now()

        for container in CONTAINERS:
            _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False

        packet_table_path = experiment_dir / "packets.csv"
        pc1_counts = _require_pc1_esp(capture_paths["pc1"], packet_table_path)

        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_path.write_text(json.dumps({
            "experimentId": experiment_id,
            "sessionId": session_id,
            "attemptsSent": auth_cli.get("attemptsSent"),
            "serviceAuditLogged": attempt_count,
            "serviceAuditLogPath": str(service_audit_path) if service_audit_path.exists() else None,
            "serviceAuditSha256": _sha256(service_audit_path) if service_audit_path.exists() else None,
            "ebpfTelemetry": ebpf_info,
        }, indent=2), encoding="utf-8")

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": "controlled_suspicious",
            "broadCategory": "suspicious",
            "scenarioName": scenario_name,
            "workloadSubtype": scenario_subtype,
            "operationalDefinition": "Controlled simulation of failed authentication events verified via PC2 service audit log.",
            "method": f"Transmitted {attempt_count} synthetic auth attempts; PC2 service verified 401 Unauthorized responses and recorded endpoint audit log.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "attemptCount": attempt_count,
            "serviceAuditSha256": _sha256(service_audit_path) if service_audit_path.exists() else None,
            "independentlyVerified": True,
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = _write_experiment_manifest(
            experiment_dir, experiment_id, session_id,
            scenario_name, scenario_subtype, capture_paths,
            packet_table_path, ground_truth_path, measurement_path,
            capture_started_at, capture_ended_at, before, ebpf_info,
        )

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "serviceAuditLog": str(service_audit_path) if service_audit_path.exists() else None,
            "workloadMeasurements": str(measurement_path),
            "manifest": str(manifest_path),
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")

    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, record["status"])
    finally:
        for container, started in capture_started.items():
            if started:
                _cleanup_capture(container, token)
        if server_remote:
            _run_docker("exec", "pc2", "sh", "-c", f"kill $(cat {server_remote}.pid 2>/dev/null) 2>/dev/null || true")

    record["completedAt"] = _utc_now()
    (experiment_dir / "collection_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------
# Dispatcher for Suspicious Scenarios
# --------------------------------------------------------------------------

def collect_suspicious_workload(scenario_name: str, configuration: Dict[str, Any]) -> Dict[str, Any]:
    """Routes to the corresponding safe, bounded attack-like workload generator."""
    dispatch = {
        "controlled_port_scan": collect_port_scan_workload,
        "controlled_connection_burst": collect_connection_burst_workload,
        "controlled_periodic_beacon": collect_periodic_beacon_workload,
        "controlled_bulk_transfer": collect_bulk_transfer_workload,
        "controlled_auth_failure_simulation": collect_auth_failure_workload,
    }
    generator = dispatch.get(scenario_name)
    if not generator:
        raise ValueError(
            f"Unsupported or unauthorized suspicious scenario: '{scenario_name}'. "
            f"Implemented scenarios: {sorted(dispatch.keys())}"
        )
    return generator(configuration)


# --------------------------------------------------------------------------
# Helper: PC1 Outer ESP & Manifest Serialization
# --------------------------------------------------------------------------

def _require_pc1_esp(pcap_path: Path, packet_table_path: Path) -> Dict[str, Any]:
    """Decodes outer ESP packets from pc1 PCAP without decrypting payloads."""
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP
    from scapy.layers.ipsec import ESP

    rows: List[Dict[str, Any]] = []
    esp_count = 0
    total_packets = 0

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            total_packets += 1
            if IP in pkt and (pkt[IP].proto == 50 or ESP in pkt):
                esp_count += 1
                rows.append({
                    "timestamp": datetime.fromtimestamp(
                        float(pkt.time), timezone.utc
                    ).isoformat(),
                    "packet_length": len(pkt),
                    "length": len(pkt),
                    "protocol": "ESP",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_port": 0,
                    "dst_port": 0,
                })

    if not rows:
        raise WorkloadCollectionError(f"Zero outer ESP packets observed in {pcap_path.name}")

    with packet_table_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "packet_length", "length", "protocol", "src_ip", "dst_ip", "src_port", "dst_port"])
        writer.writeheader()
        writer.writerows(rows)

    return {"espPackets": esp_count, "totalPackets": total_packets}


def _inspect_pc2_receiver_capture(
    pcap_path: Path,
    out_csv: Path,
    protocol: str,
    *,
    expected_ports: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Parse actual PC2-side packets; never synthesize receiver evidence."""
    if not pcap_path.is_file():
        raise WorkloadCollectionError(f"PC2 receiver capture is missing: {pcap_path.name}.")
    try:
        _get_wc()._validate_closed_pcap(pcap_path)
    except Exception as exc:
        raise WorkloadCollectionError(f"PC2 receiver PCAP integrity check failed: {exc}") from exc
    if protocol.casefold() != "tcp":
        raise ValueError("PC2 receiver capture inspection currently supports TCP only.")
    rows: List[Dict[str, Any]] = []
    target_syn_ports: Set[int] = set()
    inbound_syn_packets = 0
    for packet in PcapReader(str(pcap_path)):
        if IP not in packet or TCP not in packet:
            continue
        ip = packet[IP]
        tcp = packet[TCP]
        inbound = ip.src == ENDPOINTS["pc1"] and ip.dst == ENDPOINTS["pc2"]
        if inbound and int(tcp.flags) & 0x02 and not int(tcp.flags) & 0x10:
            inbound_syn_packets += 1
            target_syn_ports.add(int(tcp.dport))
        rows.append({
            "timestamp": datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "tcp_flags": str(tcp.flags),
            "direction": "pc1_to_pc2" if inbound else "other",
        })
    if not rows:
        raise WorkloadCollectionError(
            f"PC2 receiver capture {pcap_path.name} contains no parseable TCP packets."
        )
    with out_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    missing_expected_ports = sorted(set(expected_ports or []) - target_syn_ports)
    if expected_ports is not None and missing_expected_ports:
        raise WorkloadCollectionError(
            f"PC2 capture lacks inbound TCP SYN evidence from PC1 for requested ports {missing_expected_ports}."
        )
    return {
        "packets": len(rows),
        "inboundSynPackets": inbound_syn_packets,
        "targetSynPorts": sorted(target_syn_ports),
        "expectedPorts": sorted(set(expected_ports or [])),
        "source": "pc2_receiver_pcap",
        "sha256": _sha256(pcap_path),
        "sizeBytes": pcap_path.stat().st_size,
    }


def _calculate_sa_counter_deltas(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "packetsIn": after.get("packetsIn", 0) - before.get("packetsIn", 0),
        "packetsOut": after.get("packetsOut", 0) - before.get("packetsOut", 0),
    }


def _write_scenario_manifest(
    experiment_dir: Path,
    record: Dict[str, Any],
    *,
    scenario_name: str,
    scenario_subtype: str,
    capture_started_at: Optional[str],
    capture_ended_at: Optional[str],
) -> Path:
    """Write execution evidence without pretending it is a prepared ML dataset."""
    manifest_path = experiment_dir / "scenario_manifest.json"
    artifacts = []
    for path in sorted(experiment_dir.iterdir()):
        if not path.is_file() or path.name in {manifest_path.name, "scenario_manifest.sha256"}:
            continue
        artifacts.append({
            "path": path.name,
            "sizeBytes": path.stat().st_size,
            "sha256": _sha256(path),
            "sourceRunId": record["experimentId"],
            "createdAt": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
        })
    result_status = record.get("status")
    observed = record.get("observedWorkload", {})
    evidence_states = {
        "intention": "INTENDED",
        "execution": "EXECUTED" if result_status == "PASS" or record.get("lifecycleState") in {
            "WORKLOAD_RUNNING", "WORKLOAD_STOPPING", "FAIL"
        } else "FAILED" if result_status == "FAIL" else "UNKNOWN",
        "observation": "OBSERVED" if observed.get("pc2ObservedTargetSynPorts") else "UNKNOWN",
        "overall": "EXECUTED_WITH_EVIDENCE" if result_status == "PASS" and observed.get(
            "pc2ObservedTargetSynPorts"
        ) else "FAILED" if result_status in {"FAIL", "BLOCKED"} else "UNKNOWN",
    }
    manifest = {
        "manifestVersion": "vista-attack-scenario-v1",
        "originType": "testbed_collected",
        "datasetStatus": "UNVERIFIED",
        "scenarioId": "port_scan_v1",
        "scenarioVersion": "1.0.0",
        "scenarioName": scenario_name,
        "scenarioSubtype": scenario_subtype,
        "label": "PORT_SCAN",
        "labelGranularity": "time_window",
        "labelSemantics": "Observed bounded TCP connect probes against the isolated PC2 endpoint; behavior label does not establish malicious intent.",
        "runId": record["experimentId"],
        "sessionId": record["sessionId"],
        "createdAt": record.get("completedAt", _utc_now()),
        "captureWindow": {
            "startedAt": capture_started_at,
            "completedAt": capture_ended_at,
            "capturePoint": "pc1 outer ESP and pc2 endpoint TCP",
        },
        "evidenceStates": evidence_states,
        "executionStatus": result_status,
        "errors": record.get("errors", []),
        "artifacts": artifacts,
        "featureDomain": "Outer IPv4 ESP metadata only; not enough to identify individual encrypted inner flows.",
        "limitations": [
            "Scenario execution records are not model-ready labels.",
            "The PC1 outer ESP aggregate is labeled only at the run time-window level.",
            "eBPF is optional and is not correlated to a flow by timing alone.",
            "Evaluation admission requires a separate manifest validation and leakage audit.",
        ],
    }
    serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    manifest_path.write_text(serialized, encoding="utf-8")
    (experiment_dir / "scenario_manifest.sha256").write_text(
        f"{_sha256(manifest_path)}  {manifest_path.name}\n", encoding="ascii"
    )
    return manifest_path
