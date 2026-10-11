from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.inet import TCP
from scapy.layers.ipsec import ESP
from scapy.utils import PcapReader

from backend.services import vpn_testbed


COLLECTION_ROOT = vpn_testbed.CAPTURE_ROOT / "collections"
CONTAINERS = ("pc1", "pc2")
ENDPOINTS = {"pc1": "172.20.0.2", "pc2": "172.20.0.3"}
MAX_PROFILES = 20
MAX_PACKETS = 100


class WorkloadCollectionError(RuntimeError):
    pass


def validate_icmp_profiles(profiles: Any) -> list[dict[str, Any]]:
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("profiles must be a non-empty list of bounded ICMP profile objects.")
    if len(profiles) > MAX_PROFILES:
        raise ValueError(f"At most {MAX_PROFILES} ICMP workload profiles may be requested.")
    validated: list[dict[str, Any]] = []
    total_packets = 0
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict) or set(profile) != {
            "count", "interval_seconds", "payload_bytes"
        }:
            raise ValueError(
                f"profiles[{index}] must contain only count, interval_seconds, and payload_bytes."
            )
        count = profile["count"]
        payload = profile["payload_bytes"]
        interval = profile["interval_seconds"]
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_PACKETS:
            raise ValueError(f"profiles[{index}].count must be an integer in [1, {MAX_PACKETS}].")
        if isinstance(payload, bool) or not isinstance(payload, int) or not 16 <= payload <= 1400:
            raise ValueError(f"profiles[{index}].payload_bytes must be an integer in [16, 1400].")
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 0.1 <= interval <= 2.0:
            raise ValueError(f"profiles[{index}].interval_seconds must be in [0.1, 2.0].")
        total_packets += count
        if total_packets > MAX_PACKETS:
            raise ValueError(f"The profile sequence may request at most {MAX_PACKETS} packets.")
        validated.append({
            "count": count,
            "interval_seconds": float(interval),
            "payload_bytes": payload,
        })
    return validated


def validate_tcp_profiles(profiles: Any) -> list[dict[str, Any]]:
    return validate_icmp_profiles(profiles)


def validate_http_profiles(profiles: Any) -> list[dict[str, Any]]:
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("profiles must be a non-empty list of bounded HTTP profile objects.")
    if len(profiles) > MAX_PROFILES:
        raise ValueError(f"At most {MAX_PROFILES} HTTP workload profiles may be requested.")
    validated: list[dict[str, Any]] = []
    total_requests = 0
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            raise ValueError(f"profiles[{index}] must be a JSON object.")
        unknown = sorted(
            set(profile) - {"count", "interval_seconds", "path", "method", "payload_bytes", "expected_status"}
        )
        if unknown:
            raise ValueError(f"profiles[{index}] has unknown fields: {unknown}")
        count = profile.get("count", 1)
        interval = profile.get("interval_seconds", 0.2)
        path = profile.get("path", "/")
        method = profile.get("method", "GET")
        payload = profile.get("payload_bytes", 0)
        expected_status = profile.get("expected_status", 200)

        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_PACKETS:
            raise ValueError(f"profiles[{index}].count must be an integer in [1, {MAX_PACKETS}].")
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 0.1 <= interval <= 2.0:
            raise ValueError(f"profiles[{index}].interval_seconds must be in [0.1, 2.0].")
        if not isinstance(path, str) or not re.fullmatch(r"/[a-zA-Z0-9_\-\./]*", path) or ".." in path or len(path) > 128:
            raise ValueError(f"profiles[{index}].path must be a valid path starting with '/' and at most 128 chars.")
        if method not in {"GET", "POST", "HEAD"}:
            raise ValueError(f"profiles[{index}].method must be 'GET', 'POST', or 'HEAD'.")
        if isinstance(payload, bool) or not isinstance(payload, int) or not 0 <= payload <= 1400:
            raise ValueError(f"profiles[{index}].payload_bytes must be an integer in [0, 1400].")
        if isinstance(expected_status, bool) or not isinstance(expected_status, int) or not 100 <= expected_status <= 599:
            raise ValueError(f"profiles[{index}].expected_status must be a valid HTTP status code integer in [100, 599].")
        total_requests += count
        if total_requests > MAX_PACKETS:
            raise ValueError(f"The profile sequence may request at most {MAX_PACKETS} requests.")
        validated.append({
            "count": count,
            "interval_seconds": float(interval),
            "path": path,
            "method": method,
            "payload_bytes": payload,
            "expected_status": expected_status,
        })
    return validated


def validate_rtp_profiles(profiles: Any) -> list[dict[str, Any]]:
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("profiles must be a non-empty list of bounded RTP profile objects.")
    if len(profiles) > MAX_PROFILES:
        raise ValueError(f"At most {MAX_PROFILES} RTP workload profiles may be requested.")
    validated: list[dict[str, Any]] = []
    total_packets = 0
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            raise ValueError(f"profiles[{index}] must be a JSON object.")
        unknown = sorted(
            set(profile) - {"count", "interval_seconds", "payload_bytes", "ssrc", "payload_type", "start_sequence"}
        )
        if unknown:
            raise ValueError(f"profiles[{index}] has unknown fields: {unknown}")
        count = profile.get("count", 10)
        interval = profile.get("interval_seconds", 0.02)
        payload = profile.get("payload_bytes", 160)
        ssrc = profile.get("ssrc", 0x12345678)
        payload_type = profile.get("payload_type", 0)
        start_seq = profile.get("start_sequence", 1000)

        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_PACKETS:
            raise ValueError(f"profiles[{index}].count must be an integer in [1, {MAX_PACKETS}].")
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 0.01 <= interval <= 1.0:
            raise ValueError(f"profiles[{index}].interval_seconds must be in [0.01, 1.0].")
        if isinstance(payload, bool) or not isinstance(payload, int) or not 16 <= payload <= 1400:
            raise ValueError(f"profiles[{index}].payload_bytes must be an integer in [16, 1400].")
        if isinstance(ssrc, bool) or not isinstance(ssrc, int) or not 0 <= ssrc <= 0xFFFFFFFF:
            raise ValueError(f"profiles[{index}].ssrc must be an unsigned 32-bit integer.")
        if isinstance(payload_type, bool) or not isinstance(payload_type, int) or not 0 <= payload_type <= 127:
            raise ValueError(f"profiles[{index}].payload_type must be an integer in [0, 127].")
        if isinstance(start_seq, bool) or not isinstance(start_seq, int) or not 0 <= start_seq <= 65535:
            raise ValueError(f"profiles[{index}].start_sequence must be an integer in [0, 65535].")
        total_packets += count
        if total_packets > MAX_PACKETS:
            raise ValueError(f"The profile sequence may request at most {MAX_PACKETS} packets.")
        validated.append({
            "count": count,
            "interval_seconds": float(interval),
            "payload_bytes": payload,
            "ssrc": ssrc,
            "payload_type": payload_type,
            "start_sequence": start_seq,
        })
    return validated


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_docker(*args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [vpn_testbed._docker_path(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _require_success(result: subprocess.CompletedProcess[str], operation: str) -> str:
    if result.returncode != 0:
        raise WorkloadCollectionError(
            f"{operation} failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip() or 'no output'}"
        )
    return result.stdout.strip()


def _read_live_sa(container: str) -> dict[str, Any]:
    output = _require_success(
        _run_docker("exec", container, "swanctl", "--list-sas", "--raw"),
        f"Reading {container} StrongSwan SA state",
    )
    parsed = vpn_testbed._parse_sas_output(output)
    if not parsed.get("established") or parsed.get("child", {}).get("state") != "INSTALLED":
        raise WorkloadCollectionError(f"{container} has no established IKE_SA and installed CHILD_SA.")
    child = parsed["child"]
    if child.get("mode") != "TUNNEL":
        raise WorkloadCollectionError(
            f"{container} CHILD_SA is {child.get('mode')!r}; this collector currently verifies tunnel mode only."
        )
    return parsed


def reestablish_collection_sa() -> dict[str, Any]:
    before = {name: _read_live_sa(name) for name in CONTAINERS}
    for name, parsed in before.items():
        if parsed.get("raw", "").count("list-sa event") != 1:
            raise WorkloadCollectionError(
                f"Refusing to re-establish {name}: expected exactly one VISTA testbed IKE_SA."
            )
        identity = _sa_lifecycle_identity(parsed)
        if identity.get("connection") != "pc1-pc2":
            raise WorkloadCollectionError(
                f"Refusing to re-establish unexpected {name} connection "
                f"{identity.get('connection')!r}."
            )
    previous = _sa_lifecycle_identity(before["pc1"])
    vpn_testbed._terminate_test_connection()
    initiated = vpn_testbed._establish_sas()
    after = {name: _read_live_sa(name) for name in CONTAINERS}
    new_identity = _sa_lifecycle_identity(after["pc1"])
    if (
        _sa_lifecycle_identity(after["pc2"])["ikeSaIdentitySha256"]
        != new_identity["ikeSaIdentitySha256"]
    ):
        raise WorkloadCollectionError("The endpoints report different new IKE_SA identities.")
    if new_identity["ikeSaIdentitySha256"] == previous["ikeSaIdentitySha256"]:
        raise WorkloadCollectionError(
            "IKE_SA SPI identity did not change after terminate-and-reinit."
        )
    if not initiated.get("established") or initiated.get("child", {}).get("state") != "INSTALLED":
        raise WorkloadCollectionError(
            "StrongSwan initiate did not establish the expected IKE_SA and CHILD_SA."
        )
    return {
        "previousIkeSaIdentitySha256": previous["ikeSaIdentitySha256"],
        "newIkeSaIdentitySha256": new_identity["ikeSaIdentitySha256"],
        "reestablishedAt": _utc_now(),
        "newIkeSaAgeSeconds": new_identity["ikeSaAgeSeconds"],
        "connection": new_identity["connection"],
    }


def _safe_sa_evidence(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "established": parsed.get("established"),
        "ike": parsed.get("ike", {}),
        "child": parsed.get("child", {}),
        "pfs": parsed.get("pfs"),
    }


def _sa_lifecycle_identity(parsed: dict[str, Any]) -> dict[str, Any]:
    raw = parsed.get("raw", "")
    ike_match = re.search(
        r"initiator-spi=([0-9a-fA-F]+)\s+responder-spi=([0-9a-fA-F]+)",
        raw,
    )
    established_match = re.search(r"\bestablished=(\d+)\b", raw)
    if not ike_match or not established_match:
        raise WorkloadCollectionError(
            "Machine-readable SA output lacks IKE SPI or established-age evidence."
        )
    identity_material = ":".join(value.lower() for value in ike_match.groups())
    identity = hashlib.sha256(identity_material.encode("ascii")).hexdigest()
    return {
        "ikeSaIdentitySha256": identity,
        "ikeSaAgeSeconds": int(established_match.group(1)),
        "connection": re.search(r"list-sa event\s*\{\s*([^\s{]+)", raw).group(1)
        if re.search(r"list-sa event\s*\{\s*([^\s{]+)", raw)
        else None,
    }


def _validate_session_context(
    context: Any,
    sa_identity: dict[str, Any],
    started_at: str,
) -> dict[str, Any]:
    if context is None:
        return {
            "independenceStatus": "UNVERIFIED",
            "reason": "No observed terminate-and-reinit SA lifecycle was supplied.",
        }
    if not isinstance(context, dict) or set(context) != {
        "previousIkeSaIdentitySha256",
        "reestablishedAt",
    }:
        raise ValueError(
            "sessionContext must contain previousIkeSaIdentitySha256 and reestablishedAt."
        )
    previous_identity = context["previousIkeSaIdentitySha256"]
    if not isinstance(previous_identity, str) or not re.fullmatch(
        r"[0-9a-f]{64}", previous_identity
    ):
        raise ValueError("sessionContext previous SA identity must be a SHA-256 digest.")
    try:
        reestablished_at = datetime.fromisoformat(
            str(context["reestablishedAt"]).replace("Z", "+00:00")
        )
        session_started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("sessionContext reestablishedAt must be a timezone-aware timestamp.") from exc
    if reestablished_at.tzinfo is None or session_started.tzinfo is None:
        raise ValueError("sessionContext timestamps must include timezone information.")
    delay = (session_started - reestablished_at).total_seconds()
    if not 0 <= delay <= 60:
        raise ValueError(
            "The new SA must be observed within 60 seconds of the recorded re-establishment."
        )
    if previous_identity == sa_identity["ikeSaIdentitySha256"]:
        raise WorkloadCollectionError(
            "The negotiated IKE_SA identity did not change after re-establishment."
        )
    if sa_identity["ikeSaAgeSeconds"] > 60:
        raise WorkloadCollectionError(
            "The negotiated IKE_SA is older than 60 seconds and cannot verify a fresh session."
        )
    return {
        "independenceStatus": "VERIFIED_DISTINCT_IKE_SA",
        "previousIkeSaIdentitySha256": previous_identity,
        "ikeSaIdentitySha256": sa_identity["ikeSaIdentitySha256"],
        "reestablishedAt": reestablished_at.isoformat(),
        "observedWithinSeconds": delay,
    }


def _write_session_record(
    experiment_dir: Path,
    *,
    session_id: str,
    experiment_id: str,
    started_at: str,
    completed_at: str,
    containers: dict[str, dict[str, Any]],
    source: dict[str, Any],
    strong_swan_version: str,
    sa: dict[str, Any],
    session_context: Any,
) -> Path:
    identity = _sa_lifecycle_identity(sa)
    independence = _validate_session_context(session_context, identity, started_at)
    shared_path = experiment_dir.parent / "session_record.json"
    if shared_path.exists():
        existing = json.loads(shared_path.read_text(encoding="utf-8"))
        if existing.get("sessionId") != session_id:
            raise WorkloadCollectionError(
                "Existing session record does not match the requested session ID."
            )
        previous_identity = existing.get("vpnLifecycle", {}).get(
            "ikeSaIdentitySha256"
        )
        if previous_identity != identity["ikeSaIdentitySha256"]:
            raise WorkloadCollectionError(
                "IKE_SA changed within one collection session; use a new session ID."
            )
        prior_context = existing.get("vpnLifecycle", {}).get("reestablishment", {})
        stable_context_keys = (
            "independenceStatus",
            "previousIkeSaIdentitySha256",
            "ikeSaIdentitySha256",
            "reestablishedAt",
            "reason",
        )
        if any(prior_context.get(key) != independence.get(key) for key in stable_context_keys):
            raise WorkloadCollectionError(
                "Session re-establishment evidence changed within one collection session."
            )
        session_started_at = existing["sessionStartedAt"]
    else:
        session_started_at = (
            independence.get("reestablishedAt")
            if independence.get("independenceStatus") == "VERIFIED_DISTINCT_IKE_SA"
            else started_at
        )
    try:
        started = datetime.fromisoformat(
            session_started_at.replace("Z", "+00:00")
        )
        completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorkloadCollectionError("Session lifecycle timestamps are invalid.") from exc
    if started.tzinfo is None or completed.tzinfo is None:
        raise WorkloadCollectionError("Session lifecycle timestamps must be timezone-aware.")
    experiment_ids = sorted({
        path.parent.name
        for path in experiment_dir.parent.glob("*/collection_result.json")
    } | {experiment_id})
    record = {
        "sessionId": session_id,
        "sessionIdSource": "locally generated UUIDv4 or caller-supplied UUIDv4 recorded by this collector",
        "sessionStartedAt": started.isoformat(),
        "sessionObservedThroughAt": completed.isoformat(),
        "sessionScope": "One IKE_SA lifecycle on the direct PC1-PC2 testbed; container infrastructure may be reused.",
        "experimentIds": experiment_ids,
        "containerIds": {
            name: value["containerId"] for name, value in containers.items()
        },
        "containerImageIds": {
            name: value["imageId"] for name, value in containers.items()
        },
        "ipv4Addresses": {
            name: value["ipv4Address"] for name, value in containers.items()
        },
        "containerInfrastructureReused": True,
        "repositoryRevision": source["repositoryRevision"],
        "worktreeDirty": source["worktreeDirty"],
        "strongSwanVersion": strong_swan_version,
        "vpnLifecycle": {
            **identity,
            "reestablishment": independence,
            "independenceBasis": (
                "different observed IKE SPI pair after explicit termination and re-initiation"
                if independence.get("independenceStatus") == "VERIFIED_DISTINCT_IKE_SA"
                else independence["reason"]
            ),
        },
    }
    session_path = experiment_dir / "session_record.json"
    session_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if not shared_path.exists():
        shared_path.write_bytes(session_path.read_bytes())
    return session_path


def _capture_remote_paths(token: str) -> dict[str, str]:
    remote = f"/tmp/vista-{token}"
    return {
        "base": remote,
        "pcap": f"{remote}.pcap",
        "log": f"{remote}.log",
        "pid": f"{remote}.pid",
        "exit": f"{remote}.exit",
    }


def _validate_closed_pcap(path: Path) -> int:
    if not path.is_file():
        raise WorkloadCollectionError(f"Completed PCAP is missing: {path.name}.")
    if path.stat().st_size < 24:
        raise WorkloadCollectionError(
            f"Completed PCAP is empty or truncated (only {path.stat().st_size} bytes)."
        )
    try:
        with path.open("rb") as stream:
            global_header = stream.read(24)
            if len(global_header) != 24:
                raise ValueError("truncated global header")
            byte_order = {
                b"\xd4\xc3\xb2\xa1": "<",
                b"\x4d\x3c\xb2\xa1": "<",
                b"\xa1\xb2\xc3\xd4": ">",
                b"\xa1\xb2\x3c\x4d": ">",
            }.get(global_header[:4])
            if byte_order is None:
                raise ValueError("unsupported PCAP magic")
            major, minor, _zone, _accuracy, snaplen, _link_type = struct.unpack(
                f"{byte_order}HHIIII", global_header[4:]
            )
            if (major, minor) != (2, 4) or snaplen == 0:
                raise ValueError("invalid PCAP version or snapshot length")
            packet_count = 0
            while True:
                packet_header = stream.read(16)
                if not packet_header:
                    break
                if len(packet_header) != 16:
                    raise ValueError("truncated packet header")
                _seconds, _fraction, captured_length, original_length = struct.unpack(
                    f"{byte_order}IIII", packet_header
                )
                if (
                    captured_length > snaplen
                    or captured_length > original_length
                    or captured_length == 0
                ):
                    raise ValueError("invalid packet length")
                if len(stream.read(captured_length)) != captured_length:
                    raise ValueError("truncated packet payload")
                packet_count += 1
    except (OSError, EOFError, ValueError) as exc:
        raise WorkloadCollectionError(
            f"Completed PCAP is unreadable or truncated: {exc}"
        ) from exc
    if packet_count == 0:
        raise WorkloadCollectionError("Completed PCAP contains no readable packets.")
    return packet_count


def _start_capture(container: str, token: str, workload_filter: str = "icmp") -> None:
    if workload_filter not in {"icmp", "tcp", "udp"}:
        raise ValueError("Only bounded ICMP, TCP, and UDP collection capture filters are supported.")
    paths = _capture_remote_paths(token)
    capture_filter = f"{workload_filter} or esp or udp port 4500"
    command = (
        f"rm -f {paths['pcap']} {paths['log']} {paths['pid']} {paths['exit']}; "
        f"(tcpdump --immediate-mode -n -i eth0 -U -w {paths['pcap']} '{capture_filter}' "
        f">{paths['log']} 2>&1 & child=$!; "
        f"printf '%s\\n' \"$child\" >{paths['pid']}; "
        f"wait \"$child\"; rc=$?; printf '%s\\n' \"$rc\" >{paths['exit']}; "
        f"exit \"$rc\") </dev/null >/dev/null 2>&1 &"
    )
    _require_success(
        _run_docker("exec", container, "sh", "-c", command),
        f"Starting {container} {workload_filter.upper()} capture",
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        log = _run_docker("exec", container, "cat", paths["log"])
        pid_result = _run_docker("exec", container, "cat", paths["pid"])
        exit_result = _run_docker("exec", container, "cat", paths["exit"])
        if exit_result.returncode == 0:
            raise WorkloadCollectionError(
                f"{container} tcpdump exited before capture readiness "
                f"(exit {exit_result.stdout.strip()}): {log.stdout.strip()}"
            )
        pid = pid_result.stdout.strip()
        if (
            log.returncode == 0
            and "listening on eth0" in log.stdout.lower()
            and re.fullmatch(r"[0-9]+", pid)
        ):
            process = _run_docker(
                "exec", container, "sh", "-c", f"kill -0 {pid}"
            )
            pcap_size = _run_docker(
                "exec", container, "wc", "-c", paths["pcap"]
            )
            size_match = re.match(r"\s*(\d+)", pcap_size.stdout)
            if (
                process.returncode == 0
                and pcap_size.returncode == 0
                and size_match
                and int(size_match.group(1)) >= 24
            ):
                time.sleep(0.05)
                return
        if log.returncode == 0 and "tcpdump:" in log.stdout.lower() and (
            "error" in log.stdout.lower() or "failed" in log.stdout.lower()
        ):
            raise WorkloadCollectionError(
                f"{container} tcpdump failed to start: {log.stdout.strip()}"
            )
        time.sleep(0.1)
    raise WorkloadCollectionError(
        f"{container} tcpdump did not reach live capture readiness within ten seconds."
    )


def _copy_remote_capture_file(
    container: str,
    remote_path: str,
    destination: Path,
    operation: str,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    copied = subprocess.run(
        [vpn_testbed._docker_path(), "cp", f"{container}:{remote_path}", str(destination)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    _require_success(copied, operation)


def _wait_for_capture_dispatch(container: str, token: str) -> int:
    paths = _capture_remote_paths(token)
    pid = _require_success(
        _run_docker("exec", container, "cat", paths["pid"]),
        f"Reading {container} tcpdump process ID before flush",
    )
    if not re.fullmatch(r"[0-9]+", pid):
        raise WorkloadCollectionError(f"{container} tcpdump process ID was malformed.")
    _require_success(
        _run_docker("exec", container, "sh", "-c", f"kill -USR1 {pid}"),
        f"Requesting {container} tcpdump packet-dispatch statistics",
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        log = _run_docker("exec", container, "cat", paths["log"])
        matches = re.findall(r"(\d+)\s+packets captured", log.stdout, re.IGNORECASE)
        if log.returncode == 0 and matches:
            count = int(matches[-1])
            if count > 0:
                return count
        process = _run_docker("exec", container, "sh", "-c", f"kill -0 {pid}")
        if process.returncode != 0:
            raise WorkloadCollectionError(
                f"{container} tcpdump exited before dispatching any captured packets."
            )
        time.sleep(0.1)
        _run_docker("exec", container, "sh", "-c", f"kill -USR1 {pid}")
    log = _run_docker("exec", container, "cat", paths["log"])
    raise WorkloadCollectionError(
        f"{container} tcpdump did not dispatch captured packets within ten seconds: "
        f"{log.stdout.strip() or 'no tcpdump diagnostics'}"
    )


def _stop_capture(
    container: str,
    token: str,
    destination: Path,
    *,
    minimum_packets: int = 1,
) -> dict[str, Any]:
    paths = _capture_remote_paths(token)
    pid_output = _require_success(
        _run_docker("exec", container, "cat", paths["pid"]),
        f"Reading {container} tcpdump process ID",
    )
    if not re.fullmatch(r"[0-9]+", pid_output):
        raise WorkloadCollectionError(f"{container} tcpdump process ID was malformed.")
    dispatched_packets = _wait_for_capture_dispatch(container, token)
    _require_success(
        _run_docker("exec", container, "sh", "-c", f"kill -INT {pid_output}"),
        f"Gracefully stopping {container} tcpdump",
    )
    deadline = time.monotonic() + 15
    exit_status = None
    while time.monotonic() < deadline:
        exit_result = _run_docker("exec", container, "cat", paths["exit"])
        if exit_result.returncode == 0:
            exit_text = exit_result.stdout.strip()
            if not re.fullmatch(r"-?[0-9]+", exit_text):
                raise WorkloadCollectionError(
                    f"{container} tcpdump wrote malformed exit status {exit_text!r}."
                )
            exit_status = int(exit_text)
            break
        time.sleep(0.1)
    if exit_status is None:
        raise WorkloadCollectionError(
            f"{container} tcpdump did not exit and flush within fifteen seconds."
        )
    if exit_status != 0:
        log = _run_docker("exec", container, "cat", paths["log"])
        raise WorkloadCollectionError(
            f"{container} tcpdump exited with status {exit_status}: "
            f"{log.stdout.strip() or 'no tcpdump diagnostics'}"
        )
    _run_docker("exec", container, "sync")
    _copy_remote_capture_file(
        container,
        paths["pcap"],
        destination,
        f"Retrieving completed {container} PCAP",
    )
    packet_count = _validate_closed_pcap(destination)
    if packet_count < minimum_packets:
        raise WorkloadCollectionError(
            f"{container} PCAP has {packet_count} packets; expected at least {minimum_packets}."
        )
    log = _run_docker("exec", container, "cat", paths["log"])
    if log.returncode != 0:
        raise WorkloadCollectionError(
            f"Reading completed {container} tcpdump diagnostics failed: "
            f"{log.stderr.strip() or log.returncode}"
        )
    diagnostic_path = destination.parent / f"{container}_tcpdump.log"
    diagnostic_path.write_text(log.stdout.strip() + "\n", encoding="utf-8")
    _require_success(
        _run_docker(
            "exec", container, "rm", "-f",
            paths["pcap"], paths["log"], paths["pid"], paths["exit"],
        ),
        f"Cleaning completed {container} capture files",
    )
    return {
        "packetCount": packet_count,
        "packetsDispatchedBeforeStop": dispatched_packets,
        "exitCode": exit_status,
        "tcpdumpLog": log.stdout.strip(),
        "diagnosticLogPath": str(diagnostic_path),
        "path": str(destination),
    }


def _preserve_capture_artifacts(
    container: str,
    token: str,
    destination: Path,
    diagnostic_path: Path,
) -> dict[str, str]:
    paths = _capture_remote_paths(token)
    preserved: dict[str, str] = {}
    for key, target in (("pcap", destination), ("log", diagnostic_path)):
        if target.exists():
            preserved[key] = str(target)
            continue
        copied = subprocess.run(
            [vpn_testbed._docker_path(), "cp", f"{container}:{paths[key]}", str(target)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if copied.returncode == 0 and target.is_file():
            preserved[key] = str(target)
    return preserved


def _cleanup_capture(container: str, token: str) -> None:
    paths = _capture_remote_paths(token)
    pid = _run_docker("exec", container, "cat", paths["pid"])
    if pid.returncode == 0 and re.fullmatch(r"[0-9]+", pid.stdout.strip()):
        capture_pid = pid.stdout.strip()
        _run_docker(
            "exec", container, "kill", "-INT", capture_pid
        )
        deadline = time.monotonic() + 5
        stopped = False
        while time.monotonic() < deadline:
            exited = _run_docker("exec", container, "cat", paths["exit"])
            if exited.returncode == 0:
                stopped = True
                break
            alive = _run_docker("exec", container, "kill", "-0", capture_pid)
            if alive.returncode != 0:
                stopped = True
                break
            time.sleep(0.1)
        if not stopped:
            _run_docker("exec", container, "kill", "-KILL", capture_pid)
            verify_deadline = time.monotonic() + 1
            while time.monotonic() < verify_deadline:
                if _run_docker("exec", container, "kill", "-0", capture_pid).returncode != 0:
                    stopped = True
                    break
                time.sleep(0.05)
        if not stopped:
            raise WorkloadCollectionError(
                f"Unable to confirm capture process {capture_pid} stopped on {container}."
            )
    _require_success(_run_docker(
        "exec", container, "rm", "-f",
        paths["pid"], paths["exit"],
    ), f"Removing {container} capture process records")


def _set_lifecycle_state(record: dict[str, Any], state: str) -> None:
    record["lifecycleState"] = state
    record.setdefault("lifecycle", []).append({
        "state": state,
        "at": _utc_now(),
    })


def _generate_packet_table(
    pcap_path: Path,
    csv_path: Path,
    protocol_family: str = "ESP",
) -> dict[str, int]:
    if protocol_family not in {"ESP", "ICMP", "TCP", "UDP"}:
        raise ValueError("Packet tables are supported only for outer ESP, ICMP, TCP, and UDP.")
    requests = replies = 0
    rows: list[dict[str, Any]] = []
    for packet in PcapReader(str(pcap_path)):
        if IP not in packet:
            continue
        ip = packet[IP]
        if protocol_family == "ESP":
            src_port = dst_port = 0
            is_esp = int(ip.proto) == 50 or ESP in packet
            if UDP in packet and (
                int(packet[UDP].sport) == 4500 or int(packet[UDP].dport) == 4500
            ):
                esp_payload = bytes(packet[UDP].payload)
                is_esp = len(esp_payload) >= 8 and esp_payload[:4] != b"\x00\x00\x00\x00"
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            if not is_esp:
                continue
        elif protocol_family == "ICMP":
            if ICMP not in packet or int(ip.proto) != 1:
                continue
            src_port = dst_port = 0
            requests += int(int(packet[ICMP].type) == 8)
            replies += int(int(packet[ICMP].type) == 0)
        elif protocol_family == "TCP":
            if TCP not in packet or int(ip.proto) != 6:
                continue
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        else: # UDP
            if UDP not in packet or int(ip.proto) != 17:
                continue
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        rows.append({
            "timestamp": datetime.fromtimestamp(
                float(packet.time), timezone.utc
            ).isoformat(),
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol_family,
            "protocol_family": protocol_family,
            "packet_length": int(ip.len or len(ip)),
        })
    if not rows:
        raise WorkloadCollectionError(
            f"PC1 capture contains no readable IPv4 {protocol_family} packets."
        )
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return {
        "echoRequests": requests,
        "echoReplies": replies,
        "icmpPackets": len(rows) if protocol_family == "ICMP" else 0,
        "tcpPackets": len(rows) if protocol_family == "TCP" else 0,
        "udpPackets": len(rows) if protocol_family == "UDP" else 0,
        "espPackets": len(rows) if protocol_family == "ESP" else 0,
        "ipv4Bytes": sum(row["packet_length"] for row in rows),
    }


def _count_pc1_esp(pcap_path: Path) -> int:
    count = 0
    for packet in PcapReader(str(pcap_path)):
        if IP in packet and (int(packet[IP].proto) == 50 or ESP in packet):
            count += 1
        elif UDP in packet and int(packet[UDP].dport) == 4500:
            payload = bytes(packet[UDP].payload)
            if payload and payload[:4] != b"\x00\x00\x00\x00":
                count += 1
    return count


def _run_ping(profile: dict[str, Any]) -> dict[str, Any]:
    timeout = profile["count"] * (profile["interval_seconds"] + 1.2) + 5
    args = [
        "exec", "pc1", "ping", "-n",
        "-c", str(profile["count"]),
        "-W", "1",
        "-s", str(profile["payload_bytes"]),
        "-i", f"{profile['interval_seconds']:g}",
        ENDPOINTS["pc2"],
    ]
    started = time.monotonic()
    try:
        result = _run_docker(*args, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise WorkloadCollectionError("ICMP workload exceeded its bounded execution timeout.") from exc
    elapsed = time.monotonic() - started
    match = re.search(
        r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", result.stdout
    )
    if not match:
        raise WorkloadCollectionError(
            f"Could not parse sender ICMP counters: {result.stderr.strip() or result.stdout.strip()}"
        )
    return {
        "requested": profile,
        "packetsSent": int(match.group(1)),
        "packetsReceived": int(match.group(2)),
        "durationSeconds": elapsed,
        "exitCode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _inspect_container(container: str) -> dict[str, str]:
    result = _run_docker(
        "inspect", "--format",
        "{{.Id}}|{{.State.Status}}|{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}|{{.Image}}|{{.Config.Image}}",
        container,
    )
    value = _require_success(result, f"Inspecting {container}")
    fields = value.split("|")
    if len(fields) != 5 or fields[1] != "running" or fields[2] != ENDPOINTS[container]:
        raise WorkloadCollectionError(
            f"{container} is not the expected running endpoint ({ENDPOINTS[container]})."
        )
    return {
        "containerId": fields[0],
        "state": fields[1],
        "ipv4Address": fields[2],
        "imageId": fields[3],
        "imageReference": fields[4],
    }


def _source_provenance() -> dict[str, Any]:
    root = vpn_testbed.ROOT_DIR
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if revision.returncode != 0:
        raise WorkloadCollectionError(
            f"Unable to record repository revision: {revision.stderr.strip()}"
        )
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if status.returncode != 0:
        raise WorkloadCollectionError(
            f"Unable to record repository worktree state: {status.stderr.strip()}"
        )
    return {
        "repositoryRevision": revision.stdout.strip(),
        "worktreeDirty": bool(status.stdout.strip()),
    }


def _run_session_dataset_validation(
    experiment_dir: Path,
    session_id: str,
    current_manifest_path: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    session_dir = experiment_dir.parent
    observations_by_id: dict[str, dict[str, Any]] = {}
    for result_path in session_dir.glob("*/collection_result.json"):
        if result_path.parent == experiment_dir:
            continue
        try:
            result_record = json.loads(result_path.read_text(encoding="utf-8"))
            if result_record.get("status") != "PASS":
                continue
            previous_manifest = result_path.parent / "experiment_manifest.json"
            manifest_data = json.loads(previous_manifest.read_text(encoding="utf-8"))
            observation = json.loads(json.dumps(manifest_data["observations"][0]))
            if (
                observation.get("session_id") != session_id
                or observation.get("capture", {}).get("protocol_family") != "ESP"
            ):
                continue
            for section, keys in (
                ("capture", ("path", "raw_pcap_path")),
                ("ground_truth", ("record_path",)),
                ("workload", ("measurement_path",)),
                ("vpn", ("negotiated_sa_evidence_path",)),
            ):
                for key in keys:
                    if key in observation[section]:
                        observation[section][key] = (
                            f"{result_path.parent.name}/{observation[section][key]}"
                        )
            observation["session_record_path"] = (
                f"{result_path.parent.name}/session_record.json"
            )
            observations_by_id[observation["experiment_id"]] = observation
        except (OSError, KeyError, json.JSONDecodeError):
            continue

    current_manifest = json.loads(current_manifest_path.read_text(encoding="utf-8"))
    observation = json.loads(json.dumps(current_manifest["observations"][0]))
    for section, keys in (
        ("capture", ("path", "raw_pcap_path")),
        ("ground_truth", ("record_path",)),
        ("workload", ("measurement_path",)),
        ("vpn", ("negotiated_sa_evidence_path",)),
    ):
        for key in keys:
            if key in observation[section]:
                observation[section][key] = f"{experiment_dir.name}/{observation[section][key]}"
    observation["session_record_path"] = (
        f"{experiment_dir.name}/session_record.json"
    )
    observations_by_id[observation["experiment_id"]] = observation

    snapshot_id = uuid.uuid4().hex
    snapshot_manifest_path = session_dir / f"dataset_manifest_{snapshot_id}.json"
    snapshot = {
        "manifest_version": current_manifest["manifest_version"],
        "dataset_id": f"collection-{session_id}",
        "feature_schema_version": current_manifest["feature_schema_version"],
        "extractor_version": current_manifest["extractor_version"],
        "observations": [
            observations_by_id[key] for key in sorted(observations_by_id)
        ],
    }
    snapshot_manifest_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    dataset_output = session_dir / f"dataset_validation_{snapshot_id}"
    validation = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parents[2] / "vista-ml" / "scripts" / "prepare_experiment_dataset.py"),
            "--manifest",
            str(snapshot_manifest_path),
            "--output-dir",
            str(dataset_output),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    report_path = dataset_output / "dataset_report.json"
    if validation.returncode not in {0, 2} or not report_path.is_file():
        raise WorkloadCollectionError(
            "Dataset preparation validator did not complete: "
            f"{validation.stderr.strip() or validation.stdout.strip() or validation.returncode}"
        )
    return (
        snapshot_manifest_path,
        report_path,
        json.loads(report_path.read_text(encoding="utf-8")),
    )


def collect_icmp_workload(configuration: dict[str, Any]) -> dict[str, Any]:
    unknown = set(configuration) - {
        "profiles", "experimentId", "sessionId", "sessionContext",
        "targetLabel", "labelSchemaVersion", "workloadSubtype",
    }
    if unknown:
        raise ValueError(f"Unsupported workload collection fields: {sorted(unknown)}.")
    profiles = validate_icmp_profiles(configuration.get("profiles"))
    target_label = configuration.get("targetLabel", "controlled_icmpv4")
    workload_subtype = configuration.get("workloadSubtype", "icmpv4_echo")
    label_schema_version = configuration.get("labelSchemaVersion", "vista-target-label-schema-v1")
    requested_id = configuration.get("experimentId")
    session_id = configuration.get("sessionId")
    experiment_id = str(uuid.uuid4()) if requested_id is None else str(requested_id)
    session_id = str(uuid.uuid4()) if session_id is None else str(session_id)
    for field, value in (("experimentId", experiment_id), ("sessionId", session_id)):
        try:
            parsed_id = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{field} must be an opaque UUID.") from exc
        if parsed_id.version != 4:
            raise ValueError(f"{field} must be an opaque UUIDv4.")
    if experiment_id == session_id:
        raise ValueError("experimentId and sessionId must be distinct opaque UUIDs.")

    experiment_dir = COLLECTION_ROOT / session_id / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    started_at = _utc_now()
    record: dict[str, Any] = {
        "schemaVersion": "vista-workload-collection-v1",
        "experimentId": experiment_id,
        "sessionId": session_id,
        "startedAt": started_at,
        "requestedWorkload": {"type": "icmpv4_echo", "profiles": profiles},
        "status": "NOT TESTED",
        "errors": [],
        "artifactDirectory": str(experiment_dir),
    }
    _set_lifecycle_state(record, "PRECHECK")
    workload_started = False
    capture_started: dict[str, bool] = {container: False for container in CONTAINERS}
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_icmp.pcap",
        "pc2": experiment_dir / "pc2_receiver_icmp.pcap",
    }
    try:
        containers = {name: _inspect_container(name) for name in CONTAINERS}
        record["endpoints"] = containers
        record["strongSwanVersion"] = _require_success(
            _run_docker("exec", "pc1", "swanctl", "--version"),
            "Reading StrongSwan version",
        )
        source = _source_provenance()
        record.update(source)
        before = {name: _read_live_sa(name) for name in CONTAINERS}
        if before["pc1"]["child"].get("localTrafficSelector") != f"{ENDPOINTS['pc1']}/32":
            raise WorkloadCollectionError("The negotiated PC1 traffic selector is not the expected IPv4 endpoint.")
        if before["pc1"]["child"].get("remoteTrafficSelector") != f"{ENDPOINTS['pc2']}/32":
            raise WorkloadCollectionError("The negotiated PC2 traffic selector is not the expected IPv4 endpoint.")
        mode_output = _require_success(
            _run_docker("exec", "pc1", "ip", "xfrm", "state"),
            "Inspecting installed PC1 XFRM state",
        )
        if not re.search(r"\bmode tunnel\b", mode_output):
            raise WorkloadCollectionError("Installed XFRM state does not confirm tunnel mode.")
        record["negotiatedSaBefore"] = {
            name: _safe_sa_evidence(value) for name, value in before.items()
        }
        record["observedXfrmMode"] = "TUNNEL"
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token)
        _set_lifecycle_state(record, "CAPTURE_READY")
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        workload_started = True
        measurements = [_run_ping(profile) for profile in profiles]
        record["senderMeasurements"] = measurements
        capture_ended_at = _utc_now()
        _set_lifecycle_state(record, "CAPTURE_STOPPING")
        for container in CONTAINERS:
            stopped = _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False
            record.setdefault("captureCompletion", {})[container] = stopped
        _set_lifecycle_state(record, "ARTIFACT_VALIDATION")
        pc1_counts = _generate_packet_table(
            capture_paths["pc1"], experiment_dir / "packets.csv", "ESP"
        )
        receiver_counts = _generate_packet_table(
            capture_paths["pc2"], experiment_dir / "receiver_packets.csv", "ICMP"
        )
        expected_count = sum(profile["count"] for profile in profiles)
        sent = sum(item["packetsSent"] for item in measurements)
        received = sum(item["packetsReceived"] for item in measurements)
        after = {name: _read_live_sa(name) for name in CONTAINERS}
        before_child = before["pc1"]["child"]
        after_child = after["pc1"]["child"]
        counter_delta = {
            key: (after_child.get(key) or 0) - (before_child.get(key) or 0)
            for key in ("packetsIn", "packetsOut", "bytesIn", "bytesOut")
        }
        esp_packets = _count_pc1_esp(capture_paths["pc1"])
        record["observedWorkload"] = {
            "packetsRequested": expected_count,
            "packetsSent": sent,
            "packetsReceived": received,
            "senderDurationSeconds": sum(item["durationSeconds"] for item in measurements),
            "receiverEchoRequests": receiver_counts["echoRequests"],
            "receiverEchoReplies": receiver_counts["echoReplies"],
            "pc2CapturedIcmpPackets": receiver_counts["icmpPackets"],
            "pc1CapturedEspPackets": pc1_counts["espPackets"],
            "packetTablePackets": pc1_counts["icmpPackets"],
            "byteCount": sum(
                item["packetsSent"] * profile["payload_bytes"]
                for item, profile in zip(measurements, profiles)
            ),
            "icmpBytesSent": sum(
                item["packetsSent"] * (profile["payload_bytes"] + 8)
                for item, profile in zip(measurements, profiles)
            ),
            "pc1CapturedIpv4Bytes": pc1_counts["ipv4Bytes"],
            "saCounterDelta": counter_delta,
        }
        record["negotiatedSaAfter"] = {
            name: _safe_sa_evidence(value) for name, value in after.items()
        }
        quality_errors = []
        if sent != expected_count or received != expected_count:
            quality_errors.append("sender_count_or_echo_replies_did_not_match_requested_packets")
        if receiver_counts["echoRequests"] != expected_count:
            quality_errors.append("independent_receiver_capture_request_count_mismatch")
        if pc1_counts["espPackets"] <= 0:
            quality_errors.append("pc1_outer_interface_capture_contains_no_ESP_or_NAT_T_ESP_packets")
        if not (
            counter_delta["packetsIn"] >= expected_count
            and counter_delta["packetsOut"] >= expected_count
            and counter_delta["bytesIn"] > 0
            and counter_delta["bytesOut"] > 0
        ):
            quality_errors.append("child_sa_packet_or_byte_counters_did_not_increase")
        if any(item["exitCode"] != 0 for item in measurements):
            quality_errors.append("one_or_more_ping_commands_returned_nonzero")
        if quality_errors:
            raise WorkloadCollectionError("; ".join(quality_errors))

        packet_table_path = experiment_dir / "packets.csv"
        receiver_capture = capture_paths["pc2"]
        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_record = {
            "experimentId": experiment_id,
            "sessionId": session_id,
            "startedAt": started_at,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
            "requestedProfiles": profiles,
            "senderMeasurements": measurements,
            "independentReceiverEvidence": {
                "pcapPath": receiver_capture.name,
                "pcapSha256": _sha256(receiver_capture),
                "echoRequests": receiver_counts["echoRequests"],
                "echoReplies": receiver_counts["echoReplies"],
            },
            "pc1OuterCaptureEvidence": {
                "pcapPath": capture_paths["pc1"].name,
                "pcapSha256": _sha256(capture_paths["pc1"]),
                "icmpPackets": pc1_counts["icmpPackets"],
                "espPackets": esp_packets,
            },
        }
        measurement_path.write_text(json.dumps(measurement_record, indent=2), encoding="utf-8")
        sa_path = experiment_dir / "negotiated_sa.json"
        sa_record = {
            "observedAt": capture_started_at,
            "pc1": _safe_sa_evidence(before["pc1"]),
            "pc2": _safe_sa_evidence(before["pc2"]),
            "verifiedXfrmMode": "TUNNEL",
            "afterTrafficPc1": _safe_sa_evidence(after["pc1"]),
        }
        sa_path.write_text(json.dumps(sa_record, indent=2), encoding="utf-8")
        session_path = _write_session_record(
            experiment_dir,
            session_id=session_id,
            experiment_id=experiment_id,
            started_at=started_at,
            completed_at=capture_ended_at,
            containers=containers,
            source=source,
            strong_swan_version=record["strongSwanVersion"],
            sa=before["pc1"],
            session_context=configuration.get("sessionContext"),
        )
        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": target_label,
            "labelSchemaVersion": label_schema_version,
            "workloadSubtype": workload_subtype,
            "method": "Bounded ICMP echo generated by pc1; independently corroborated by pc2 receiver-side ICMP capture and sender ping counters.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "requestedPackets": expected_count,
            "senderPacketsSent": sent,
            "senderPacketsReceived": received,
            "receiverEchoRequests": receiver_counts["echoRequests"],
            "receiverEchoReplies": receiver_counts["echoReplies"],
            "receiverCaptureSha256": _sha256(receiver_capture),
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")
        manifest_path = experiment_dir / "experiment_manifest.json"
        manifest = {
            "manifest_version": "vista-strongswan-experiment-v2",
            "dataset_id": f"collection-{session_id}",
            "feature_schema_version": "vista-flow-v1",
            "extractor_version": "vista-ml-pcap-features-v1",
            "observations": [{
                "experiment_id": experiment_id,
                "session_id": session_id,
                "session_record_path": "session_record.json",
                "session_record_sha256": _sha256(session_path),
                "capture": {
                    "path": "packets.csv",
                    "format": "packet_table_csv",
                    "sha256": _sha256(packet_table_path),
                    "started_at": capture_started_at,
                    "completed_at": capture_ended_at,
                    "interface": "eth0",
                    "capture_point": "outer",
                    "ip_version": 4,
                    "protocol_family": "ESP",
                    "raw_pcap_path": "pc1_outer_icmp.pcap",
                    "raw_pcap_format": "pcap",
                    "raw_pcap_sha256": _sha256(capture_paths["pc1"]),
                    "raw_pcap_size_bytes": capture_paths["pc1"].stat().st_size,
                },
                "ground_truth": {
                    "label": target_label,
                    "label_schema_version": label_schema_version,
                    "workload_subtype": workload_subtype,
                    "record_path": "ground_truth.json",
                    "record_sha256": _sha256(ground_truth_path),
                    "record_field": "label",
                    "method": ground_truth_record["method"],
                    "independently_verified": True,
                },
                "workload": {
                    "type": "icmpv4_echo",
                    "subtype": workload_subtype,
                    "configuration": {"profiles": profiles, "observed": record["observedWorkload"]},
                    "measurement_path": "workload_measurements.json",
                    "measurement_sha256": _sha256(measurement_path),
                },
                "vpn": {
                    "requested_configuration": {
                        "source": "existing live testbed SA; collector does not reconfigure StrongSwan",
                        "ipVersion": "IPv4",
                        "mode": "tunnel",
                    },
                    "effective_configuration": {
                        "ike": before["pc1"]["ike"],
                        "child": before["pc1"]["child"],
                        "xfrmMode": "TUNNEL",
                    },
                    "negotiated_sa_evidence_path": "negotiated_sa.json",
                    "negotiated_sa_evidence_sha256": _sha256(sa_path),
                },
                "data_quality": {"status": "accepted", "reasons": []},
            }],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        session_manifest_path, dataset_report_path, dataset_report = (
            _run_session_dataset_validation(experiment_dir, session_id, manifest_path)
        )
        record["datasetPreparation"] = {
            "status": dataset_report["status"],
            "acceptedObservations": dataset_report["accepted_observations"],
            "quarantinedObservations": dataset_report["quarantined_observations"],
            "independentSessions": dataset_report["independent_session_count"],
            "blocker": dataset_report["blocker"],
            "reportPath": str(dataset_report_path),
        }
        current_exclusion = next((
            item for item in dataset_report.get("exclusions", [])
            if item.get("experiment_id") == experiment_id
        ), None)
        if current_exclusion:
            record["datasetPreparation"]["currentObservationAdmission"] = "QUARANTINED"
            if set(current_exclusion.get("reasons", [])) != {
                "session_independence_unverified"
            }:
                raise WorkloadCollectionError(
                    "Dataset preparation quarantined this experiment: "
                    f"{current_exclusion.get('reasons', [])}"
                )
        else:
            record["datasetPreparation"]["currentObservationAdmission"] = "ACCEPTED"
        if (
            dataset_report["quarantined_observations"] > 0
            and current_exclusion is None
        ):
            record["datasetPreparation"]["historicalQuarantines"] = (
                dataset_report["quarantined_observations"]
            )
        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "negotiatedSa": str(sa_path),
            "sessionRecord": str(session_path),
            "manifest": str(manifest_path),
            "sessionDatasetManifest": str(session_manifest_path),
            "datasetReport": str(dataset_report_path),
            "sha256": {
                "pc1Pcap": _sha256(capture_paths["pc1"]),
                "pc2ReceiverPcap": _sha256(receiver_capture),
                "packetTable": _sha256(packet_table_path),
                "groundTruth": _sha256(ground_truth_path),
                "workloadMeasurements": _sha256(measurement_path),
                "negotiatedSa": _sha256(sa_path),
                "manifest": _sha256(manifest_path),
            },
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")
    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        record["failureStage"] = record.get("lifecycleState", "PRECHECK")
        _set_lifecycle_state(record, record["status"])
    finally:
        for container, started in capture_started.items():
            if started:
                try:
                    diagnostic_path = experiment_dir / f"{container}_tcpdump.log"
                    preserved = _preserve_capture_artifacts(
                        container,
                        token,
                        capture_paths[container],
                        diagnostic_path,
                    )
                    if preserved:
                        record.setdefault("failureArtifacts", {})[container] = preserved
                    _cleanup_capture(container, token)
                except Exception as cleanup_error:
                    record["errors"].append(f"{container} capture cleanup failed: {cleanup_error}")
                    record["status"] = "FAIL"
        if record["status"] in {"FAIL", "BLOCKED"}:
            diagnostics = {
                "status": record["status"],
                "failureStage": record.get("failureStage", "PRECHECK"),
                "errors": record.get("errors", []),
                "lifecycle": record.get("lifecycle", []),
                "workloadStarted": workload_started,
                "experimentId": experiment_id,
                "sessionId": session_id,
                "failedAt": _utc_now(),
                "failureArtifacts": record.get("failureArtifacts", {}),
            }
            (experiment_dir / "failure_diagnostics.json").write_text(
                json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8"
            )
        record["completedAt"] = _utc_now()
        result_path = experiment_dir / "collection_result.json"
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        record["resultPath"] = str(result_path)
    return record


def _start_tcp_listener(token: str, port: int) -> str:
    remote = f"/tmp/vista-{token}-tcp"
    command = (
        f"nc -l -p {port} >{remote}.recv 2>{remote}.log & "
        f"echo $! >{remote}.pid"
    )
    _require_success(
        _run_docker("exec", "pc2", "sh", "-c", command),
        "Starting bounded TCP marker receiver",
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = _run_docker("exec", "pc2", "ss", "-ltn")
        if result.returncode == 0 and re.search(rf":{port}\s", result.stdout):
            return remote
        log = _run_docker("exec", "pc2", "cat", f"{remote}.log")
        if log.returncode == 0 and log.stdout.strip():
            raise WorkloadCollectionError(
                f"TCP receiver failed to start: {log.stdout.strip()}"
            )
        time.sleep(0.1)
    raise WorkloadCollectionError("TCP marker receiver did not bind its bounded port.")


def _send_tcp_markers(
    profiles: list[dict[str, Any]],
    port: int,
) -> dict[str, Any]:
    client = subprocess.Popen(
        [
            vpn_testbed._docker_path(), "exec", "-i", "pc1",
            "nc", "-N", ENDPOINTS["pc2"], str(port),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    started = time.monotonic()
    profile_results: list[dict[str, Any]] = []
    expected_digest = hashlib.sha256()
    sent_bytes = 0
    try:
        if client.stdin is None:
            raise WorkloadCollectionError("TCP sender stdin could not be opened.")
        for profile_index, profile in enumerate(profiles):
            profile_started = time.monotonic()
            profile_sent = 0
            for message_index in range(profile["count"]):
                seed = hashlib.sha256(
                    f"vista-tcp-marker-v1:{profile_index}:{message_index}".encode("ascii")
                ).digest()
                repeats = (profile["payload_bytes"] + len(seed) - 1) // len(seed)
                payload = (seed * repeats)[:profile["payload_bytes"]]
                client.stdin.write(payload)
                client.stdin.flush()
                expected_digest.update(payload)
                sent_bytes += len(payload)
                profile_sent += len(payload)
                if message_index + 1 < profile["count"]:
                    time.sleep(profile["interval_seconds"])
            profile_duration = time.monotonic() - profile_started
            profile_results.append({
                "requested": profile,
                "messagesSent": profile["count"],
                "bytesSent": profile_sent,
                "durationSeconds": profile_duration,
                "throughputBytesPerSecond": (
                    profile_sent / profile_duration if profile_duration > 0 else None
                ),
            })
        client.stdin.close()
        try:
            exit_code = client.wait(
                timeout=max(10, sum(
                    item["count"] * item["interval_seconds"] for item in profiles
                ) + 10)
            )
        except subprocess.TimeoutExpired as exc:
            client.terminate()
            client.wait(timeout=3)
            raise WorkloadCollectionError("TCP sender exceeded its bounded execution timeout.") from exc
        stdout = client.stdout.read().decode(errors="replace") if client.stdout else ""
        stderr = client.stderr.read().decode(errors="replace") if client.stderr else ""
    except Exception:
        if client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=3)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=3)
        raise
    duration = time.monotonic() - started
    return {
        "profiles": profile_results,
        "messagesSent": sum(profile["count"] for profile in profiles),
        "bytesSent": sent_bytes,
        "durationSeconds": duration,
        "throughputBytesPerSecond": sent_bytes / duration if duration > 0 else None,
        "expectedPayloadSha256": expected_digest.hexdigest(),
        "clientExitCode": exit_code,
        "clientStdout": stdout,
        "clientStderr": stderr,
    }


def collect_tcp_marker_workload(configuration: dict[str, Any]) -> dict[str, Any]:
    unknown = set(configuration) - {
        "profiles", "experimentId", "sessionId", "sessionContext",
        "targetLabel", "labelSchemaVersion", "workloadSubtype",
    }
    if unknown:
        raise ValueError(f"Unsupported workload collection fields: {sorted(unknown)}.")
    profiles = validate_tcp_profiles(configuration.get("profiles"))
    target_label = configuration.get("targetLabel", "controlled_tcp_marker")
    workload_subtype = configuration.get("workloadSubtype", "tcp_marker")
    label_schema_version = configuration.get("labelSchemaVersion", "vista-target-label-schema-v1")
    requested_id = configuration.get("experimentId")
    session_id = configuration.get("sessionId")
    experiment_id = str(uuid.uuid4()) if requested_id is None else str(requested_id)
    session_id = str(uuid.uuid4()) if session_id is None else str(session_id)
    for field, value in (("experimentId", experiment_id), ("sessionId", session_id)):
        try:
            parsed_id = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{field} must be an opaque UUID.") from exc
        if parsed_id.version != 4:
            raise ValueError(f"{field} must be an opaque UUIDv4.")
    if experiment_id == session_id:
        raise ValueError("experimentId and sessionId must be distinct opaque UUIDs.")

    experiment_dir = COLLECTION_ROOT / session_id / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    port = 40000 + (int(token[:4], 16) % 20000)
    started_at = _utc_now()
    record: dict[str, Any] = {
        "schemaVersion": "vista-workload-collection-v1",
        "experimentId": experiment_id,
        "sessionId": session_id,
        "startedAt": started_at,
        "requestedWorkload": {"type": "tcp_marker", "profiles": profiles},
        "status": "NOT TESTED",
        "errors": [],
        "artifactDirectory": str(experiment_dir),
    }
    _set_lifecycle_state(record, "PRECHECK")
    capture_started: dict[str, bool] = {container: False for container in CONTAINERS}
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_tcp.pcap",
        "pc2": experiment_dir / "pc2_receiver_tcp.pcap",
    }
    receiver_remote = ""
    receiver_pid = ""
    workload_started = False
    try:
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
                raise WorkloadCollectionError(
                    f"{endpoint} CHILD_SA selectors do not cover the expected IPv4 endpoints."
                )
        mode_output = _require_success(
            _run_docker("exec", "pc1", "ip", "xfrm", "state"),
            "Inspecting installed PC1 XFRM state",
        )
        if not re.search(r"\bmode tunnel\b", mode_output):
            raise WorkloadCollectionError("Installed XFRM state does not confirm tunnel mode.")
        record["negotiatedSaBefore"] = {
            name: _safe_sa_evidence(value) for name, value in before.items()
        }
        record["observedXfrmMode"] = "TUNNEL"
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, "tcp")
        _set_lifecycle_state(record, "CAPTURE_READY")
        receiver_remote = _start_tcp_listener(token, port)
        receiver_pid = _require_success(
            _run_docker("exec", "pc2", "cat", f"{receiver_remote}.pid"),
            "Reading TCP receiver process ID",
        )
        if not re.fullmatch(r"[0-9]+", receiver_pid):
            raise WorkloadCollectionError("TCP receiver process ID was malformed.")
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        workload_started = True
        sender = _send_tcp_markers(profiles, port)
        deadline = time.monotonic() + 5
        received_bytes = -1
        while time.monotonic() < deadline:
            byte_count = _run_docker("exec", "pc2", "wc", "-c", f"{receiver_remote}.recv")
            if byte_count.returncode == 0 and re.match(r"\s*(\d+)", byte_count.stdout):
                received_bytes = int(re.match(r"\s*(\d+)", byte_count.stdout).group(1))
                if received_bytes >= sender["bytesSent"]:
                    break
            time.sleep(0.1)
        received_payload_path = experiment_dir / "receiver_payload.bin"
        copied_payload = subprocess.run(
            [
                vpn_testbed._docker_path(), "cp",
                f"pc2:{receiver_remote}.recv", str(received_payload_path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        _require_success(copied_payload, "Retrieving independent TCP receiver payload")
        received_sha = _sha256(received_payload_path)
        capture_ended_at = _utc_now()
        _set_lifecycle_state(record, "CAPTURE_STOPPING")
        for container in CONTAINERS:
            stopped = _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False
            record.setdefault("captureCompletion", {})[container] = stopped
        _set_lifecycle_state(record, "ARTIFACT_VALIDATION")
        pc1_counts = _generate_packet_table(
            capture_paths["pc1"], experiment_dir / "packets.csv", "ESP"
        )
        receiver_counts = _generate_packet_table(
            capture_paths["pc2"], experiment_dir / "receiver_packets.csv", "TCP"
        )
        after = {name: _read_live_sa(name) for name in CONTAINERS}
        before_child = before["pc1"]["child"]
        after_child = after["pc1"]["child"]
        counter_delta = {
            key: (after_child.get(key) or 0) - (before_child.get(key) or 0)
            for key in ("packetsIn", "packetsOut", "bytesIn", "bytesOut")
        }
        esp_packets = _count_pc1_esp(capture_paths["pc1"])
        record["senderMeasurements"] = sender
        record["observedWorkload"] = {
            "messagesRequested": sum(profile["count"] for profile in profiles),
            "messagesSent": sender["messagesSent"],
            "bytesSent": sender["bytesSent"],
            "bytesReceived": received_bytes,
            "durationSeconds": sender["durationSeconds"],
            "throughputBytesPerSecond": sender["throughputBytesPerSecond"],
            "pc1CapturedTcpPackets": receiver_counts["tcpPackets"],
            "pc2CapturedTcpPackets": receiver_counts["tcpPackets"],
            "pc1CapturedEspPackets": pc1_counts["espPackets"],
            "pc1CapturedIpv4Bytes": pc1_counts["ipv4Bytes"],
            "receiverPayloadSha256": received_sha,
            "saCounterDelta": counter_delta,
        }
        record["negotiatedSaAfter"] = {
            name: _safe_sa_evidence(value) for name, value in after.items()
        }
        if sender["clientExitCode"] != 0:
            raise WorkloadCollectionError(
                f"TCP client exited {sender['clientExitCode']}: {sender['clientStderr']}"
            )
        if received_bytes != sender["bytesSent"] or received_sha != sender["expectedPayloadSha256"]:
            raise WorkloadCollectionError(
                "TCP receiver byte count or payload hash does not match the sender."
            )
        if receiver_counts["tcpPackets"] <= 0 or pc1_counts["espPackets"] <= 0:
            raise WorkloadCollectionError(
                "The endpoint captures do not verify TCP and corresponding outer ESP packets."
            )
        if not (
            counter_delta["packetsIn"] > 0
            and counter_delta["packetsOut"] > 0
            and counter_delta["bytesIn"] > 0
            and counter_delta["bytesOut"] > 0
        ):
            raise WorkloadCollectionError("CHILD_SA packet and byte counters did not increase.")

        packet_table_path = experiment_dir / "packets.csv"
        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_record = {
            "experimentId": experiment_id,
            "sessionId": session_id,
            "startedAt": started_at,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
            "requestedProfiles": profiles,
            "sender": sender,
            "receiver": {
                "bytesReceived": received_bytes,
                "payloadSha256": received_sha,
                "payloadPath": received_payload_path.name,
                "capturedTcpPackets": receiver_counts["tcpPackets"],
            },
            "pc1OuterCapture": {
                "pcapPath": capture_paths["pc1"].name,
                "pcapSha256": _sha256(capture_paths["pc1"]),
                "tcpPackets": pc1_counts["tcpPackets"],
                "espPackets": esp_packets,
            },
        }
        measurement_path.write_text(json.dumps(measurement_record, indent=2), encoding="utf-8")
        sa_path = experiment_dir / "negotiated_sa.json"
        sa_record = {
            "observedAt": capture_started_at,
            "pc1": _safe_sa_evidence(before["pc1"]),
            "pc2": _safe_sa_evidence(before["pc2"]),
            "verifiedXfrmMode": "TUNNEL",
            "afterTrafficPc1": _safe_sa_evidence(after["pc1"]),
        }
        sa_path.write_text(json.dumps(sa_record, indent=2), encoding="utf-8")
        session_path = _write_session_record(
            experiment_dir,
            session_id=session_id,
            experiment_id=experiment_id,
            started_at=started_at,
            completed_at=capture_ended_at,
            containers=containers,
            source=source,
            strong_swan_version=record["strongSwanVersion"],
            sa=before["pc1"],
            session_context=configuration.get("sessionContext"),
        )
        ground_truth_path = experiment_dir / "ground_truth.json"
        message_count = sum(profile["count"] for profile in profiles)
        ground_truth_record = {
            "label": target_label,
            "labelSchemaVersion": label_schema_version,
            "workloadSubtype": workload_subtype,
            "method": "Bounded deterministic marker bytes sent by pc1 over one TCP connection; pc2 independently records and hashes the received payload.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "messagesSent": message_count,
            "bytesSent": sender["bytesSent"],
            "bytesReceived": received_bytes,
            "senderPayloadSha256": sender["expectedPayloadSha256"],
            "receiverPayloadSha256": received_sha,
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")
        manifest_path = experiment_dir / "experiment_manifest.json"
        manifest = {
            "manifest_version": "vista-strongswan-experiment-v2",
            "dataset_id": f"collection-{session_id}",
            "feature_schema_version": "vista-flow-v1",
            "extractor_version": "vista-ml-pcap-features-v1",
            "observations": [{
                "experiment_id": experiment_id,
                "session_id": session_id,
                "session_record_path": "session_record.json",
                "session_record_sha256": _sha256(session_path),
                "capture": {
                    "path": "packets.csv",
                    "format": "packet_table_csv",
                    "sha256": _sha256(packet_table_path),
                    "started_at": capture_started_at,
                    "completed_at": capture_ended_at,
                    "interface": "eth0",
                    "capture_point": "outer",
                    "ip_version": 4,
                    "protocol_family": "ESP",
                    "raw_pcap_path": "pc1_outer_tcp.pcap",
                    "raw_pcap_format": "pcap",
                    "raw_pcap_sha256": _sha256(capture_paths["pc1"]),
                    "raw_pcap_size_bytes": capture_paths["pc1"].stat().st_size,
                },
                "ground_truth": {
                    "label": target_label,
                    "label_schema_version": label_schema_version,
                    "workload_subtype": workload_subtype,
                    "record_path": "ground_truth.json",
                    "record_sha256": _sha256(ground_truth_path),
                    "record_field": "label",
                    "method": ground_truth_record["method"],
                    "independently_verified": True,
                },
                "workload": {
                    "type": "tcp_marker",
                    "subtype": workload_subtype,
                    "configuration": {
                        "profiles": profiles,
                        "observed": record["observedWorkload"],
                    },
                    "measurement_path": "workload_measurements.json",
                    "measurement_sha256": _sha256(measurement_path),
                },
                "vpn": {
                    "requested_configuration": {
                        "source": "existing live testbed SA; collector does not reconfigure StrongSwan",
                        "ipVersion": "IPv4",
                        "mode": "tunnel",
                    },
                    "effective_configuration": {
                        "ike": before["pc1"]["ike"],
                        "child": before["pc1"]["child"],
                        "xfrmMode": "TUNNEL",
                    },
                    "negotiated_sa_evidence_path": "negotiated_sa.json",
                    "negotiated_sa_evidence_sha256": _sha256(sa_path),
                },
                "data_quality": {"status": "accepted", "reasons": []},
            }],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        session_manifest_path, dataset_report_path, dataset_report = (
            _run_session_dataset_validation(experiment_dir, session_id, manifest_path)
        )
        record["datasetPreparation"] = {
            "status": dataset_report["status"],
            "acceptedObservations": dataset_report["accepted_observations"],
            "quarantinedObservations": dataset_report["quarantined_observations"],
            "independentSessions": dataset_report["independent_session_count"],
            "blocker": dataset_report["blocker"],
            "reportPath": str(dataset_report_path),
        }
        current_exclusion = next((
            item for item in dataset_report.get("exclusions", [])
            if item.get("experiment_id") == experiment_id
        ), None)
        if current_exclusion:
            record["datasetPreparation"]["currentObservationAdmission"] = "QUARANTINED"
            if set(current_exclusion.get("reasons", [])) != {
                "session_independence_unverified"
            }:
                raise WorkloadCollectionError(
                    "Dataset preparation quarantined this experiment: "
                    f"{current_exclusion.get('reasons', [])}"
                )
        else:
            record["datasetPreparation"]["currentObservationAdmission"] = "ACCEPTED"
        if (
            dataset_report["quarantined_observations"] > 0
            and current_exclusion is None
        ):
            record["datasetPreparation"]["historicalQuarantines"] = (
                dataset_report["quarantined_observations"]
            )
        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "receiverPayload": str(received_payload_path),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "negotiatedSa": str(sa_path),
            "sessionRecord": str(session_path),
            "manifest": str(manifest_path),
            "sessionDatasetManifest": str(session_manifest_path),
            "datasetReport": str(dataset_report_path),
            "sha256": {
                "pc1Pcap": _sha256(capture_paths["pc1"]),
                "pc2ReceiverPcap": _sha256(capture_paths["pc2"]),
                "receiverPayload": received_sha,
                "packetTable": _sha256(packet_table_path),
                "groundTruth": _sha256(ground_truth_path),
                "workloadMeasurements": _sha256(measurement_path),
                "negotiatedSa": _sha256(sa_path),
                "manifest": _sha256(manifest_path),
            },
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")
    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        record["failureStage"] = record.get("lifecycleState", "PRECHECK")
        _set_lifecycle_state(record, record["status"])
    finally:
        if receiver_pid:
            _run_docker(
                "exec", "pc2", "sh", "-c", f"kill -TERM {receiver_pid}"
            )
        if receiver_remote:
            _run_docker(
                "exec", "pc2", "rm", "-f",
                f"{receiver_remote}.recv", f"{receiver_remote}.log",
                f"{receiver_remote}.pid",
            )
        for container, started in capture_started.items():
            if started:
                try:
                    diagnostic_path = experiment_dir / f"{container}_tcpdump.log"
                    preserved = _preserve_capture_artifacts(
                        container,
                        token,
                        capture_paths[container],
                        diagnostic_path,
                    )
                    if preserved:
                        record.setdefault("failureArtifacts", {})[container] = preserved
                    _cleanup_capture(container, token)
                except Exception as cleanup_error:
                    record["errors"].append(f"{container} capture cleanup failed: {cleanup_error}")
        if record["status"] in {"FAIL", "BLOCKED"}:
            diagnostics = {
                "status": record["status"],
                "failureStage": record.get("failureStage", "PRECHECK"),
                "errors": record.get("errors", []),
                "lifecycle": record.get("lifecycle", []),
                "workloadStarted": workload_started,
                "experimentId": experiment_id,
                "sessionId": session_id,
                "failedAt": _utc_now(),
                "failureArtifacts": record.get("failureArtifacts", {}),
            }
            (experiment_dir / "failure_diagnostics.json").write_text(
                json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8"
            )
        record["completedAt"] = _utc_now()
        result_path = experiment_dir / "collection_result.json"
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        record["resultPath"] = str(result_path)
    return record


_HTTP_SERVER_SCRIPT = r'''use strict;
use warnings;
use IO::Socket::INET;

my ($port, $remote_base, $max_requests) = @ARGV;
$max_requests = int($max_requests || 100);

my $server = IO::Socket::INET->new(
    LocalAddr => '172.20.0.3',
    LocalPort => $port,
    Proto => 'tcp',
    Listen => 10,
    Reuse => 1
) or die "Cannot bind server to 172.20.0.3:$port: $!";

open my $rf, '>', "$remote_base.ready" or die "Cannot write ready file: $!";
print $rf "READY\n";
close $rf;

my @recorded_requests = ();
my $req_count = 0;

sub write_evidence {
    open my $ef, '>', "$remote_base.evidence.json" or return;
    print $ef "{\n";
    print $ef "  \"totalRequestsReceived\": " . scalar(@recorded_requests) . ",\n";
    print $ef "  \"serverPort\": $port,\n";
    print $ef "  \"requests\": [\n";
    for my $i (0 .. $#recorded_requests) {
        my $r = $recorded_requests[$i];
        print $ef "    {\n";
        print $ef "      \"index\": $r->{index},\n";
        print $ef "      \"method\": \"$r->{method}\",\n";
        print $ef "      \"path\": \"$r->{path}\",\n";
        print $ef "      \"clientIp\": \"$r->{clientIp}\",\n";
        print $ef "      \"requestBodyBytes\": $r->{requestBodyBytes},\n";
        print $ef "      \"responseStatus\": $r->{responseStatus},\n";
        print $ef "      \"responseBytes\": $r->{responseBytes},\n";
        print $ef "      \"responseSha256\": \"$r->{responseSha256}\",\n";
        print $ef "      \"timestamp\": $r->{timestamp}\n";
        print $ef "    }" . ($i < $#recorded_requests ? "," : "") . "\n";
    }
    print $ef "  ]\n";
    print $ef "}\n";
    close $ef;
}

$SIG{TERM} = sub { write_evidence(); exit 0; };
$SIG{INT}  = sub { write_evidence(); exit 0; };

while ($req_count < $max_requests) {
    my $client = $server->accept();
    last unless $client;

    my $peer_ip = $client->peerhost || '172.20.0.2';
    my $request_line = <$client>;
    if (!defined $request_line) {
        close $client;
        next;
    }
    $request_line =~ s/\r?\n$//;
    my ($method, $path, $proto) = split /\s+/, $request_line, 3;
    $method ||= 'GET';
    $path ||= '/';
    $proto ||= 'HTTP/1.1';

    my %headers;
    my $content_length = 0;
    while (my $line = <$client>) {
        $line =~ s/\r?\n$//;
        last if $line eq '';
        if ($line =~ /^([^:]+):\s*(.*)$/) {
            $headers{lc $1} = $2;
        }
    }
    if (exists $headers{'content-length'}) {
        $content_length = int($headers{'content-length'});
    }
    my $req_body = '';
    if ($content_length > 0) {
        read($client, $req_body, $content_length);
    }

    my $status = 200;
    my $status_text = "OK";
    if ($path =~ m{^/notfound}) {
        $status = 404;
        $status_text = "Not Found";
    } elsif ($path =~ m{^/error}) {
        $status = 500;
        $status_text = "Internal Server Error";
    }

    my $resp_body = "VISTA-HTTP-RESPONSE: status=$status req=$req_count path=$path bytes=" . length($req_body);
    open my $pipe, '|-', "sha256sum > $remote_base.tmp_sha" or die $!;
    print $pipe $resp_body;
    close $pipe;
    open my $sf, '<', "$remote_base.tmp_sha";
    my $resp_sha = <$sf> || '';
    close $sf;
    $resp_sha =~ s/\s+.*$//;
    chomp $resp_sha;

    my $resp_len = length($resp_body);
    my $response = "HTTP/1.1 $status $status_text\r\n" .
                   "Content-Type: text/plain\r\n" .
                   "Content-Length: $resp_len\r\n" .
                   "Connection: close\r\n" .
                   "Server: VISTA-HTTP-Server/1.0\r\n" .
                   "\r\n" .
                   $resp_body;
    print $client $response;
    close $client;

    push @recorded_requests, {
        index => $req_count,
        method => $method,
        path => $path,
        clientIp => $peer_ip,
        requestBodyBytes => length($req_body),
        responseStatus => $status,
        responseBytes => $resp_len,
        responseSha256 => $resp_sha,
        timestamp => time()
    };
    $req_count++;
}

write_evidence();
exit 0;
'''


_HTTP_CLIENT_SCRIPT = r'''use strict;
use warnings;
use IO::Socket::INET;

my ($target_host, $port, $remote_base, @specs) = @ARGV;

my @client_results = ();
my $req_idx = 0;
my $total_sent_bytes = 0;
my $total_recv_bytes = 0;

for my $spec (@specs) {
    my ($count, $interval, $path, $method, $payload_bytes, $expected_status) = split /:/, $spec;
    $count = int($count || 1);
    $interval = $interval + 0;
    $path ||= '/';
    $method ||= 'GET';
    $payload_bytes = int($payload_bytes || 0);
    $expected_status = int($expected_status || 200);

    for (my $c = 0; $c < $count; $c++) {
        my $t0 = time();
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target_host,
            PeerPort => $port,
            Proto => 'tcp',
            Timeout => 10
        );
        if (!$sock) {
            push @client_results, {
                index => $req_idx++,
                path => $path,
                method => $method,
                statusCode => 0,
                statusLine => "CONNECT_FAILED",
                responseBytes => 0,
                responseSha256 => "",
                durationSeconds => time() - $t0,
                error => "Connect failed: $!"
            };
            select(undef, undef, undef, $interval) if $c + 1 < $count;
            next;
        }

        my $body = '';
        if ($method eq 'POST' && $payload_bytes > 0) {
            $body = 'X' x $payload_bytes;
        }
        my $body_len = length($body);
        my $req = "$method $path HTTP/1.1\r\n" .
                  "Host: $target_host:$port\r\n" .
                  "User-Agent: VISTA-HTTP-Client/1.0\r\n" .
                  "Connection: close\r\n";
        if ($body_len > 0) {
            $req .= "Content-Length: $body_len\r\n\r\n$body";
        } else {
            $req .= "\r\n";
        }

        print $sock $req;
        $total_sent_bytes += length($req);

        my $status_line = <$sock> || '';
        $status_line =~ s/\r?\n$//;
        my ($proto, $status, $msg) = split /\s+/, $status_line, 3;
        $status = int($status || 0);

        my %resp_headers;
        my $content_len = -1;
        while (my $line = <$sock>) {
            $line =~ s/\r?\n$//;
            last if $line eq '';
            if ($line =~ /^([^:]+):\s*(.*)$/) {
                $resp_headers{lc $1} = $2;
            }
        }
        if (exists $resp_headers{'content-length'}) {
            $content_len = int($resp_headers{'content-length'});
        }

        my $resp_body = '';
        if ($content_len >= 0) {
            read($sock, $resp_body, $content_len);
        } else {
            local $/ = undef;
            $resp_body = <$sock> || '';
        }
        close $sock;
        $total_recv_bytes += length($status_line) + length($resp_body);

        open my $pipe, '|-', "sha256sum > $remote_base.tmp_client_sha" or die $!;
        print $pipe $resp_body;
        close $pipe;
        open my $cf, '<', "$remote_base.tmp_client_sha";
        my $client_sha = <$cf> || '';
        close $cf;
        $client_sha =~ s/\s+.*$//;
        chomp $client_sha;

        my $duration = time() - $t0;
        push @client_results, {
            index => $req_idx++,
            path => $path,
            method => $method,
            statusCode => $status,
            statusLine => $status_line,
            responseBytes => length($resp_body),
            responseSha256 => $client_sha,
            durationSeconds => $duration
        };

        select(undef, undef, undef, $interval) if $c + 1 < $count;
    }
}

open my $out, '>', "$remote_base.client.json" or die "Cannot write client results: $!";
print $out "{\n";
print $out "  \"totalRequestsSent\": " . scalar(@client_results) . ",\n";
print $out "  \"totalBytesSent\": $total_sent_bytes,\n";
print $out "  \"totalBytesReceived\": $total_recv_bytes,\n";
print $out "  \"requests\": [\n";
for my $i (0 .. $#client_results) {
    my $r = $client_results[$i];
    print $out "    {\n";
    print $out "      \"index\": $r->{index},\n";
    print $out "      \"path\": \"$r->{path}\",\n";
    print $out "      \"method\": \"$r->{method}\",\n";
    print $out "      \"statusCode\": $r->{statusCode},\n";
    print $out "      \"statusLine\": \"$r->{statusLine}\",\n";
    print $out "      \"responseBytes\": $r->{responseBytes},\n";
    print $out "      \"responseSha256\": \"$r->{responseSha256}\",\n";
    print $out "      \"durationSeconds\": $r->{durationSeconds}\n";
    print $out "    }" . ($i < $#client_results ? "," : "") . "\n";
}
print $out "  ]\n";
print $out "}\n";
close $out;
exit 0;
'''


def _start_http_server(token: str, port: int, max_requests: int) -> tuple[str, str]:
    remote_base = f"/tmp/vista-{token}-http-srv"
    script_path = f"/tmp/vista-{token}-srv.pl"
    deploy = subprocess.run(
        [vpn_testbed._docker_path(), "exec", "-i", "pc2", "sh", "-c", f"cat > {script_path}"],
        input=_HTTP_SERVER_SCRIPT.encode("utf-8"),
        capture_output=True,
        text=False,
        timeout=15,
        check=False,
    )
    if deploy.returncode != 0:
        raise WorkloadCollectionError(
            f"Failed to deploy HTTP server script to pc2: {deploy.stderr.decode(errors='replace')}"
        )
    cmd = (
        f"perl {script_path} {port} {remote_base} {max_requests} >{remote_base}.log 2>&1 & "
        f"echo $! >{remote_base}.pid"
    )
    _require_success(
        _run_docker("exec", "pc2", "sh", "-c", cmd),
        "Starting bounded HTTP server on pc2",
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ready = _run_docker("exec", "pc2", "test", "-f", f"{remote_base}.ready")
        if ready.returncode == 0:
            pid = _require_success(
                _run_docker("exec", "pc2", "cat", f"{remote_base}.pid"),
                "Reading HTTP server PID",
            )
            return remote_base, pid
        log = _run_docker("exec", "pc2", "cat", f"{remote_base}.log")
        if log.returncode == 0 and "Cannot bind server" in log.stdout:
            raise WorkloadCollectionError(f"HTTP server failed to bind: {log.stdout.strip()}")
        time.sleep(0.1)
    raise WorkloadCollectionError("HTTP server did not reach readiness within timeout.")


def _run_http_client(profiles: list[dict[str, Any]], port: int, token: str) -> dict[str, Any]:
    remote_base = f"/tmp/vista-{token}-http-cli"
    script_path = f"/tmp/vista-{token}-cli.pl"
    deploy = subprocess.run(
        [vpn_testbed._docker_path(), "exec", "-i", "pc1", "sh", "-c", f"cat > {script_path}"],
        input=_HTTP_CLIENT_SCRIPT.encode("utf-8"),
        capture_output=True,
        text=False,
        timeout=15,
        check=False,
    )
    if deploy.returncode != 0:
        raise WorkloadCollectionError(
            f"Failed to deploy HTTP client script to pc1: {deploy.stderr.decode(errors='replace')}"
        )
    specs = [
        f"{p['count']}:{p['interval_seconds']}:{p['path']}:{p['method']}:{p['payload_bytes']}:{p['expected_status']}"
        for p in profiles
    ]
    total_timeout = max(15, sum(p["count"] * p["interval_seconds"] for p in profiles) + 15)
    run_res = _run_docker(
        "exec", "pc1", "perl", script_path, ENDPOINTS["pc2"], str(port), remote_base, *specs,
        timeout=total_timeout,
    )
    if run_res.returncode != 0:
        raise WorkloadCollectionError(
            f"HTTP client exited with code {run_res.returncode}: {run_res.stderr.strip() or run_res.stdout.strip()}"
        )
    out_res = _run_docker("exec", "pc1", "cat", f"{remote_base}.client.json")
    if out_res.returncode != 0 or not out_res.stdout.strip():
        raise WorkloadCollectionError("Failed to retrieve HTTP client measurement JSON.")
    try:
        return json.loads(out_res.stdout)
    except json.JSONDecodeError as exc:
        raise WorkloadCollectionError(f"Malformed HTTP client output JSON: {exc}")


def collect_http_workload(configuration: dict[str, Any]) -> dict[str, Any]:
    unknown = set(configuration) - {
        "profiles", "experimentId", "sessionId", "sessionContext",
        "targetLabel", "labelSchemaVersion", "workloadSubtype",
    }
    if unknown:
        raise ValueError(f"Unsupported workload collection fields: {sorted(unknown)}.")
    profiles = validate_http_profiles(configuration.get("profiles"))
    target_label = configuration.get("targetLabel", "controlled_http")
    workload_subtype = configuration.get(
        "workloadSubtype",
        "http_post" if any(p.get("method") == "POST" for p in profiles) else "http_get",
    )
    label_schema_version = configuration.get("labelSchemaVersion", "vista-target-label-schema-v1")
    requested_id = configuration.get("experimentId")
    session_id = configuration.get("sessionId")
    experiment_id = str(uuid.uuid4()) if requested_id is None else str(requested_id)
    session_id = str(uuid.uuid4()) if session_id is None else str(session_id)
    for field, value in (("experimentId", experiment_id), ("sessionId", session_id)):
        try:
            parsed_id = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{field} must be an opaque UUID.") from exc
        if parsed_id.version != 4:
            raise ValueError(f"{field} must be an opaque UUIDv4.")
    if experiment_id == session_id:
        raise ValueError("experimentId and sessionId must be distinct opaque UUIDs.")

    experiment_dir = COLLECTION_ROOT / session_id / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    port = 40000 + (int(token[:4], 16) % 20000)
    started_at = _utc_now()
    record: dict[str, Any] = {
        "schemaVersion": "vista-workload-collection-v1",
        "experimentId": experiment_id,
        "sessionId": session_id,
        "startedAt": started_at,
        "requestedWorkload": {"type": "http_traffic", "profiles": profiles},
        "status": "NOT TESTED",
        "errors": [],
        "artifactDirectory": str(experiment_dir),
    }
    _set_lifecycle_state(record, "PRECHECK")
    capture_started: dict[str, bool] = {container: False for container in CONTAINERS}
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_http.pcap",
        "pc2": experiment_dir / "pc2_receiver_http.pcap",
    }
    server_remote = ""
    server_pid = ""
    workload_started = False
    try:
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
                raise WorkloadCollectionError(
                    f"{endpoint} CHILD_SA selectors do not cover the expected IPv4 endpoints."
                )
        mode_output = _require_success(
            _run_docker("exec", "pc1", "ip", "xfrm", "state"),
            "Inspecting installed PC1 XFRM state",
        )
        if not re.search(r"\bmode tunnel\b", mode_output):
            raise WorkloadCollectionError("Installed XFRM state does not confirm tunnel mode.")
        record["negotiatedSaBefore"] = {
            name: _safe_sa_evidence(value) for name, value in before.items()
        }
        record["observedXfrmMode"] = "TUNNEL"
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, "tcp")
        _set_lifecycle_state(record, "CAPTURE_READY")
        expected_requests = sum(p["count"] for p in profiles)
        server_remote, server_pid = _start_http_server(token, port, expected_requests)
        if not re.fullmatch(r"[0-9]+", server_pid):
            raise WorkloadCollectionError("HTTP server process ID was malformed.")
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        workload_started = True

        client_results = _run_http_client(profiles, port, token)

        # Wait up to 5s for server evidence file to be written
        server_evidence_path = experiment_dir / "server_evidence.json"
        deadline = time.monotonic() + 5
        server_evidence: dict[str, Any] = {}
        while time.monotonic() < deadline:
            check = _run_docker("exec", "pc2", "test", "-f", f"{server_remote}.evidence.json")
            if check.returncode == 0:
                copied = subprocess.run(
                    [
                        vpn_testbed._docker_path(), "cp",
                        f"pc2:{server_remote}.evidence.json", str(server_evidence_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if copied.returncode == 0 and server_evidence_path.is_file():
                    try:
                        server_evidence = json.loads(server_evidence_path.read_text(encoding="utf-8"))
                        if server_evidence.get("totalRequestsReceived", 0) >= expected_requests:
                            break
                    except (json.JSONDecodeError, OSError):
                        pass
            time.sleep(0.1)

        if not server_evidence:
            raise WorkloadCollectionError("Independent server evidence could not be retrieved from pc2.")

        capture_ended_at = _utc_now()
        _set_lifecycle_state(record, "CAPTURE_STOPPING")
        for container in CONTAINERS:
            stopped = _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False
            record.setdefault("captureCompletion", {})[container] = stopped
        _set_lifecycle_state(record, "ARTIFACT_VALIDATION")

        pc1_counts = _generate_packet_table(
            capture_paths["pc1"], experiment_dir / "packets.csv", "ESP"
        )
        receiver_counts = _generate_packet_table(
            capture_paths["pc2"], experiment_dir / "receiver_packets.csv", "TCP"
        )
        after = {name: _read_live_sa(name) for name in CONTAINERS}
        before_child = before["pc1"]["child"]
        after_child = after["pc1"]["child"]
        counter_delta = {
            key: (after_child.get(key) or 0) - (before_child.get(key) or 0)
            for key in ("packetsIn", "packetsOut", "bytesIn", "bytesOut")
        }
        esp_packets = _count_pc1_esp(capture_paths["pc1"])

        client_requests = client_results.get("requests", [])
        server_requests = server_evidence.get("requests", [])

        record["senderMeasurements"] = client_results
        record["serverEvidence"] = server_evidence
        record["observedWorkload"] = {
            "requestsRequested": expected_requests,
            "requestsSent": client_results.get("totalRequestsSent", 0),
            "requestsReceivedByServer": server_evidence.get("totalRequestsReceived", 0),
            "bytesSent": client_results.get("totalBytesSent", 0),
            "bytesReceived": client_results.get("totalBytesReceived", 0),
            "pc1CapturedEspPackets": pc1_counts["espPackets"],
            "pc2CapturedTcpPackets": receiver_counts["tcpPackets"],
            "saCounterDelta": counter_delta,
        }
        record["negotiatedSaAfter"] = {
            name: _safe_sa_evidence(value) for name, value in after.items()
        }

        # Quality validations
        if client_results.get("totalRequestsSent") != expected_requests:
            raise WorkloadCollectionError(
                f"Client sent {client_results.get('totalRequestsSent')} requests; expected {expected_requests}."
            )
        if server_evidence.get("totalRequestsReceived") != expected_requests:
            raise WorkloadCollectionError(
                f"Server received {server_evidence.get('totalRequestsReceived')} requests; expected {expected_requests}."
            )
        if len(client_requests) != len(server_requests):
            raise WorkloadCollectionError("Request count mismatch between client and server records.")

        for idx, (cli_req, srv_req) in enumerate(zip(client_requests, server_requests)):
            if cli_req.get("statusCode") != srv_req.get("responseStatus"):
                raise WorkloadCollectionError(
                    f"Request {idx} status mismatch: client observed {cli_req.get('statusCode')}, server sent {srv_req.get('responseStatus')}."
                )
            if cli_req.get("statusCode") != 200:
                raise WorkloadCollectionError(
                    f"Request {idx} failed with non-200 status code: {cli_req.get('statusCode')}."
                )
            if cli_req.get("responseBytes") != srv_req.get("responseBytes"):
                raise WorkloadCollectionError(
                    f"Request {idx} response byte count mismatch: client {cli_req.get('responseBytes')}, server {srv_req.get('responseBytes')}."
                )
            if cli_req.get("responseSha256") != srv_req.get("responseSha256"):
                raise WorkloadCollectionError(
                    f"Request {idx} payload hash mismatch between client and server."
                )

        if pc1_counts["espPackets"] <= 0 or receiver_counts["tcpPackets"] <= 0:
            raise WorkloadCollectionError(
                "Capture does not verify outer ESP packets on PC1 and receiver TCP packets on PC2."
            )
        if not (
            counter_delta["packetsIn"] > 0
            and counter_delta["packetsOut"] > 0
            and counter_delta["bytesIn"] > 0
            and counter_delta["bytesOut"] > 0
        ):
            raise WorkloadCollectionError("CHILD_SA packet and byte counters did not increase.")

        client_measurements_path = experiment_dir / "client_measurements.json"
        client_measurements_path.write_text(json.dumps(client_results, indent=2), encoding="utf-8")

        packet_table_path = experiment_dir / "packets.csv"
        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_record = {
            "experimentId": experiment_id,
            "sessionId": session_id,
            "startedAt": started_at,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
            "requestedProfiles": profiles,
            "senderMeasurements": client_results,
            "independentReceiverEvidence": {
                "serverEvidencePath": server_evidence_path.name,
                "serverEvidenceSha256": _sha256(server_evidence_path),
                "totalRequestsReceived": server_evidence.get("totalRequestsReceived"),
                "pcapPath": capture_paths["pc2"].name,
                "pcapSha256": _sha256(capture_paths["pc2"]),
                "capturedTcpPackets": receiver_counts["tcpPackets"],
            },
            "pc1OuterCaptureEvidence": {
                "pcapPath": capture_paths["pc1"].name,
                "pcapSha256": _sha256(capture_paths["pc1"]),
                "espPackets": esp_packets,
            },
        }
        measurement_path.write_text(json.dumps(measurement_record, indent=2), encoding="utf-8")

        sa_path = experiment_dir / "negotiated_sa.json"
        sa_record = {
            "observedAt": capture_started_at,
            "pc1": _safe_sa_evidence(before["pc1"]),
            "pc2": _safe_sa_evidence(before["pc2"]),
            "verifiedXfrmMode": "TUNNEL",
            "afterTrafficPc1": _safe_sa_evidence(after["pc1"]),
        }
        sa_path.write_text(json.dumps(sa_record, indent=2), encoding="utf-8")

        session_path = _write_session_record(
            experiment_dir,
            session_id=session_id,
            experiment_id=experiment_id,
            started_at=started_at,
            completed_at=capture_ended_at,
            containers=containers,
            source=source,
            strong_swan_version=record["strongSwanVersion"],
            sa=before["pc1"],
            session_context=configuration.get("sessionContext"),
        )

        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": target_label,
            "labelSchemaVersion": label_schema_version,
            "workloadSubtype": workload_subtype,
            "method": "Bounded HTTP/1.1 client/server exchange generated between pc1 and pc2 over IPsec tunnel; independently verified by pc2 server-side access evidence and pc1 outer ESP capture.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "requestsRequested": expected_requests,
            "requestsCompleted": len(client_requests),
            "senderBytesSent": client_results.get("totalBytesSent", 0),
            "senderBytesReceived": client_results.get("totalBytesReceived", 0),
            "serverEvidenceSha256": _sha256(server_evidence_path),
            "statusCodes": [r.get("statusCode") for r in client_requests],
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = experiment_dir / "experiment_manifest.json"
        manifest = {
            "manifest_version": "vista-strongswan-experiment-v2",
            "dataset_id": f"collection-{session_id}",
            "feature_schema_version": "vista-flow-v1",
            "extractor_version": "vista-ml-pcap-features-v1",
            "observations": [{
                "experiment_id": experiment_id,
                "session_id": session_id,
                "session_record_path": "session_record.json",
                "session_record_sha256": _sha256(session_path),
                "capture": {
                    "path": "packets.csv",
                    "format": "packet_table_csv",
                    "sha256": _sha256(packet_table_path),
                    "started_at": capture_started_at,
                    "completed_at": capture_ended_at,
                    "interface": "eth0",
                    "capture_point": "outer",
                    "ip_version": 4,
                    "protocol_family": "ESP",
                    "raw_pcap_path": "pc1_outer_http.pcap",
                    "raw_pcap_format": "pcap",
                    "raw_pcap_sha256": _sha256(capture_paths["pc1"]),
                    "raw_pcap_size_bytes": capture_paths["pc1"].stat().st_size,
                },
                "ground_truth": {
                    "label": target_label,
                    "label_schema_version": label_schema_version,
                    "workload_subtype": workload_subtype,
                    "record_path": "ground_truth.json",
                    "record_sha256": _sha256(ground_truth_path),
                    "record_field": "label",
                    "method": ground_truth_record["method"],
                    "independently_verified": True,
                },
                "workload": {
                    "type": "http_traffic",
                    "subtype": workload_subtype,
                    "configuration": {"profiles": profiles, "observed": record["observedWorkload"]},
                    "measurement_path": "workload_measurements.json",
                    "measurement_sha256": _sha256(measurement_path),
                },
                "vpn": {
                    "requested_configuration": {
                        "source": "existing live testbed SA; collector does not reconfigure StrongSwan",
                        "ipVersion": "IPv4",
                        "mode": "tunnel",
                    },
                    "effective_configuration": {
                        "ike": before["pc1"]["ike"],
                        "child": before["pc1"]["child"],
                        "xfrmMode": "TUNNEL",
                    },
                    "negotiated_sa_evidence_path": "negotiated_sa.json",
                    "negotiated_sa_evidence_sha256": _sha256(sa_path),
                },
                "data_quality": {"status": "accepted", "reasons": []},
            }],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        session_manifest_path, dataset_report_path, dataset_report = (
            _run_session_dataset_validation(experiment_dir, session_id, manifest_path)
        )
        record["datasetPreparation"] = {
            "status": dataset_report["status"],
            "acceptedObservations": dataset_report["accepted_observations"],
            "quarantinedObservations": dataset_report["quarantined_observations"],
            "independentSessions": dataset_report["independent_session_count"],
            "blocker": dataset_report["blocker"],
            "reportPath": str(dataset_report_path),
        }
        current_exclusion = next((
            item for item in dataset_report.get("exclusions", [])
            if item.get("experiment_id") == experiment_id
        ), None)
        if current_exclusion:
            record["datasetPreparation"]["currentObservationAdmission"] = "QUARANTINED"
            if set(current_exclusion.get("reasons", [])) != {
                "session_independence_unverified"
            }:
                raise WorkloadCollectionError(
                    "Dataset preparation quarantined this experiment: "
                    f"{current_exclusion.get('reasons', [])}"
                )
        else:
            record["datasetPreparation"]["currentObservationAdmission"] = "ACCEPTED"
        if (
            dataset_report["quarantined_observations"] > 0
            and current_exclusion is None
        ):
            record["datasetPreparation"]["historicalQuarantines"] = (
                dataset_report["quarantined_observations"]
            )

        record["artifacts"] = {
            "pc1Pcap": str(capture_paths["pc1"]),
            "pc2ReceiverPcap": str(capture_paths["pc2"]),
            "packetTable": str(packet_table_path),
            "groundTruth": str(ground_truth_path),
            "workloadMeasurements": str(measurement_path),
            "clientMeasurements": str(client_measurements_path),
            "serverEvidence": str(server_evidence_path),
            "negotiatedSa": str(sa_path),
            "sessionRecord": str(session_path),
            "manifest": str(manifest_path),
            "sessionDatasetManifest": str(session_manifest_path),
            "datasetReport": str(dataset_report_path),
            "sha256": {
                "pc1Pcap": _sha256(capture_paths["pc1"]),
                "pc2ReceiverPcap": _sha256(capture_paths["pc2"]),
                "packetTable": _sha256(packet_table_path),
                "groundTruth": _sha256(ground_truth_path),
                "workloadMeasurements": _sha256(measurement_path),
                "clientMeasurements": _sha256(client_measurements_path),
                "serverEvidence": _sha256(server_evidence_path),
                "negotiatedSa": _sha256(sa_path),
                "manifest": _sha256(manifest_path),
            },
        }
        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")
    except Exception as exc:
        record["status"] = "FAIL" if workload_started else "BLOCKED"
        record["errors"].append(str(exc))
        record["failureStage"] = record.get("lifecycleState", "PRECHECK")
        _set_lifecycle_state(record, record["status"])
    finally:
        if server_pid:
            _run_docker("exec", "pc2", "sh", "-c", f"kill -TERM {server_pid}")
        if server_remote:
            _run_docker(
                "exec", "pc2", "rm", "-f",
                f"{server_remote}.evidence.json", f"{server_remote}.log",
                f"{server_remote}.pid", f"{server_remote}.ready", f"{server_remote}.tmp_sha",
                f"/tmp/vista-{token}-srv.pl",
            )
        _run_docker(
            "exec", "pc1", "rm", "-f",
            f"/tmp/vista-{token}-http-cli.client.json", f"/tmp/vista-{token}-http-cli.tmp_client_sha",
            f"/tmp/vista-{token}-cli.pl",
        )
        for container, started in capture_started.items():
            if started:
                try:
                    diagnostic_path = experiment_dir / f"{container}_tcpdump.log"
                    preserved = _preserve_capture_artifacts(
                        container,
                        token,
                        capture_paths[container],
                        diagnostic_path,
                    )
                    if preserved:
                        record.setdefault("failureArtifacts", {})[container] = preserved
                    _cleanup_capture(container, token)
                except Exception as cleanup_error:
                    record["errors"].append(f"{container} capture cleanup failed: {cleanup_error}")
        if record["status"] in {"FAIL", "BLOCKED"}:
            diagnostics = {
                "status": record["status"],
                "failureStage": record.get("failureStage", "PRECHECK"),
                "errors": record.get("errors", []),
                "lifecycle": record.get("lifecycle", []),
                "workloadStarted": workload_started,
                "experimentId": experiment_id,
                "sessionId": session_id,
                "failedAt": _utc_now(),
                "failureArtifacts": record.get("failureArtifacts", {}),
            }
            (experiment_dir / "failure_diagnostics.json").write_text(
                json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8"
            )
        record["completedAt"] = _utc_now()
        result_path = experiment_dir / "collection_result.json"
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        record["resultPath"] = str(result_path)
    return record


_RTP_RECEIVER_SCRIPT = r'''use strict;
use warnings;
use IO::Socket::INET;

my ($port, $remote_base, $max_packets) = @ARGV;
$max_packets = int($max_packets || 10);

my $sock = IO::Socket::INET->new(
    LocalAddr => '172.20.0.3',
    LocalPort => $port,
    Proto     => 'udp',
    ReusePort => 1,
) or die "Cannot bind UDP socket: $!";

open my $rf, '>', "$remote_base.ready" or die "Cannot write ready: $!";
print $rf "READY\n";
close $rf;

my $payload_file = "$remote_base.payload.bin";
open my $pf, '>:raw', $payload_file or die "Cannot open payload file: $!";

my $count = 0;
my ($first_seq, $last_seq);
my $observed_ssrc;
my $total_bytes = 0;
my $t_start = time();

while ($count < $max_packets) {
    my $buf;
    my $peer = $sock->recv($buf, 2048);
    last unless defined $peer and length($buf) >= 12;

    my ($v_p_x_cc, $m_pt, $seq, $ts, $ssrc) = unpack('CCnNN', substr($buf, 0, 12));
    my $v = ($v_p_x_cc >> 6) & 0x03;
    next unless $v == 2; # RFC 3550 RTP version 2

    $first_seq = $seq unless defined $first_seq;
    $last_seq = $seq;
    $observed_ssrc = $ssrc unless defined $observed_ssrc;

    my $payload = substr($buf, 12);
    print $pf $payload;
    $total_bytes += length($payload);
    $count++;
}
close $pf;
my $t_end = time();

my $sha_out = `sha256sum $payload_file`;
$sha_out =~ s/\s+.*$//s;
chomp $sha_out;

open my $ef, '>', "$remote_base.evidence.json" or die "Cannot write evidence: $!";
print $ef "{\n";
print $ef "  \"totalPacketsReceived\": $count,\n";
print $ef "  \"totalPayloadBytes\": $total_bytes,\n";
print $ef "  \"startSequence\": " . (defined $first_seq ? $first_seq : 0) . ",\n";
print $ef "  \"endSequence\": " . (defined $last_seq ? $last_seq : 0) . ",\n";
print $ef "  \"ssrc\": " . (defined $observed_ssrc ? $observed_ssrc : 0) . ",\n";
print $ef "  \"payloadSha256\": \"$sha_out\",\n";
print $ef "  \"durationSeconds\": " . ($t_end - $t_start) . "\n";
print $ef "}\n";
close $ef;
exit 0;
'''

_RTP_SENDER_SCRIPT = r'''use strict;
use warnings;
use IO::Socket::INET;

my ($target_host, $port, $remote_base, $count, $interval_sec, $payload_bytes, $ssrc, $start_seq) = @ARGV;
$count = int($count || 10);
$interval_sec = $interval_sec + 0.0;
$payload_bytes = int($payload_bytes || 160);
$ssrc = int($ssrc || 0x12345678);
$start_seq = int($start_seq || 1000);

my $sock = IO::Socket::INET->new(
    PeerAddr => $target_host,
    PeerPort => $port,
    Proto    => 'udp',
) or die "Cannot create sender UDP socket: $!";

my $payload_file = "$remote_base.sent_payload.bin";
open my $pf, '>:raw', $payload_file or die "Cannot open sent payload file: $!";

my $seq = $start_seq;
my $ts = 160000;
my $total_sent = 0;
my $total_bytes = 0;
my $t_start = time();

for (my $i = 0; $i < $count; $i++) {
    my $header = pack('CCnNN', 0x80, 0, $seq, $ts, $ssrc);
    my $payload = pack('C*', map { ($i * 7 + $_) % 256 } (0 .. $payload_bytes - 1));
    print $pf $payload;
    $sock->send($header . $payload);
    $total_sent++;
    $total_bytes += length($payload);
    $seq = ($seq + 1) % 65536;
    $ts += 160;
    select(undef, undef, undef, $interval_sec) if $i < $count - 1 and $interval_sec > 0;
}
close $pf;
my $t_end = time();

my $sha_out = `sha256sum $payload_file`;
$sha_out =~ s/\s+.*$//s;
chomp $sha_out;

open my $mf, '>', "$remote_base.client.json" or die "Cannot write client measurement: $!";
print $mf "{\n";
print $mf "  \"totalPacketsSent\": $total_sent,\n";
print $mf "  \"totalPayloadBytes\": $total_bytes,\n";
print $mf "  \"startSequence\": $start_seq,\n";
print $mf "  \"endSequence\": " . (($seq - 1) % 65536) . ",\n";
print $mf "  \"ssrc\": $ssrc,\n";
print $mf "  \"payloadSha256\": \"$sha_out\",\n";
print $mf "  \"durationSeconds\": " . ($t_end - $t_start) . "\n";
print $mf "}\n";
close $mf;
exit 0;
'''


def _start_rtp_receiver(token: str, port: int, max_packets: int) -> tuple[str, str]:
    remote_base = f"/tmp/vista-{token}-rtp-srv"
    script_path = f"/tmp/vista-{token}-srv.pl"
    deploy = subprocess.run(
        [vpn_testbed._docker_path(), "exec", "-i", "pc2", "sh", "-c", f"cat > {script_path}"],
        input=_RTP_RECEIVER_SCRIPT.encode("utf-8"),
        capture_output=True,
        text=False,
        timeout=15,
        check=False,
    )
    if deploy.returncode != 0:
        raise WorkloadCollectionError(
            f"Failed to deploy RTP receiver script to pc2: {deploy.stderr.decode(errors='replace')}"
        )
    cmd = (
        f"perl {script_path} {port} {remote_base} {max_packets} >{remote_base}.log 2>&1 & "
        f"echo $! >{remote_base}.pid"
    )
    _require_success(
        _run_docker("exec", "pc2", "sh", "-c", cmd),
        "Starting bounded RTP receiver on pc2",
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ready = _run_docker("exec", "pc2", "test", "-f", f"{remote_base}.ready")
        if ready.returncode == 0:
            pid = _require_success(
                _run_docker("exec", "pc2", "cat", f"{remote_base}.pid"),
                "Reading RTP receiver PID",
            )
            return remote_base, pid
        log = _run_docker("exec", "pc2", "cat", f"{remote_base}.log")
        if log.returncode == 0 and "Cannot bind" in log.stdout:
            raise WorkloadCollectionError(f"RTP receiver failed to bind: {log.stdout.strip()}")
        time.sleep(0.1)
    raise WorkloadCollectionError("RTP receiver did not reach readiness within timeout.")


def _run_rtp_sender(profile: dict[str, Any], port: int, token: str) -> dict[str, Any]:
    remote_base = f"/tmp/vista-{token}-rtp-cli"
    script_path = f"/tmp/vista-{token}-cli.pl"
    deploy = subprocess.run(
        [vpn_testbed._docker_path(), "exec", "-i", "pc1", "sh", "-c", f"cat > {script_path}"],
        input=_RTP_SENDER_SCRIPT.encode("utf-8"),
        capture_output=True,
        text=False,
        timeout=15,
        check=False,
    )
    if deploy.returncode != 0:
        raise WorkloadCollectionError(
            f"Failed to deploy RTP sender script to pc1: {deploy.stderr.decode(errors='replace')}"
        )
    count = profile["count"]
    interval_sec = profile["interval_seconds"]
    payload_bytes = profile["payload_bytes"]
    ssrc = profile.get("ssrc", 0x12345678)
    start_seq = profile.get("start_sequence", 1000)
    total_timeout = max(15, count * interval_sec + 15)

    run_res = _run_docker(
        "exec", "pc1", "perl", script_path, ENDPOINTS["pc2"], str(port), remote_base,
        str(count), str(interval_sec), str(payload_bytes), str(ssrc), str(start_seq),
        timeout=total_timeout,
    )
    if run_res.returncode != 0:
        raise WorkloadCollectionError(
            f"RTP sender exited with code {run_res.returncode}: {run_res.stderr.strip() or run_res.stdout.strip()}"
        )
    out_res = _run_docker("exec", "pc1", "cat", f"{remote_base}.client.json")
    if out_res.returncode != 0 or not out_res.stdout.strip():
        raise WorkloadCollectionError("Failed to retrieve RTP sender measurement JSON.")
    try:
        return json.loads(out_res.stdout)
    except json.JSONDecodeError as exc:
        raise WorkloadCollectionError(f"Malformed RTP sender output JSON: {exc}")


def collect_rtp_workload(configuration: dict[str, Any]) -> dict[str, Any]:
    unknown = set(configuration) - {
        "profiles", "experimentId", "sessionId", "sessionContext",
        "targetLabel", "labelSchemaVersion", "workloadSubtype",
    }
    if unknown:
        raise ValueError(f"Unsupported workload collection fields: {sorted(unknown)}.")
    profiles = validate_rtp_profiles(configuration.get("profiles"))
    target_label = configuration.get("targetLabel", "controlled_rtp_voip")
    workload_subtype = configuration.get("workloadSubtype", "rtp_voip")
    label_schema_version = configuration.get("labelSchemaVersion", "vista-target-label-schema-v2")
    requested_id = configuration.get("experimentId")
    session_id = configuration.get("sessionId")
    experiment_id = str(uuid.uuid4()) if requested_id is None else str(requested_id)
    session_id = str(uuid.uuid4()) if session_id is None else str(session_id)
    for field, value in (("experimentId", experiment_id), ("sessionId", session_id)):
        try:
            parsed_id = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{field} must be an opaque UUID.") from exc
        if parsed_id.version != 4:
            raise ValueError(f"{field} must be an opaque UUIDv4.")
    if experiment_id == session_id:
        raise ValueError("experimentId and sessionId must be distinct opaque UUIDs.")

    experiment_dir = COLLECTION_ROOT / session_id / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    port = 45000 + (int(token[:4], 16) % 15000)
    started_at = _utc_now()
    record: dict[str, Any] = {
        "schemaVersion": "vista-workload-collection-v1",
        "experimentId": experiment_id,
        "sessionId": session_id,
        "startedAt": started_at,
        "requestedWorkload": {"type": "rtp_voip", "profiles": profiles},
        "status": "NOT TESTED",
        "errors": [],
        "artifactDirectory": str(experiment_dir),
    }
    _set_lifecycle_state(record, "PRECHECK")
    capture_started: dict[str, bool] = {container: False for container in CONTAINERS}
    capture_paths = {
        "pc1": experiment_dir / "pc1_outer_rtp.pcap",
        "pc2": experiment_dir / "pc2_receiver_rtp.pcap",
    }
    server_remote = ""
    server_pid = ""
    workload_started = False
    try:
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
                raise WorkloadCollectionError(
                    f"{endpoint} CHILD_SA selectors do not cover the expected IPv4 endpoints."
                )
        mode_output = _require_success(
            _run_docker("exec", "pc1", "ip", "xfrm", "state"),
            "Inspecting installed PC1 XFRM state",
        )
        if not re.search(r"\bmode tunnel\b", mode_output):
            raise WorkloadCollectionError("Installed XFRM state does not confirm tunnel mode.")
        record["negotiatedSaBefore"] = {
            name: _safe_sa_evidence(value) for name, value in before.items()
        }
        record["observedXfrmMode"] = "TUNNEL"
        _set_lifecycle_state(record, "CAPTURE_STARTING")
        capture_started_at = _utc_now()
        for container in CONTAINERS:
            capture_started[container] = True
            _start_capture(container, token, "udp")
        _set_lifecycle_state(record, "CAPTURE_READY")
        expected_packets = sum(p["count"] for p in profiles)
        server_remote, server_pid = _start_rtp_receiver(token, port, expected_packets)
        if not re.fullmatch(r"[0-9]+", server_pid):
            raise WorkloadCollectionError("RTP receiver process ID was malformed.")
        _set_lifecycle_state(record, "WORKLOAD_RUNNING")
        workload_started = True

        sender_results = _run_rtp_sender(profiles[0], port, token)

        server_evidence_path = experiment_dir / "server_evidence.json"
        deadline = time.monotonic() + 5
        server_evidence: dict[str, Any] = {}
        while time.monotonic() < deadline:
            check = _run_docker("exec", "pc2", "test", "-f", f"{server_remote}.evidence.json")
            if check.returncode == 0:
                copied = subprocess.run(
                    [
                        vpn_testbed._docker_path(), "cp",
                        f"pc2:{server_remote}.evidence.json", str(server_evidence_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if copied.returncode == 0 and server_evidence_path.is_file():
                    try:
                        server_evidence = json.loads(server_evidence_path.read_text(encoding="utf-8"))
                        if server_evidence.get("totalPacketsReceived", 0) >= expected_packets:
                            break
                    except (json.JSONDecodeError, OSError):
                        pass
            time.sleep(0.1)

        if not server_evidence:
            raise WorkloadCollectionError("Independent RTP receiver evidence could not be retrieved from pc2.")

        capture_ended_at = _utc_now()
        _set_lifecycle_state(record, "CAPTURE_STOPPING")
        for container in CONTAINERS:
            stopped = _stop_capture(container, token, capture_paths[container])
            capture_started[container] = False
            record.setdefault("captureCompletion", {})[container] = stopped
        _set_lifecycle_state(record, "ARTIFACT_VALIDATION")

        pc1_counts = _generate_packet_table(
            capture_paths["pc1"], experiment_dir / "packets.csv", "ESP"
        )
        receiver_counts = _generate_packet_table(
            capture_paths["pc2"], experiment_dir / "receiver_packets.csv", "UDP"
        )
        after = {name: _read_live_sa(name) for name in CONTAINERS}
        before_child = before["pc1"]["child"]
        after_child = after["pc1"]["child"]
        counter_delta = {
            key: (after_child.get(key) or 0) - (before_child.get(key) or 0)
            for key in ("packetsIn", "packetsOut", "bytesIn", "bytesOut")
        }
        esp_packets = _count_pc1_esp(capture_paths["pc1"])

        record["senderMeasurements"] = sender_results
        record["serverEvidence"] = server_evidence
        record["observedWorkload"] = {
            "packetsRequested": expected_packets,
            "packetsSent": sender_results.get("totalPacketsSent", 0),
            "packetsReceivedByReceiver": server_evidence.get("totalPacketsReceived", 0),
            "payloadBytesSent": sender_results.get("totalPayloadBytes", 0),
            "payloadBytesReceived": server_evidence.get("totalPayloadBytes", 0),
            "pc1CapturedEspPackets": pc1_counts["espPackets"],
            "pc2CapturedUdpPackets": receiver_counts["udpPackets"],
            "saCounterDelta": counter_delta,
        }
        record["negotiatedSaAfter"] = {
            name: _safe_sa_evidence(value) for name, value in after.items()
        }

        # Quality validations
        if sender_results.get("totalPacketsSent") != expected_packets:
            raise WorkloadCollectionError(
                f"Sender sent {sender_results.get('totalPacketsSent')} packets; expected {expected_packets}."
            )
        if server_evidence.get("totalPacketsReceived") != expected_packets:
            raise WorkloadCollectionError(
                f"Receiver received {server_evidence.get('totalPacketsReceived')} packets; expected {expected_packets}."
            )
        if sender_results.get("totalPayloadBytes") != server_evidence.get("totalPayloadBytes"):
            raise WorkloadCollectionError("RTP payload byte count mismatch between sender and receiver.")
        if sender_results.get("payloadSha256") != server_evidence.get("payloadSha256"):
            raise WorkloadCollectionError("RTP payload hash mismatch between sender and receiver.")
        if sender_results.get("ssrc") != server_evidence.get("ssrc"):
            raise WorkloadCollectionError("RTP SSRC mismatch between sender and receiver.")
        if pc1_counts["espPackets"] <= 0 or receiver_counts["udpPackets"] <= 0:
            raise WorkloadCollectionError(
                "Capture does not verify outer ESP packets on PC1 and receiver UDP packets on PC2."
            )
        if not (
            counter_delta["packetsOut"] > 0
            and counter_delta["bytesOut"] > 0
        ):
            raise WorkloadCollectionError("CHILD_SA packet and byte counters did not increase.")

        sender_measurements_path = experiment_dir / "sender_measurements.json"
        sender_measurements_path.write_text(json.dumps(sender_results, indent=2), encoding="utf-8")

        packet_table_path = experiment_dir / "packets.csv"
        measurement_path = experiment_dir / "workload_measurements.json"
        measurement_record = {
            "experimentId": experiment_id,
            "sessionId": session_id,
            "startedAt": started_at,
            "captureStartedAt": capture_started_at,
            "captureEndedAt": capture_ended_at,
            "requestedProfiles": profiles,
            "senderMeasurements": sender_results,
            "independentReceiverEvidence": {
                "serverEvidencePath": server_evidence_path.name,
                "serverEvidenceSha256": _sha256(server_evidence_path),
                "totalPacketsReceived": server_evidence.get("totalPacketsReceived"),
                "pcapPath": capture_paths["pc2"].name,
                "pcapSha256": _sha256(capture_paths["pc2"]),
                "capturedUdpPackets": receiver_counts["udpPackets"],
            },
            "pc1OuterCaptureEvidence": {
                "pcapPath": capture_paths["pc1"].name,
                "pcapSha256": _sha256(capture_paths["pc1"]),
                "espPackets": esp_packets,
            },
        }
        measurement_path.write_text(json.dumps(measurement_record, indent=2), encoding="utf-8")

        sa_path = experiment_dir / "negotiated_sa.json"
        sa_record = {
            "observedAt": capture_started_at,
            "pc1": _safe_sa_evidence(before["pc1"]),
            "pc2": _safe_sa_evidence(before["pc2"]),
            "verifiedXfrmMode": "TUNNEL",
            "afterTrafficPc1": _safe_sa_evidence(after["pc1"]),
        }
        sa_path.write_text(json.dumps(sa_record, indent=2), encoding="utf-8")

        session_path = _write_session_record(
            experiment_dir,
            session_id=session_id,
            experiment_id=experiment_id,
            started_at=started_at,
            completed_at=capture_ended_at,
            containers=containers,
            source=source,
            strong_swan_version=record["strongSwanVersion"],
            sa=before["pc1"],
            session_context=configuration.get("sessionContext"),
        )
        ground_truth_path = experiment_dir / "ground_truth.json"
        ground_truth_record = {
            "label": target_label,
            "labelSchemaVersion": label_schema_version,
            "workloadSubtype": workload_subtype,
            "method": "Bounded RFC 3550 RTP/UDP voice-over-IP audio frames generated by pc1; pc2 independently receives, verifies sequence continuity, and hashes payload.",
            "experimentId": experiment_id,
            "sessionId": session_id,
            "packetsSent": sender_results.get("totalPacketsSent"),
            "packetsReceived": server_evidence.get("totalPacketsReceived"),
            "payloadBytesSent": sender_results.get("totalPayloadBytes"),
            "payloadBytesReceived": server_evidence.get("totalPayloadBytes"),
            "ssrc": sender_results.get("ssrc"),
            "senderPayloadSha256": sender_results.get("payloadSha256"),
            "receiverPayloadSha256": server_evidence.get("payloadSha256"),
        }
        ground_truth_path.write_text(json.dumps(ground_truth_record, indent=2), encoding="utf-8")

        manifest_path = experiment_dir / "experiment_manifest.json"
        manifest = {
            "manifest_version": "vista-strongswan-experiment-v2",
            "dataset_id": f"collection-{session_id}",
            "feature_schema_version": "vista-flow-v1",
            "extractor_version": "vista-ml-pcap-features-v1",
            "observations": [{
                "experiment_id": experiment_id,
                "session_id": session_id,
                "session_record_path": "session_record.json",
                "session_record_sha256": _sha256(session_path),
                "capture": {
                    "path": "packets.csv",
                    "format": "packet_table_csv",
                    "sha256": _sha256(packet_table_path),
                    "started_at": capture_started_at,
                    "completed_at": capture_ended_at,
                    "interface": "eth0",
                    "capture_point": "outer",
                    "ip_version": 4,
                    "protocol_family": "ESP",
                    "raw_pcap_path": "pc1_outer_rtp.pcap",
                    "raw_pcap_format": "pcap",
                    "raw_pcap_sha256": _sha256(capture_paths["pc1"]),
                    "raw_pcap_size_bytes": capture_paths["pc1"].stat().st_size,
                },
                "ground_truth": {
                    "label": target_label,
                    "label_schema_version": label_schema_version,
                    "workload_subtype": workload_subtype,
                    "record_path": "ground_truth.json",
                    "record_sha256": _sha256(ground_truth_path),
                    "record_field": "label",
                    "method": ground_truth_record["method"],
                    "independently_verified": True,
                },
                "workload": {
                    "type": "rtp_voip",
                    "subtype": workload_subtype,
                    "configuration": {
                        "profiles": profiles,
                        "observed": record["observedWorkload"],
                    },
                    "measurement_path": "workload_measurements.json",
                    "measurement_sha256": _sha256(measurement_path),
                },
                "vpn": {
                    "requested_configuration": {
                        "source": "existing live testbed SA; collector does not reconfigure StrongSwan",
                        "ipVersion": "IPv4",
                        "mode": "tunnel",
                    },
                    "effective_configuration": {
                        "ike": before["pc1"]["ike"],
                        "child": before["pc1"]["child"],
                        "xfrmMode": "TUNNEL",
                    },
                    "negotiated_sa_evidence_path": "negotiated_sa.json",
                    "negotiated_sa_evidence_sha256": _sha256(sa_path),
                },
                "data_quality": {"status": "accepted", "reasons": []},
            }],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        session_manifest_path, dataset_report_path, dataset_report = (
            _run_session_dataset_validation(experiment_dir, session_id, manifest_path)
        )
        record["datasetPreparation"] = {
            "status": dataset_report["status"],
            "acceptedObservations": dataset_report["accepted_observations"],
            "quarantinedObservations": dataset_report["quarantined_observations"],
            "independentSessions": dataset_report["independent_session_count"],
            "blocker": dataset_report["blocker"],
            "reportPath": str(dataset_report_path),
        }
        current_exclusion = next((
            item for item in dataset_report.get("exclusions", [])
            if item.get("experiment_id") == experiment_id
        ), None)
        if current_exclusion:
            record["datasetPreparation"]["currentObservationAdmission"] = "QUARANTINED"
            if set(current_exclusion.get("reasons", [])) != {"session_independence_unverified"}:
                raise WorkloadCollectionError(
                    f"Observation was quarantined during admission check: {current_exclusion['reasons']}"
                )
        else:
            record["datasetPreparation"]["currentObservationAdmission"] = "ACCEPTED"

        record["status"] = "PASS"
        _set_lifecycle_state(record, "PASS")
    except Exception as exc:
        record["status"] = "FAIL"
        record["errors"].append(str(exc))
        _set_lifecycle_state(record, "FAIL")
    finally:
        if server_remote:
            _run_docker("exec", "pc2", "rm", "-f", f"{server_remote}.pid", f"{server_remote}.ready")
        for container in CONTAINERS:
            if capture_started[container]:
                try:
                    diagnostic_path = experiment_dir / f"{container}_capture_diagnostics.txt"
                    preserved = _preserve_capture_artifacts(
                        container,
                        token,
                        capture_paths[container],
                        diagnostic_path,
                    )
                    if preserved:
                        record.setdefault("failureArtifacts", {})[container] = preserved
                    _cleanup_capture(container, token)
                except Exception as cleanup_error:
                    record["errors"].append(f"{container} capture cleanup failed: {cleanup_error}")
        if record["status"] in {"FAIL", "BLOCKED"}:
            diagnostics = {
                "status": record["status"],
                "failureStage": record.get("failureStage", "PRECHECK"),
                "errors": record.get("errors", []),
                "lifecycle": record.get("lifecycle", []),
                "workloadStarted": workload_started,
                "experimentId": experiment_id,
                "sessionId": session_id,
                "failedAt": _utc_now(),
                "failureArtifacts": record.get("failureArtifacts", {}),
            }
            (experiment_dir / "failure_diagnostics.json").write_text(
                json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8"
            )
        record["completedAt"] = _utc_now()
        result_path = experiment_dir / "collection_result.json"
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        record["resultPath"] = str(result_path)
    return record


# Controlled suspicious / attack workload exports
from backend.services.attack_workloads import (  # noqa: E402
    collect_auth_failure_workload,
    collect_bulk_transfer_workload,
    collect_connection_burst_workload,
    collect_periodic_beacon_workload,
    collect_port_scan_workload,
    collect_suspicious_workload,
    validate_auth_failure_config,
    validate_bulk_transfer_config,
    validate_connection_burst_config,
    validate_periodic_beacon_config,
    validate_port_scan_config,
)
