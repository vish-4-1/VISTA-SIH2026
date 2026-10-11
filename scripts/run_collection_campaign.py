#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services import workload_collection as collector


MAX_SESSIONS = 15
MAX_RUNTIME_SECONDS = 900
DEFAULT_WORKLOADS = ("icmpv4", "tcp_marker")
WORKLOADS = DEFAULT_WORKLOADS
IDLE_BETWEEN_WORKLOADS_SECONDS = 1.0

PROFILE_SPACE = [
    {"count": count, "interval_seconds": interval, "payload_bytes": size}
    for count in (3, 5, 7, 10)
    for interval in (0.2, 0.4, 0.6, 0.8)
    for size in (32, 64, 128, 256, 512, 1024, 1400)
]

HTTP_GET_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "path": path,
        "method": "GET",
        "payload_bytes": 0,
        "expected_status": 200,
    }
    for count in (3, 4, 5, 6, 7)
    for interval in (0.2, 0.3, 0.4)
    for path in ("/api/v1/telemetry", "/api/v1/status", "/metrics", "/health", "/data/query")
]

HTTP_POST_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "path": path,
        "method": "POST",
        "payload_bytes": payload,
        "expected_status": 200,
    }
    for count in (2, 3, 4, 5)
    for interval in (0.25, 0.35, 0.45)
    for path in ("/api/v1/upload", "/data/sensor", "/data/event", "/api/v1/submit", "/log/event")
    for payload in (64, 128, 256, 512)
]

WORKLOAD_PROFILES: dict[str, list[dict[str, Any]]] = {
    "icmpv4": PROFILE_SPACE,
    "tcp_marker": PROFILE_SPACE,
    "http": HTTP_GET_PROFILE_SPACE,
    "http_get": HTTP_GET_PROFILE_SPACE,
    "http_post": HTTP_POST_PROFILE_SPACE,
}

VARIED_PROFILE_SPACE = [
    {"count": count, "interval_seconds": interval, "payload_bytes": size}
    for count in (4, 6, 8, 12)
    for interval in (0.15, 0.35, 0.55, 0.75)
    for size in (48, 96, 192, 384, 768, 1200)
]

VARIED_HTTP_GET_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "path": path,
        "method": "GET",
        "payload_bytes": 0,
        "expected_status": 200,
    }
    for count in (2, 4, 6, 8)
    for interval in (0.15, 0.25, 0.35)
    for path in ("/metrics", "/health", "/data/query", "/api/v1/status", "/api/v1/telemetry")
]

VARIED_HTTP_POST_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "path": path,
        "method": "POST",
        "payload_bytes": payload,
        "expected_status": 200,
    }
    for count in (3, 4, 6)
    for interval in (0.2, 0.3, 0.4)
    for path in ("/data/sensor", "/data/event", "/api/v1/submit", "/log/event", "/api/v1/upload")
    for payload in (96, 192, 384, 768)
]

RTP_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "payload_bytes": payload,
        "ssrc": 0x11223344 + idx,
        "payload_type": 0,
        "start_sequence": 1000 + idx * 100,
    }
    for idx, (count, interval, payload) in enumerate([
        (10, 0.02, 160),
        (15, 0.02, 160),
        (20, 0.02, 160),
        (10, 0.04, 320),
        (15, 0.03, 240),
        (25, 0.02, 160),
    ])
]

VARIED_RTP_PROFILE_SPACE = [
    {
        "count": count,
        "interval_seconds": interval,
        "payload_bytes": payload,
        "ssrc": 0x22334455 + idx,
        "payload_type": 0,
        "start_sequence": 2000 + idx * 100,
    }
    for idx, (count, interval, payload) in enumerate([
        (8, 0.03, 160),
        (12, 0.025, 240),
        (18, 0.02, 160),
        (24, 0.02, 320),
    ])
]

WORKLOAD_PROFILES: dict[str, list[dict[str, Any]]] = {
    "icmpv4": PROFILE_SPACE,
    "tcp_marker": PROFILE_SPACE,
    "http": HTTP_GET_PROFILE_SPACE,
    "http_get": HTTP_GET_PROFILE_SPACE,
    "http_post": HTTP_POST_PROFILE_SPACE,
    "rtp_voip": RTP_PROFILE_SPACE,
}

VARIED_WORKLOAD_PROFILES: dict[str, list[dict[str, Any]]] = {
    "icmpv4": VARIED_PROFILE_SPACE,
    "tcp_marker": VARIED_PROFILE_SPACE,
    "http": VARIED_HTTP_GET_PROFILE_SPACE,
    "http_get": VARIED_HTTP_GET_PROFILE_SPACE,
    "http_post": VARIED_HTTP_POST_PROFILE_SPACE,
    "rtp_voip": VARIED_RTP_PROFILE_SPACE,
}

WORKLOAD_SETS: dict[str, tuple[str, ...]] = {
    "icmp_tcp": ("icmpv4", "tcp_marker"),
    "http": ("http_get", "http_post"),
    "all": ("icmpv4", "tcp_marker", "http_get", "http_post"),
    "unified": ("icmpv4", "tcp_marker", "http_get", "http_post"),
    "rtp": ("rtp_voip",),
    "expanded": ("icmpv4", "tcp_marker", "http_get", "http_post", "rtp_voip"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_campaign_schedule(
    session_count: int,
    seed: int,
    workload_set: str = "icmp_tcp",
    recipe_mode: str = "standard",
) -> list[dict[str, Any]]:
    if not 1 <= session_count <= MAX_SESSIONS:
        raise ValueError(f"sessions must be in [1, {MAX_SESSIONS}].")
    workloads = WORKLOAD_SETS.get(workload_set, WORKLOAD_SETS["icmp_tcp"])
    profiles_pool = (
        VARIED_WORKLOAD_PROFILES if recipe_mode == "varied" else WORKLOAD_PROFILES
    )
    rng = random.Random(seed)
    schedules: list[dict[str, Any]] = []
    for session_index in range(session_count):
        profiles = {}
        for workload in workloads:
            profile_order = profiles_pool[workload].copy()
            rng.shuffle(profile_order)
            profiles[workload] = profile_order[session_index % len(profile_order)]
        order = list(workloads)
        rng.shuffle(order)
        schedules.append({
            "sessionIndex": session_index,
            "workloadOrder": order,
            "profiles": profiles,
        })
    return schedules


def _dispatch_workload(workload: str, configuration: dict[str, Any]) -> dict[str, Any]:
    if workload == "tcp_marker":
        configuration.setdefault("targetLabel", "controlled_tcp_marker")
        configuration.setdefault("workloadSubtype", "tcp_marker")
        configuration.setdefault("labelSchemaVersion", "vista-target-label-schema-v1")
        return collector.collect_tcp_marker_workload(configuration)
    elif workload == "icmpv4":
        configuration.setdefault("targetLabel", "controlled_icmpv4")
        configuration.setdefault("workloadSubtype", "icmpv4_echo")
        configuration.setdefault("labelSchemaVersion", "vista-target-label-schema-v1")
        return collector.collect_icmp_workload(configuration)
    elif workload in {"http", "http_get", "http_post"}:
        configuration.setdefault("targetLabel", "controlled_http")
        configuration.setdefault(
            "workloadSubtype",
            workload if workload in {"http_get", "http_post"} else "http_get",
        )
        configuration.setdefault("labelSchemaVersion", "vista-target-label-schema-v1")
        return collector.collect_http_workload(configuration)
    elif workload == "rtp_voip":
        configuration.setdefault("targetLabel", "controlled_rtp_voip")
        configuration.setdefault("workloadSubtype", "rtp_voip")
        configuration.setdefault("labelSchemaVersion", "vista-target-label-schema-v2")
        return collector.collect_rtp_workload(configuration)
    raise ValueError(f"Unknown workload: {workload}")


def _preflight() -> dict[str, Any]:
    docker_info = subprocess.run(
        [collector.vpn_testbed._docker_path(), "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if docker_info.returncode != 0 or not docker_info.stdout.strip():
        raise collector.WorkloadCollectionError(
            "Docker preflight failed: "
            f"{docker_info.stderr.strip() or docker_info.stdout.strip()}"
        )
    endpoints = {
        name: collector._inspect_container(name)
        for name in collector.CONTAINERS
    }
    utilities = {}
    for name, commands in {
        "pc1": ("tcpdump", "ping", "swanctl", "perl"),
        "pc2": ("tcpdump", "nc", "swanctl", "perl"),
    }.items():
        check = collector._run_docker(
            "exec", name, "sh", "-c",
            " && ".join(f"command -v {command} >/dev/null" for command in commands),
        )
        if check.returncode != 0:
            raise collector.WorkloadCollectionError(
                f"Preflight utilities missing on {name}: "
                f"{check.stderr.strip() or check.stdout.strip()}"
            )
        utilities[name] = list(commands)
    sa = {
        name: collector._read_live_sa(name)
        for name in collector.CONTAINERS
    }
    return {
        "dockerServerVersion": docker_info.stdout.strip(),
        "endpoints": endpoints,
        "utilities": utilities,
        "tunnelEstablished": all(
            value.get("established")
            and value.get("child", {}).get("state") == "INSTALLED"
            for value in sa.values()
        ),
        "ikeSaIdentitySha256": collector._sa_lifecycle_identity(
            sa["pc1"]
        )["ikeSaIdentitySha256"],
    }


def _collect_observations(
    campaign_dir: Path,
    session_runs: list[dict[str, Any]],
) -> tuple[Path, Path, dict[str, Any]] | None:
    observations = []
    schema_version = "vista-strongswan-experiment-v2"
    for session in session_runs:
        for result in session["experiments"]:
            if result.get("status") != "PASS":
                continue
            experiment_dir = Path(result["artifactDirectory"])
            manifest_path = experiment_dir / "experiment_manifest.json"
            if not manifest_path.is_file():
                continue
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            observation = json.loads(json.dumps(manifest["observations"][0]))
            observation_dir = (
                campaign_dir / "artifacts"
                / observation["session_id"] / observation["experiment_id"]
            )
            observation_dir.mkdir(parents=True, exist_ok=False)
            artifact_fields = [
                ("capture", "path"),
                ("capture", "raw_pcap_path"),
                ("ground_truth", "record_path"),
                ("workload", "measurement_path"),
                ("vpn", "negotiated_sa_evidence_path"),
            ]
            artifact_paths = [
                (section, field, observation[section][field])
                for section, field in artifact_fields
            ]
            artifact_paths.append((
                "observation", "session_record_path",
                observation["session_record_path"],
            ))
            for section, field, relative_path in artifact_paths:
                source = (experiment_dir / relative_path).resolve()
                if not source.is_file() or experiment_dir.resolve() not in source.parents:
                    raise collector.WorkloadCollectionError(
                        f"Campaign source artifact is missing or escapes experiment directory: {relative_path}"
                    )
                target = observation_dir / source.name
                shutil.copy2(source, target)
                if target.read_bytes() != source.read_bytes():
                    raise collector.WorkloadCollectionError(
                        f"Campaign artifact copy did not verify: {source.name}"
                    )
                rewritten = str(
                    Path("artifacts")
                    / observation["session_id"]
                    / observation["experiment_id"]
                    / target.name
                )
                if section == "observation":
                    observation["session_record_path"] = rewritten
                else:
                    observation[section][field] = rewritten
            observations.append(observation)
    if not observations:
        return None

    manifest_path = campaign_dir / "campaign_manifest.json"
    manifest = {
        "manifest_version": schema_version,
        "dataset_id": campaign_dir.name,
        "feature_schema_version": "vista-flow-v1",
        "extractor_version": "vista-ml-pcap-features-v1",
        "observations": observations,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    output_dir = campaign_dir / "dataset_preparation"
    command = [
        sys.executable,
        str(ROOT / "vista-ml" / "scripts" / "prepare_experiment_dataset.py"),
        "--manifest", str(manifest_path),
        "--output-dir", str(output_dir),
    ]
    validation = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    report_path = output_dir / "dataset_report.json"
    if validation.returncode not in {0, 2} or not report_path.is_file():
        raise collector.WorkloadCollectionError(
            "Campaign dataset preparation failed: "
            f"{validation.stderr.strip() or validation.stdout.strip() or validation.returncode}"
        )
    return manifest_path, report_path, json.loads(report_path.read_text(encoding="utf-8"))


def run_campaign(
    session_count: int,
    seed: int,
    campaign_id: str | None = None,
    rerun_of: str | None = None,
    max_runtime_seconds: int = MAX_RUNTIME_SECONDS,
    workload_set: str = "icmp_tcp",
    recipe_mode: str = "standard",
) -> dict[str, Any]:
    if not 1 <= session_count <= MAX_SESSIONS:
        raise ValueError(f"sessions must be in [1, {MAX_SESSIONS}].")
    if not 60 <= max_runtime_seconds <= MAX_RUNTIME_SECONDS:
        raise ValueError(
            f"max_runtime_seconds must be in [60, {MAX_RUNTIME_SECONDS}]."
        )
    campaign_id = str(uuid.uuid4()) if campaign_id is None else str(campaign_id)
    if uuid.UUID(campaign_id).version != 4:
        raise ValueError("campaign_id must be a UUIDv4.")
    if rerun_of is not None and uuid.UUID(rerun_of).version != 4:
        raise ValueError("rerun_of must be a UUIDv4 campaign ID.")
    campaign_root = collector.COLLECTION_ROOT / "campaigns"
    campaign_dir = campaign_root / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=False)
    started_at = _utc_now()
    deadline = time.monotonic() + max_runtime_seconds
    summary: dict[str, Any] = {
        "schemaVersion": "vista-collection-campaign-v1",
        "campaignId": campaign_id,
        "rerunOf": rerun_of,
        "status": "RUNNING",
        "requestedSessions": session_count,
        "workloadSet": workload_set,
        "recipeMode": recipe_mode,
        "seed": seed,
        "startedAt": started_at,
        "maxRuntimeSeconds": max_runtime_seconds,
        "schedule": make_campaign_schedule(
            session_count, seed, workload_set=workload_set, recipe_mode=recipe_mode
        ),
        "sessions": [],
        "errors": [],
        "artifactDirectory": str(campaign_dir),
    }
    try:
        summary["preflight"] = _preflight()
        for plan in summary["schedule"]:
            if time.monotonic() >= deadline:
                summary["errors"].append("campaign_runtime_deadline_reached")
                break
            session_id = str(uuid.uuid4())
            session = {
                "sessionId": session_id,
                "sessionIndex": plan["sessionIndex"],
                "workloadOrder": plan["workloadOrder"],
                "profiles": plan["profiles"],
                "status": "BLOCKED",
                "experiments": [],
            }
            try:
                reconnect = collector.reestablish_collection_sa()
                session["saReestablishment"] = reconnect
                session_context = {
                    "previousIkeSaIdentitySha256": reconnect[
                        "previousIkeSaIdentitySha256"
                    ],
                    "reestablishedAt": reconnect["reestablishedAt"],
                }
                session["status"] = "RUNNING"
                for workload_index, workload in enumerate(plan["workloadOrder"]):
                    if time.monotonic() >= deadline:
                        session["status"] = "BLOCKED"
                        session.setdefault("errors", []).append(
                            "campaign_runtime_deadline_reached_before_experiment"
                        )
                        break
                    if workload_index > 0 and IDLE_BETWEEN_WORKLOADS_SECONDS > 0:
                        time.sleep(IDLE_BETWEEN_WORKLOADS_SECONDS)
                    experiment_id = str(uuid.uuid4())
                    configuration = {
                        "profiles": [plan["profiles"][workload]],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                        "sessionContext": session_context,
                    }
                    run = _dispatch_workload(workload, configuration)
                    session["experiments"].append(run)
                if len(session["experiments"]) == len(plan["workloadOrder"]) and all(
                    run.get("status") == "PASS"
                    for run in session["experiments"]
                ):
                    session["status"] = "PASS"
                    session["independenceStatus"] = "VERIFIED_DISTINCT_IKE_SA"
                elif session["status"] != "BLOCKED":
                    session["status"] = "FAIL"
            except Exception as exc:
                session["status"] = "FAIL"
                session.setdefault("errors", []).append(str(exc))
                try:
                    restored = collector.vpn_testbed._establish_sas()
                    session["baselineTunnelRestored"] = bool(
                        restored.get("established")
                        and restored.get("child", {}).get("state") == "INSTALLED"
                    )
                except Exception as restore_error:
                    session["baselineTunnelRestored"] = False
                    session["errors"].append(
                        f"tunnel recovery failed: {restore_error}"
                    )
                    summary["errors"].append("testbed_recovery_failed; campaign stopped")
                    summary["sessions"].append(session)
                    break
            summary["sessions"].append(session)

        summary["completedSessions"] = sum(
            session["status"] == "PASS" for session in summary["sessions"]
        )
        summary["failedSessions"] = sum(
            session["status"] == "FAIL" for session in summary["sessions"]
        )
        summary["blockedSessions"] = sum(
            session["status"] == "BLOCKED" for session in summary["sessions"]
        )
        summary["independentlyVerifiedSessions"] = sum(
            session.get("independenceStatus") == "VERIFIED_DISTINCT_IKE_SA"
            and session["status"] == "PASS"
            for session in summary["sessions"]
        )
        prepared = _collect_observations(campaign_dir, summary["sessions"])
        if prepared:
            manifest_path, report_path, report = prepared
            summary["datasetPreparation"] = {
                "status": report["status"],
                "acceptedObservations": report["accepted_observations"],
                "quarantinedObservations": report["quarantined_observations"],
                "independentSessions": report["independent_session_count"],
                "classDistribution": report["class_distribution"],
                "blocker": report["blocker"],
                "manifestPath": str(manifest_path),
                "reportPath": str(report_path),
            }
        if summary["errors"]:
            summary["status"] = "PARTIAL"
        elif summary["completedSessions"] == session_count:
            summary["status"] = "PASS"
        else:
            summary["status"] = "PARTIAL"
    except Exception as exc:
        summary["status"] = "BLOCKED"
        summary["errors"].append(str(exc))
    summary["completedAt"] = _utc_now()
    summary_path = campaign_dir / "campaign_summary.json"
    summary["summaryPath"] = str(summary_path)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run a bounded, seeded collection campaign. Every session re-establishes "
            "the dedicated PC1-PC2 IKE_SA before collecting workload classes."
        )
    )
    parser.add_argument("--sessions", type=int, default=15)
    parser.add_argument("--seed", type=int, default=26160)
    parser.add_argument("--campaign-id")
    parser.add_argument(
        "--rerun-of",
        help="Optional prior campaign UUIDv4; all reruns get a new campaign ID and artifacts.",
    )
    parser.add_argument("--max-runtime-seconds", type=int, default=900)
    parser.add_argument(
        "--workload-set",
        "--workload",
        dest="workload_set",
        choices=["icmp_tcp", "http", "all", "unified", "rtp", "expanded"],
        default="unified",
        help="Workload set to collect: unified (default, all 3 classes with GET and POST), icmp_tcp, http, all, rtp, or expanded.",
    )
    parser.add_argument(
        "--recipe-mode",
        choices=["standard", "varied"],
        default="standard",
        help="Workload recipe profile mode: standard (Phase 8 baseline) or varied (changed payload sizes, counts, intervals).",
    )
    args = parser.parse_args()
    result = run_campaign(
        args.sessions,
        args.seed,
        args.campaign_id,
        args.rerun_of,
        args.max_runtime_seconds,
        workload_set=args.workload_set,
        recipe_mode=args.recipe_mode,
    )
    print(json.dumps(result, indent=2))
    if result["status"] not in {"PASS", "PARTIAL"}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
