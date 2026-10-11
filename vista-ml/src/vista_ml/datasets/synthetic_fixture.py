"""Deterministic software-test fixtures; these records are never captured traffic."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from vista_ml.data.schema import REQUIRED_COLUMNS

FIXTURE_SCHEMA_VERSION = "vista-synthetic-flow-fixture-v1"
GENERATOR_VERSION = "1.0.0"
NAMESPACE = uuid.UUID("87e8287a-a6bf-4a1b-859e-24f51bbb7d7d")
NORMAL_LABELS = {
    "VoIP", "Video_Streaming", "Web_Browsing", "WhatsApp", "Email_IMAP", "ICMP"
}
ATTACK_LABELS = {
    "PORT_SCAN", "DOS", "BRUTE_FORCE", "C2_BEACONING", "DATA_EXFILTRATION"
}
FIXTURE_LABELS = NORMAL_LABELS | ATTACK_LABELS | {"NORMAL"}
EXTRA_COLUMNS = [
    "session_id", "spi_in", "spi_out", "origin_type", "label_granularity"
]
FEATURE_COLUMNS = [
    "packet_count", "byte_count", "flow_duration", "mean_packet_size",
    "std_packet_size", "min_packet_size", "max_packet_size",
    "mean_inter_arrival_time", "std_inter_arrival_time",
    "min_inter_arrival_time", "max_inter_arrival_time", "packets_per_second",
    "bytes_per_second", "forward_packet_count", "backward_packet_count",
    "forward_bytes", "backward_bytes", "direction_ratio",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_config(seed: Any, class_counts: Any) -> tuple[int, dict[str, int]]:
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be an integer in [0, 2^32-1].")
    if not isinstance(class_counts, dict) or not class_counts:
        raise ValueError("class_counts must be a non-empty mapping of label to positive row count.")
    counts: dict[str, int] = {}
    for label, count in class_counts.items():
        if label not in FIXTURE_LABELS:
            raise ValueError(f"Unsupported synthetic fixture label: {label!r}.")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"class_counts[{label!r}] must be a positive integer.")
        counts[label] = count
    if sum(counts.values()) > 10000:
        raise ValueError("A synthetic fixture is limited to 10000 rows.")
    return seed, counts


def generate_fixture_rows(seed: int, class_counts: dict[str, int]) -> pd.DataFrame:
    """Generate reproducible, internally consistent flow-shaped test rows."""
    seed, class_counts = _validate_config(seed, class_counts)
    rng = np.random.default_rng(seed)
    rows: list[dict[str, Any]] = []
    row_index = 0
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for label in sorted(class_counts):
        for _ in range(class_counts[label]):
            row_index += 1
            experiment_id = str(uuid.uuid5(NAMESPACE, f"{seed}:experiment:{row_index}"))
            session_id = str(uuid.uuid5(NAMESPACE, f"{seed}:session:{row_index}"))
            scenario_id = str(uuid.uuid5(NAMESPACE, f"{seed}:scenario:{row_index}"))
            flow_id = str(uuid.uuid5(NAMESPACE, f"{seed}:flow:{row_index}"))
            # SPIs are synthetic identifiers; every session owns one stable pair.
            spi_in = f"{int(rng.integers(1, 2**32)):08x}"
            spi_out = f"{int(rng.integers(1, 2**32)):08x}"
            while spi_out == spi_in:
                spi_out = f"{int(rng.integers(1, 2**32)):08x}"

            packet_count = int(rng.integers(4, 31))
            lengths = rng.integers(72, 1451, size=packet_count, endpoint=False)
            gaps = rng.uniform(0.01, 0.8, size=packet_count - 1)
            duration = float(gaps.sum())
            directions = rng.integers(0, 2, size=packet_count).astype(bool)
            forward_packets = int(directions.sum())
            backward_packets = packet_count - forward_packets
            forward_bytes = int(lengths[directions].sum())
            backward_bytes = int(lengths[~directions].sum())
            byte_count = int(lengths.sum())
            start = base_time + timedelta(seconds=row_index * 10)
            end = start + timedelta(seconds=duration)
            normal = label in NORMAL_LABELS or label == "NORMAL"

            rows.append({
                "experiment_id": experiment_id,
                "scenario_id": scenario_id,
                "flow_id": flow_id,
                "session_id": session_id,
                "timestamp_start": start.isoformat(),
                "timestamp_end": end.isoformat(),
                "traffic_type": "synthetic_benign" if normal else "synthetic_controlled_behavior",
                "attack_type": "none" if normal else label,
                "label": label,
                "label_granularity": "flow_fixture",
                "ipsec_mode": "tunnel",
                "ike_version": 2,
                "cipher": "aes256-gcm16",
                "integrity_algorithm": "aead",
                "dh_group": "modp2048",
                "pfs_enabled": True,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "flow_duration": duration,
                "mean_packet_size": float(lengths.mean()),
                "std_packet_size": float(lengths.std(ddof=0)),
                "min_packet_size": int(lengths.min()),
                "max_packet_size": int(lengths.max()),
                "mean_inter_arrival_time": float(gaps.mean()),
                "std_inter_arrival_time": float(gaps.std(ddof=0)),
                "min_inter_arrival_time": float(gaps.min()),
                "max_inter_arrival_time": float(gaps.max()),
                "packets_per_second": packet_count / duration,
                "bytes_per_second": byte_count / duration,
                "forward_packet_count": forward_packets,
                "backward_packet_count": backward_packets,
                "forward_bytes": forward_bytes,
                "backward_bytes": backward_bytes,
                "direction_ratio": forward_packets / packet_count,
                "spi_in": spi_in,
                "spi_out": spi_out,
                "origin_type": "synthetic_fixture",
            })
    frame = pd.DataFrame(rows, columns=REQUIRED_COLUMNS + EXTRA_COLUMNS)
    validate_fixture_frame(frame)
    return frame


def validate_fixture_frame(frame: pd.DataFrame) -> None:
    required = set(REQUIRED_COLUMNS + EXTRA_COLUMNS)
    missing_columns = sorted(required - set(frame.columns))
    if missing_columns:
        raise ValueError(f"Fixture is missing required columns: {missing_columns}.")
    if frame.empty:
        raise ValueError("Fixture contains no records.")
    if frame["origin_type"].isna().any() or not frame["origin_type"].eq("synthetic_fixture").all():
        raise ValueError("Synthetic fixture origin_type must be explicit on every row.")
    for column in ("experiment_id", "scenario_id", "flow_id", "session_id"):
        values = frame[column]
        if values.isna().any() or values.astype(str).str.strip().eq("").any():
            raise ValueError(f"{column} contains a missing identifier.")
        if column != "session_id" and values.duplicated().any():
            raise ValueError(f"{column} contains duplicate identifiers.")
    if not frame["label"].isin(FIXTURE_LABELS).all():
        raise ValueError("Fixture contains an unsupported label.")
    for column in FEATURE_COLUMNS:
        values = pd.to_numeric(frame[column], errors="coerce")
        if values.isna().any() or not np.isfinite(values.to_numpy(dtype=float)).all():
            raise ValueError(f"Feature {column!r} contains missing or non-finite values.")
    for column in ("spi_in", "spi_out"):
        if not frame[column].astype(str).str.fullmatch(r"[0-9a-f]{8}").all():
            raise ValueError(f"{column} must contain synthetic 32-bit hexadecimal SPI identifiers.")
    if (frame["spi_in"].astype(str) == frame["spi_out"].astype(str)).any():
        raise ValueError("Inbound and outbound SPI identifiers must differ.")
    for session_id, group in frame.groupby("session_id", sort=False):
        if group["spi_in"].nunique() != 1 or group["spi_out"].nunique() != 1:
            raise ValueError(f"Session {session_id} has inconsistent SPI values.")
    starts = pd.to_datetime(frame["timestamp_start"], utc=True, errors="coerce")
    ends = pd.to_datetime(frame["timestamp_end"], utc=True, errors="coerce")
    if starts.isna().any() or ends.isna().any() or not (ends > starts).all():
        raise ValueError("Fixture timestamps must be valid and each end must follow its start.")
    durations = (ends - starts).dt.total_seconds().to_numpy()
    if not np.allclose(durations, frame["flow_duration"].astype(float), rtol=0, atol=1e-6):
        raise ValueError("timestamp and flow_duration relationships are inconsistent.")
    if not np.array_equal(
        frame["packet_count"].astype(int).to_numpy(),
        frame["forward_packet_count"].astype(int).to_numpy()
        + frame["backward_packet_count"].astype(int).to_numpy(),
    ):
        raise ValueError("Directional packet counts do not sum to packet_count.")
    if not np.array_equal(
        frame["byte_count"].astype(int).to_numpy(),
        frame["forward_bytes"].astype(int).to_numpy()
        + frame["backward_bytes"].astype(int).to_numpy(),
    ):
        raise ValueError("Directional byte counts do not sum to byte_count.")


def write_synthetic_fixture(
    output_dir: str | Path,
    *,
    seed: int,
    class_counts: dict[str, int],
) -> dict[str, Any]:
    """Write a new fixture directory. Existing output is never overwritten."""
    seed, class_counts = _validate_config(seed, class_counts)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=False)
    frame = generate_fixture_rows(seed, class_counts)
    csv_path = destination / "flows.csv"
    frame.to_csv(csv_path, index=False, lineterminator="\n")
    manifest = {
        "manifestVersion": "vista-synthetic-fixture-manifest-v1",
        "datasetId": str(uuid.uuid5(NAMESPACE, f"dataset:{seed}:{json.dumps(class_counts, sort_keys=True)}")),
        "datasetVersion": "1.0.0",
        "schemaVersion": FIXTURE_SCHEMA_VERSION,
        "featureSchemaVersion": "vista-flow-v1",
        "originType": "synthetic_fixture",
        "admissionStatus": "SYNTHETIC_FIXTURE",
        "generator": {"name": "vista_ml.datasets.synthetic_fixture", "version": GENERATOR_VERSION},
        "seed": seed,
        "configuration": {"classCounts": class_counts},
        "labelSemantics": "Synthetic class-conditioned flow-shaped software-test data; no network traffic was generated or captured.",
        "labelGranularity": "flow_fixture",
        "featureColumns": FEATURE_COLUMNS,
        "metadataColumnsExcludedFromFeatures": [
            "experiment_id", "scenario_id", "flow_id", "session_id", "label",
            "attack_type", "traffic_type", "spi_in", "spi_out", "origin_type",
            "label_granularity",
        ],
        "classCounts": frame["label"].value_counts().sort_index().to_dict(),
        "rowCount": int(len(frame)),
        "artifacts": [{
            "path": csv_path.name,
            "sizeBytes": csv_path.stat().st_size,
            "sha256": _sha256(csv_path),
            "sourceRunId": str(uuid.uuid5(NAMESPACE, f"dataset:{seed}:{json.dumps(class_counts, sort_keys=True)}")),
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }],
        "split": {"status": "NOT_CREATED", "reason": "Fixtures are software-test inputs, not evaluation evidence."},
        "limitations": [
            "Values are generated by a deterministic software fixture; no PCAP, eBPF, endpoint, or testbed evidence exists.",
            "Rows must not be mixed with collected records or used as real-world model evaluation evidence.",
            "Synthetic SPIs and protocol metadata are identifiers for contract testing only.",
        ],
    }
    manifest_path = destination / "dataset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "dataset_manifest.sha256").write_text(
        f"{_sha256(manifest_path)}  {manifest_path.name}\n", encoding="ascii"
    )
    return manifest


def validate_fixture_artifacts(manifest_path: str | Path) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("originType") != "synthetic_fixture":
        raise ValueError("Manifest originType must be synthetic_fixture.")
    if manifest.get("admissionStatus") != "SYNTHETIC_FIXTURE":
        raise ValueError("Synthetic fixtures cannot use a collected-data admission status.")
    if manifest.get("schemaVersion") != FIXTURE_SCHEMA_VERSION:
        raise ValueError("Unsupported synthetic fixture schema version.")
    actual_manifest_hash = _sha256(path)
    hash_sidecar = path.with_name("dataset_manifest.sha256")
    expected_manifest_hash = hash_sidecar.read_text(encoding="ascii").split()[0]
    if actual_manifest_hash != expected_manifest_hash:
        raise ValueError("Dataset manifest SHA-256 mismatch.")
    if len(manifest.get("artifacts", [])) != 1:
        raise ValueError("Fixture manifest must reference exactly one CSV artifact.")
    artifact = manifest["artifacts"][0]
    data_path = path.parent / artifact["path"]
    if not data_path.is_file():
        raise ValueError("Fixture CSV artifact is missing.")
    if data_path.stat().st_size != artifact.get("sizeBytes") or _sha256(data_path) != artifact.get("sha256"):
        raise ValueError("Fixture CSV artifact size or SHA-256 mismatch.")
    frame = pd.read_csv(data_path)
    validate_fixture_frame(frame)
    if len(frame) != manifest.get("rowCount"):
        raise ValueError("Fixture row count does not match manifest.")
    if frame["label"].value_counts().sort_index().to_dict() != manifest.get("classCounts"):
        raise ValueError("Fixture class counts do not match manifest.")
    return {"status": "SYNTHETIC_FIXTURE", "rows": len(frame), "sha256": artifact["sha256"]}
