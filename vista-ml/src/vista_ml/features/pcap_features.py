from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from vista_ml.data.schema import REQUIRED_COLUMNS


PacketLike = dict[str, Any]


def _read_packet_table(path: str | Path | pd.DataFrame) -> pd.DataFrame:
    if isinstance(path, pd.DataFrame):
        return path.copy()

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP packet source not found: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(file_path)
    if suffix in {".parquet", ".pq"}:
        return pd.read_parquet(file_path)
    if suffix == ".json":
        return pd.read_json(file_path)
    raise ValueError(
        "Unsupported packet file format. Use CSV, JSON, or Parquet with packet-level rows."
    )


def _ensure_flow_id(frame: pd.DataFrame) -> pd.DataFrame:
    if "flow_id" not in frame.columns:
        source_cols = [
            col for col in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
            if col in frame.columns
        ]
        if source_cols:
            frame = frame.copy()
            frame["flow_id"] = (
                frame[source_cols].fillna("-").astype(str).agg(lambda row: "|".join(row), axis=1)
            )
        else:
            frame = frame.copy()
            frame["flow_id"] = "unknown_flow_" + np.arange(len(frame)).astype(str)
    return frame


def _compute_flow_features(packet_df: pd.DataFrame) -> pd.DataFrame:
    data = packet_df.copy()
    data = _ensure_flow_id(data)

    if "timestamp" in data.columns:
        data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    else:
        data["timestamp"] = pd.NaT

    if "packet_length" not in data.columns and "packet_len" in data.columns:
        data["packet_length"] = data["packet_len"]
    if "packet_length" not in data.columns and "length" in data.columns:
        data["packet_length"] = data["length"]
    if "packet_length" not in data.columns:
        data["packet_length"] = 0

    data["packet_length"] = pd.to_numeric(data["packet_length"], errors="coerce").fillna(0)

    grouped = (
        data.groupby("flow_id", dropna=False)
        .agg(
            packet_count=("packet_length", "size"),
            byte_count=("packet_length", "sum"),
            timestamp_start=("timestamp", "min"),
            timestamp_end=("timestamp", "max"),
            mean_packet_size=("packet_length", "mean"),
            std_packet_size=("packet_length", "std"),
            min_packet_size=("packet_length", "min"),
            max_packet_size=("packet_length", "max"),
        )
        .reset_index()
    )

    grouped["flow_duration"] = (
        (grouped["timestamp_end"] - grouped["timestamp_start"]).dt.total_seconds()
        .fillna(0.0)
    )
    grouped["packets_per_second"] = np.where(
        grouped["flow_duration"] > 0,
        grouped["packet_count"] / grouped["flow_duration"],
        0.0,
    )
    grouped["bytes_per_second"] = np.where(
        grouped["flow_duration"] > 0,
        grouped["byte_count"] / grouped["flow_duration"],
        0.0,
    )

    if "direction" in data.columns:
        direction_summary = (
            data.groupby("flow_id")
            .agg(
                forward_packet_count=("direction", lambda s: int((s == "forward").sum())),
                backward_packet_count=("direction", lambda s: int((s == "backward").sum())),
            )
            .reset_index()
        )
        grouped = grouped.merge(direction_summary, on="flow_id", how="left")
        grouped["forward_bytes"] = grouped.get("forward_packet_count", 0).fillna(0) * grouped["mean_packet_size"]
        grouped["backward_bytes"] = grouped.get("backward_packet_count", 0).fillna(0) * grouped["mean_packet_size"]
    else:
        grouped["forward_packet_count"] = 0
        grouped["backward_packet_count"] = 0
        grouped["forward_bytes"] = 0.0
        grouped["backward_bytes"] = 0.0

    grouped["direction_ratio"] = np.where(
        grouped["forward_packet_count"] + grouped["backward_packet_count"] > 0,
        grouped["forward_packet_count"] / (grouped["forward_packet_count"] + grouped["backward_packet_count"]),
        0.0,
    )

    if "inter_arrival_time" in data.columns:
        inter_summary = data.groupby("flow_id")["inter_arrival_time"].agg([
            "mean",
            "std",
            "min",
            "max",
        ])
        inter_summary = inter_summary.rename(columns={
            "mean": "mean_inter_arrival_time",
            "std": "std_inter_arrival_time",
            "min": "min_inter_arrival_time",
            "max": "max_inter_arrival_time",
        })
        grouped = grouped.merge(inter_summary, on="flow_id", how="left")
    else:
        grouped["mean_inter_arrival_time"] = 0.0
        grouped["std_inter_arrival_time"] = 0.0
        grouped["min_inter_arrival_time"] = 0.0
        grouped["max_inter_arrival_time"] = 0.0

    grouped["experiment_id"] = "pcap_experiment"
    grouped["scenario_id"] = "pcap_scenario"
    grouped["traffic_type"] = "unknown"
    grouped["attack_type"] = "none"
    grouped["label"] = "UNKNOWN"
    grouped["ipsec_mode"] = "unknown"
    grouped["ike_version"] = "unknown"
    grouped["cipher"] = "unknown"
    grouped["integrity_algorithm"] = "unknown"
    grouped["dh_group"] = "unknown"
    grouped["pfs_enabled"] = False
    grouped["ebpf_event_count"] = np.nan
    grouped["socket_event_count"] = np.nan
    grouped["process_event_count"] = np.nan
    grouped["network_event_count"] = np.nan
    grouped["unique_process_count"] = np.nan

    canonical_columns = [
        "experiment_id",
        "scenario_id",
        "flow_id",
        "timestamp_start",
        "timestamp_end",
        "traffic_type",
        "attack_type",
        "label",
        "ipsec_mode",
        "ike_version",
        "cipher",
        "integrity_algorithm",
        "dh_group",
        "pfs_enabled",
        "packet_count",
        "byte_count",
        "flow_duration",
        "mean_packet_size",
        "std_packet_size",
        "min_packet_size",
        "max_packet_size",
        "mean_inter_arrival_time",
        "std_inter_arrival_time",
        "min_inter_arrival_time",
        "max_inter_arrival_time",
        "packets_per_second",
        "bytes_per_second",
        "forward_packet_count",
        "backward_packet_count",
        "forward_bytes",
        "backward_bytes",
        "direction_ratio",
        "ebpf_event_count",
        "socket_event_count",
        "process_event_count",
        "network_event_count",
        "unique_process_count",
    ]
    for col in canonical_columns:
        if col not in grouped.columns:
            grouped[col] = np.nan
    return grouped[canonical_columns]


def extract_flow_features(pcap_path: str | Path | pd.DataFrame) -> pd.DataFrame:
    """Extract flow statistics from packet-level capture data.

    This interface is intentionally lightweight and avoids packet payload inspection.
    It accepts either a path or an in-memory DataFrame of packet-level rows with timestamps
    and packet lengths. Fields such as src_ip, dst_ip, src_port, dst_port, protocol, and
    flow_id are used for flow grouping when available; otherwise a synthetic flow identifier
    is created.
    """
    packet_df = _read_packet_table(pcap_path)
    if packet_df.empty:
        return pd.DataFrame(columns=[
            col for col in REQUIRED_COLUMNS if col != "label"
        ] + ["ebpf_event_count", "socket_event_count", "process_event_count", "network_event_count", "unique_process_count"])
    return _compute_flow_features(packet_df)
