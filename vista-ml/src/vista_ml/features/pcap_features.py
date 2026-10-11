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
        required = {"src_ip", "dst_ip", "protocol"}
        if not required.issubset(source_cols):
            raise ValueError(
                "Packet rows need flow_id or source/destination IP addresses and protocol."
            )
        frame = frame.copy()
        for column in ("src_port", "dst_port"):
            if column not in frame.columns:
                frame[column] = 0
        flow_ids = []
        for row in frame.itertuples(index=False):
            values = row._asdict()
            endpoints = sorted(
                (
                    (str(values["src_ip"]), int(values["src_port"])),
                    (str(values["dst_ip"]), int(values["dst_port"])),
                )
            )
            flow_ids.append(
                f"{values['protocol']}|{endpoints[0][0]}:{endpoints[0][1]}"
                f"|{endpoints[1][0]}:{endpoints[1][1]}"
            )
        frame["flow_id"] = flow_ids
    return frame


def _compute_flow_features(packet_df: pd.DataFrame) -> pd.DataFrame:
    data = packet_df.copy()
    data = _ensure_flow_id(data)

    if "timestamp" not in data.columns:
        raise ValueError("Packet rows need timestamps to match the runtime flow schema.")
    data["timestamp"] = pd.to_datetime(
        data["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    if data["timestamp"].isna().any():
        raise ValueError("Packet rows contain missing or invalid timestamps.")

    if "packet_length" not in data.columns and "packet_len" in data.columns:
        data["packet_length"] = data["packet_len"]
    if "packet_length" not in data.columns and "length" in data.columns:
        data["packet_length"] = data["length"]
    if "packet_length" not in data.columns:
        raise ValueError("Packet rows need packet_length, packet_len, or length.")

    data["packet_length"] = pd.to_numeric(data["packet_length"], errors="coerce")
    if data["packet_length"].isna().any() or (data["packet_length"] <= 0).any():
        raise ValueError("Packet rows contain missing, invalid, or non-positive packet lengths.")
    if "direction" not in data.columns:
        if not {"src_ip", "dst_ip"}.issubset(data.columns):
            raise ValueError("Packet rows need direction or source/destination IP addresses.")
        if "src_port" not in data.columns:
            data["src_port"] = 0
        if "dst_port" not in data.columns:
            data["dst_port"] = 0
        data["direction"] = np.where(
            [
                (str(src_ip), int(src_port)) <= (str(dst_ip), int(dst_port))
                for src_ip, dst_ip, src_port, dst_port in zip(
                    data["src_ip"], data["dst_ip"], data["src_port"], data["dst_port"]
                )
            ],
            "forward",
            "backward",
        )
    if not data["direction"].isin({"forward", "backward"}).all():
        raise ValueError("Packet direction must be 'forward' or 'backward'.")
    data["forward_length"] = np.where(
        data["direction"] == "forward", data["packet_length"], 0
    )
    data["backward_length"] = np.where(
        data["direction"] == "backward", data["packet_length"], 0
    )

    grouped = (
        data.groupby("flow_id", dropna=False, sort=False)
        .agg(
            packet_count=("packet_length", "size"),
            byte_count=("packet_length", "sum"),
            timestamp_start=("timestamp", "min"),
            timestamp_end=("timestamp", "max"),
            mean_packet_size=("packet_length", "mean"),
            std_packet_size=("packet_length", lambda values: values.std(ddof=0)),
            min_packet_size=("packet_length", "min"),
            max_packet_size=("packet_length", "max"),
            forward_packet_count=("direction", lambda values: int((values == "forward").sum())),
            backward_packet_count=("direction", lambda values: int((values == "backward").sum())),
            forward_bytes=("forward_length", "sum"),
            backward_bytes=("backward_length", "sum"),
        )
        .reset_index()
    )

    grouped["flow_duration"] = (
        (grouped["timestamp_end"] - grouped["timestamp_start"])
        .dt.total_seconds()
        .round(4)
    )
    grouped["mean_packet_size"] = grouped["mean_packet_size"].round(1)
    grouped["std_packet_size"] = grouped["std_packet_size"].round(1)
    grouped["packets_per_second"] = np.where(
        grouped["flow_duration"] > 0,
        grouped["packet_count"] / grouped["flow_duration"],
        np.nan,
    )
    grouped["bytes_per_second"] = np.where(
        grouped["flow_duration"] > 0,
        grouped["byte_count"] / grouped["flow_duration"],
        np.nan,
    )

    grouped["direction_ratio"] = np.where(
        grouped["forward_packet_count"] + grouped["backward_packet_count"] > 0,
        grouped["forward_packet_count"] / grouped["packet_count"],
        0.0,
    ).round(3)

    inter_summary = data.groupby("flow_id", sort=False)["timestamp"].apply(
        lambda values: values.sort_values().diff().dt.total_seconds().dropna().to_numpy()
    )
    inter_stats = []
    for flow_id, deltas in inter_summary.items():
        if len(deltas):
            inter_stats.append(
                {
                    "flow_id": flow_id,
                    "mean_inter_arrival_time": round(float(np.mean(deltas)), 5),
                    "std_inter_arrival_time": round(float(np.std(deltas)), 5),
                    "min_inter_arrival_time": round(float(np.min(deltas)), 5),
                    "max_inter_arrival_time": round(float(np.max(deltas)), 5),
                }
            )
        else:
            inter_stats.append(
                {
                    "flow_id": flow_id,
                    "mean_inter_arrival_time": np.nan,
                    "std_inter_arrival_time": np.nan,
                    "min_inter_arrival_time": np.nan,
                    "max_inter_arrival_time": np.nan,
                }
            )
    grouped = grouped.merge(pd.DataFrame(inter_stats), on="flow_id", how="left")

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
