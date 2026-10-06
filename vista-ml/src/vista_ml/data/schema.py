from __future__ import annotations

from typing import Iterable

import pandas as pd

REQUIRED_COLUMNS = [
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
]

OPTIONAL_EBPF_COLUMNS = [
    "ebpf_event_count",
    "socket_event_count",
    "process_event_count",
    "network_event_count",
    "unique_process_count",
]

FEATURE_GROUPS = {
    "NETWORK_BASIC": ["packet_count", "byte_count", "flow_duration"],
    "PACKET_SIZE": [
        "mean_packet_size",
        "std_packet_size",
        "min_packet_size",
        "max_packet_size",
    ],
    "TIMING": [
        "mean_inter_arrival_time",
        "std_inter_arrival_time",
        "min_inter_arrival_time",
        "max_inter_arrival_time",
    ],
    "RATE": ["packets_per_second", "bytes_per_second"],
    "DIRECTION": [
        "forward_packet_count",
        "backward_packet_count",
        "forward_bytes",
        "backward_bytes",
        "direction_ratio",
    ],
    "EBPF": [
        "ebpf_event_count",
        "socket_event_count",
        "process_event_count",
        "network_event_count",
        "unique_process_count",
    ],
}

ALL_FEATURE_COLUMNS = [
    col
    for group in FEATURE_GROUPS.values()
    for col in group
]

LABELS = [
    "NORMAL",
    "PORT_SCAN",
    "DOS",
    "BRUTE_FORCE",
    "C2_BEACONING",
    "DATA_EXFILTRATION",
]


def ensure_required_columns(df: pd.DataFrame, required: Iterable[str] | None = None) -> pd.DataFrame:
    required_cols = list(required) if required is not None else REQUIRED_COLUMNS
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return df


def validate_dataset(df: pd.DataFrame, required: Iterable[str] | None = None) -> pd.DataFrame:
    df = df.copy()
    required_cols = list(required) if required is not None else REQUIRED_COLUMNS
    if df.empty:
        raise ValueError("Dataset is empty.")
    ensure_required_columns(df, required_cols)

    # Keep the canonical schema order and drop any extra source-specific fields.
    df = df.loc[:, required_cols]

    for col in ["pfs_enabled", "packet_count", "byte_count", "flow_duration", "direction_ratio"]:
        if col in df.columns and df[col].isna().all():
            continue
    return df


def select_feature_columns(df: pd.DataFrame, groups: Iterable[str] | None = None) -> list[str]:
    if groups is None:
        return ALL_FEATURE_COLUMNS

    selected: list[str] = []
    for group_name in groups:
        selected.extend(FEATURE_GROUPS.get(group_name, []))
    return [col for col in selected if col in df.columns]
