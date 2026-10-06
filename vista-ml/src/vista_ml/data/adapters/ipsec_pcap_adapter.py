from __future__ import annotations

from pathlib import Path

import pandas as pd


def adapt_ipsec_pcap(
    packet_path: str | Path | pd.DataFrame,
    output_path: str | Path | None = None,
    label: str = "UNKNOWN",
) -> pd.DataFrame:
    if isinstance(packet_path, pd.DataFrame):
        packet_df = packet_path.copy()
    else:
        packet_df = pd.read_csv(packet_path)
    packet_df = packet_df.copy()

    if "flow_id" not in packet_df.columns:
        packet_df["flow_id"] = packet_df.index.astype(str)
    if "timestamp" not in packet_df.columns and "timestamp_start" in packet_df.columns:
        packet_df["timestamp"] = packet_df["timestamp_start"]
    if "packet_length" not in packet_df.columns and "packet_len" in packet_df.columns:
        packet_df["packet_length"] = packet_df["packet_len"]
    if "packet_length" not in packet_df.columns and "length" in packet_df.columns:
        packet_df["packet_length"] = packet_df["length"]

    flow_df = packet_df.groupby("flow_id").agg(
        packet_count=("packet_length", "size"),
        byte_count=("packet_length", "sum"),
        flow_duration=("timestamp", lambda s: (s.max() - s.min()).total_seconds() if len(s) else 0.0),
        mean_packet_size=("packet_length", "mean"),
        std_packet_size=("packet_length", "std"),
        min_packet_size=("packet_length", "min"),
        max_packet_size=("packet_length", "max"),
    ).reset_index()
    flow_df["experiment_id"] = "ipsec_pcap_experiment"
    flow_df["scenario_id"] = "ipsec_scenario"
    flow_df["timestamp_start"] = pd.Timestamp("2024-01-01")
    flow_df["timestamp_end"] = pd.Timestamp("2024-01-01")
    flow_df["traffic_type"] = "encrypted_flow"
    flow_df["attack_type"] = "none"
    flow_df["label"] = label
    flow_df["ipsec_mode"] = "unknown"
    flow_df["ike_version"] = "unknown"
    flow_df["cipher"] = "unknown"
    flow_df["integrity_algorithm"] = "unknown"
    flow_df["dh_group"] = "unknown"
    flow_df["pfs_enabled"] = pd.NA
    flow_df["mean_inter_arrival_time"] = 0.0
    flow_df["std_inter_arrival_time"] = 0.0
    flow_df["min_inter_arrival_time"] = 0.0
    flow_df["max_inter_arrival_time"] = 0.0
    flow_df["packets_per_second"] = 0.0
    flow_df["bytes_per_second"] = 0.0
    flow_df["forward_packet_count"] = 0
    flow_df["backward_packet_count"] = 0
    flow_df["forward_bytes"] = 0.0
    flow_df["backward_bytes"] = 0.0
    flow_df["direction_ratio"] = 0.0
    flow_df["ebpf_event_count"] = pd.NA
    flow_df["socket_event_count"] = pd.NA
    flow_df["process_event_count"] = pd.NA
    flow_df["network_event_count"] = pd.NA
    flow_df["unique_process_count"] = pd.NA

    if output_path is not None:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        flow_df.to_parquet(out_path, index=False)
    return flow_df
