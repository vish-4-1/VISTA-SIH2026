from __future__ import annotations

from pathlib import Path

import pandas as pd

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import REQUIRED_COLUMNS
from vista_ml.features.ebpf_features import aggregate_ebpf_features, load_ebpf_events
from vista_ml.features.pcap_features import extract_flow_features


def test_feature_extraction_from_packet_csv(tmp_path: Path) -> None:
    packet_csv = tmp_path / "packet_sample.csv"
    pd.DataFrame(
        {
            "timestamp": ["2024-01-01T00:00:00", "2024-01-01T00:00:01", "2024-01-01T00:00:02"],
            "packet_length": [100, 120, 140],
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1"],
            "dst_ip": ["10.0.0.2", "10.0.0.2", "10.0.0.2"],
            "direction": ["forward", "forward", "backward"],
        }
    ).to_csv(packet_csv, index=False)

    features = extract_flow_features(packet_csv)
    assert not features.empty
    assert "packet_count" in features.columns
    assert features["packet_count"].iloc[0] >= 3


def test_ebpf_feature_aggregation(tmp_path: Path) -> None:
    ebpf_csv = tmp_path / "ebpf_events.csv"
    pd.DataFrame(
        {
            "timestamp": ["2024-01-01T00:00:00", "2024-01-01T00:00:01"],
            "flow_id": ["f1", "f1"],
            "pid": [101, 103],
            "process_name": ["vpn", "ssh"],
            "event_type": ["socket", "network"],
            "socket_id": ["s1", "s2"],
            "bytes": [10, 20],
            "packets": [2, 3],
        }
    ).to_csv(ebpf_csv, index=False)

    events = load_ebpf_events(ebpf_csv)
    aggregated = aggregate_ebpf_features(events)
    assert "ebpf_event_count" in aggregated.columns
    assert aggregated["ebpf_event_count"].sum() >= 2


def test_feature_extractors_accept_pandas_dataframes() -> None:
    packet_df = pd.DataFrame(
        {
            "timestamp": ["2024-01-01T00:00:00", "2024-01-01T00:00:01", "2024-01-01T00:00:02"],
            "packet_length": [100, 120, 140],
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1"],
            "dst_ip": ["10.0.0.2", "10.0.0.2", "10.0.0.2"],
            "direction": ["forward", "forward", "backward"],
        }
    )
    features = extract_flow_features(packet_df)
    assert not features.empty
    assert "packet_count" in features.columns

    ebpf_df = pd.DataFrame(
        {
            "timestamp": ["2024-01-01T00:00:00", "2024-01-01T00:00:01"],
            "flow_id": ["f1", "f1"],
            "event_type": ["socket", "network"],
            "socket_id": ["s1", "s2"],
            "process_name": ["vpn", "ssh"],
            "pid": [101, 103],
            "bytes": [10, 20],
            "packets": [2, 3],
        }
    )
    aggregated = aggregate_ebpf_features(load_ebpf_events(ebpf_df))
    assert aggregated["ebpf_event_count"].sum() >= 2

    dataset_df = pd.DataFrame(
        {
            "experiment_id": ["exp1", "exp1"],
            "scenario_id": ["s1", "s1"],
            "flow_id": ["f1", "f2"],
            "timestamp_start": ["2024-01-01T00:00:00", "2024-01-01T00:00:05"],
            "timestamp_end": ["2024-01-01T00:00:10", "2024-01-01T00:00:15"],
            "traffic_type": ["encrypted_flow", "encrypted_flow"],
            "attack_type": ["normal", "normal"],
            "label": ["NORMAL", "NORMAL"],
            "ipsec_mode": ["tunnel", "tunnel"],
            "ike_version": [2, 2],
            "cipher": ["aes256-gcm", "aes256-gcm"],
            "integrity_algorithm": ["sha256", "sha256"],
            "dh_group": ["curve25519", "curve25519"],
            "pfs_enabled": [True, True],
            "packet_count": [20, 30],
            "byte_count": [1000, 3000],
            "flow_duration": [10.0, 15.0],
            "mean_packet_size": [50.0, 75.0],
            "std_packet_size": [5.0, 7.0],
            "min_packet_size": [40.0, 60.0],
            "max_packet_size": [60.0, 90.0],
            "mean_inter_arrival_time": [0.5, 0.6],
            "std_inter_arrival_time": [0.1, 0.2],
            "min_inter_arrival_time": [0.4, 0.5],
            "max_inter_arrival_time": [0.7, 0.9],
            "packets_per_second": [2.0, 2.0],
            "bytes_per_second": [100.0, 200.0],
            "forward_packet_count": [10, 15],
            "backward_packet_count": [10, 15],
            "forward_bytes": [500.0, 1500.0],
            "backward_bytes": [500.0, 1500.0],
            "direction_ratio": [0.5, 0.5],
            "ebpf_event_count": [10, 12],
            "socket_event_count": [3, 4],
            "process_event_count": [2, 3],
            "network_event_count": [7, 8],
            "unique_process_count": [2, 3],
        }
    )
    loaded = load_dataset(dataset_df)
    assert all(column in loaded.columns for column in REQUIRED_COLUMNS)
    assert len(loaded.columns) == len(REQUIRED_COLUMNS)
