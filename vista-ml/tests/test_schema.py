from __future__ import annotations

import pandas as pd
import pytest

from vista_ml.data.schema import REQUIRED_COLUMNS, validate_dataset


def _make_valid_dataset() -> pd.DataFrame:
    base = {
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
    return pd.DataFrame(base)


def test_dataset_schema_validation() -> None:
    df = _make_valid_dataset()
    validated = validate_dataset(df)
    assert list(validated.columns) == REQUIRED_COLUMNS


def test_missing_required_columns_raises() -> None:
    df = pd.DataFrame({"flow_id": ["f1"]})
    with pytest.raises(ValueError):
        validate_dataset(df)
