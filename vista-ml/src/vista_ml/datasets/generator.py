from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from vista_ml.utils.reproducibility import set_random_seed


LABELS = [
    "NORMAL",
    "PORT_SCAN",
    "DOS",
    "BRUTE_FORCE",
    "C2_BEACONING",
    "DATA_EXFILTRATION",
]

CIPHERS = ["aes128-cbc", "aes256-cbc", "aes128-gcm", "aes256-gcm"]
DHS = ["modp1024", "modp1536", "modp2048", "ecp256", "curve25519"]
MODES = ["tunnel", "transport"]


def _generate_flow_profile(label: str, rng: np.random.Generator) -> dict[str, float | bool | int | str]:
    profiles = {
        "NORMAL": {
            "packet_count": 90,
            "byte_count": 12000,
            "flow_duration": 1.8,
            "mean_packet_size": 140,
            "std_packet_size": 20,
            "min_packet_size": 60,
            "max_packet_size": 200,
            "mean_inter_arrival_time": 0.015,
            "std_inter_arrival_time": 0.01,
            "min_inter_arrival_time": 0.001,
            "max_inter_arrival_time": 0.05,
            "packets_per_second": 55,
            "bytes_per_second": 8000,
            "forward_packet_count": 52,
            "backward_packet_count": 38,
            "forward_bytes": 7000,
            "backward_bytes": 5000,
            "direction_ratio": 0.58,
            "ebpf_event_count": 20,
            "socket_event_count": 8,
            "process_event_count": 5,
            "network_event_count": 15,
            "unique_process_count": 4,
        },
        "PORT_SCAN": {
            "packet_count": 300,
            "byte_count": 24000,
            "flow_duration": 2.3,
            "mean_packet_size": 110,
            "std_packet_size": 25,
            "min_packet_size": 40,
            "max_packet_size": 180,
            "mean_inter_arrival_time": 0.008,
            "std_inter_arrival_time": 0.004,
            "min_inter_arrival_time": 0.0005,
            "max_inter_arrival_time": 0.02,
            "packets_per_second": 130,
            "bytes_per_second": 10000,
            "forward_packet_count": 180,
            "backward_packet_count": 120,
            "forward_bytes": 14000,
            "backward_bytes": 10000,
            "direction_ratio": 0.6,
            "ebpf_event_count": 60,
            "socket_event_count": 30,
            "process_event_count": 8,
            "network_event_count": 45,
            "unique_process_count": 6,
        },
        "DOS": {
            "packet_count": 410,
            "byte_count": 36000,
            "flow_duration": 1.2,
            "mean_packet_size": 90,
            "std_packet_size": 18,
            "min_packet_size": 40,
            "max_packet_size": 160,
            "mean_inter_arrival_time": 0.002,
            "std_inter_arrival_time": 0.001,
            "min_inter_arrival_time": 0.0001,
            "max_inter_arrival_time": 0.01,
            "packets_per_second": 340,
            "bytes_per_second": 32000,
            "forward_packet_count": 230,
            "backward_packet_count": 180,
            "forward_bytes": 21000,
            "backward_bytes": 15000,
            "direction_ratio": 0.56,
            "ebpf_event_count": 100,
            "socket_event_count": 44,
            "process_event_count": 10,
            "network_event_count": 78,
            "unique_process_count": 7,
        },
        "BRUTE_FORCE": {
            "packet_count": 180,
            "byte_count": 21000,
            "flow_duration": 4.0,
            "mean_packet_size": 120,
            "std_packet_size": 24,
            "min_packet_size": 50,
            "max_packet_size": 180,
            "mean_inter_arrival_time": 0.02,
            "std_inter_arrival_time": 0.015,
            "min_inter_arrival_time": 0.004,
            "max_inter_arrival_time": 0.08,
            "packets_per_second": 45,
            "bytes_per_second": 5200,
            "forward_packet_count": 96,
            "backward_packet_count": 84,
            "forward_bytes": 11800,
            "backward_bytes": 9200,
            "direction_ratio": 0.53,
            "ebpf_event_count": 80,
            "socket_event_count": 35,
            "process_event_count": 12,
            "network_event_count": 58,
            "unique_process_count": 8,
        },
        "C2_BEACONING": {
            "packet_count": 70,
            "byte_count": 9200,
            "flow_duration": 150.0,
            "mean_packet_size": 130,
            "std_packet_size": 24,
            "min_packet_size": 50,
            "max_packet_size": 170,
            "mean_inter_arrival_time": 1.2,
            "std_inter_arrival_time": 0.5,
            "min_inter_arrival_time": 0.1,
            "max_inter_arrival_time": 3.0,
            "packets_per_second": 0.5,
            "bytes_per_second": 60,
            "forward_packet_count": 38,
            "backward_packet_count": 32,
            "forward_bytes": 5100,
            "backward_bytes": 4100,
            "direction_ratio": 0.54,
            "ebpf_event_count": 24,
            "socket_event_count": 12,
            "process_event_count": 7,
            "network_event_count": 19,
            "unique_process_count": 5,
        },
        "DATA_EXFILTRATION": {
            "packet_count": 240,
            "byte_count": 52000,
            "flow_duration": 12.0,
            "mean_packet_size": 220,
            "std_packet_size": 38,
            "min_packet_size": 80,
            "max_packet_size": 340,
            "mean_inter_arrival_time": 0.03,
            "std_inter_arrival_time": 0.02,
            "min_inter_arrival_time": 0.001,
            "max_inter_arrival_time": 0.15,
            "packets_per_second": 20,
            "bytes_per_second": 4300,
            "forward_packet_count": 110,
            "backward_packet_count": 130,
            "forward_bytes": 28000,
            "backward_bytes": 24000,
            "direction_ratio": 0.46,
            "ebpf_event_count": 90,
            "socket_event_count": 40,
            "process_event_count": 11,
            "network_event_count": 70,
            "unique_process_count": 9,
        },
    }

    base = profiles[label]
    row = {}
    for key, value in base.items():
        if isinstance(value, (int, float)):
            sigma = max(value * 0.35, 1.0)
            noise = rng.normal(0.0, sigma)
            row[key] = max(value + noise, 0.0)
        else:
            row[key] = value
    return row


def generate_sample_dataset(
    output_path: str | Path | None = None,
    n_experiments: int = 50,
    flows_per_experiment: int = 15,
    seed: int = 42,
) -> pd.DataFrame:
    set_random_seed(seed)
    rng = np.random.default_rng(seed)
    rows = []

    for exp_idx in range(1, n_experiments + 1):
        experiment_id = f"experiment_{exp_idx:03d}"
        scenario_id = f"scenario_{exp_idx:03d}"
        for flow_idx in range(1, flows_per_experiment + 1):
            label = LABELS[exp_idx % len(LABELS)] if flow_idx % 5 == 0 else LABELS[(exp_idx + flow_idx) % len(LABELS)]
            if label == "NORMAL" and flow_idx % 3 == 0:
                label = "NORMAL"

            profile = _generate_flow_profile(label, rng)
            start_ts = pd.Timestamp("2024-01-01") + pd.to_timedelta(exp_idx * 10 + flow_idx * 3, unit="min")
            duration = max(profile["flow_duration"], 0.1)
            end_ts = start_ts + pd.to_timedelta(duration, unit="s")
            pfs_enabled = bool(rng.integers(0, 2))
            mode = str(rng.choice(MODES))
            cipher = str(rng.choice(CIPHERS))
            dh_group = str(rng.choice(DHS))
            ike_version = int(rng.choice([1, 2]))
            traffic_type = "encrypted_flow"
            attack_type = "none" if label == "NORMAL" else label

            row = {
                "experiment_id": experiment_id,
                "scenario_id": scenario_id,
                "flow_id": f"{experiment_id}_flow_{flow_idx:03d}",
                "timestamp_start": start_ts,
                "timestamp_end": end_ts,
                "traffic_type": traffic_type,
                "attack_type": attack_type,
                "label": label,
                "ipsec_mode": mode,
                "ike_version": ike_version,
                "cipher": cipher,
                "integrity_algorithm": "sha256",
                "dh_group": dh_group,
                "pfs_enabled": pfs_enabled,
                "packet_count": int(max(profile["packet_count"], 1)),
                "byte_count": int(max(profile["byte_count"], 1)),
                "flow_duration": float(duration),
                "mean_packet_size": float(profile["mean_packet_size"]),
                "std_packet_size": float(profile["std_packet_size"]),
                "min_packet_size": float(profile["min_packet_size"]),
                "max_packet_size": float(profile["max_packet_size"]),
                "mean_inter_arrival_time": float(profile["mean_inter_arrival_time"]),
                "std_inter_arrival_time": float(profile["std_inter_arrival_time"]),
                "min_inter_arrival_time": float(profile["min_inter_arrival_time"]),
                "max_inter_arrival_time": float(profile["max_inter_arrival_time"]),
                "packets_per_second": float(profile["packets_per_second"]),
                "bytes_per_second": float(profile["bytes_per_second"]),
                "forward_packet_count": int(max(profile["forward_packet_count"], 0)),
                "backward_packet_count": int(max(profile["backward_packet_count"], 0)),
                "forward_bytes": float(profile["forward_bytes"]),
                "backward_bytes": float(profile["backward_bytes"]),
                "direction_ratio": float(profile["direction_ratio"]),
                "ebpf_event_count": float(profile["ebpf_event_count"]),
                "socket_event_count": float(profile["socket_event_count"]),
                "process_event_count": float(profile["process_event_count"]),
                "network_event_count": float(profile["network_event_count"]),
                "unique_process_count": float(profile["unique_process_count"]),
            }
            rows.append(row)

    df = pd.DataFrame(rows)
    if output_path is not None:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out_path, index=False)
    return df
