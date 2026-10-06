from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_ebpf_events(path: str | Path | pd.DataFrame) -> pd.DataFrame:
    if isinstance(path, pd.DataFrame):
        events = path.copy()
    else:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"eBPF events file not found: {file_path}")

        suffix = file_path.suffix.lower()
        if suffix == ".csv":
            events = pd.read_csv(file_path)
        elif suffix in {".parquet", ".pq"}:
            events = pd.read_parquet(file_path)
        elif suffix == ".json":
            events = pd.read_json(file_path)
        else:
            raise ValueError("Unsupported eBPF source format. Use CSV, JSON, or Parquet.")

    if events.empty:
        return pd.DataFrame(columns=[
            "timestamp",
            "flow_id",
            "pid",
            "process_name",
            "event_type",
            "socket_id",
            "bytes",
            "packets",
        ])

    events = events.copy()
    if "timestamp" in events.columns:
        events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
    if "flow_id" not in events.columns:
        if "socket_id" in events.columns:
            events["flow_id"] = events["socket_id"].astype(str)
        elif "pid" in events.columns:
            events["flow_id"] = events["pid"].astype(str)
        else:
            events["flow_id"] = "unknown_flow"
    return events


def aggregate_ebpf_features(events: pd.DataFrame) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame(columns=[
            "flow_id",
            "ebpf_event_count",
            "socket_event_count",
            "process_event_count",
            "network_event_count",
            "unique_process_count",
        ])

    data = events.copy()
    if "flow_id" not in data.columns:
        data["flow_id"] = "unknown_flow"
    if "event_type" not in data.columns:
        data["event_type"] = "unknown"
    if "socket_id" not in data.columns:
        data["socket_id"] = pd.NA
    if "process_name" not in data.columns:
        data["process_name"] = pd.NA
    if "pid" not in data.columns:
        data["pid"] = pd.NA
    if "bytes" not in data.columns:
        data["bytes"] = 0
    if "packets" not in data.columns:
        data["packets"] = 0

    group_cols = ["flow_id"]
    aggregated = (
        data.groupby(group_cols, dropna=False)
        .agg(
            ebpf_event_count=("event_type", "size"),
            socket_event_count=("socket_id", lambda s: s.notna().sum()),
            process_event_count=("pid", lambda s: s.notna().sum()),
            network_event_count=("event_type", lambda s: (s == "network").sum()),
            unique_process_count=("process_name", lambda s: s.dropna().nunique()),
        )
        .reset_index()
    )
    return aggregated
