from __future__ import annotations

from pathlib import Path

import pandas as pd


PROVENANCE = {
    "dataset_name": "USTC-TFC2016",
    "source": "USTC-TFC2016 benchmark",
    "version_date": "benchmark release",
    "download_location": "https://www.unb.ca/cic/datasets/vpn.html",
    "license": "Verify dataset license for redistribution and usage.",
    "label_definition": "Traffic class labels as reported by the dataset metadata.",
    "feature_definition": "Source features are used when provided; VISTA-derived features are added by the canonical adapter stage.",
    "limitations": "Not all source rows contain IPsec parameters or eBPF telemetry; those values stay absent in the canonical schema.",
}


def adapt_ustc_tfc2016(
    dataset_path: str | Path | pd.DataFrame,
    output_path: str | Path | None = None,
    label_column: str = "label",
) -> pd.DataFrame:
    if isinstance(dataset_path, pd.DataFrame):
        source = dataset_path.copy()
    else:
        source = pd.read_csv(dataset_path)
    source = source.copy()
    if label_column not in source.columns and "Label" in source.columns:
        source = source.rename(columns={"Label": label_column})
    if "experiment_id" not in source.columns:
        source["experiment_id"] = "ustc_tfc2016_experiment"
    if "scenario_id" not in source.columns:
        source["scenario_id"] = "ustc_tfc2016_scenario"
    if "flow_id" not in source.columns:
        source["flow_id"] = source.index.astype(str)
    if "timestamp_start" not in source.columns:
        source["timestamp_start"] = pd.Timestamp("2024-01-01")
    if "timestamp_end" not in source.columns:
        source["timestamp_end"] = source["timestamp_start"]
    if "traffic_type" not in source.columns:
        source["traffic_type"] = "public_dataset"
    if "attack_type" not in source.columns:
        source["attack_type"] = "unknown"
    if "label" not in source.columns:
        source["label"] = source[label_column]
    if "ipsec_mode" not in source.columns:
        source["ipsec_mode"] = "unknown"
    if "ike_version" not in source.columns:
        source["ike_version"] = "unknown"
    if "cipher" not in source.columns:
        source["cipher"] = "unknown"
    if "integrity_algorithm" not in source.columns:
        source["integrity_algorithm"] = "unknown"
    if "dh_group" not in source.columns:
        source["dh_group"] = "unknown"
    if "pfs_enabled" not in source.columns:
        source["pfs_enabled"] = pd.NA
    for name in [
        "ebpf_event_count",
        "socket_event_count",
        "process_event_count",
        "network_event_count",
        "unique_process_count",
    ]:
        if name not in source.columns:
            source[name] = pd.NA
    if output_path is not None:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        source.to_parquet(out_path, index=False)
    return source
