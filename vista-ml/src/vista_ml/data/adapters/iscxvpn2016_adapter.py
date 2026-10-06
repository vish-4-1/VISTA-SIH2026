from __future__ import annotations

from pathlib import Path

import pandas as pd


PROVENANCE = {
    "dataset_name": "ISCXVPN2016 TimeBasedFeatures 15s",
    "evaluation_category": "Public Dataset Validation",
    "source": "ISCXVPN2016 flow features distributed in the Zenodo derived-data archive",
    "doi": "https://doi.org/10.5281/zenodo.15862668",
    "download_location": "https://zenodo.org/records/15862668",
    "license": "CC BY 4.0 for the Zenodo deposit; cite the original ISCXVPN2016 paper and follow its terms.",
    "original_dataset": "https://www.unb.ca/cic/datasets/vpn.html",
    "original_dataset_citation": "Drapper Gil et al., Characterization of Encrypted and VPN Traffic Using Time-Related Features, ICISSP 2016.",
    "label_definition": "Fourteen application labels; the VPN- prefix denotes VPN traffic, and unprefixed labels denote non-VPN traffic.",
    "feature_definition": "The source's numeric TimeBasedFeatures columns are retained unchanged; no unavailable VISTA telemetry or cryptographic metadata is imputed.",
    "limitations": "This subset has no attack labels, cryptographic configuration labels, packet/session IDs, or independent experiment groups. It supports application/VPN classification only; row-stratified metrics may be optimistic.",
}


def adapt_iscxvpn2016(
    dataset_path: str | Path | pd.DataFrame,
    output_path: str | Path | None = None,
    label_column: str = "label",
) -> pd.DataFrame:
    if isinstance(dataset_path, pd.DataFrame):
        source = dataset_path.copy()
    else:
        source = pd.read_csv(dataset_path)
    if label_column not in source.columns:
        if "Label" in source.columns:
            label_column = "Label"
        elif "class" in source.columns:
            label_column = "class"
        else:
            raise ValueError(f"Could not find label column {label_column!r}, 'Label', or 'class'.")
    source = source.copy()
    labels = source[label_column].astype("string").str.strip()
    source["label"] = labels
    traffic_type = labels.str.upper().str.startswith("VPN-").map({True: "vpn", False: "nonvpn"})
    source["experiment_id"] = source.get("experiment_id", "iscxvpn2016_15s")
    source["scenario_id"] = source.get("scenario_id", "iscxvpn2016_15s")
    source["flow_id"] = source.get("flow_id", source.index.astype(str))
    source["timestamp_start"] = source.get("timestamp_start", pd.NaT)
    source["timestamp_end"] = source.get("timestamp_end", source["timestamp_start"])
    source["traffic_type"] = source.get("traffic_type", traffic_type)
    source["attack_type"] = source.get("attack_type", "not_labeled")
    source["ipsec_mode"] = source.get("ipsec_mode", "unknown")
    source["ike_version"] = source.get("ike_version", "unknown")
    source["cipher"] = source.get("cipher", "unknown")
    source["integrity_algorithm"] = source.get("integrity_algorithm", "unknown")
    source["dh_group"] = source.get("dh_group", "unknown")
    source["pfs_enabled"] = source.get("pfs_enabled", pd.NA)
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
