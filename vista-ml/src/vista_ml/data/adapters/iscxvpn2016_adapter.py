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
    "limitations": "This subset has no attack labels, cryptographic configuration labels, or independent experiment groups. The supplied consolidated CSV is not eligible for leakage-safe evaluation without a source-provided capture/session identifier.",
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
    if labels.isna().any() or labels.eq("").any():
        raise ValueError("ISCXVPN2016 label column contains missing or empty labels.")
    source["label"] = labels
    source["traffic_type"] = labels.str.upper().str.startswith("VPN-").map(
        {True: "vpn", False: "nonvpn"}
    )
    if output_path is not None:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        source.to_parquet(out_path, index=False)
    return source
