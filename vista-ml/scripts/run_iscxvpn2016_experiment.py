from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from vista_ml.data.adapters.iscxvpn2016_adapter import adapt_iscxvpn2016, PROVENANCE
from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.models.random_forest import train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle, train_xgboost_classifier


ARCHIVE_PATH = ROOT / "data" / "raw" / "public" / "iscxvpn2016_zenodo_15862668" / "Data.zip"
ARCHIVE_MEMBER = "Data/ISCXVPN2016/Original_ISCXFlowMeter_CSVs/TimeBasedFeatures-Dataset-15s.csv"
EXTRACTED_CSV_PATH = ARCHIVE_PATH.parent / "TimeBasedFeatures-Dataset-15s.csv"


def _resolve_dataset_path(dataset_csv: Path | None) -> Path:
    if dataset_csv is not None:
        if not dataset_csv.is_file():
            raise FileNotFoundError(f"ISCXVPN2016 CSV not found: {dataset_csv}")
        return dataset_csv

    if EXTRACTED_CSV_PATH.is_file():
        return EXTRACTED_CSV_PATH
    if not ARCHIVE_PATH.is_file():
        raise FileNotFoundError(
            f"Dataset archive missing: {ARCHIVE_PATH}. Download Zenodo record 10.5281/zenodo.15862668 "
            "or pass --dataset-csv with an ISCXVPN2016 flow CSV."
        )

    EXTRACTED_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ARCHIVE_PATH) as archive:
        with archive.open(ARCHIVE_MEMBER) as source, EXTRACTED_CSV_PATH.open("wb") as target:
            shutil.copyfileobj(source, target)
    return EXTRACTED_CSV_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="Train VISTA classifiers on ISCXVPN2016 flow features.")
    parser.add_argument("--dataset-csv", type=Path, help="Path to an ISCXVPN2016 TimeBasedFeatures CSV.")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    dataset_path = _resolve_dataset_path(args.dataset_csv)
    adapted = adapt_iscxvpn2016(dataset_path)
    label_counts = adapted["label"].value_counts()
    if label_counts.size < 2 or label_counts.min() < 2:
        raise ValueError("Each classification label needs at least two samples for a stratified train/test split.")

    feature_columns = adapted.select_dtypes(include=[np.number]).columns.tolist()
    if not feature_columns:
        raise ValueError("No numeric CICFlowMeter feature columns were found in the source CSV.")
    X = adapted[feature_columns].replace([np.inf, -np.inf], np.nan)
    valid_rows = adapted["label"].notna() & X.notna().all(axis=1)
    adapted = adapted.loc[valid_rows].reset_index(drop=True)
    X = X.loc[valid_rows].reset_index(drop=True)
    y_application = adapted["label"].astype(str)
    y_vpn = adapted["traffic_type"].map({"vpn": "VPN", "nonvpn": "NONVPN"})
    if y_vpn.isna().any():
        raise ValueError("Source labels include values that cannot be mapped to VPN/non-VPN.")

    train_idx, test_idx = train_test_split(
        np.arange(len(adapted)),
        test_size=args.test_size,
        random_state=42,
        stratify=y_application,
    )
    out_dir = ROOT / "reports" / "iscxvpn2016"
    out_dir.mkdir(parents=True, exist_ok=True)
    model_dir = ROOT / "models" / "iscxvpn2016"
    model_dir.mkdir(parents=True, exist_ok=True)
    adapted.to_parquet(out_dir / "adapted_15s.parquet", index=False)

    tasks = {
        "application_vpn_14class": y_application,
        "vpn_status_binary": y_vpn,
    }
    results = {}
    for task_name, target in tasks.items():
        task_dir = out_dir / task_name
        target_train, target_test = target.iloc[train_idx], target.iloc[test_idx]
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        label_names = sorted(target.unique())

        for model_name, train_model in [
            ("random_forest", train_random_forest_classifier),
            ("xgboost", train_xgboost_classifier),
        ]:
            model = train_model(X_train, target_train, random_state=42)
            model_path = model_dir / f"{task_name}_{model_name}.joblib"
            save_model_bundle(model, model_path, {
                "dataset": PROVENANCE,
                "task": task_name,
                "target_classes": label_names,
                "feature_columns": feature_columns,
                "random_seed": 42,
                "test_size": args.test_size,
                "split_strategy": "stratified row split; source has no session or experiment identifier",
            })
            metrics = evaluate_classifier(
                model,
                X_test,
                target_test,
                label_names,
                task_dir / model_name,
            )
            results.setdefault(task_name, {})[model_name] = metrics

    summary = {
        "evaluation_category": "Public Dataset Validation",
        "interpretation": "Flow-level VPN/application classification only; this is not evidence of attack detection or IPsec cryptographic-configuration inference.",
        "provenance": PROVENANCE,
        "dataset_summary": {
            "rows": len(adapted),
            "source_feature_count": len(feature_columns),
            "source_csv": str(dataset_path.relative_to(ROOT)) if dataset_path.is_relative_to(ROOT) else str(dataset_path),
            "class_distribution": label_counts.to_dict(),
            "vpn_status_distribution": y_vpn.value_counts().to_dict(),
        },
        "split": {
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
            "test_size": args.test_size,
            "random_state": 42,
            "strategy": "stratified row split; capture/session identifiers are unavailable",
        },
        "results": results,
    }
    with open(out_dir / "dataset_summary.json", "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, default=str)
    print(f"ISCXVPN2016 data: {len(adapted)} rows, {len(feature_columns)} source features, {len(train_idx)} train / {len(test_idx)} test rows")
    print("Result category: Public Dataset Validation.")
    print("Tasks: 14-class application/VPN label and binary VPN-vs-non-VPN status.")
    print("No attack or cryptographic inference labels are present in this dataset.")
    for task_name, model_results in results.items():
        for model_name, metrics in model_results.items():
            print(f"{task_name} / {model_name}: accuracy={metrics['accuracy']:.4f}, macro_f1={metrics['macro_f1']:.4f}")
    print(f"Summary written to {out_dir / 'dataset_summary.json'}")


if __name__ == "__main__":
    main()
