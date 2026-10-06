from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import joblib
import pandas as pd

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.datasets.splitter import check_group_leakage, experiment_aware_split
from vista_ml.evaluation.evaluate import evaluate_classifier


def main() -> None:
    dataset_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}. Run generate_sample_dataset.py first.")

    df = load_dataset(dataset_path)
    feature_columns = [col for col in ALL_FEATURE_COLUMNS if col in df.columns]
    train_df, test_df = experiment_aware_split(df, group_col="experiment_id", test_size=0.2, random_state=42)
    check_group_leakage(train_df, test_df)

    X_test = test_df[feature_columns].copy()
    y_test = test_df["label"].copy()

    model_paths = {
        "random_forest": ROOT / "models" / "random_forest_baseline.joblib",
        "xgboost": ROOT / "models" / "xgboost_classifier.joblib",
    }
    results = {}
    for name, path in model_paths.items():
        if not path.exists():
            print(f"Skipping {name}: model not found at {path}")
            continue
        model = joblib.load(path)
        metrics = evaluate_classifier(model, X_test, y_test, sorted(y_test.unique()), ROOT / "reports" / "metrics")
        results[name] = metrics
        print(f"{name}: {metrics}")

    with open(ROOT / "reports" / "metrics" / "model_summary.json", "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)


if __name__ == "__main__":
    main()
