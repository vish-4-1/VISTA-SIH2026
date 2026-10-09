from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pandas as pd

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.datasets.splitter import check_group_leakage, experiment_aware_split
from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.models.random_forest import save_model_bundle, train_random_forest_classifier
from vista_ml.utils.reproducibility import set_random_seed


def main() -> None:
    set_random_seed(42)
    dataset_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}. Run generate_sample_dataset.py first.")
    df = load_dataset(dataset_path)
    feature_columns = [col for col in ALL_FEATURE_COLUMNS if col in df.columns]
    train_df, test_df = experiment_aware_split(df, group_col="experiment_id", test_size=0.2, random_state=42)
    check_group_leakage(train_df, test_df, group_col="experiment_id")

    X_train = train_df[feature_columns].copy()
    y_train = train_df["label"].copy()
    X_test = test_df[feature_columns].copy()
    y_test = test_df["label"].copy()

    model = train_random_forest_classifier(X_train, y_train, random_state=42)
    save_model_bundle(model, ROOT / "models" / "random_forest_baseline.joblib", {
        "model": "RandomForestClassifier",
        "prediction_task": "flow traffic-label classification",
        "training_data_scope": "synthetic development dataset",
        "training_dataset": "data/sample/synthetic_vista_dataset.parquet",
        "evaluation_scope": "experiment-aware group holdout; offline synthetic-data evaluation",
        "probability_calibration": "not evaluated",
        "feature_columns": feature_columns,
        "random_seed": 42,
        "dataset_shape": df.shape,
        "train_experiments": train_df["experiment_id"].nunique(),
        "test_experiments": test_df["experiment_id"].nunique(),
    })

    metrics = evaluate_classifier(model, X_test, y_test, sorted(y_test.unique()), ROOT / "reports" / "metrics")
    print(f"Dataset shape: {df.shape}")
    print(f"Train experiments={train_df['experiment_id'].nunique()}, test experiments={test_df['experiment_id'].nunique()}")
    print(f"Random Forest metrics: {metrics}")


if __name__ == "__main__":
    main()
