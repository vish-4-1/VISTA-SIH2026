from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pandas as pd

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.evaluation.metrics import summarise_anomaly_results
from vista_ml.models.isolation_forest import save_model_bundle, train_isolation_forest


def main() -> None:
    dataset_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}. Run generate_sample_dataset.py first.")

    df = load_dataset(dataset_path)
    feature_columns = [col for col in ALL_FEATURE_COLUMNS if col in df.columns]
    normal_df = df[df["label"] == "NORMAL"].copy()
    anomaly_df = df[df["label"] != "NORMAL"].copy()

    model = train_isolation_forest(normal_df[feature_columns], contamination=0.1, random_state=42)
    save_model_bundle(model, ROOT / "models" / "isolation_forest.joblib", {
        "model": "IsolationForest",
        "feature_columns": feature_columns,
        "random_seed": 42,
    })

    normal_score = model.decision_function(normal_df[feature_columns])
    anomaly_score = model.decision_function(anomaly_df[feature_columns])
    threshold = float(pd.Series(normal_score).quantile(0.9))
    normal_pred = (normal_score < threshold).astype(int)
    anomaly_pred = (anomaly_score < threshold).astype(int)

    y_true = pd.Series([0] * len(normal_df) + [1] * len(anomaly_df), name="label")
    y_pred = pd.Series(list(normal_pred) + list(anomaly_pred), name="pred")
    results = summarise_anomaly_results(y_true, y_pred)
    (ROOT / "reports" / "metrics").mkdir(parents=True, exist_ok=True)
    with open(ROOT / "reports" / "metrics" / "anomaly_results.json", "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    print(f"Isolation Forest threshold={threshold:.4f}")
    print(f"Anomaly result={results}")


if __name__ == "__main__":
    main()
