from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.models.isolation_forest import save_model_bundle, train_isolation_forest
from vista_ml.utils.artifacts import create_candidate_run_dirs


def main() -> None:
    dataset_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}. Run generate_sample_dataset.py first.")

    df = load_dataset(dataset_path)
    feature_columns = [col for col in ALL_FEATURE_COLUMNS if col in df.columns]
    normal_df = df[df["label"] == "NORMAL"].copy()

    model = train_isolation_forest(normal_df[feature_columns], contamination=0.1, random_state=42)
    model_dir, report_dir = create_candidate_run_dirs(ROOT, "synthetic-anomaly")
    model_path = model_dir / "isolation_forest.joblib"
    save_model_bundle(model, model_path, {
        "model": "IsolationForest",
        "prediction_task": "flow anomaly detection",
        "training_data_scope": "synthetic development dataset",
        "validated_for_inference": False,
        "feature_schema_version": "vista-flow-v1",
        "training_dataset": "data/sample/synthetic_vista_dataset.parquet",
        "evaluation_scope": "candidate fit only; no independent anomaly threshold or evaluation set",
        "feature_columns": feature_columns,
        "random_seed": 42,
    })
    result = {
        "status": "candidate_fit_only",
        "threshold": None,
        "evaluation_metrics": None,
        "reason": "No independent labeled calibration set is available; a training-set quantile is not a validated threshold.",
        "model_path": str(model_path.relative_to(ROOT)),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    with (report_dir / "anomaly_candidate_status.json").open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(f"Isolation Forest candidate saved: {model_path}")
    print("No threshold or anomaly performance claim was produced.")


if __name__ == "__main__":
    main()
