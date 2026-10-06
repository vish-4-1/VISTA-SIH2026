from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import joblib

from vista_ml.data.loader import load_dataset
from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.explainability.shap_analysis import explain_xgboost
from vista_ml.models.xgboost_model import train_xgboost_classifier


def main() -> None:
    dataset_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}. Run generate_sample_dataset.py first.")
    df = load_dataset(dataset_path)
    feature_columns = [col for col in ALL_FEATURE_COLUMNS if col in df.columns]
    X = df[feature_columns].copy()
    y = df["label"].copy()

    model_path = ROOT / "models" / "xgboost_classifier.joblib"
    if model_path.exists():
        model = joblib.load(model_path)
    else:
        model = train_xgboost_classifier(X, y, random_state=42)
        joblib.dump(model, model_path)

    summary = explain_xgboost(model, X.head(200), output_dir=ROOT / "reports" / "shap")
    print(f"SHAP top features: {summary['top_features'][:5]}")


if __name__ == "__main__":
    main()
