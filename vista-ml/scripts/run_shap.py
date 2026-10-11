from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import joblib
import pandas as pd

from vista_ml.data.loader import load_dataset
from vista_ml.explainability.shap_analysis import explain_xgboost


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explain a validated XGBoost model on its exact held-out evaluation dataset."
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=ROOT / "models" / "xgboost_classifier.joblib",
        help="Model bundle path.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet",
        help="Held-out dataset file whose SHA-256 is recorded in model metadata.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory for explanation artifacts.",
    )
    args = parser.parse_args()

    metadata_path = args.model.with_suffix(".metadata.json")
    if not args.model.is_file():
        raise FileNotFoundError(f"Model artifact not found: {args.model}")
    if not metadata_path.is_file():
        raise ValueError(f"Model metadata is required: {metadata_path}")
    if not args.dataset.is_file():
        raise FileNotFoundError(f"Held-out evaluation dataset not found: {args.dataset}")
    if args.output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing SHAP artifacts: {args.output_dir}")

    with metadata_path.open("r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    if metadata.get("validated_for_inference") is not True:
        raise ValueError("SHAP is unavailable: model metadata does not approve inference.")
    if metadata.get("feature_schema_version") != "vista-flow-v1":
        raise ValueError("SHAP is unavailable: model metadata does not match vista-flow-v1.")
    evaluation = metadata.get("held_out_evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("split") != "test":
        raise ValueError("SHAP requires metadata identifying an independent held-out test dataset.")
    dataset_hash = _sha256(args.dataset)
    if evaluation.get("dataset_sha256") != dataset_hash:
        raise ValueError("The supplied dataset does not match the model's recorded held-out test data.")

    feature_columns = metadata.get("feature_columns")
    if not isinstance(feature_columns, list) or not feature_columns:
        raise ValueError("Model metadata must declare its ordered feature_columns.")
    df = load_dataset(args.dataset)
    missing = [column for column in feature_columns if column not in df.columns]
    if missing:
        raise ValueError(f"Held-out dataset is missing model features: {missing}")
    features = df.loc[:, feature_columns].apply(pd.to_numeric, errors="coerce")
    if features.isna().any().any():
        raise ValueError("Held-out SHAP data contains missing or non-numeric model features.")

    model = joblib.load(args.model)
    sample = features.sample(n=min(200, len(features)), random_state=42).sort_index()
    summary = explain_xgboost(
        model,
        sample,
        output_dir=args.output_dir,
        max_samples=len(sample),
        model_version=str(metadata.get("model_version", args.model.stem)),
        feature_schema_version=metadata["feature_schema_version"],
    )
    summary["evaluation_dataset_sha256"] = dataset_hash
    with (args.output_dir / "top_features.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print(f"Held-out SHAP artifacts written to {args.output_dir}")


if __name__ == "__main__":
    main()
