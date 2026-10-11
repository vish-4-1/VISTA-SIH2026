from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

from vista_ml.data.adapters.iscxvpn2016_adapter import adapt_iscxvpn2016, PROVENANCE
from vista_ml.datasets.splitter import grouped_train_validation_test_split
from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.models.random_forest import train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle, train_xgboost_classifier


ARCHIVE_PATH = ROOT / "data" / "raw" / "public" / "iscxvpn2016_zenodo_15862668" / "Data.zip"
ARCHIVE_MEMBER = "Data/ISCXVPN2016/Original_ISCXFlowMeter_CSVs/TimeBasedFeatures-Dataset-15s.csv"


def _read_dataset(dataset_csv: Path | None) -> pd.DataFrame:
    if dataset_csv is not None:
        if not dataset_csv.is_file():
            raise FileNotFoundError(f"ISCXVPN2016 CSV not found: {dataset_csv}")
        return pd.read_csv(dataset_csv)
    if not ARCHIVE_PATH.is_file():
        raise FileNotFoundError(
            f"Dataset archive missing: {ARCHIVE_PATH}. Download Zenodo record 10.5281/zenodo.15862668 "
            "or pass --dataset-csv with an ISCXVPN2016 flow CSV."
        )
    with zipfile.ZipFile(ARCHIVE_PATH) as archive:
        with archive.open(ARCHIVE_MEMBER) as source:
            return pd.read_csv(source)


def _validate_splits(
    splits: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame],
    group_column: str,
    targets: dict[str, pd.Series],
) -> None:
    train, validation, test = splits
    for target_name, target in targets.items():
        expected = set(target.astype(str).unique())
        for split_name, split in zip(("train", "validation", "test"), splits):
            observed = set(target.loc[split.index].astype(str).unique())
            if observed != expected:
                missing = sorted(expected - observed)
                raise ValueError(
                    f"{target_name} split {split_name} is missing classes {missing}; "
                    "the capture groups cannot support a complete three-way evaluation."
                )

    group_sets = [
        set(split[group_column].astype(str))
        for split in (train, validation, test)
    ]
    if any(
        group_sets[left] & group_sets[right]
        for left, right in ((0, 1), (0, 2), (1, 2))
    ):
        raise ValueError("Capture-group leakage detected across train/validation/test.")


def _validation_score(model, features: pd.DataFrame, target: pd.Series) -> dict[str, float]:
    predicted = pd.Series(model.predict(features), index=target.index).astype(str)
    expected = target.astype(str)
    return {
        "accuracy": float(accuracy_score(expected, predicted)),
        "macro_f1": float(f1_score(expected, predicted, average="macro", zero_division=0)),
    }


def _hashed_groups(values: pd.Series) -> list[str]:
    return sorted({
        hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        for value in values
    })


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate ISCXVPN2016 application/VPN classifiers with independent capture groups."
    )
    parser.add_argument("--dataset-csv", type=Path, help="Path to an ISCXVPN2016 flow CSV.")
    parser.add_argument(
        "--group-column",
        required=True,
        help="Source-provided independent capture/session identifier; never use a row ID.",
    )
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    source = _read_dataset(args.dataset_csv)
    if args.group_column not in source.columns:
        raise ValueError(
            f"Required independent group column {args.group_column!r} is absent. "
            "This ISCXVPN2016 archive does not provide capture/session IDs in its consolidated "
            "TimeBasedFeatures CSV; row-level evaluation is intentionally disabled."
        )
    if args.group_column in {"Label", "label", "class"}:
        raise ValueError("The target label cannot also be used as the independent group identifier.")

    adapted = adapt_iscxvpn2016(source)
    excluded = {args.group_column, "label", "traffic_type"}
    feature_columns = [
        column for column in adapted.select_dtypes(include=[np.number]).columns
        if column not in excluded
    ]
    if not feature_columns:
        raise ValueError("No numeric source feature columns were found in the CSV.")
    numeric_features = adapted[feature_columns].apply(pd.to_numeric, errors="coerce")
    invalid = ~np.isfinite(numeric_features.to_numpy(dtype=float)).all(axis=1)
    if invalid.any():
        raise ValueError(
            f"Source contains {int(invalid.sum())} rows with missing or non-finite features; "
            "repair or explicitly document those source records before training."
        )

    adapted = adapted.reset_index(drop=True)
    X = numeric_features.reset_index(drop=True)
    targets = {
        "application_vpn_14class": adapted["label"].astype(str),
        "vpn_status_binary": adapted["traffic_type"].map({"vpn": "VPN", "nonvpn": "NONVPN"}),
    }
    if any(target.isna().any() for target in targets.values()):
        raise ValueError("ISCXVPN2016 contains labels that cannot be mapped to both evaluation tasks.")

    splits = grouped_train_validation_test_split(
        adapted,
        group_col=args.group_column,
        target_col="label",
        validation_size=args.validation_size,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    _validate_splits(splits, args.group_column, targets)
    train, validation, test = splits
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    report_dir = ROOT / "reports" / "candidates" / "iscxvpn2016" / run_id
    model_dir = ROOT / "models" / "candidates" / "iscxvpn2016" / run_id
    report_dir.mkdir(parents=True, exist_ok=False)
    model_dir.mkdir(parents=True, exist_ok=False)

    split_manifest = {
        "group_column": args.group_column,
        "random_state": args.random_state,
        "validation_size": args.validation_size,
        "test_size": args.test_size,
        "counts": {
            name: {"rows": len(split), "groups": split[args.group_column].nunique()}
            for name, split in zip(("train", "validation", "test"), splits)
        },
        "group_hashes": {
            name: _hashed_groups(split[args.group_column])
            for name, split in zip(("train", "validation", "test"), splits)
        },
        "overlap_checked": True,
        "all_target_classes_present_in_each_split": True,
    }
    with (report_dir / "split_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(split_manifest, handle, indent=2)

    results = {}
    trainers = [
        ("random_forest", train_random_forest_classifier),
        ("xgboost", train_xgboost_classifier),
    ]
    for task_name, target in targets.items():
        y_train = target.loc[train.index]
        y_validation = target.loc[validation.index]
        y_test = target.loc[test.index]
        candidates = []
        for model_name, train_model in trainers:
            model = train_model(X.loc[train.index], y_train, random_state=args.random_state)
            score = _validation_score(model, X.loc[validation.index], y_validation)
            candidates.append((model_name, model, score))
        selected_name, selected_model, validation_metrics = max(
            candidates,
            key=lambda candidate: candidate[2]["macro_f1"],
        )
        classes = sorted(target.unique())
        test_metrics = evaluate_classifier(
            selected_model,
            X.loc[test.index],
            y_test,
            classes,
            report_dir / task_name / "held_out_test",
        )
        model_path = model_dir / f"{task_name}_{selected_name}.joblib"
        save_model_bundle(
            selected_model,
            model_path,
            {
                "dataset": PROVENANCE,
                "task": task_name,
                "target_classes": classes,
                "feature_columns": feature_columns,
                "feature_schema_version": "iscxvpn2016-timefeatures-v1",
                "runtime_feature_compatible": False,
                "validated_for_inference": False,
                "inference_blocker": (
                    "Source TimeBasedFeatures are not extracted by the VISTA live-flow feature pipeline."
                ),
                "selection_metric": "validation_macro_f1",
                "validation_metrics": validation_metrics,
                "held_out_test_metrics": test_metrics,
                "group_column": args.group_column,
                "split_manifest": str(report_dir / "split_manifest.json"),
                "random_state": args.random_state,
            },
        )
        results[task_name] = {
            "selected_candidate": selected_name,
            "validation_metrics": validation_metrics,
            "held_out_test_metrics": test_metrics,
            "candidate_model": str(model_path.relative_to(ROOT)),
            "eligible_for_live_inference": False,
        }

    summary = {
        "run_id": run_id,
        "status": "candidate_evaluation_completed_not_runtime_verified",
        "evaluation_category": "Public Dataset Validation",
        "provenance": PROVENANCE,
        "dataset_summary": {
            "rows": len(adapted),
            "feature_count": len(feature_columns),
            "feature_columns": feature_columns,
            "group_column": args.group_column,
            "class_distribution": adapted["label"].value_counts().to_dict(),
            "vpn_status_distribution": targets["vpn_status_binary"].value_counts().to_dict(),
        },
        "split": split_manifest,
        "results": results,
    }
    with (report_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, default=str)
    print(f"Candidate run complete: {run_id}")
    print(f"Reports: {report_dir}")
    print(f"Models: {model_dir}")
    print("Candidate artifacts are not enabled for live inference.")


if __name__ == "__main__":
    main()
