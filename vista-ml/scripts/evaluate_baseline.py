#!/usr/bin/env python3
"""
VISTA Phase 10 — Baseline Evaluator Module.
Provides reproducible evaluation metrics, per-class statistics, confusion matrices,
and session-grouped cross-validation routines for controlled benign workload classification.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupKFold

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

TARGET_CLASSES = [
    "controlled_icmpv4",
    "controlled_tcp_marker",
    "controlled_http",
]


def evaluate_predictions(
    y_true: pd.Series | np.ndarray | list[str],
    y_pred: pd.Series | np.ndarray | list[str],
    label_names: list[str] | None = None,
) -> dict[str, Any]:
    """Computes overall and per-class metrics and confusion matrix."""
    if label_names is None:
        label_names = TARGET_CLASSES

    acc = float(accuracy_score(y_true, y_pred))
    macro_p = float(precision_score(y_true, y_pred, labels=label_names, average="macro", zero_division=0))
    macro_r = float(recall_score(y_true, y_pred, labels=label_names, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, labels=label_names, average="macro", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=label_names)
    cm_list = cm.tolist()

    report = classification_report(
        y_true,
        y_pred,
        labels=label_names,
        output_dict=True,
        zero_division=0,
    )

    per_class: dict[str, dict[str, float | int]] = {}
    for lbl in label_names:
        if lbl in report:
            per_class[lbl] = {
                "precision": float(report[lbl]["precision"]),
                "recall": float(report[lbl]["recall"]),
                "f1_score": float(report[lbl]["f1-score"]),
                "support": int(report[lbl]["support"]),
            }
        else:
            per_class[lbl] = {"precision": 0.0, "recall": 0.0, "f1_score": 0.0, "support": 0}

    return {
        "accuracy": acc,
        "macro_precision": macro_p,
        "macro_recall": macro_r,
        "macro_f1": macro_f1,
        "confusion_matrix": cm_list,
        "label_order": list(label_names),
        "per_class": per_class,
    }


def evaluate_cv_folds(
    clf: Any,
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series | np.ndarray,
    n_splits: int = 3,
    label_names: list[str] | None = None,
) -> dict[str, Any]:
    """Executes GroupKFold cross-validation, guaranteeing no group overlap between train and val."""
    if label_names is None:
        label_names = TARGET_CLASSES

    gkf = GroupKFold(n_splits=n_splits)
    fold_metrics: list[dict[str, Any]] = []
    y_true_all: list[str] = []
    y_pred_all: list[str] = []

    for fold_idx, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups)):
        # Validate strict group separation
        train_groups = set(groups.iloc[train_idx] if hasattr(groups, "iloc") else groups[train_idx])
        val_groups = set(groups.iloc[val_idx] if hasattr(groups, "iloc") else groups[val_idx])
        overlap = train_groups & val_groups
        if overlap:
            raise ValueError(f"Group leakage detected in fold {fold_idx}: {overlap}")

        X_tr, y_tr = X.iloc[train_idx], y.iloc[train_idx]
        X_va, y_va = X.iloc[val_idx], y.iloc[val_idx]

        clf.fit(X_tr, y_tr)
        preds = clf.predict(X_va)

        y_true_all.extend(list(y_va))
        y_pred_all.extend(list(preds))

        fold_eval = evaluate_predictions(y_va, preds, label_names=label_names)
        fold_eval["fold_index"] = fold_idx
        fold_eval["val_groups"] = sorted(list(val_groups))
        fold_eval["val_sample_count"] = len(val_idx)
        fold_metrics.append(fold_eval)

    accuracies = [f["accuracy"] for f in fold_metrics]
    f1s = [f["macro_f1"] for f in fold_metrics]
    precisions = [f["macro_precision"] for f in fold_metrics]
    recalls = [f["macro_recall"] for f in fold_metrics]

    overall_eval = evaluate_predictions(y_true_all, y_pred_all, label_names=label_names)

    return {
        "n_splits": n_splits,
        "mean_accuracy": float(np.mean(accuracies)),
        "std_accuracy": float(np.std(accuracies)),
        "mean_macro_f1": float(np.mean(f1s)),
        "std_macro_f1": float(np.std(f1s)),
        "min_macro_f1": float(np.min(f1s)),
        "max_macro_f1": float(np.max(f1s)),
        "mean_macro_precision": float(np.mean(precisions)),
        "std_macro_precision": float(np.std(precisions)),
        "mean_macro_recall": float(np.mean(recalls)),
        "std_macro_recall": float(np.std(recalls)),
        "aggregated_confusion_matrix": overall_eval["confusion_matrix"],
        "aggregated_per_class": overall_eval["per_class"],
        "fold_metrics": fold_metrics,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate baseline models on VISTA flow features.")
    parser.add_argument("--model-path", type=str, help="Path to serialized joblib model")
    parser.add_argument("--dataset-csv", type=str, help="Path to prepared dataset CSV")
    args = parser.parse_args()

    if not args.model_path or not args.dataset_csv:
        print("Usage: python evaluate_baseline.py --model-path <model.joblib> --dataset-csv <dataset.csv>")
        sys.exit(1)

    import joblib

    model = joblib.load(args.model_path)
    df = pd.read_csv(args.dataset_csv)
    schema_path = ROOT / "schemas" / "vista-flow-v1.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    feature_cols = [ft["name"] for ft in schema["features"]]

    X = df[feature_cols]
    y = df["label"]
    preds = model.predict(X)
    res = evaluate_predictions(y, preds)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
