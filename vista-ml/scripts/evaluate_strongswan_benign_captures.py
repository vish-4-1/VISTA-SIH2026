from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from vista_ml.models.random_forest import save_model_bundle, train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle as save_xgboost_bundle
from vista_ml.models.xgboost_model import train_xgboost_classifier
from vista_ml.features.pcap_features import extract_flow_features


TRAINING_RUNS = (
    "20261005T155313Z",
)
HELD_OUT_RUN = "20261005T155356Z"
TASK_NAME = "benign_outer_esp_icmp_vs_tcp"
SCHEMA_PATH = ROOT / "schemas" / "vista-flow-v1.json"
with SCHEMA_PATH.open("r", encoding="utf-8") as schema_handle:
    FEATURE_SCHEMA = json.load(schema_handle)
FEATURE_COLUMNS = [feature["name"] for feature in FEATURE_SCHEMA["features"]]
EXPECTED_LABELS = {"ICMP_NORMAL", "TCP_NORMAL"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _feature_importance(model, feature_columns: list[str]) -> list[dict[str, float | str]]:
    values = getattr(model, "feature_importances_", None)
    if values is None:
        values = getattr(getattr(model, "estimator", None), "feature_importances_", None)
    if values is None:
        return []
    return [
        {"feature": feature, "importance": float(value)}
        for feature, value in sorted(
            zip(feature_columns, values),
            key=lambda item: float(item[1]),
            reverse=True,
        )
    ]


def _load_run(run_id: str) -> tuple[pd.DataFrame, Path]:
    run_dir = ROOT / "data" / "processed" / "strongswan" / run_id
    label_path = run_dir / "normal_traffic_features.parquet"
    if not label_path.is_file():
        raise FileNotFoundError(f"StrongSwan label index not found: {label_path}")
    frame = pd.read_parquet(label_path)
    required = {"experiment_id", "label"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"{label_path} is missing required label/index columns: {missing}")
    if frame.empty:
        raise ValueError(f"StrongSwan label index is empty: {label_path}")
    if frame["label"].isna().any() or frame["experiment_id"].isna().any():
        raise ValueError(f"{label_path} contains missing labels or experiment identifiers.")
    labels = set(frame["label"].astype(str))
    if labels != EXPECTED_LABELS:
        raise ValueError(
            f"{label_path} has labels {sorted(labels)}, expected {sorted(EXPECTED_LABELS)}."
        )
    if frame["experiment_id"].astype(str).duplicated().any():
        raise ValueError(f"{label_path} has duplicate experiment identifiers.")

    packet_dir = run_dir / "packets"
    extracted = []
    for row in frame[["experiment_id", "label"]].itertuples(index=False):
        experiment_id = str(row.experiment_id)
        packet_path = packet_dir / f"{experiment_id}.csv"
        if not packet_path.is_file():
            raise FileNotFoundError(f"Packet capture table not found: {packet_path}")
        packets = pd.read_csv(packet_path)
        if "protocol" not in packets.columns or set(packets["protocol"].dropna()) != {"ESP"}:
            raise ValueError(f"{packet_path} is not an IPv4 ESP packet capture table.")
        feature_frame = extract_flow_features(packets)
        if len(feature_frame) != 1:
            raise ValueError(
                f"{packet_path} produced {len(feature_frame)} flows; exactly one is required."
            )
        extracted.append(
            {
                "experiment_id": experiment_id,
                "label": str(row.label),
                **feature_frame.loc[:, FEATURE_COLUMNS].iloc[0].to_dict(),
                "packet_capture_path": str(packet_path.relative_to(ROOT)),
                "packet_capture_sha256": _sha256(packet_path),
            }
        )

    result = pd.DataFrame(extracted)
    numeric = result.loc[:, FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    if numeric.isna().any().any() or not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise ValueError(f"{run_id} contains missing or non-finite runtime feature values.")
    if (numeric < 0).any().any():
        raise ValueError(f"{run_id} contains negative runtime feature values.")
    result.loc[:, FEATURE_COLUMNS] = numeric
    result["capture_group"] = f"{run_id}:" + frame["experiment_id"].astype(str)
    result["source_run"] = run_id
    return result, label_path


def _classification_metrics(y_true: pd.Series, predictions: np.ndarray, probabilities: np.ndarray, labels: list[str]) -> dict:
    report = classification_report(
        y_true,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )
    class_indices = {label: index for index, label in enumerate(labels)}
    positive_index = class_indices["TCP_NORMAL"]
    binary_target = (y_true.to_numpy() == "TCP_NORMAL").astype(int)
    return {
        "sample_count": int(len(y_true)),
        "class_distribution": y_true.value_counts().sort_index().to_dict(),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "macro_precision": float(report["macro avg"]["precision"]),
        "macro_recall": float(report["macro avg"]["recall"]),
        "macro_f1": float(f1_score(y_true, predictions, average="macro", zero_division=0)),
        "per_class": {label: report[label] for label in labels},
        "confusion_matrix": {
            "labels": labels,
            "values": confusion_matrix(y_true, predictions, labels=labels).tolist(),
        },
        "tcp_normal_roc_auc": float(roc_auc_score(binary_target, probabilities[:, positive_index])),
        "tcp_normal_average_precision": float(
            average_precision_score(binary_target, probabilities[:, positive_index])
        ),
        "probability_calibration": "not evaluated; raw classifier probabilities only",
    }


def _choose_candidate(
    validation: pd.DataFrame,
    train: pd.DataFrame,
    feature_columns: list[str],
    labels: list[str],
    random_state: int,
) -> tuple[str, object, dict[str, dict]]:
    candidates = []
    metrics: dict[str, dict] = {}
    for name, trainer in (
        ("random_forest", train_random_forest_classifier),
        ("xgboost", train_xgboost_classifier),
    ):
        model = trainer(
            train.loc[:, feature_columns],
            train["label"].astype(str),
            random_state=random_state,
        )
        predictions = model.predict(validation.loc[:, feature_columns])
        probabilities = model.predict_proba(validation.loc[:, feature_columns])
        score = _classification_metrics(
            validation["label"].astype(str), predictions, probabilities, labels
        )
        metrics[name] = score
        candidates.append((name, model, score))

    # Select using validation macro-F1 only; ties prefer the simpler baseline.
    selected = max(
        candidates,
        key=lambda item: (
            item[2]["macro_f1"],
            item[2]["accuracy"],
            item[0] == "random_forest",
        ),
    )
    return selected[0], selected[1], metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train a candidate benign ICMP-vs-TCP classifier on prior StrongSwan captures "
            "and evaluate once on a separate capture run."
        )
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    args = parser.parse_args()
    if not 0.1 <= args.validation_size <= 0.4:
        raise ValueError("validation-size must be between 0.1 and 0.4.")

    train_frames = []
    dataset_files = {}
    for run_id in TRAINING_RUNS:
        frame, path = _load_run(run_id)
        train_frames.append(frame)
        dataset_files[run_id] = {
            "label_index_path": str(path.relative_to(ROOT)),
            "label_index_sha256": _sha256(path),
            "rows": int(len(frame)),
            "class_distribution": frame["label"].value_counts().sort_index().to_dict(),
            "packet_captures": [
                {"path": row.packet_capture_path, "sha256": row.packet_capture_sha256}
                for row in frame.itertuples()
            ],
        }
    training_pool = pd.concat(train_frames, ignore_index=True)
    held_out, test_path = _load_run(HELD_OUT_RUN)
    dataset_files[HELD_OUT_RUN] = {
        "label_index_path": str(test_path.relative_to(ROOT)),
        "label_index_sha256": _sha256(test_path),
        "rows": int(len(held_out)),
        "class_distribution": held_out["label"].value_counts().sort_index().to_dict(),
        "packet_captures": [
            {"path": row.packet_capture_path, "sha256": row.packet_capture_sha256}
            for row in held_out.itertuples()
        ],
    }
    if set(training_pool["source_run"]) & set(held_out["source_run"]):
        raise RuntimeError("Held-out capture run overlaps training/validation runs.")

    group_labels = training_pool[["capture_group", "label"]].drop_duplicates()
    if group_labels["capture_group"].duplicated().any():
        raise ValueError("A capture group contains inconsistent target labels.")
    train_groups, validation_groups = train_test_split(
        group_labels["capture_group"].to_numpy(),
        test_size=args.validation_size,
        random_state=args.random_state,
        stratify=group_labels["label"].to_numpy(),
    )
    train = training_pool[training_pool["capture_group"].isin(train_groups)].copy()
    validation = training_pool[
        training_pool["capture_group"].isin(validation_groups)
    ].copy()
    train_group_set = set(train["capture_group"])
    validation_group_set = set(validation["capture_group"])
    test_group_set = set(held_out["capture_group"])
    if (
        train_group_set & validation_group_set
        or train_group_set & test_group_set
        or validation_group_set & test_group_set
    ):
        raise RuntimeError("Capture-group leakage found across train, validation, and held-out test.")
    for split_name, split in (("train", train), ("validation", validation), ("test", held_out)):
        if set(split["label"].astype(str)) != EXPECTED_LABELS:
            raise ValueError(f"{split_name} split does not contain both expected labels.")

    split_frames = {"train": train, "validation": validation, "test": held_out}
    split_feature_rows = {
        name: {
            tuple(row)
            for row in split.loc[:, FEATURE_COLUMNS].itertuples(index=False, name=None)
        }
        for name, split in split_frames.items()
    }
    feature_overlap = {
        f"{left}_{right}": len(split_feature_rows[left] & split_feature_rows[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    }
    if any(feature_overlap.values()):
        raise ValueError(f"Exact duplicate feature vectors cross splits: {feature_overlap}")
    duplicate_rows_within_splits = {
        name: int(split.duplicated(subset=FEATURE_COLUMNS).sum())
        for name, split in split_frames.items()
    }
    all_splits = pd.concat([train, validation, held_out], ignore_index=True)
    packet_count_by_label = {
        str(label): sorted(int(value) for value in group["packet_count"].unique())
        for label, group in all_splits.groupby("label")
    }
    packet_count_shortcut = (
        len(packet_count_by_label) == 2
        and all(len(values) == 1 for values in packet_count_by_label.values())
        and len({values[0] for values in packet_count_by_label.values()}) == 2
    )

    labels = sorted(EXPECTED_LABELS)
    selected_name, selected_model, validation_metrics = _choose_candidate(
        validation,
        train,
        FEATURE_COLUMNS,
        labels,
        args.random_state,
    )
    test_predictions = selected_model.predict(held_out.loc[:, FEATURE_COLUMNS])
    test_probabilities = selected_model.predict_proba(held_out.loc[:, FEATURE_COLUMNS])

    run_id = (
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:8]}"
    )
    model_dir = ROOT / "models" / "candidates" / TASK_NAME / run_id
    report_dir = ROOT / "reports" / "candidates" / TASK_NAME / run_id
    model_dir.mkdir(parents=True, exist_ok=False)
    report_dir.mkdir(parents=True, exist_ok=False)

    split_manifest = {
        "strategy": "capture-group stratified train/validation split plus separate held-out collection run",
        "random_state": args.random_state,
        "validation_size": args.validation_size,
        "capture_groups": {
            "train": sorted(train_group_set),
            "validation": sorted(validation_group_set),
            "test": sorted(test_group_set),
        },
        "rows": {
            "train": int(len(train)),
            "validation": int(len(validation)),
            "test": int(len(held_out)),
        },
        "class_distributions": {
            name: split["label"].value_counts().sort_index().to_dict()
            for name, split in (("train", train), ("validation", validation), ("test", held_out))
        },
        "group_overlap": {"train_validation": 0, "train_test": 0, "validation_test": 0},
        "exact_feature_vector_overlap_between_splits": feature_overlap,
        "exact_duplicate_feature_rows_within_splits": duplicate_rows_within_splits,
        "capture_point": "PC1 outer IPv4 interface; native ESP packets",
    }
    with (report_dir / "split_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(split_manifest, handle, indent=2)

    predictions = pd.DataFrame(
        {
            "capture_group": held_out["capture_group"].to_numpy(),
            "source_run": held_out["source_run"].to_numpy(),
            "experiment_id": held_out["experiment_id"].to_numpy(),
            "true_label": held_out["label"].astype(str).to_numpy(),
            "predicted_label": np.asarray(test_predictions, dtype=str),
        }
    )
    for index, label in enumerate(selected_model.classes_):
        predictions[f"probability_{label}"] = test_probabilities[:, index]
    prediction_path = report_dir / "held_out_predictions.csv"
    predictions.to_csv(prediction_path, index=False)
    saved_predictions = pd.read_csv(prediction_path)
    saved_probabilities = saved_predictions.loc[
        :, [f"probability_{label}" for label in selected_model.classes_]
    ].to_numpy(dtype=float)
    test_metrics = _classification_metrics(
        saved_predictions["true_label"].astype(str),
        saved_predictions["predicted_label"].astype(str).to_numpy(),
        saved_probabilities,
        labels,
    )

    model_path = model_dir / f"{selected_name}.joblib"
    model_metadata = {
        "model_name": selected_name,
        "model_version": run_id,
        "artifact_version": run_id,
        "prediction_task": TASK_NAME,
        "target_classes": labels,
        "feature_schema_version": FEATURE_SCHEMA["schema_version"],
        "feature_columns": FEATURE_COLUMNS,
        "feature_schema": FEATURE_SCHEMA,
        "feature_schema_sha256": _sha256(SCHEMA_PATH),
        "missing_value_policy": FEATURE_SCHEMA["missing_value_policy"],
        "preprocessing": FEATURE_SCHEMA["preprocessing"],
        "target_label_source": (
            "Controlled testbed workload selected as ICMP echo or TCP marker; not attack ground truth."
        ),
        "capture_point": "PC1 outer IPv4 interface; packets are native ESP.",
        "training_dataset_provenance": (
            "Controlled local StrongSwan testbed captures; ICMP echo and TCP marker workload labels."
        ),
        "validated_for_inference": False,
        "runtime_feature_compatible": FEATURE_SCHEMA["runtime_feature_compatible"],
        "runtime_eligibility": "blocked",
        "validation_status": "narrow-controlled-testbed-evaluation-only",
        "inference_blocker": (
            "This two-class lab model distinguishes fixed benign workload recipes only. The backend "
            "currently excludes ESP and IKE inputs from inference; the model is not eligible for "
            "production application or attack classification."
        ),
        "training_runs": list(TRAINING_RUNS),
        "held_out_run": HELD_OUT_RUN,
        "source_dataset_hashes": {
            run: {
                "label_index": details["label_index_sha256"],
                "packet_captures": {
                    capture["path"]: capture["sha256"]
                    for capture in details["packet_captures"]
                },
            }
            for run, details in dataset_files.items()
        },
        "selected_on_validation": True,
        "validation_metrics": validation_metrics[selected_name],
        "held_out_test_metrics": test_metrics,
        "feature_importance": _feature_importance(selected_model, FEATURE_COLUMNS),
        "split_manifest": str((report_dir / "split_manifest.json").relative_to(ROOT)),
        "evaluation_provenance": {
            "held_out_run": HELD_OUT_RUN,
            "held_out_prediction_sha256": _sha256(prediction_path),
            "metrics_computed_from_saved_held_out_predictions": True,
            "evaluation_report": str(
                (report_dir / "evaluation.json").relative_to(ROOT)
            ),
            "packet_count_by_label": packet_count_by_label,
            "packet_count_is_perfect_label_proxy": packet_count_shortcut,
        },
        "random_state": args.random_state,
        "python_version": sys.version,
        "dependency_versions": {
            package: importlib.metadata.version(package)
            for package in ("numpy", "pandas", "scikit-learn", "xgboost", "joblib")
        },
    }
    saver = save_model_bundle if selected_name == "random_forest" else save_xgboost_bundle
    saver(selected_model, model_path, model_metadata)

    report = {
        "run_id": run_id,
        "status": "candidate_evaluated_not_approved_for_inference",
        "task": TASK_NAME,
        "scope": "benign ICMP-vs-TCP workload classification from outer ESP metadata",
        "dataset_provenance": "Existing controlled VISTA StrongSwan captures; no external dataset used.",
        "source_files": dataset_files,
        "row_counts": {
            "train": int(len(train)),
            "validation": int(len(validation)),
            "held_out_test": int(len(held_out)),
        },
        "feature_schema_version": FEATURE_SCHEMA["schema_version"],
        "feature_columns": FEATURE_COLUMNS,
        "feature_leakage_review": (
            "Only vista-flow-v1 packet/timing/direction features were used; target, scenario, capture, and "
            "experiment identifiers were excluded. No exact feature vectors overlap between splits. "
            "However packet_count is a perfect proxy for these generated workload labels: all ICMP captures "
            "share one count and all TCP captures share another. This reflects a controlled-recipe shortcut, "
            "not general traffic-classification generalization."
        ),
        "missing_data_policy": "Reject; no imputations or default values.",
        "exact_duplicate_feature_vector_overlap_between_splits": feature_overlap,
        "packet_count_by_label": packet_count_by_label,
        "packet_count_is_perfect_label_proxy": packet_count_shortcut,
        "selection": {
            "metric": "validation macro F1",
            "tie_break": "validation accuracy, then Random Forest baseline",
            "candidates": validation_metrics,
            "selected": selected_name,
        },
        "held_out_test": test_metrics,
        "feature_importance": _feature_importance(selected_model, FEATURE_COLUMNS),
        "held_out_predictions": str(prediction_path.relative_to(ROOT)),
        "held_out_predictions_sha256": _sha256(prediction_path),
        "model_candidate": str(model_path.relative_to(ROOT)),
        "limitations": [
            "Only two controlled benign workload recipes (ICMP echo and a TCP marker) are represented.",
            "Packet count alone perfectly separates these labels because capture recipes have fixed packet counts.",
            "Captures share one controlled StrongSwan topology and crypto configuration.",
            "The test set is a separate collection run but the same runtime/topology; it is not external validation.",
            "This experiment does not support attack detection, application identification, cipher/DH/PFS detection, or production inference.",
            "No probability calibration was evaluated.",
        ],
    }
    with (report_dir / "evaluation.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    print(json.dumps({
        "status": report["status"],
        "selected_model": selected_name,
        "training_rows": len(train),
        "validation_rows": len(validation),
        "held_out_test_rows": len(held_out),
        "validation_macro_f1": validation_metrics[selected_name]["macro_f1"],
        "held_out_test": test_metrics,
        "model_candidate": str(model_path.relative_to(ROOT)),
        "report": str((report_dir / "evaluation.json").relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
