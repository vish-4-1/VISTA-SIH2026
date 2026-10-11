from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
for path in (ROOT / "src", SCRIPT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from evaluate_strongswan_benign_captures import (  # noqa: E402
    FEATURE_COLUMNS,
    HELD_OUT_RUN,
    _load_run,
)

DEFAULT_EVALUATION = (
    ROOT / "reports/candidates/benign_outer_esp_icmp_vs_tcp/"
    "20261010T020048Z-b045d473/evaluation.json"
)
LABELS = ["ICMP_NORMAL", "TCP_NORMAL"]
POSITIVE_LABEL = "TCP_NORMAL"
FEATURE_GROUPS = {
    "packet_count": ["packet_count"],
    "size_statistics": [
        "mean_packet_size", "std_packet_size", "min_packet_size", "max_packet_size",
    ],
    "timing_statistics": [
        "flow_duration", "mean_inter_arrival_time", "std_inter_arrival_time",
        "min_inter_arrival_time", "max_inter_arrival_time",
    ],
    "rates": ["packets_per_second", "bytes_per_second"],
    "directional_counts_and_bytes": [
        "forward_packet_count", "backward_packet_count", "forward_bytes",
        "backward_bytes", "direction_ratio",
    ],
    "volume_and_direction": [
        "packet_count", "byte_count", "packets_per_second", "bytes_per_second",
        "forward_packet_count", "backward_packet_count", "forward_bytes",
        "backward_bytes", "direction_ratio",
    ],
}


def _metrics(y_true: pd.Series, predictions: np.ndarray, probabilities: np.ndarray) -> dict:
    report = classification_report(
        y_true, predictions, labels=LABELS, output_dict=True, zero_division=0
    )
    binary_target = (y_true.to_numpy() == POSITIVE_LABEL).astype(int)
    score = probabilities[:, LABELS.index(POSITIVE_LABEL)]
    return {
        "records": int(len(y_true)),
        "class_distribution": y_true.value_counts().reindex(LABELS, fill_value=0).to_dict(),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "macro_precision": float(report["macro avg"]["precision"]),
        "macro_recall": float(report["macro avg"]["recall"]),
        "macro_f1": float(f1_score(y_true, predictions, average="macro", zero_division=0)),
        "per_class": {label: report[label] for label in LABELS},
        "confusion_matrix": confusion_matrix(y_true, predictions, labels=LABELS).tolist(),
        "tcp_normal_roc_auc": float(roc_auc_score(binary_target, score)),
        "tcp_normal_average_precision": float(
            average_precision_score(binary_target, score)
        ),
    }


def _feature_matrix(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    return frame.loc[:, columns].astype(float)


def _train_ablation_forest(
    train: pd.DataFrame, columns: list[str], random_state: int
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=300,
        random_state=random_state,
        n_jobs=1,
        class_weight="balanced_subsample",
    )
    model.fit(_feature_matrix(train, columns), train["label"].astype(str))
    return model


def _evaluate_model(model, train: pd.DataFrame, test: pd.DataFrame, columns: list[str]) -> dict:
    probabilities = model.predict_proba(_feature_matrix(test, columns))
    classes = list(model.classes_)
    aligned = np.zeros((len(test), len(LABELS)), dtype=float)
    for source_index, label in enumerate(classes):
        aligned[:, LABELS.index(str(label))] = probabilities[:, source_index]
    return _metrics(
        test["label"].astype(str),
        np.asarray(model.predict(_feature_matrix(test, columns)), dtype=str),
        aligned,
    )


def _capture_hash_duplicates(frame: pd.DataFrame) -> list[list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for row in frame.itertuples():
        grouped[str(row.packet_capture_sha256)].append(str(row.capture_group))
    return [sorted(ids) for ids in grouped.values() if len(ids) > 1]


def _near_duplicate_pairs(frame: pd.DataFrame) -> list[dict[str, str]]:
    values = frame.loc[:, FEATURE_COLUMNS].to_numpy(dtype=float)
    result = []
    for left in range(len(frame)):
        for right in range(left + 1, len(frame)):
            scale = np.maximum(np.maximum(np.abs(values[left]), np.abs(values[right])), 1.0)
            relative_delta = np.abs(values[left] - values[right]) / scale
            if np.all(relative_delta <= 1e-6) and not np.array_equal(
                values[left], values[right]
            ):
                result.append({
                    "left": str(frame.iloc[left]["capture_group"]),
                    "right": str(frame.iloc[right]["capture_group"]),
                })
    return result


def run_audit(evaluation_path: Path, random_state: int) -> dict:
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    predictions_path = ROOT / evaluation["held_out_predictions"]
    candidate_path = ROOT / evaluation["model_candidate"]
    split_path = evaluation_path.parent / "split_manifest.json"
    predictions = pd.read_csv(predictions_path)
    held_out, _ = _load_run(HELD_OUT_RUN)
    train_pool, _ = _load_run("20261005T155313Z")
    split = json.loads(split_path.read_text(encoding="utf-8"))
    group_splits = split["capture_groups"]
    run_to_split = {
        name: {str(group).split(":", 1)[0] for group in group_ids}
        for name, group_ids in group_splits.items()
    }
    session_overlap = {
        f"{left}_{right}": sorted(run_to_split[left] & run_to_split[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    }

    # Reconstruct the exact persisted held-out evaluation before computing ablations.
    saved_model = joblib.load(candidate_path)
    reproduced_labels = np.asarray(
        saved_model.predict(_feature_matrix(held_out, FEATURE_COLUMNS)), dtype=str
    )
    persisted_labels = predictions["predicted_label"].astype(str).to_numpy()
    if len(reproduced_labels) != len(predictions) or not np.array_equal(
        reproduced_labels, persisted_labels
    ):
        raise ValueError("Saved candidate predictions do not reproduce from its model and source features.")
    saved_probability = saved_model.predict_proba(
        _feature_matrix(held_out, FEATURE_COLUMNS)
    )
    if not np.allclose(
        saved_probability,
        predictions[[f"probability_{label}" for label in saved_model.classes_]].to_numpy(float),
        rtol=1e-8,
        atol=1e-10,
    ):
        raise ValueError("Saved candidate probabilities do not reproduce from source features.")

    test_labels = predictions["true_label"].astype(str)
    metric_from_artifacts = _metrics(
        test_labels,
        persisted_labels,
        predictions[[f"probability_{label}" for label in LABELS]].to_numpy(float),
    )
    for metric in (
        "accuracy", "macro_precision", "macro_recall", "macro_f1",
        "tcp_normal_roc_auc", "tcp_normal_average_precision",
    ):
        if not np.isclose(metric_from_artifacts[metric], evaluation["held_out_test"][metric]):
            raise ValueError(f"Saved metric {metric} differs from the evaluation report.")

    train_groups = set(group_splits["train"])
    validation_groups = set(group_splits["validation"])
    train = train_pool[train_pool["capture_group"].isin(train_groups)].copy()
    validation = train_pool[
        train_pool["capture_group"].isin(validation_groups)
    ].copy()
    if set(train["capture_group"]) != train_groups or set(validation["capture_group"]) != validation_groups:
        raise ValueError("Split manifest capture groups do not match source packet tables.")
    if set(held_out["capture_group"]) != set(group_splits["test"]):
        raise ValueError("Held-out split manifest does not match source packet tables.")

    comparisons: dict[str, dict] = {"saved_candidate_full_features": metric_from_artifacts}
    majority = DummyClassifier(strategy="prior")
    majority.fit(_feature_matrix(train, FEATURE_COLUMNS), train["label"].astype(str))
    comparisons["majority_class_baseline"] = _evaluate_model(
        majority, train, held_out, FEATURE_COLUMNS
    )

    shallow_tree = DecisionTreeClassifier(max_depth=1, random_state=random_state)
    shallow_tree.fit(_feature_matrix(train, FEATURE_COLUMNS), train["label"].astype(str))
    comparisons["decision_tree_depth_1"] = _evaluate_model(
        shallow_tree, train, held_out, FEATURE_COLUMNS
    )

    models_to_fit = {
        "packet_count_only": ["packet_count"],
        "without_packet_count": [name for name in FEATURE_COLUMNS if name != "packet_count"],
        "without_size_statistics": [
            name for name in FEATURE_COLUMNS if name not in FEATURE_GROUPS["size_statistics"]
        ],
        "without_timing_statistics": [
            name for name in FEATURE_COLUMNS if name not in FEATURE_GROUPS["timing_statistics"]
        ],
        "without_rates": [name for name in FEATURE_COLUMNS if name not in FEATURE_GROUPS["rates"]],
        "without_directional_features": [
            name for name in FEATURE_COLUMNS
            if name not in FEATURE_GROUPS["directional_counts_and_bytes"]
        ],
        "without_volume_and_direction": [
            name for name in FEATURE_COLUMNS
            if name not in FEATURE_GROUPS["volume_and_direction"]
        ],
    }
    models_to_fit.update({
        f"without_feature_{feature}": [
            name for name in FEATURE_COLUMNS if name != feature
        ]
        for feature in FEATURE_COLUMNS
    })
    for name, columns in models_to_fit.items():
        model = _train_ablation_forest(train, columns, random_state)
        comparisons[name] = _evaluate_model(model, train, held_out, columns)
        comparisons[name]["features_used"] = columns

    single_feature_baselines = {}
    for feature in FEATURE_COLUMNS:
        model = _train_ablation_forest(train, [feature], random_state)
        result = _evaluate_model(model, train, held_out, [feature])
        single_feature_baselines[feature] = {
            "accuracy": result["accuracy"],
            "macro_f1": result["macro_f1"],
            "confusion_matrix": result["confusion_matrix"],
        }

    full = pd.concat([train_pool, held_out], ignore_index=True)
    feature_distribution = {}
    for feature in FEATURE_COLUMNS:
        feature_distribution[feature] = {}
        for label, rows in full.groupby("label", sort=True):
            vals = pd.to_numeric(rows[feature], errors="coerce")
            feature_distribution[feature][str(label)] = {
                "unique_values": sorted(float(value) for value in vals.unique()),
                "minimum": float(vals.min()),
                "median": float(vals.median()),
                "maximum": float(vals.max()),
            }

    run_distribution = {}
    for run_id, run_rows in full.groupby("source_run", sort=True):
        run_distribution[str(run_id)] = {
            "record_count": int(len(run_rows)),
            "class_distribution": run_rows["label"].value_counts().sort_index().to_dict(),
            "features": {
                feature: {
                    "minimum": float(run_rows[feature].min()),
                    "median": float(run_rows[feature].median()),
                    "maximum": float(run_rows[feature].max()),
                    "unique_values": int(run_rows[feature].nunique()),
                }
                for feature in FEATURE_COLUMNS
            },
        }

    identifiers_reveal_label = set()
    for row in full.itertuples():
        normalized_prefix = (
            "icmp_normal" if str(row.label) == "ICMP_NORMAL" else "tcp_normal"
        )
        if (
            str(row.experiment_id).startswith(normalized_prefix + "_")
            or Path(str(row.packet_capture_path)).stem.startswith(normalized_prefix + "_")
        ):
            identifiers_reveal_label.add(str(row.experiment_id))

    class_metrics = metric_from_artifacts
    n = class_metrics["records"]
    accuracy = class_metrics["accuracy"]
    z = 1.959963984540054
    denominator = 1 + z * z / n
    center = (accuracy + z * z / (2 * n)) / denominator
    half_width = z * np.sqrt(accuracy * (1 - accuracy) / n + z * z / (4 * n * n)) / denominator
    capture_hash = hashlib.sha256(predictions_path.read_bytes()).hexdigest()

    return {
        "report_version": 1,
        "status": "AUDIT_COMPLETE_CANDIDATE_NOT_VALIDATED",
        "task": evaluation["task"],
        "source_evaluation": str(evaluation_path.relative_to(ROOT)),
        "held_out_predictions_sha256": capture_hash,
        "source_provenance": [
            {
                "processing_run": run_id,
                "label_index_path": details["label_index_path"],
                "label_index_sha256": details["label_index_sha256"],
                "packet_table_count": len(details["packet_captures"]),
                "packet_tables": details["packet_captures"],
                "raw_pcap_for_each_observation_available": all(
                    Path(item["path"]).suffix.lower() in {".pcap", ".pcapng"}
                    for item in details["packet_captures"]
                ),
            }
            for run_id, details in evaluation["source_files"].items()
        ],
        "ground_truth_provenance": {
            "source": "explicit label column in normal_traffic_features.parquet",
            "independent_endpoint_records_available": False,
            "label_origin_independently_verified": False,
            "limitation": (
                "The current packet tables have no per-observation ground-truth sidecar or raw-PCAP "
                "manifest; labels and experiment/file names use the same ICMP/TCP workload names."
            ),
        },
        "reproduction": {
            "saved_candidate_labels_reproduced": True,
            "saved_candidate_probabilities_reproduced": True,
            "metrics_recomputed_from_saved_predictions": True,
            "reported_metrics_match": True,
        },
        "sample_and_group_limits": {
            "records": {
                "train": len(train),
                "validation": len(validation),
                "test": len(held_out),
            },
            "processing_runs_by_split": {
                split_name: sorted(runs) for split_name, runs in run_to_split.items()
            },
            "processing_run_overlap": session_overlap,
            "verified_source_session_ids_available": False,
            "independent_test_processing_runs": len(run_to_split["test"]),
            "limitation": (
                "The source has only processing-run IDs, not independently verified capture-session IDs. "
                "Train and validation share one processing run, so validation is not session-independent; "
                "the held-out set is one separate processing run, not 50 independent sessions."
            ),
            "record_level_accuracy_wilson_95_interval": [
                max(0.0, float(center - half_width)),
                min(1.0, float(center + half_width)),
            ],
            "interval_caveat": (
                "Record-level interval assumes independent observations and is descriptive only; "
                "within-run captures are clustered, so it is not a session-level confidence interval."
            ),
        },
        "shortcut_and_duplicate_audit": {
            "packet_count_by_class": feature_distribution["packet_count"],
            "packet_count_perfectly_determines_class": all(
                len(values["unique_values"]) == 1
                for values in feature_distribution["packet_count"].values()
            ) and len({
                values["unique_values"][0]
                for values in feature_distribution["packet_count"].values()
            }) == len(LABELS),
            "feature_distributions_by_class": feature_distribution,
            "feature_distributions_by_processing_run": run_distribution,
            "class_labels_recoverable_from_experiment_ids_or_packet_table_filenames": bool(
                identifiers_reveal_label
            ),
            "label_revealing_identifiers": sorted(identifiers_reveal_label),
            "identifier_feature_boundary": (
                "Identifiers and filenames were excluded from model inputs, but expose the labels to "
                "any downstream process that uses metadata or file paths. New collection IDs must be opaque."
            ),
            "duplicate_packet_table_hash_groups": _capture_hash_duplicates(full),
            "near_duplicate_feature_pairs_relative_tolerance_1e-6": _near_duplicate_pairs(full),
            "exact_duplicate_feature_rows_by_split": {
                name: int(frame.duplicated(subset=FEATURE_COLUMNS).sum())
                for name, frame in (
                    ("train", train), ("validation", validation), ("test", held_out)
                )
            },
            "exact_feature_overlap_across_splits": split.get(
                "exact_feature_vector_overlap_between_splits", {}
            ),
        },
        "baseline_and_ablation_comparison": comparisons,
        "single_feature_baselines": single_feature_baselines,
        "perfect_single_feature_shortcuts": sorted(
            feature for feature, result in single_feature_baselines.items()
            if result["macro_f1"] == 1.0
        ),
        "original_validation_model_comparison": evaluation.get("selection", {}).get(
            "candidates", {}
        ),
        "decision": (
            "No classifier demonstrates defensible generalization beyond the two fixed recipes. "
            "Results are diagnostic because the training set has six records, validation has two "
            "records in the same processing run, and there is only one held-out processing run."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reproduce and audit the StrongSwan workload candidate and feature shortcuts."
    )
    parser.add_argument("--evaluation", type=Path, default=DEFAULT_EVALUATION)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "reports/audits/phase3-20261010/shortcut_ablation_report.json",
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and not args.overwrite:
        raise FileExistsError(f"Refusing to overwrite audit evidence: {output}")
    result = run_audit(args.evaluation.resolve(), args.random_state)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "output": str(output),
        "comparison_metrics": {
            name: metrics["macro_f1"]
            for name, metrics in result["baseline_and_ablation_comparison"].items()
        },
        "processing_run_overlap": result["sample_and_group_limits"]["processing_run_overlap"],
        "packet_count_perfectly_determines_class": result["shortcut_and_duplicate_audit"][
            "packet_count_perfectly_determines_class"
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
