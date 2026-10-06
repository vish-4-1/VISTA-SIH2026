from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import normalized_mutual_info_score

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.data.schema import ALL_FEATURE_COLUMNS, LABELS, OPTIONAL_EBPF_COLUMNS, REQUIRED_COLUMNS
from vista_ml.datasets.generator import generate_sample_dataset
from vista_ml.datasets.splitter import check_group_leakage, experiment_aware_split
from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.evaluation.metrics import summarise_anomaly_results
from vista_ml.explainability.shap_analysis import explain_xgboost
from vista_ml.models.isolation_forest import save_model_bundle as save_isolation_bundle
from vista_ml.models.isolation_forest import train_isolation_forest
from vista_ml.models.random_forest import save_model_bundle as save_random_forest_bundle
from vista_ml.models.random_forest import train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle as save_xgboost_bundle
from vista_ml.models.xgboost_model import train_xgboost_classifier


DATASET_CATEGORY = "Synthetic testbed-model validation; not measured StrongSwan telemetry"
LIMITATIONS = [
    "All rows and features are generated from parameterized synthetic profiles; none are measured PCAP/eBPF values.",
    "Network and eBPF feature profiles are selected by the synthetic target label; high held-out scores are expected and do not estimate real-world generalization.",
    "The labels are synthetic development targets and do not demonstrate real attack-detection performance.",
    "Cipher, DH group, PFS, IKE version, and IPsec mode are independently sampled synthetic metadata only; they are not inference targets in this run.",
    "Synthetic eBPF columns are simulated for schema/pipeline checks and must not be reported as collected telemetry.",
]


def _write_json(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(content, handle, indent=2, default=str)


def main() -> None:
    output_dir = ROOT / "data" / "processed" / "testbed_validation"
    report_dir = ROOT / "reports" / "testbed_synthetic_validation"
    model_dir = ROOT / "models" / "testbed_synthetic_validation"
    dataset_path = output_dir / "synthetic_testbed_flows_seed42.parquet"
    metadata_path = output_dir / "synthetic_testbed_flows_seed42.dataset-card.json"

    dataset = generate_sample_dataset(
        output_path=dataset_path,
        n_experiments=60,
        flows_per_experiment=20,
        seed=42,
    )
    missing_columns = [column for column in REQUIRED_COLUMNS + OPTIONAL_EBPF_COLUMNS if column not in dataset.columns]
    if missing_columns:
        raise ValueError(f"Generated dataset is missing canonical columns: {missing_columns}")

    feature_columns = [column for column in ALL_FEATURE_COLUMNS if column in dataset.columns]
    missing_labels = sorted(set(LABELS) - set(dataset["label"].unique()))
    if missing_labels:
        raise ValueError(f"Generated dataset is missing expected labels: {missing_labels}")

    configuration_columns = ["ike_version", "ipsec_mode", "cipher", "dh_group", "pfs_enabled"]
    configuration_label_nmi = {
        column: float(
            normalized_mutual_info_score(
                dataset["label"].astype(str),
                dataset[column].astype(str),
            )
        )
        for column in configuration_columns
    }

    train_df, test_df = experiment_aware_split(
        dataset,
        group_col="experiment_id",
        test_size=0.2,
        random_state=42,
    )
    check_group_leakage(train_df, test_df)
    if set(train_df["label"].unique()) != set(LABELS) or set(test_df["label"].unique()) != set(LABELS):
        raise ValueError("Every synthetic class must be represented in both experiment-group partitions.")

    X_train = train_df[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X_test = test_df[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y_train = train_df["label"].astype(str)
    y_test = test_df["label"].astype(str)
    label_names = sorted(LABELS)

    dataset_card = {
        "dataset_name": "VISTA Synthetic StrongSwan-Testbed Validation Flows",
        "dataset_category": DATASET_CATEGORY,
        "schema": {
            "version": "VISTA canonical flow schema",
            "required_columns": REQUIRED_COLUMNS,
            "optional_ebpf_columns": OPTIONAL_EBPF_COLUMNS,
            "feature_columns": feature_columns,
            "row_unit": "one synthetic flow record",
        },
        "generation": {
            "generator": "vista_ml.datasets.generator.generate_sample_dataset",
            "random_seed": 42,
            "experiments": int(dataset["experiment_id"].nunique()),
            "flows_per_experiment": 20,
            "rows": len(dataset),
            "feature_source": "parameterized synthetic profiles with seeded random variation",
        },
        "labels": {
            label: ("normal baseline" if label == "NORMAL" else "synthetic representative scenario")
            for label in LABELS
        },
        "class_distribution": dataset["label"].value_counts().sort_index().to_dict(),
        "split": {
            "strategy": "GroupShuffleSplit by experiment_id",
            "train_experiments": int(train_df["experiment_id"].nunique()),
            "test_experiments": int(test_df["experiment_id"].nunique()),
            "group_leakage_checked": True,
        },
        "leakage_audit": {
            "experiment_ids_shared_between_train_and_test": sorted(
                set(train_df["experiment_id"].astype(str)) & set(test_df["experiment_id"].astype(str))
            ),
            "numeric_features_generated_conditionally_on_label": True,
            "configuration_metadata_normalized_mutual_information_with_label": configuration_label_nmi,
            "interpretation": "No group overlap; synthetic flow profiles are label-conditioned by design, so supervised scores are not independent evidence of real-world performance.",
        },
        "synthetic_fields": {
            "ebpf_features": "simulated; not collected from the Docker testbed",
            "ipsec_configuration": "sampled independently of the target label; not inferred from observed traffic",
        },
        "limitations": LIMITATIONS,
        "allowed_interpretation": "Validates schema, group splitting, model fit/evaluation, Isolation Forest, and SHAP pipeline behavior only.",
    }
    _write_json(metadata_path, dataset_card)

    summary = {
        "dataset_category": DATASET_CATEGORY,
        "dataset_path": str(dataset_path.relative_to(ROOT)),
        "dataset_card_path": str(metadata_path.relative_to(ROOT)),
        "rows": len(dataset),
        "experiments": int(dataset["experiment_id"].nunique()),
        "features": feature_columns,
        "class_distribution": dataset["label"].value_counts().sort_index().to_dict(),
        "leakage_audit": dataset_card["leakage_audit"],
        "limitations": LIMITATIONS,
        "results": {},
    }

    for model_name, trainer, saver in (
        ("random_forest", train_random_forest_classifier, save_random_forest_bundle),
        ("xgboost", train_xgboost_classifier, save_xgboost_bundle),
    ):
        model = trainer(X_train, y_train, random_state=42)
        metadata = {
            "dataset_category": DATASET_CATEGORY,
            "dataset": str(dataset_path.relative_to(ROOT)),
            "features": feature_columns,
            "target": "synthetic six-class label; not evidence of real attack detection",
            "synthetic_only": True,
        }
        saver(model, model_dir / f"{model_name}.joblib", metadata)
        metrics = evaluate_classifier(
            model,
            X_test,
            y_test,
            label_names,
            report_dir / model_name,
            binary_threshold=0.5,
        )
        summary["results"][model_name] = {
            key: metrics[key]
            for key in ("accuracy", "macro_f1", "macro_precision", "macro_recall", "binary_metrics")
        }
        if model_name == "xgboost":
            summary["shap"] = explain_xgboost(
                model,
                X_test,
                output_dir=report_dir / "shap",
                max_samples=200,
            )

    normal_train = X_train.loc[y_train == "NORMAL"]
    anomaly_model = train_isolation_forest(
        normal_train,
        contamination=0.1,
        random_state=42,
    )
    anomaly_train_scores = anomaly_model.decision_function(normal_train)
    anomaly_threshold = float(np.quantile(anomaly_train_scores, 0.05))
    anomaly_scores = anomaly_model.decision_function(X_test)
    anomaly_predictions = (anomaly_scores < anomaly_threshold).astype(int)
    anomaly_truth = (y_test != "NORMAL").astype(int)
    anomaly_metrics = summarise_anomaly_results(anomaly_truth, anomaly_predictions)
    anomaly_metadata = {
        "dataset_category": DATASET_CATEGORY,
        "dataset": str(dataset_path.relative_to(ROOT)),
        "trained_on": "synthetic NORMAL training experiments only",
        "threshold_source": "5th percentile of NORMAL training decision_function scores",
        "synthetic_only": True,
    }
    save_isolation_bundle(
        anomaly_model,
        model_dir / "isolation_forest.joblib",
        anomaly_metadata,
    )
    summary["results"]["isolation_forest"] = {
        "train_normal_rows": len(normal_train),
        "anomaly_threshold": anomaly_threshold,
        **anomaly_metrics,
    }

    _write_json(report_dir / "summary.json", summary)
    print(f"Synthetic dataset: {len(dataset)} rows, {dataset['experiment_id'].nunique()} experiments, {len(feature_columns)} features")
    print(f"Grouped split: {train_df['experiment_id'].nunique()} train / {test_df['experiment_id'].nunique()} test experiments")
    for model_name, metrics in summary["results"].items():
        if model_name == "isolation_forest":
            print(
                f"{model_name}: precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
                f"F1={metrics['f1']:.3f}, FPR={metrics['false_positive_rate']:.3f}"
            )
        else:
            print(f"{model_name}: accuracy={metrics['accuracy']:.3f}, macro_f1={metrics['macro_f1']:.3f}")
    print(f"Dataset: {dataset_path}")
    print(f"Dataset card: {metadata_path}")
    print(f"Report: {report_dir / 'summary.json'}")
    print("Synthetic-only pipeline validation; do not present these metrics as measured StrongSwan performance.")


if __name__ == "__main__":
    main()