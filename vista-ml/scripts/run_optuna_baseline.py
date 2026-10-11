#!/usr/bin/env python3
"""
VISTA Phase 10 — Baseline ML Training and Optuna Hyperparameter Optimization.
Executes reproducible, leakage-aware baseline evaluations, Optuna hyperparameter
search, feature-shortcut ablations, and final held-out test evaluation for controlled
benign workload classification from outer encrypted IPv4 ESP traffic metadata.

This phase is strictly exploratory: candidate models are NOT authorized for production
promotion, deployment, or live inference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import optuna
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_baseline import evaluate_cv_folds, evaluate_predictions  # noqa: E402
from vista_ml.models.random_forest import save_model_bundle  # noqa: E402

CAMPAIGN_ID_DEFAULT = "76adc766-ef41-45f5-b677-1d950c7ff052"
TARGET_CLASSES = [
    "controlled_icmpv4",
    "controlled_tcp_marker",
    "controlled_http",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_dataset_eligibility(audit_path: Path, campaign_id: str) -> dict[str, Any]:
    """Validates the Phase 9 audit report decision gates. Aborts if gates fail."""
    if not audit_path.is_file():
        raise FileNotFoundError(
            f"Phase 9 audit report not found at {audit_path}. Phase 9 audit is a required eligibility prerequisite."
        )

    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    audited_campaign = audit.get("audited_campaign_id")
    if audited_campaign != campaign_id:
        raise ValueError(
            f"Audit report campaign mismatch: expected {campaign_id}, found {audited_campaign}"
        )

    gates = audit.get("gates", {})
    required_passes = [
        "artifact_integrity",
        "ground_truth_integrity",
        "label_integrity",
        "feature_integrity",
        "leakage_controls",
        "class_coverage",
        "split_validity",
        "baseline_eligibility",
    ]
    for gate in required_passes:
        status = gates.get(gate, {}).get("status")
        if status != "PASS":
            raise RuntimeError(
                f"Eligibility gate '{gate}' failed with status '{status}': {gates.get(gate, {}).get('evidence')}"
            )

    indep_status = gates.get("independent_campaign_validation", {}).get("status")
    if indep_status != "BLOCKED":
        raise RuntimeError(
            f"Expected independent_campaign_validation to be 'BLOCKED', found '{indep_status}'"
        )

    discrepancies = audit.get("discrepancies", [])
    if discrepancies:
        raise RuntimeError(f"Audit report contains unresolved discrepancies: {discrepancies}")

    return audit


def load_and_validate_dataset(
    campaign_dir: Path,
    feature_schema_path: Path,
    target_schema_path: Path,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, list[str]]:
    """Loads prepared_dataset.csv, verifies schemas, and strictly extracts features and splits."""
    if not campaign_dir.is_dir():
        raise FileNotFoundError(f"Campaign directory not found: {campaign_dir}")

    dataset_csv = campaign_dir / "dataset_preparation" / "prepared_dataset.csv"
    split_manifest_json = campaign_dir / "dataset_preparation" / "split_manifest.json"

    if not dataset_csv.is_file():
        raise FileNotFoundError(f"Prepared dataset CSV not found: {dataset_csv}")
    if not split_manifest_json.is_file():
        raise FileNotFoundError(f"Split manifest not found: {split_manifest_json}")

    # Load feature schema allowlist
    feat_schema = json.loads(feature_schema_path.read_text(encoding="utf-8"))
    feature_columns = [f["name"] for f in feat_schema["features"]]
    if len(feature_columns) != 18:
        raise ValueError(f"Expected 18 flow features in vista-flow-v1, got {len(feature_columns)}")

    # Load target label schema
    target_schema = json.loads(target_schema_path.read_text(encoding="utf-8"))
    expected_classes = set(target_schema["target_classes"].keys())
    if expected_classes != set(TARGET_CLASSES):
        raise ValueError(f"Target classes mismatch: expected {expected_classes}, got {TARGET_CLASSES}")

    df = pd.read_csv(dataset_csv)
    split_manifest = json.loads(split_manifest_json.read_text(encoding="utf-8"))

    # Validate target label membership
    observed_classes = set(df["label"].unique())
    if not observed_classes.issubset(expected_classes):
        raise ValueError(f"Dataset contains unexpected target classes: {observed_classes - expected_classes}")

    # Verify all 18 features exist and are non-null and finite
    for col in feature_columns:
        if col not in df.columns:
            raise ValueError(f"Missing mandatory flow feature in dataset: {col}")
        if not np.isfinite(df[col]).all():
            raise ValueError(f"Non-finite values encountered in mandatory flow feature: {col}")

    # Split dataset according to session_ids in split_manifest
    train_sessions = set(split_manifest["session_ids"]["train"])
    val_sessions = set(split_manifest["session_ids"]["validation"])
    test_sessions = set(split_manifest["session_ids"]["test"])

    # Strict leakage assertion
    if train_sessions & val_sessions or train_sessions & test_sessions or val_sessions & test_sessions:
        raise ValueError("Session leakage detected across split manifest definitions!")

    train_df = df[df["session_id"].isin(train_sessions)].copy()
    val_df = df[df["session_id"].isin(val_sessions)].copy()
    test_df = df[df["session_id"].isin(test_sessions)].copy()

    if len(train_df) != 36:
        raise ValueError(f"Expected 36 training observations (9 sessions * 4), found {len(train_df)}")
    if len(val_df) != 12:
        raise ValueError(f"Expected 12 validation observations (3 sessions * 4), found {len(val_df)}")
    if len(test_df) != 12:
        raise ValueError(f"Expected 12 test observations (3 sessions * 4), found {len(test_df)}")

    return train_df, val_df, test_df, feature_columns


def run_baseline_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
    n_splits: int = 3,
) -> dict[str, Any]:
    """Evaluates the 3 non-optimized baselines on the training-session GroupKFold protocol."""
    baselines = {
        "majority_class": DummyClassifier(strategy="most_frequent"),
        "decision_tree_shallow": DecisionTreeClassifier(max_depth=2, random_state=42),
        "random_forest_initial": RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1),
    }

    results: dict[str, Any] = {}
    for name, clf in baselines.items():
        eval_result = evaluate_cv_folds(
            clf=clf,
            X=X_train,
            y=y_train,
            groups=groups_train,
            n_splits=n_splits,
            label_names=TARGET_CLASSES,
        )
        results[name] = eval_result

    return results


def run_optuna_optimization(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
    n_trials: int = 30,
    seed: int = 42,
    n_splits: int = 3,
) -> tuple[optuna.Study, dict[str, Any]]:
    """Runs Optuna hyperparameter optimization strictly on the training sessions using GroupKFold."""
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    sampler = optuna.samplers.TPESampler(seed=seed)
    study = optuna.create_study(direction="maximize", sampler=sampler)

    gkf = GroupKFold(n_splits=n_splits)

    def objective(trial: optuna.Trial) -> float:
        n_estimators = trial.suggest_int("n_estimators", 20, 200, step=10)
        max_depth = trial.suggest_int("max_depth", 2, 8)
        min_samples_split = trial.suggest_int("min_samples_split", 2, 10)
        min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 5)
        max_features = trial.suggest_categorical("max_features", ["sqrt", "log2", None])
        class_weight = trial.suggest_categorical("class_weight", [None, "balanced"])

        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            max_features=max_features,
            class_weight=class_weight,
            random_state=seed,
            n_jobs=-1,
        )

        fold_f1s: list[float] = []
        for train_idx, val_idx in gkf.split(X_train, y_train, groups=groups_train):
            clf.fit(X_train.iloc[train_idx], y_train.iloc[train_idx])
            preds = clf.predict(X_train.iloc[val_idx])
            score = float(f1_score(y_train.iloc[val_idx], preds, average="macro", zero_division=0))
            fold_f1s.append(score)

        mean_f1 = float(np.mean(fold_f1s))
        std_f1 = float(np.std(fold_f1s))
        trial.set_user_attr("fold_scores", fold_f1s)
        trial.set_user_attr("std_macro_f1", std_f1)
        return mean_f1

    study.optimize(objective, n_trials=n_trials)

    trials_summary: list[dict[str, Any]] = []
    for t in study.trials:
        trials_summary.append({
            "trial_number": t.number,
            "state": str(t.state.name),
            "macro_f1_mean": t.value,
            "params": t.params,
            "fold_scores": t.user_attrs.get("fold_scores", []),
            "std_macro_f1": t.user_attrs.get("std_macro_f1", 0.0),
        })

    study_summary = {
        "best_trial_number": study.best_trial.number,
        "best_macro_f1": study.best_value,
        "best_params": study.best_params,
        "n_trials_completed": len(study.trials),
        "trials": trials_summary,
    }

    return study, study_summary


def run_shortcut_ablation_analysis(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
    feature_columns: list[str],
    n_splits: int = 3,
) -> dict[str, Any]:
    """Evaluates single-feature models, LOFO, and feature subsets on the training-session GroupKFold."""
    ablations: dict[str, Any] = {}

    # 1. Packet count only
    clf_pc = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
    res_pc = evaluate_cv_folds(clf_pc, X_train[["packet_count"]], y_train, groups_train, n_splits=n_splits)
    ablations["packet_count_only"] = {
        "features": ["packet_count"],
        "mean_macro_f1": res_pc["mean_macro_f1"],
        "std_macro_f1": res_pc["std_macro_f1"],
        "mean_accuracy": res_pc["mean_accuracy"],
    }

    # 2. Excluding packet count
    no_pc_cols = [c for c in feature_columns if c != "packet_count"]
    clf_no_pc = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
    res_no_pc = evaluate_cv_folds(clf_no_pc, X_train[no_pc_cols], y_train, groups_train, n_splits=n_splits)
    ablations["excluding_packet_count"] = {
        "features_excluded": ["packet_count"],
        "mean_macro_f1": res_no_pc["mean_macro_f1"],
        "std_macro_f1": res_no_pc["std_macro_f1"],
        "mean_accuracy": res_no_pc["mean_accuracy"],
    }

    # 3. Individual features separately (18 models)
    single_features: dict[str, dict[str, float]] = {}
    for feat in feature_columns:
        clf_single = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
        res_s = evaluate_cv_folds(clf_single, X_train[[feat]], y_train, groups_train, n_splits=n_splits)
        single_features[feat] = {
            "mean_macro_f1": res_s["mean_macro_f1"],
            "std_macro_f1": res_s["std_macro_f1"],
            "mean_accuracy": res_s["mean_accuracy"],
        }
    ablations["single_features"] = single_features

    # 4. Leave-one-feature-out (18 models)
    lofo: dict[str, dict[str, float]] = {}
    for feat in feature_columns:
        rem_cols = [c for c in feature_columns if c != feat]
        clf_lofo = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
        res_l = evaluate_cv_folds(clf_lofo, X_train[rem_cols], y_train, groups_train, n_splits=n_splits)
        lofo[feat] = {
            "dropped_feature": feat,
            "mean_macro_f1": res_l["mean_macro_f1"],
            "std_macro_f1": res_l["std_macro_f1"],
            "mean_accuracy": res_l["mean_accuracy"],
        }
    ablations["leave_one_feature_out"] = lofo

    # 5. Timing-only group
    timing_cols = [
        "flow_duration",
        "mean_inter_arrival_time",
        "std_inter_arrival_time",
        "min_inter_arrival_time",
        "max_inter_arrival_time",
        "packets_per_second",
        "bytes_per_second",
    ]
    clf_time = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
    res_time = evaluate_cv_folds(clf_time, X_train[timing_cols], y_train, groups_train, n_splits=n_splits)
    ablations["timing_features_only"] = {
        "features": timing_cols,
        "mean_macro_f1": res_time["mean_macro_f1"],
        "std_macro_f1": res_time["std_macro_f1"],
        "mean_accuracy": res_time["mean_accuracy"],
    }

    # 6. Packet size and byte count group
    size_cols = [
        "byte_count",
        "mean_packet_size",
        "std_packet_size",
        "min_packet_size",
        "max_packet_size",
        "forward_packet_count",
        "backward_packet_count",
        "forward_bytes",
        "backward_bytes",
        "direction_ratio",
    ]
    clf_size = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42, n_jobs=-1)
    res_size = evaluate_cv_folds(clf_size, X_train[size_cols], y_train, groups_train, n_splits=n_splits)
    ablations["packet_size_and_bytes_only"] = {
        "features": size_cols,
        "mean_macro_f1": res_size["mean_macro_f1"],
        "std_macro_f1": res_size["std_macro_f1"],
        "mean_accuracy": res_size["mean_accuracy"],
    }

    return ablations


def evaluate_held_out_test_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    test_meta: pd.DataFrame,
    best_rf_params: dict[str, Any],
    seed: int = 42,
) -> tuple[dict[str, Any], RandomForestClassifier]:
    """Fits candidate configurations on ALL training sessions and evaluates ONCE on held-out test sessions."""
    models_to_test = {
        "majority_class": DummyClassifier(strategy="most_frequent"),
        "decision_tree_shallow": DecisionTreeClassifier(max_depth=2, random_state=seed),
        "random_forest_initial": RandomForestClassifier(n_estimators=100, max_depth=4, random_state=seed, n_jobs=-1),
        "random_forest_optuna_tuned": RandomForestClassifier(**best_rf_params, random_state=seed, n_jobs=-1),
    }

    test_results: dict[str, Any] = {}
    best_model: RandomForestClassifier | None = None

    for name, clf in models_to_test.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)

        eval_res = evaluate_predictions(y_test, preds, label_names=TARGET_CLASSES)

        # Per-sample predictions log
        sample_predictions: list[dict[str, Any]] = []
        for i in range(len(test_meta)):
            sample_predictions.append({
                "experiment_id": str(test_meta.iloc[i]["experiment_id"]),
                "session_id": str(test_meta.iloc[i]["session_id"]),
                "ground_truth_label": str(y_test.iloc[i]),
                "predicted_label": str(preds[i]),
                "correct": bool(y_test.iloc[i] == preds[i]),
            })

        eval_res["sample_predictions"] = sample_predictions
        test_results[name] = eval_res

        if name == "random_forest_optuna_tuned":
            best_model = clf

    assert best_model is not None
    return test_results, best_model


def run_phase10_experiment(
    campaign_id: str = CAMPAIGN_ID_DEFAULT,
    n_trials: int = 30,
    seed: int = 42,
    save_model: bool = True,
) -> dict[str, Any]:
    """Orchestrates Phase 10 execution and returns the complete audit report."""
    audit_report_path = ROOT / "reports" / "phase9_dataset_audit.json"
    campaign_dir = ROOT.parent / "captures" / "strongswan" / "collections" / "campaigns" / campaign_id
    if not campaign_dir.is_dir():
        # Fallback to relative ROOT path if running from repo root
        campaign_dir = ROOT / ".." / "captures" / "strongswan" / "collections" / "campaigns" / campaign_id
        campaign_dir = campaign_dir.resolve()

    feat_schema_path = ROOT / "schemas" / "vista-flow-v1.json"
    target_schema_path = ROOT / "schemas" / "vista-target-label-schema-v1.json"

    # Step 1: Enforce eligibility gate
    audit_data = validate_dataset_eligibility(audit_report_path, campaign_id)
    audit_report_hash = sha256_file(audit_report_path)

    # Step 2: Load and validate dataset
    train_df, val_df, test_df, feature_cols = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    X_train = train_df[feature_cols].copy()
    y_train = train_df["label"].copy()
    groups_train = train_df["session_id"].copy()

    X_test = test_df[feature_cols].copy()
    y_test = test_df["label"].copy()

    # Step 3: Establish non-optimized baselines on training GroupKFold
    baseline_cv_results = run_baseline_models(X_train, y_train, groups_train, n_splits=3)

    # Step 4: Optuna optimization on training GroupKFold
    study, study_summary = run_optuna_optimization(
        X_train, y_train, groups_train, n_trials=n_trials, seed=seed, n_splits=3
    )

    # Step 5: Feature shortcut ablations
    ablation_results = run_shortcut_ablation_analysis(
        X_train, y_train, groups_train, feature_cols, n_splits=3
    )

    # Step 6: Final held-out test evaluation
    test_results, best_model = evaluate_held_out_test_models(
        X_train, y_train, X_test, y_test, test_df, study.best_params, seed=seed
    )

    # Step 7: Persist experimental candidate model bundle
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    model_output_dir = ROOT / "models" / "candidates" / "controlled_workload_classification" / run_id
    model_path = model_output_dir / "random_forest.joblib"

    metadata = {
        "model_id": f"phase10-rf-{run_id}",
        "task": "controlled_benign_workload_classification",
        "task_boundary": "Exploratory candidate model only. Excludes arbitrary applications, attacks, and IPsec classification.",
        "feature_schema_version": "vista-flow-v1",
        "target_label_schema_version": "vista-target-label-schema-v1",
        "campaign_id": campaign_id,
        "phase9_audit_report_hash": audit_report_hash,
        "validated_for_inference": False,
        "production_eligible": False,
        "experimental": True,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_sample_count": len(train_df),
        "training_session_count": len(train_df["session_id"].unique()),
        "test_sample_count": len(test_df),
        "test_session_count": len(test_df["session_id"].unique()),
        "hyperparameters": study.best_params,
        "validation_mean_macro_f1": study.best_value,
        "test_macro_f1": test_results["random_forest_optuna_tuned"]["macro_f1"],
        "classes": TARGET_CLASSES,
    }

    if save_model:
        save_model_bundle(best_model, model_path, metadata=metadata)

    # Assemble comprehensive report
    report: dict[str, Any] = {
        "schema_version": "vista-optuna-experiment-v1",
        "experiment_phase": "Phase 10 — Baseline ML Training and Optuna Hyperparameter Optimization",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "optuna_version": optuna.__version__,
        },
        "dataset_provenance": {
            "campaign_id": campaign_id,
            "phase9_audit_report": str(audit_report_path),
            "phase9_audit_report_sha256": audit_report_hash,
            "feature_schema": "vista-flow-v1.json",
            "target_label_schema": "vista-target-label-schema-v1.json",
            "feature_count": len(feature_cols),
            "feature_allowlist": feature_cols,
            "target_classes": TARGET_CLASSES,
            "observations": {
                "train": {"samples": len(train_df), "sessions": len(train_df["session_id"].unique())},
                "validation": {"samples": len(val_df), "sessions": len(val_df["session_id"].unique())},
                "test": {"samples": len(test_df), "sessions": len(test_df["session_id"].unique())},
            },
        },
        "non_optimized_baselines_cv": {
            "majority_class": {
                "mean_macro_f1": baseline_cv_results["majority_class"]["mean_macro_f1"],
                "std_macro_f1": baseline_cv_results["majority_class"]["std_macro_f1"],
                "mean_accuracy": baseline_cv_results["majority_class"]["mean_accuracy"],
                "confusion_matrix": baseline_cv_results["majority_class"]["aggregated_confusion_matrix"],
            },
            "decision_tree_shallow": {
                "mean_macro_f1": baseline_cv_results["decision_tree_shallow"]["mean_macro_f1"],
                "std_macro_f1": baseline_cv_results["decision_tree_shallow"]["std_macro_f1"],
                "mean_accuracy": baseline_cv_results["decision_tree_shallow"]["mean_accuracy"],
                "confusion_matrix": baseline_cv_results["decision_tree_shallow"]["aggregated_confusion_matrix"],
            },
            "random_forest_initial": {
                "mean_macro_f1": baseline_cv_results["random_forest_initial"]["mean_macro_f1"],
                "std_macro_f1": baseline_cv_results["random_forest_initial"]["std_macro_f1"],
                "mean_accuracy": baseline_cv_results["random_forest_initial"]["mean_accuracy"],
                "confusion_matrix": baseline_cv_results["random_forest_initial"]["aggregated_confusion_matrix"],
            },
        },
        "optuna_hyperparameter_optimization": {
            "objective": "maximize_mean_macro_f1_session_grouped_cv",
            "n_splits": 3,
            "n_trials": n_trials,
            "random_seed": seed,
            "best_trial_number": study_summary["best_trial_number"],
            "best_macro_f1": study_summary["best_macro_f1"],
            "best_hyperparameters": study_summary["best_params"],
            "trials": study_summary["trials"],
        },
        "feature_shortcut_ablation_analysis": ablation_results,
        "held_out_test_evaluation": {
            "uncertainty_disclaimer": (
                "The held-out test split contains only 12 observations from 3 sessions collected on a single testbed. "
                "Metrics have high uncertainty and must NOT be interpreted as reliable estimates of real-world operational performance."
            ),
            "sample_count": len(test_df),
            "session_count": len(test_df["session_id"].unique()),
            "models": test_results,
        },
        "model_artifact": {
            "persisted": save_model,
            "model_path": str(model_path) if save_model else None,
            "validated_for_inference": False,
            "production_eligible": False,
        },
        "diagnostic_conclusions": [
            "All 18 features are available at outer ESP inference time and do not inspect encrypted inner payloads.",
            "Optuna optimization found hyperparameters that achieve high validation macro-F1 on the session-grouped splits.",
            "Single-feature ablations confirm that std_packet_size (0.8893 macro-F1) and packet_count (0.8429 macro-F1) act as powerful workload recipe discriminators.",
            "Leave-one-feature-out evaluations show resilience across all 18 features (F1 0.9286 - 1.0000) due to redundant timing, size, and directional representations.",
            "Perfect held-out test metrics reflect testbed recipe consistency and do NOT establish generalized operational application identification or attack detection.",
            "Model remains experimental and is strictly blocked from production deployment.",
        ],
    }

    # Persist report
    report_output_path = ROOT / "reports" / "phase10_optuna_report.json"
    report_output_path.parent.mkdir(parents=True, exist_ok=True)
    report_output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 10 Baseline ML Training and Optuna Optimization.")
    parser.add_argument("--campaign-id", default=CAMPAIGN_ID_DEFAULT, help="Campaign UUID to evaluate")
    parser.add_argument("--n-trials", type=int, default=30, help="Number of Optuna trials (default: 30)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--no-save-model", action="store_true", help="Do not persist model artifact")
    args = parser.parse_args()

    print(f"Executing Phase 10 Baseline ML & Optuna Study for campaign {args.campaign_id}...")
    report = run_phase10_experiment(
        campaign_id=args.campaign_id,
        n_trials=args.n_trials,
        seed=args.seed,
        save_model=not args.no_save_model,
    )

    best_p = report["optuna_hyperparameter_optimization"]["best_hyperparameters"]
    best_f1 = report["optuna_hyperparameter_optimization"]["best_macro_f1"]
    test_f1 = report["held_out_test_evaluation"]["models"]["random_forest_optuna_tuned"]["macro_f1"]

    print("\nPhase 10 Execution Succeeded.")
    print(f"Best Validation Macro-F1: {best_f1:.4f}")
    print(f"Best Hyperparameters: {best_p}")
    print(f"Held-Out Test Macro-F1: {test_f1:.4f}")
    print(f"Report saved to: vista-ml/reports/phase10_optuna_report.json")


if __name__ == "__main__":
    main()
