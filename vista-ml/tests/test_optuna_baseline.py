#!/usr/bin/env python3
"""
Unit and regression tests for VISTA Phase 10 — Baseline ML Training and Optuna Optimization.
Tests eligibility-gate enforcement, feature allowlisting, group separation, deterministic study
configuration, trial logging, test-set isolation, and artifact metadata.
Uses fast synthetic fixtures rather than running live campaigns.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[2]
import sys
if str(ROOT / "vista-ml" / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "vista-ml" / "scripts"))
if str(ROOT / "vista-ml" / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "vista-ml" / "src"))

from evaluate_baseline import evaluate_cv_folds, evaluate_predictions  # noqa: E402
from run_optuna_baseline import (  # noqa: E402
    TARGET_CLASSES,
    load_and_validate_dataset,
    run_baseline_models,
    run_optuna_optimization,
    validate_dataset_eligibility,
)

FEATURE_COLUMNS = [
    "packet_count", "byte_count", "flow_duration", "mean_packet_size",
    "std_packet_size", "min_packet_size", "max_packet_size",
    "mean_inter_arrival_time", "std_inter_arrival_time", "min_inter_arrival_time",
    "max_inter_arrival_time", "packets_per_second", "bytes_per_second",
    "forward_packet_count", "backward_packet_count", "forward_bytes",
    "backward_bytes", "direction_ratio",
]


def _build_synthetic_audit_report(
    path: Path,
    campaign_id: str = "76adc766-ef41-45f5-b677-1d950c7ff052",
    corrupt_gate: str | None = None,
    corrupt_indep: bool = False,
    with_discrepancy: bool = False,
) -> Path:
    gates = {
        "artifact_integrity": {"status": "PASS", "evidence": "Verified"},
        "ground_truth_integrity": {"status": "PASS", "evidence": "Verified"},
        "label_integrity": {"status": "PASS", "evidence": "Verified"},
        "feature_integrity": {"status": "PASS", "evidence": "Verified"},
        "leakage_controls": {"status": "PASS", "evidence": "Verified"},
        "class_coverage": {"status": "PASS", "evidence": "Verified"},
        "split_validity": {"status": "PASS", "evidence": "Verified"},
        "independent_campaign_validation": {"status": "BLOCKED", "evidence": "Single campaign"},
        "baseline_eligibility": {"status": "PASS", "evidence": "Qualified"},
    }
    if corrupt_gate:
        gates[corrupt_gate]["status"] = "FAIL"
    if corrupt_indep:
        gates["independent_campaign_validation"]["status"] = "PASS"

    audit = {
        "schema_version": "vista-dataset-audit-v1",
        "audited_campaign_id": campaign_id,
        "gates": gates,
        "discrepancies": ["Test discrepancy"] if with_discrepancy else [],
    }
    path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return path


def _build_synthetic_dataset_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Builds a synthetic 15-session dataset with prepared_dataset.csv and split_manifest.json."""
    campaign_dir = tmp_path / "campaign"
    prep_dir = campaign_dir / "dataset_preparation"
    prep_dir.mkdir(parents=True, exist_ok=True)

    session_ids = [str(uuid.uuid4()) for _ in range(15)]
    train_sessions = session_ids[:9]
    val_sessions = session_ids[9:12]
    test_sessions = session_ids[12:]

    rows = []
    classes = ["controlled_icmpv4", "controlled_tcp_marker", "controlled_http", "controlled_http"]

    for s_idx, sid in enumerate(session_ids):
        for c_idx, label in enumerate(classes):
            row = {
                "experiment_id": str(uuid.uuid4()),
                "session_id": sid,
                "label": label,
                "capture_path": f"artifacts/{sid}/packets.csv",
                "capture_sha256": "abcdef1234567890",
            }
            # Fill 18 features with synthetic numeric values
            for f_idx, feat in enumerate(FEATURE_COLUMNS):
                base = 10.0 * (c_idx + 1) + f_idx + s_idx * 0.1
                row[feat] = base
            rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(prep_dir / "prepared_dataset.csv", index=False)

    split_manifest = {
        "session_ids": {
            "train": train_sessions,
            "validation": val_sessions,
            "test": test_sessions,
        }
    }
    (prep_dir / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")

    feat_schema_path = tmp_path / "vista-flow-v1.json"
    feat_schema_path.write_text(json.dumps({
        "schema_version": "vista-flow-v1",
        "features": [{"name": f, "order": i} for i, f in enumerate(FEATURE_COLUMNS)]
    }), encoding="utf-8")

    target_schema_path = tmp_path / "vista-target-label-schema-v1.json"
    target_schema_path.write_text(json.dumps({
        "schema_version": "vista-target-label-schema-v1",
        "target_classes": {c: {} for c in TARGET_CLASSES}
    }), encoding="utf-8")

    return campaign_dir, feat_schema_path, target_schema_path


def test_eligibility_gate_enforcement_pass(tmp_path: Path):
    audit_file = _build_synthetic_audit_report(tmp_path / "audit_pass.json")
    audit = validate_dataset_eligibility(audit_file, "76adc766-ef41-45f5-b677-1d950c7ff052")
    assert audit["audited_campaign_id"] == "76adc766-ef41-45f5-b677-1d950c7ff052"
    assert audit["gates"]["baseline_eligibility"]["status"] == "PASS"


def test_eligibility_gate_enforcement_missing_or_failed(tmp_path: Path):
    # 1. Non-existent file
    with pytest.raises(FileNotFoundError):
        validate_dataset_eligibility(tmp_path / "missing.json", "76adc766-ef41-45f5-b677-1d950c7ff052")

    # 2. Campaign mismatch
    audit_file = _build_synthetic_audit_report(tmp_path / "audit_mismatch.json", campaign_id="wrong-id")
    with pytest.raises(ValueError, match="Audit report campaign mismatch"):
        validate_dataset_eligibility(audit_file, "76adc766-ef41-45f5-b677-1d950c7ff052")

    # 3. Failed gate
    audit_fail = _build_synthetic_audit_report(tmp_path / "audit_fail.json", corrupt_gate="artifact_integrity")
    with pytest.raises(RuntimeError, match="Eligibility gate 'artifact_integrity' failed"):
        validate_dataset_eligibility(audit_fail, "76adc766-ef41-45f5-b677-1d950c7ff052")

    # 4. Independent campaign validation falsely marked PASS
    audit_unblocked = _build_synthetic_audit_report(tmp_path / "audit_unblocked.json", corrupt_indep=True)
    with pytest.raises(RuntimeError, match="independent_campaign_validation to be 'BLOCKED'"):
        validate_dataset_eligibility(audit_unblocked, "76adc766-ef41-45f5-b677-1d950c7ff052")

    # 5. Report contains discrepancies
    audit_discrepancy = _build_synthetic_audit_report(tmp_path / "audit_disc.json", with_discrepancy=True)
    with pytest.raises(RuntimeError, match="unresolved discrepancies"):
        validate_dataset_eligibility(audit_discrepancy, "76adc766-ef41-45f5-b677-1d950c7ff052")


def test_feature_allowlist_enforcement(tmp_path: Path):
    campaign_dir, feat_schema_path, target_schema_path = _build_synthetic_dataset_fixture(tmp_path)
    train_df, val_df, test_df, feature_cols = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    assert feature_cols == FEATURE_COLUMNS
    assert len(train_df) == 36
    assert len(val_df) == 12
    assert len(test_df) == 12

    # Verify no metadata columns in feature allowlist
    metadata_cols = {"experiment_id", "session_id", "label", "capture_path", "capture_sha256"}
    assert not (set(feature_cols) & metadata_cols)


def test_group_separation_no_leakage(tmp_path: Path):
    campaign_dir, feat_schema_path, target_schema_path = _build_synthetic_dataset_fixture(tmp_path)
    train_df, _, _, feature_cols = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    X = train_df[feature_cols]
    y = train_df["label"]
    groups = train_df["session_id"]

    clf = RandomForestClassifier(n_estimators=10, max_depth=2, random_state=42)
    cv_res = evaluate_cv_folds(clf, X, y, groups, n_splits=3)

    assert cv_res["n_splits"] == 3
    assert len(cv_res["fold_metrics"]) == 3

    # Every fold must have 3 validation sessions and 0 session overlap
    for fold in cv_res["fold_metrics"]:
        val_groups = set(fold["val_groups"])
        assert len(val_groups) == 3
        train_groups = set(groups.unique()) - val_groups
        assert not (val_groups & train_groups)


def test_deterministic_study_configuration(tmp_path: Path):
    campaign_dir, feat_schema_path, target_schema_path = _build_synthetic_dataset_fixture(tmp_path)
    train_df, _, _, feature_cols = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    X = train_df[feature_cols]
    y = train_df["label"]
    groups = train_df["session_id"]

    study1, summary1 = run_optuna_optimization(X, y, groups, n_trials=5, seed=42, n_splits=3)
    study2, summary2 = run_optuna_optimization(X, y, groups, n_trials=5, seed=42, n_splits=3)

    assert summary1["best_params"] == summary2["best_params"]
    assert summary1["best_macro_f1"] == summary2["best_macro_f1"]
    assert summary1["best_trial_number"] == summary2["best_trial_number"]


def test_trial_logging(tmp_path: Path):
    campaign_dir, feat_schema_path, target_schema_path = _build_synthetic_dataset_fixture(tmp_path)
    train_df, _, _, feature_cols = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    X = train_df[feature_cols]
    y = train_df["label"]
    groups = train_df["session_id"]

    _, summary = run_optuna_optimization(X, y, groups, n_trials=3, seed=42, n_splits=3)
    assert len(summary["trials"]) == 3

    for trial in summary["trials"]:
        assert "trial_number" in trial
        assert trial["state"] == "COMPLETE"
        assert "params" in trial
        assert "fold_scores" in trial
        assert len(trial["fold_scores"]) == 3
        assert "std_macro_f1" in trial


def test_test_set_isolation(tmp_path: Path):
    campaign_dir, feat_schema_path, target_schema_path = _build_synthetic_dataset_fixture(tmp_path)
    train_df, val_df, test_df, _ = load_and_validate_dataset(
        campaign_dir, feat_schema_path, target_schema_path
    )

    # Ensure zero overlap between train and test session IDs
    train_sessions = set(train_df["session_id"].unique())
    test_sessions = set(test_df["session_id"].unique())
    assert not (train_sessions & test_sessions)

    # Ensure zero overlap between train and test experiment IDs
    train_experiments = set(train_df["experiment_id"].unique())
    test_experiments = set(test_df["experiment_id"].unique())
    assert not (train_experiments & test_experiments)


def test_saved_phase10_report_schema_and_gates():
    """Verify vista-ml/reports/phase10_optuna_report.json conforms to schema and bounds."""
    report_path = ROOT / "vista-ml" / "reports" / "phase10_optuna_report.json"
    assert report_path.is_file(), f"Missing Phase 10 report at {report_path}"

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "vista-optuna-experiment-v1"
    assert report["dataset_provenance"]["campaign_id"] == "76adc766-ef41-45f5-b677-1d950c7ff052"
    assert report["dataset_provenance"]["feature_count"] == 18

    # Check non-optimized baselines
    baselines = report["non_optimized_baselines_cv"]
    assert "majority_class" in baselines
    assert "decision_tree_shallow" in baselines
    assert "random_forest_initial" in baselines
    assert baselines["majority_class"]["mean_macro_f1"] == pytest.approx(0.2222, abs=1e-3)

    # Check Optuna section
    optuna_sec = report["optuna_hyperparameter_optimization"]
    assert optuna_sec["n_trials"] == 30
    assert optuna_sec["best_macro_f1"] >= 0.95
    assert len(optuna_sec["trials"]) == 30

    # Check ablation section
    ablations = report["feature_shortcut_ablation_analysis"]
    assert "packet_count_only" in ablations
    assert "excluding_packet_count" in ablations
    assert len(ablations["single_features"]) == 18
    assert len(ablations["leave_one_feature_out"]) == 18
    assert "timing_features_only" in ablations
    assert "packet_size_and_bytes_only" in ablations

    # Check test evaluation
    test_eval = report["held_out_test_evaluation"]
    assert "uncertainty_disclaimer" in test_eval
    assert "random_forest_optuna_tuned" in test_eval["models"]
    assert len(test_eval["models"]["random_forest_optuna_tuned"]["sample_predictions"]) == 12

    # Check non-production metadata
    model_art = report["model_artifact"]
    assert model_art["validated_for_inference"] is False
    assert model_art["production_eligible"] is False
