"""
Unit tests for VISTA Phase 12 Robustness Validation Under Changed Traffic Recipes.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "phase12_robustness_report.json"
NEW_CAMPAIGN_ID = "d645e930-010c-4f8a-a10a-fe7f22aef309"
NEW_CAMPAIGN_DIR = ROOT.parent / "captures" / "strongswan" / "collections" / "campaigns" / NEW_CAMPAIGN_ID

import sys
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_robustness_campaign import (
    compute_session_bootstrap_interval,
    compute_feature_distribution_shift,
    run_within_session_permutation_test,
)


def test_new_campaign_artifact_integrity():
    assert NEW_CAMPAIGN_DIR.is_dir(), f"Campaign directory missing at {NEW_CAMPAIGN_DIR}"
    summary_path = NEW_CAMPAIGN_DIR / "campaign_summary.json"
    manifest_path = NEW_CAMPAIGN_DIR / "campaign_manifest.json"
    dataset_csv = NEW_CAMPAIGN_DIR / "dataset_preparation" / "prepared_dataset.csv"
    dataset_report = NEW_CAMPAIGN_DIR / "dataset_preparation" / "dataset_report.json"

    assert summary_path.is_file()
    assert manifest_path.is_file()
    assert dataset_csv.is_file()
    assert dataset_report.is_file()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "PASS"
    assert summary["completedSessions"] == 15
    assert summary["independentlyVerifiedSessions"] == 15
    assert summary["recipeMode"] == "varied"
    assert summary["seed"] == 26162

    prep = summary["datasetPreparation"]
    assert prep["status"] == "READY_FOR_REVIEW"
    assert prep["acceptedObservations"] == 60
    assert prep["quarantinedObservations"] == 0
    assert prep["independentSessions"] == 15


def test_session_bootstrap_interval_mechanics():
    df = pd.DataFrame({
        "session_id": ["s1", "s1", "s2", "s2", "s3", "s3"],
        "label": ["A", "B", "A", "B", "A", "B"],
    })
    preds = np.array(["A", "B", "A", "B", "A", "A"])  # 5/6 correct

    boot = compute_session_bootstrap_interval(df, preds, n_bootstrap=50, seed=42)
    assert boot["n_bootstrap"] == 50
    assert boot["n_clusters_sessions"] == 3
    acc_ci = boot["accuracy_95ci_bootstrap"]
    assert 0.0 <= acc_ci[0] <= acc_ci[1] <= 1.0


def test_within_session_permutation_mechanics():
    X_train = pd.DataFrame({
        "feat1": [1.0, 2.0, 10.0, 20.0, 1.1, 2.1, 10.1, 20.1, 1.2, 2.2, 10.2, 20.2],
        "feat2": [0.1, 0.2, 1.0, 2.0, 0.1, 0.2, 1.0, 2.0, 0.1, 0.2, 1.0, 2.0],
    })
    y_train = pd.Series(["A", "B", "C", "C", "A", "B", "C", "C", "A", "B", "C", "C"])
    groups_train = pd.Series(["s1", "s1", "s1", "s1", "s2", "s2", "s2", "s2", "s3", "s3", "s3", "s3"])

    res = run_within_session_permutation_test(
        X_train, y_train, groups_train, n_permutations=5, seed=42, n_splits=3
    )
    assert res["n_permutations"] == 5
    assert 0.0 <= res["p_value"] <= 1.0
    assert "within_session" in res["strategy"]
    assert len(res["permuted_scores_sample"]) == 5


def test_distribution_shift_computation():
    df_base = pd.DataFrame({
        "packet_count": [10.0, 20.0, 30.0],
        "std_packet_size": [0.0, 50.0, 100.0],
    })
    df_new = pd.DataFrame({
        "packet_count": [15.0, 25.0, 35.0],
        "std_packet_size": [0.0, 40.0, 80.0],
    })

    shift = compute_feature_distribution_shift(df_base, df_new, ["packet_count", "std_packet_size"])
    assert "packet_count" in shift
    assert shift["packet_count"]["mean_shift"] == 5.0
    assert shift["std_packet_size"]["exact_zero_counts"]["base"] == 1
    assert shift["std_packet_size"]["exact_zero_counts"]["new"] == 1


def test_phase12_robustness_report_content():
    assert REPORT_PATH.is_file(), f"Report missing at {REPORT_PATH}"
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    assert report["schema_version"] == "vista-phase12-robustness-v1"
    assert report["verdict"] == "ROBUSTNESS_SUPPORTED_WITHIN_TESTED_SCOPE"

    camp_eval = report["campaigns_evaluated"]["new_varied_recipe_campaign"]["evaluation"]
    assert camp_eval["sample_count"] == 60
    assert camp_eval["session_count"] == 15
    assert camp_eval["accuracy"] >= 0.95
    assert camp_eval["misclassifications_count"] == 2

    # Safeguards preserved
    safeguards = report["safeguards_preserved"]
    assert safeguards["validated_for_inference"] is False
    assert safeguards["production_eligible"] is False
    assert safeguards["experimental"] is True

    # Multiplexing assessment
    assert report["multiplexed_traffic_experiment"]["feasibility"] == "ARCHITECTURALLY_BLOCKED_FOR_SINGLE_ESP_SA"
