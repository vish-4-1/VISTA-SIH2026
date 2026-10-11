"""
Unit tests for VISTA Phase 11 Data Leakage Audit and Independent-Campaign Validation.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "phase11_leakage_audit_report.json"
SCHEMA_FLOW_PATH = ROOT / "schemas" / "vista-flow-v1.json"
SCHEMA_LABEL_PATH = ROOT / "schemas" / "vista-target-label-schema-v1.json"

import sys
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from audit_phase11_leakage import (
    build_feature_lineage_table,
    compute_wilson_interval,
    inspect_decision_trees,
    run_session_grouped_permutation_test,
)


def test_feature_lineage_table_completeness():
    lineage = build_feature_lineage_table()
    assert len(lineage) == 18

    feat_schema = json.loads(SCHEMA_FLOW_PATH.read_text(encoding="utf-8"))
    schema_names = [f["name"] for f in feat_schema["features"]]
    lineage_names = [f["name"] for f in lineage]
    assert set(lineage_names) == set(schema_names)

    for entry in lineage:
        assert entry["available_at_inference"] is True
        assert entry["potentially_label_derived"] is False
        assert "leakage_risk" in entry
        assert "NO_LEAKAGE" in entry["leakage_risk"]


def test_wilson_interval_calculation():
    # 0 successes
    low, high = compute_wilson_interval(0, 10)
    assert low == 0.0
    assert 0.0 < high < 1.0

    # 12 / 12
    low, high = compute_wilson_interval(12, 12)
    assert 0.7 < low < 0.8
    assert high == 1.0

    # 58 / 60
    low, high = compute_wilson_interval(58, 60)
    assert 0.85 < low < 0.95
    assert 0.95 < high <= 1.0


def test_session_grouped_permutation_mechanics():
    # Synthetic small dataset with 3 sessions, 2 classes
    X = pd.DataFrame({
        "feat1": [1.0, 1.1, 5.0, 5.1, 1.2, 5.2],
        "feat2": [0.1, 0.2, 0.8, 0.9, 0.1, 0.8],
    })
    y = pd.Series(["A", "A", "B", "B", "A", "B"])
    groups = pd.Series(["s1", "s1", "s2", "s2", "s3", "s3"])

    res = run_session_grouped_permutation_test(
        X, y, groups, n_permutations=5, seed=42, n_splits=3
    )
    assert res["n_permutations"] == 5
    assert 0.0 <= res["p_value"] <= 1.0
    assert "session" in res["experimental_unit"]
    assert len(res["permuted_scores_sample"]) == 5


def test_decision_tree_inspections():
    X_train = pd.DataFrame({
        "std_packet_size": [0.0, 0.0, 50.0, 60.0, 80.0, 90.0],
        "packet_count": [10, 10, 20, 20, 40, 50],
    })
    y_train = pd.Series(["controlled_icmpv4", "controlled_icmpv4", "controlled_tcp_marker", "controlled_tcp_marker", "controlled_http", "controlled_http"])
    groups_train = pd.Series(["s1", "s1", "s2", "s2", "s3", "s3"])

    X_test = pd.DataFrame({
        "std_packet_size": [0.0, 55.0, 85.0],
        "packet_count": [10, 20, 45],
    })
    y_test = pd.Series(["controlled_icmpv4", "controlled_tcp_marker", "controlled_http"])

    res = inspect_decision_trees(
        X_train, y_train, X_test, y_test, groups_train, ["std_packet_size", "packet_count"], seed=42
    )
    assert "depth_1_decision_tree" in res
    assert "depth_2_decision_tree" in res
    assert res["depth_1_decision_tree"]["split_feature"] == "std_packet_size"
    assert res["depth_1_decision_tree"]["test_accuracy"] >= 0.6


def test_phase11_audit_report_integrity_and_safeguards():
    assert REPORT_PATH.is_file(), f"Audit report missing at {REPORT_PATH}"
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    # Schema & provenance
    assert report["schema_version"] == "vista-phase11-leakage-audit-v1"
    assert "provenance" in report
    assert report["provenance"]["feature_count"] == 18

    # Reproduction check
    rep = report["step3_phase10_reproduction"]["reproduction_comparison"]
    assert rep["best_trial_number"]["match"] is True
    assert rep["best_cv_macro_f1"]["match"] is True
    assert rep["test_macro_f1"]["match"] is True

    # Audit decision
    dec = report["step6_and_7_audit_decision"]
    assert dec["final_decision"] == "NO_LEAKAGE_DETECTED_WITHIN_SCOPE"
    assert dec["hypotheses_evaluation"]["hypothesis_1_data_leakage"]["confirmed"] is False
    assert dec["hypotheses_evaluation"]["hypothesis_2_recipe_specific_correlation"]["confirmed"] is True
    assert dec["hypotheses_evaluation"]["hypothesis_3_within_campaign_separability"]["confirmed"] is True
    assert dec["hypotheses_evaluation"]["hypothesis_4_evaluation_limitations"]["confirmed"] is True

    # Production safeguards
    safeguards = dec["production_safeguards"]
    assert safeguards["validated_for_inference"] is False
    assert safeguards["production_eligible"] is False
    assert safeguards["experimental"] is True

    # Independent campaign evaluation
    indep = report["step5_independent_campaign_validation"]["combined_independent_evaluation"]
    assert indep["total_samples"] == 60
    assert indep["total_independent_sessions"] == 30
    assert indep["accuracy"] > 0.95
