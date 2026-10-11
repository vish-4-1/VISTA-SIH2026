from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_strongswan_shortcuts import DEFAULT_EVALUATION, run_audit  # noqa: E402


def test_saved_candidate_reproduces_but_shortcuts_and_session_limits_are_reported() -> None:
    report = run_audit(DEFAULT_EVALUATION, random_state=42)
    assert report["reproduction"]["saved_candidate_labels_reproduced"] is True
    assert report["reproduction"]["saved_candidate_probabilities_reproduced"] is True
    assert report["reproduction"]["reported_metrics_match"] is True
    assert report["ground_truth_provenance"]["label_origin_independently_verified"] is False
    assert all(
        item["raw_pcap_for_each_observation_available"] is False
        for item in report["source_provenance"]
    )
    assert report["sample_and_group_limits"]["records"] == {
        "train": 6,
        "validation": 2,
        "test": 50,
    }
    assert report["sample_and_group_limits"]["processing_run_overlap"]["train_validation"] == [
        "20261005T155313Z"
    ]
    assert report["sample_and_group_limits"]["verified_source_session_ids_available"] is False
    shortcuts = report["shortcut_and_duplicate_audit"]
    assert shortcuts["packet_count_perfectly_determines_class"] is True
    assert shortcuts["class_labels_recoverable_from_experiment_ids_or_packet_table_filenames"] is True
    assert len(report["perfect_single_feature_shortcuts"]) == 14
    assert shortcuts["exact_duplicate_feature_rows_by_split"]["test"] == 2
    comparisons = report["baseline_and_ablation_comparison"]
    assert comparisons["packet_count_only"]["macro_f1"] == 1.0
    assert comparisons["without_packet_count"]["macro_f1"] == 1.0
    assert comparisons["majority_class_baseline"]["accuracy"] == 0.5
    assert report["decision"].startswith("No classifier demonstrates defensible generalization")
