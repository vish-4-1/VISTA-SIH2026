from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ML_ROOT = REPO_ROOT / "vista-ml"


def _repo_path(value: str) -> Path:
    path = Path(value.replace("\\", "/"))
    if path.parts[0] in {"reports", "models", "schemas", "data"}:
        return ML_ROOT / path
    return REPO_ROOT / path


def test_candidate_evidence_metrics_and_eligibility_match_saved_artifacts() -> None:
    capability = json.loads(
        (ML_ROOT / "reports" / "ml_capability_report.json").read_text(encoding="utf-8")
    )
    candidate = next(
        item for item in capability["datasets"]
        if item["name"] == "StrongSwan controlled benign outer-ESP workload captures"
    )["evaluation"]
    report_path = _repo_path(candidate["report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    model_path = _repo_path(candidate["model_candidate"])
    metadata_path = model_path.with_suffix(".metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    prediction_path = _repo_path(candidate["held_out_predictions"])
    predictions = pd.read_csv(prediction_path)

    digest = hashlib.sha256(prediction_path.read_bytes()).hexdigest()
    assert digest == report["held_out_predictions_sha256"]
    assert digest == metadata["evaluation_provenance"]["held_out_prediction_sha256"]
    assert metadata["prediction_task"] == report["task"]
    assert metadata["model_version"] == report["run_id"]
    assert metadata["feature_schema_version"] == report["feature_schema_version"]
    assert metadata["validated_for_inference"] is False
    assert metadata["runtime_eligibility"] == "blocked"
    assert metadata["evaluation_provenance"]["metrics_computed_from_saved_held_out_predictions"] is True

    labels = ["ICMP_NORMAL", "TCP_NORMAL"]
    y_true = predictions["true_label"].astype(str)
    y_pred = predictions["predicted_label"].astype(str)
    positive_probability = predictions["probability_TCP_NORMAL"].to_numpy(dtype=float)
    metrics = report["held_out_test"]
    assert accuracy_score(y_true, y_pred) == metrics["accuracy"]
    assert precision_score(y_true, y_pred, average="macro") == metrics["macro_precision"]
    assert recall_score(y_true, y_pred, average="macro") == metrics["macro_recall"]
    assert f1_score(y_true, y_pred, average="macro") == metrics["macro_f1"]
    assert roc_auc_score((y_true == "TCP_NORMAL").astype(int), positive_probability) == metrics["tcp_normal_roc_auc"]
    assert average_precision_score((y_true == "TCP_NORMAL").astype(int), positive_probability) == metrics["tcp_normal_average_precision"]
    assert confusion_matrix(y_true, y_pred, labels=labels).tolist() == metrics["confusion_matrix"]["values"]

    manifest_path = _repo_path(metadata["split_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    groups = manifest["capture_groups"]
    assert len(groups["train"]) == 6
    assert len(groups["validation"]) == 2
    assert len(groups["test"]) == len(predictions) == 50
    assert not (set(groups["train"]) & set(groups["validation"]))
    assert not (set(groups["train"]) & set(groups["test"]))
    assert not (set(groups["validation"]) & set(groups["test"]))
    assert predictions["capture_group"].is_unique
    assert report["packet_count_is_perfect_label_proxy"] is True
    assert metadata["feature_schema"]["runtime_feature_compatible"] is True
