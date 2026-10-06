from __future__ import annotations

from pathlib import Path

import pandas as pd

from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.explainability.shap_analysis import explain_xgboost
from vista_ml.models.random_forest import train_random_forest_classifier
from vista_ml.models.xgboost_model import predict_binary, train_xgboost_classifier


def _make_training_data() -> tuple[pd.DataFrame, pd.Series]:
    rows = []
    for i in range(20):
        label = "NORMAL" if i % 2 == 0 else "PORT_SCAN"
        rows.append(
            {
                "feature_a": i * 1.1,
                "feature_b": i * 0.8,
                "feature_c": float(i % 5),
                "label": label,
            }
        )
    df = pd.DataFrame(rows)
    return df[["feature_a", "feature_b", "feature_c"]], df["label"]


def test_random_forest_prediction_shape() -> None:
    X, y = _make_training_data()
    model = train_random_forest_classifier(X, y, random_state=42)
    predictions = model.predict(X)
    assert predictions.shape[0] == len(X)


def test_xgboost_training_and_shap(tmp_path: Path) -> None:
    X, y = _make_training_data()
    model = train_xgboost_classifier(X, y, random_state=42)
    predictions = model.predict(X)
    assert predictions.shape[0] == len(X)
    summary = explain_xgboost(model, X, output_dir=tmp_path)
    assert isinstance(summary["top_features"], list)
    assert len(summary["top_features"]) > 0
    assert (tmp_path / "top_features.json").exists()


def test_multiclass_probabilities_can_be_thresholded_to_binary() -> None:
    class ProbabilityModel:
        classes_ = ["NORMAL", "PORT_SCAN", "DOS"]

        def predict_proba(self, X: pd.DataFrame) -> list[list[float]]:
            return [[0.7, 0.2, 0.1], [0.2, 0.3, 0.5]]

    predictions = predict_binary(ProbabilityModel(), pd.DataFrame(index=range(2)), threshold=0.5)
    assert predictions.tolist() == ["NORMAL", "ATTACK"]


def test_evaluation_writes_thresholded_binary_metrics(tmp_path: Path) -> None:
    class ProbabilityModel:
        classes_ = ["NORMAL", "PORT_SCAN", "DOS"]

        def predict(self, X: pd.DataFrame) -> list[str]:
            return ["NORMAL", "DOS"]

        def predict_proba(self, X: pd.DataFrame) -> list[list[float]]:
            return [[0.7, 0.2, 0.1], [0.2, 0.3, 0.5]]

    X = pd.DataFrame({"feature": [0, 1]})
    y = pd.Series(["NORMAL", "PORT_SCAN"])
    metrics = evaluate_classifier(
        ProbabilityModel(),
        X,
        y,
        ["NORMAL", "PORT_SCAN", "DOS"],
        tmp_path,
        binary_threshold=0.5,
    )

    assert metrics["binary_metrics"]["accuracy"] == 1.0
    assert metrics["binary_metrics"]["threshold"] == 0.5
    assert (tmp_path / "binary_metrics.json").exists()
    assert (tmp_path / "binary_confusion_matrix.png").exists()
