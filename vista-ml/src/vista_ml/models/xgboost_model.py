from __future__ import annotations

from pathlib import Path

import numpy as np
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier


class LabelMappedXGBClassifier:
    def __init__(self, estimator: XGBClassifier, label_encoder: LabelEncoder) -> None:
        self.estimator = estimator
        self.label_encoder = label_encoder

    @property
    def classes_(self) -> np.ndarray:
        return self.label_encoder.classes_

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        encoded = self.estimator.predict(X).astype(int)
        return self.label_encoder.inverse_transform(encoded)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.estimator.predict_proba(X)

    def get_booster(self):
        return self.estimator.get_booster()


def predict_binary(
    model: LabelMappedXGBClassifier,
    X: pd.DataFrame,
    threshold: float = 0.5,
    normal_label: str = "NORMAL",
    attack_label: str = "ATTACK",
) -> np.ndarray:
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")

    classes = np.asarray(model.classes_)
    normal_indices = np.flatnonzero(classes == normal_label)
    if len(normal_indices) != 1:
        raise ValueError(f"normal_label {normal_label!r} must match exactly one model class")

    probabilities = np.asarray(model.predict_proba(X))
    attack_probability = 1.0 - probabilities[:, normal_indices[0]]
    return np.where(attack_probability >= threshold, attack_label, normal_label)


def train_xgboost_classifier(
    X: pd.DataFrame,
    y: pd.Series,
    random_state: int = 42,
    n_estimators: int = 250,
    max_depth: int = 6,
    learning_rate: float = 0.08,
    **kwargs,
) -> LabelMappedXGBClassifier:
    y_array = np.asarray(y)
    label_encoder = LabelEncoder()
    encoded = label_encoder.fit_transform(y_array)
    class_count = len(label_encoder.classes_)
    objective = "binary:logistic" if class_count == 2 else "multi:softprob"
    estimator = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        subsample=0.9,
        colsample_bytree=0.9,
        objective=objective,
        eval_metric="mlogloss",
        random_state=random_state,
        n_jobs=1,
        **kwargs,
    )
    if class_count > 2:
        estimator.set_params(num_class=class_count)
    estimator.fit(X, encoded)
    return LabelMappedXGBClassifier(estimator, label_encoder)


def save_model_bundle(model, output_path: str | Path, metadata: dict | None = None) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    if metadata is not None:
        import json

        meta_path = output_path.with_suffix(".metadata.json")
        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, default=str)
