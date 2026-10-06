from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


def train_random_forest_classifier(
    X: pd.DataFrame,
    y: pd.Series,
    random_state: int = 42,
    n_estimators: int = 300,
    **kwargs,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced_subsample",
        **kwargs,
    )
    model.fit(X, y)
    return model


def save_model_bundle(model, output_path: str | Path, metadata: dict | None = None) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    if metadata is not None:
        meta_path = output_path.with_suffix(".metadata.json")
        import json

        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, default=str)
