from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


def train_isolation_forest(
    X: pd.DataFrame,
    contamination: float = 0.1,
    random_state: int = 42,
    n_estimators: int = 250,
    **kwargs,
) -> IsolationForest:
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1,
        **kwargs,
    )
    model.fit(X)
    return model


def save_model_bundle(model, output_path: str | Path, metadata: dict | None = None) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    if metadata is not None:
        import json

        meta_path = output_path.with_suffix(".metadata.json")
        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, default=str)
