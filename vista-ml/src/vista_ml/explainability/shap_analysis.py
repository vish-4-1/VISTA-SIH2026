from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import shap
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def explain_xgboost(model, X: pd.DataFrame, output_dir: str | Path | None = None, max_samples: int = 200) -> dict:
    if X.empty:
        raise ValueError("Cannot generate SHAP explanations for an empty dataset.")

    sample = X.head(max_samples).copy()
    explainer = shap.TreeExplainer(model.get_booster())
    shap_values = explainer(sample)
    values = shap_values.values
    if values.ndim == 3:
        importance = np.abs(values).mean(axis=(0, 2))
        class_labels = getattr(model, "classes_", range(values.shape[2]))
        class_explanations = [
            (str(label), shap_values[:, :, index])
            for index, label in enumerate(class_labels)
        ]
    else:
        importance = np.abs(values).mean(axis=0)
        class_explanations = [("", shap_values)]

    feature_names = list(sample.columns)
    top_features = sorted(
        zip(feature_names, importance),
        key=lambda item: abs(item[1]),
        reverse=True,
    )[:10]

    if output_dir is not None:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for class_label, class_values in class_explanations:
            class_slug = "".join(
                character if character.isalnum() or character in "-_" else "_"
                for character in class_label
            )
            suffix = f"_{class_slug}" if class_slug else ""
            shap.plots.beeswarm(class_values, max_display=10, show=False)
            plt.savefig(out_dir / f"beeswarm{suffix}.png", dpi=150, bbox_inches="tight")
            plt.close()

            shap.plots.bar(class_values, max_display=10, show=False)
            plt.savefig(out_dir / f"bar_importance{suffix}.png", dpi=150, bbox_inches="tight")
            plt.close()

    summary = {
        "top_features": [
            {"feature": feature_name, "shap_value": float(value)}
            for feature_name, value in top_features
        ]
    }
    if output_dir is not None:
        with open(Path(output_dir) / "top_features.json", "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
    return summary
