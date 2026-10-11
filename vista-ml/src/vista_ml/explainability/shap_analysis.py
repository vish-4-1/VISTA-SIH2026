from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import shap
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _validate_feature_order(model, X: pd.DataFrame) -> None:
    fitted_features = getattr(model, "feature_names_in_", None)
    if fitted_features is None and hasattr(model, "estimator"):
        fitted_features = getattr(model.estimator, "feature_names_in_", None)
    if fitted_features is None and hasattr(model, "get_booster"):
        fitted_features = getattr(model.get_booster(), "feature_names", None)
    if fitted_features is not None and list(X.columns) != list(fitted_features):
        raise ValueError(
            f"SHAP feature order {list(X.columns)} does not match fitted model order "
            f"{list(fitted_features)}."
        )


def _class_explanations(model, shap_values, values: np.ndarray) -> list[tuple[str, object]]:
    if values.ndim == 3:
        class_labels = list(getattr(model, "classes_", range(values.shape[2])))
        if len(class_labels) != values.shape[2]:
            raise ValueError("SHAP class dimension does not match the model's class mapping.")
        return [
            (str(label), shap_values[:, :, index])
            for index, label in enumerate(class_labels)
        ]
    return [("", shap_values)]


def resolve_tree_explainer(model) -> shap.TreeExplainer:
    """Resolve and return a SHAP TreeExplainer for supported tree/booster models."""
    if hasattr(model, "get_booster"):
        booster = model.get_booster()
    elif hasattr(model, "estimator") and hasattr(model.estimator, "get_booster"):
        booster = model.estimator.get_booster()
    else:
        booster = model
    return shap.TreeExplainer(booster)


resolve_shap_explainer = resolve_tree_explainer


def explain_xgboost(
    model,
    X: pd.DataFrame,
    output_dir: str | Path | None = None,
    max_samples: int = 200,
    model_version: str | None = None,
    feature_schema_version: str | None = None,
) -> dict:
    if X.empty:
        raise ValueError("Cannot generate SHAP explanations for an empty dataset.")

    sample = X.head(max_samples).copy()
    _validate_feature_order(model, sample)
    explainer = resolve_tree_explainer(model)
    shap_values = explainer(sample)
    values = shap_values.values
    if values.ndim == 3:
        importance = np.abs(values).mean(axis=(0, 2))
    else:
        importance = np.abs(values).mean(axis=0)
    class_explanations = _class_explanations(model, shap_values, values)

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
        "scope": "global",
        "importance_measure": "mean_absolute_shap_value",
        "sample_count": len(sample),
        "model_version": model_version,
        "feature_schema_version": feature_schema_version,
        "feature_order": feature_names,
        "top_features": [
            {"feature": feature_name, "shap_value": float(value)}
            for feature_name, value in top_features
        ]
    }
    if output_dir is not None:
        with open(Path(output_dir) / "top_features.json", "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
    return summary


def explain_xgboost_flow(
    model,
    flow_features: pd.DataFrame,
    model_version: str,
    feature_schema_version: str,
) -> dict:
    if len(flow_features) != 1:
        raise ValueError("A per-flow SHAP explanation requires exactly one selected flow.")
    _validate_feature_order(model, flow_features)

    explainer = resolve_tree_explainer(model)
    shap_values = explainer(flow_features)
    values = np.asarray(shap_values.values)
    feature_names = list(flow_features.columns)
    class_labels = list(getattr(model, "classes_", []))

    if values.ndim == 3:
        if len(class_labels) != values.shape[2]:
            raise ValueError("SHAP class dimension does not match the model's class mapping.")
        class_values = {
            str(label): [
                {"feature": name, "shap_value": float(value)}
                for name, value in zip(feature_names, values[0, :, index])
            ]
            for index, label in enumerate(class_labels)
        }
    elif values.ndim == 2:
        class_values = {
            class_labels[-1] if class_labels else "model_output": [
                {"feature": name, "shap_value": float(value)}
                for name, value in zip(feature_names, values[0])
            ]
        }
    else:
        raise ValueError(f"Unsupported SHAP output shape: {values.shape}.")

    return {
        "scope": "per_flow",
        "model_version": model_version,
        "feature_schema_version": feature_schema_version,
        "feature_order": feature_names,
        "predicted_class": str(model.predict(flow_features)[0]),
        "class_explanations": class_values,
    }
