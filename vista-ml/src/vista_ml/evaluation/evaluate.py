from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from vista_ml.evaluation.metrics import compute_classification_metrics
from vista_ml.models.xgboost_model import predict_binary


def plot_confusion_matrix(y_true, y_pred, labels, output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, cmap="Blues")
    fig.colorbar(im, ax=ax)
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def evaluate_classifier(
    model,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    label_names: list[str],
    out_dir: str | Path,
    binary_threshold: float | None = None,
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    y_pred = model.predict(X_test)
    metrics = compute_classification_metrics(y_test, y_pred)
    report = classification_report(
        y_test,
        y_pred,
        labels=label_names,
        output_dict=True,
        zero_division=0,
    )
    metrics["macro_precision"] = report["macro avg"]["precision"]
    metrics["macro_recall"] = report["macro avg"]["recall"]
    metrics["macro_f1"] = report["macro avg"]["f1-score"]
    metrics["label_report"] = report
    metrics["classes"] = label_names

    if binary_threshold is not None:
        binary_true = y_test.map(lambda label: "NORMAL" if label == "NORMAL" else "ATTACK")
        binary_pred = predict_binary(model, X_test, threshold=binary_threshold)
        binary_metrics = compute_classification_metrics(binary_true, binary_pred)
        binary_report = classification_report(
            binary_true,
            binary_pred,
            labels=["NORMAL", "ATTACK"],
            output_dict=True,
            zero_division=0,
        )
        binary_metrics["label_report"] = binary_report
        binary_metrics["threshold"] = binary_threshold
        metrics["binary_metrics"] = binary_metrics
        plot_confusion_matrix(
            binary_true,
            binary_pred,
            ["NORMAL", "ATTACK"],
            out_dir / "binary_confusion_matrix.png",
        )
        with open(out_dir / "binary_metrics.json", "w", encoding="utf-8") as handle:
            json.dump(binary_metrics, handle, indent=2, default=str)

    metrics_df = pd.DataFrame([
        {"metric": key, "value": value}
        for key, value in metrics.items()
        if key not in {"label_report", "classes", "binary_metrics"}
    ])
    if binary_threshold is not None:
        metrics_df = pd.concat(
            [
                metrics_df,
                pd.DataFrame(
                    [
                        {"metric": f"binary_{key}", "value": value}
                        for key, value in metrics["binary_metrics"].items()
                        if key not in {"label_report", "threshold"}
                    ]
                ),
            ],
            ignore_index=True,
        )
    metrics_df.to_csv(out_dir / "metrics.csv", index=False)
    plot_confusion_matrix(y_test, y_pred, label_names, out_dir / "confusion_matrix.png")
    with open(out_dir / "classification_report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    return metrics
