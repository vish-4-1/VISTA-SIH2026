"""
VISTA Training Pipeline — Threat Intelligence (Attack Detection & Attribution)
==============================================================================
Task: Multiclass Attack Detection & Security Attribution.
Detects whether traffic inside or around IPsec VPN tunnels is BENIGN or represents an attack
(DOS_FLOOD, PORT_SCAN, BRUTE_FORCE, C2_BEACONING, DATA_EXFILTRATION).

Dataset: VISTA IPsec Synthetic Testbed Dataset (ipsec_traffic_classification_v2.csv)
Splitting: Session-aware GroupShuffleSplit on session_id to prevent inter-session leakage.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

from vista_ml.models.xgboost_model import LabelMappedXGBClassifier, save_model_bundle
from vista_ml.evaluation.evaluate import plot_confusion_matrix
from vista_ml.utils.reproducibility import set_random_seed

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "mean_inter_arrival_time",
    "std_inter_arrival_time",
    "min_inter_arrival_time",
    "max_inter_arrival_time",
    "packets_per_second",
    "bytes_per_second",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "direction_ratio",
]


def extract_canonical_features(df: pd.DataFrame) -> pd.DataFrame:
    """Transforms raw CSV columns into the standard 18-feature VISTA canonical schema."""
    f = pd.DataFrame(index=df.index)
    f["packet_count"] = df["packet_count"].astype(float)
    f["byte_count"] = df["total_bytes"].astype(float)
    f["flow_duration"] = df["flow_duration_sec"].astype(float)
    f["mean_packet_size"] = df["mean_packet_length"].astype(float)
    f["std_packet_size"] = df["std_packet_length"].astype(float)
    f["min_packet_size"] = df["min_packet_length"].astype(float)
    f["max_packet_size"] = df["max_packet_length"].astype(float)
    f["mean_inter_arrival_time"] = df["mean_iat_sec"].astype(float)
    f["std_inter_arrival_time"] = df["std_iat_sec"].astype(float)
    f["min_inter_arrival_time"] = np.maximum(0.0001, df["mean_iat_sec"] - 2 * df["std_iat_sec"])
    f["max_inter_arrival_time"] = df["mean_iat_sec"] + 2 * df["std_iat_sec"]
    f["packets_per_second"] = df["packet_count"] / np.maximum(0.01, df["flow_duration_sec"])
    f["bytes_per_second"] = df["byte_rate_Bps"].astype(float)
    f["forward_packet_count"] = (df["packet_count"] * df["outbound_bytes_ratio"]).round()
    f["backward_packet_count"] = df["packet_count"] - f["forward_packet_count"]
    f["forward_bytes"] = df["total_bytes"] * df["outbound_bytes_ratio"]
    f["backward_bytes"] = df["total_bytes"] * (1.0 - df["outbound_bytes_ratio"])
    f["direction_ratio"] = df["outbound_bytes_ratio"].astype(float)
    return f[FEATURE_COLUMNS]


def train_and_evaluate():
    set_random_seed(42)
    csv_path = PROJECT_ROOT / "DATASET" / "ipsec_traffic_classification_v2.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    raw_df = pd.read_csv(csv_path)
    print(f"Loaded {len(raw_df)} total flows across {raw_df['session_id'].nunique()} sessions.")
    print("Class distribution:\n", raw_df["attack_type"].value_counts())

    # Session-aware group split
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(raw_df, groups=raw_df["session_id"]))

    train_data = raw_df.iloc[train_idx].copy()
    test_data = raw_df.iloc[test_idx].copy()

    # Leakage assertion
    train_sessions = set(train_data["session_id"])
    test_sessions = set(test_data["session_id"])
    assert len(train_sessions.intersection(test_sessions)) == 0, "Session leakage detected!"
    print(f"Train: {len(train_data)} flows ({len(train_sessions)} sessions) | Test: {len(test_data)} flows ({len(test_sessions)} sessions). Session leakage: 0%.")

    X_train = extract_canonical_features(train_data)
    y_train = train_data["attack_type"]
    X_test = extract_canonical_features(test_data)
    y_test = test_data["attack_type"]

    classes = sorted(y_train.unique().tolist())
    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train)

    # Train XGBoost
    xgb = XGBClassifier(
        n_estimators=130,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    xgb.fit(X_train, y_train_encoded)
    wrapped_model = LabelMappedXGBClassifier(xgb, le)

    # Multi-class Evaluation
    y_pred = wrapped_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    macro_prec = precision_score(y_test, y_pred, average="macro")
    macro_rec = recall_score(y_test, y_pred, average="macro")
    report = classification_report(y_test, y_pred, labels=classes, output_dict=True, zero_division=0)

    # Binary Attack Detection Evaluation (BENIGN vs ATTACK)
    binary_true = (y_test != "BENIGN").astype(int)
    binary_pred = (pd.Series(y_pred, index=y_test.index) != "BENIGN").astype(int)
    bin_acc = accuracy_score(binary_true, binary_pred)
    bin_f1 = f1_score(binary_true, binary_pred)
    bin_prec = precision_score(binary_true, binary_pred)
    bin_rec = recall_score(binary_true, binary_pred)

    print("\n" + "=" * 60)
    print("ATTACK CLASSIFIER EVALUATION RESULTS (Threat Intelligence)")
    print("=" * 60)
    print(f"Multiclass Accuracy: {acc:.4f} | Macro F1: {macro_f1:.4f}")
    print(f"Binary Detection (Is Malicious): Accuracy = {bin_acc:.4f}, Precision = {bin_prec:.4f}, Recall = {bin_rec:.4f}, F1 = {bin_f1:.4f}")
    print("\nDetailed Multi-Class Report:")
    print(classification_report(y_test, y_pred, labels=classes, digits=4))

    # Save artifacts
    models_dir = ROOT / "models"
    reports_dir = ROOT / "reports" / "metrics"
    figures_dir = ROOT / "reports" / "figures"
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "model": "XGBClassifier",
        "model_pipeline": "Threat Intelligence Attack Classifier",
        "prediction_task": "flow attack detection and attribution",
        "target_variable": "attack_type",
        "classes": classes,
        "feature_columns": FEATURE_COLUMNS,
        "feature_count": len(FEATURE_COLUMNS),
        "training_dataset": "DATASET/ipsec_traffic_classification_v2.csv",
        "training_data_scope": "VISTA IPsec synthetic testbed sessions",
        "split_strategy": "Session-aware GroupShuffleSplit on session_id (0% group leakage)",
        "train_samples": len(train_data),
        "test_samples": len(test_data),
        "train_sessions": len(train_sessions),
        "test_sessions": len(test_sessions),
        "binary_detection_metrics": {
            "accuracy": bin_acc,
            "precision": bin_prec,
            "recall": bin_rec,
            "f1": bin_f1,
        },
        "model_version": "2.0.0",
        "random_seed": 42,
    }

    # Save under dedicated name
    save_model_bundle(wrapped_model, models_dir / "attack_classifier.joblib", metadata)
    # Also save as xgboost_classifier.joblib for full backward compatibility
    save_model_bundle(wrapped_model, models_dir / "xgboost_classifier.joblib", metadata)

    eval_summary = {
        "model_pipeline": "Threat Intelligence Attack Classifier",
        "prediction_task": "flow attack detection and attribution",
        "model": "XGBoost",
        "classes": classes,
        "accuracy": acc,
        "macro_f1": macro_f1,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "binary_detection": {
            "accuracy": bin_acc,
            "precision": bin_prec,
            "recall": bin_rec,
            "f1": bin_f1,
        },
        "label_report": report,
        "evaluation_provenance": {
            "dataset": "VISTA IPsec Synthetic Traffic Dataset (ipsec_traffic_classification_v2.csv)",
            "method": "Session-aware group holdout (GroupShuffleSplit on session_id); zero inter-session leakage.",
            "limitations": "Model detects known attack traffic profiles by packet timing and length distributions; unverified ML predictions must be correlated with SOC telemetry.",
        },
    }

    with open(reports_dir / "attack_classifier_metrics.json", "w", encoding="utf-8") as f:
        json.dump(eval_summary, f, indent=2, default=str)

    plot_confusion_matrix(y_test, y_pred, classes, figures_dir / "attack_confusion_matrix.png")
    print(f"Artifacts saved to {models_dir / 'attack_classifier.joblib'} and {reports_dir / 'attack_classifier_metrics.json'}")
    return eval_summary


if __name__ == "__main__":
    train_and_evaluate()
