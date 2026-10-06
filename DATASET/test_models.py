"""
VISTA Model Testing & Benchmarking Suite (V2)
==============================================
Tests the upgraded VISTA V2 synthetic datasets across the 3 core tasks:
  Task 1: Encrypted Application Traffic Classification (RF & XGBoost)
  Task 2: Multi-class Attack Detection & Classification (RF & XGBoost)
  Task 3: Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
  Task 4: Multi-Layer Correlation & Composite Risk Scoring
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
from xgboost import XGBClassifier
import shap

# Paths
DATA_DIR = Path(__file__).resolve().parent
TRAFFIC_CSV = DATA_DIR / "ipsec_traffic_classification_v2.csv"
SECURITY_CSV = DATA_DIR / "ipsec_security_audit_v2.csv"
CORRELATED_CSV = DATA_DIR / "vista_correlated_sessions_v2.csv"

def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f" {title.upper()} ")
    print("=" * 70)

def main():
    print_banner("1. Loading VISTA V2 Datasets")
    if not TRAFFIC_CSV.exists():
        print(f"Error: {TRAFFIC_CSV} does not exist. Run DS_GEN_V2.py first.")
        return

    df_traffic = pd.read_csv(TRAFFIC_CSV)
    df_security = pd.read_csv(SECURITY_CSV)
    df_corr = pd.read_csv(CORRELATED_CSV)

    print(f"Traffic flows: {len(df_traffic):,} (Benign: {(df_traffic['is_attack']==0).sum():,}, Attack: {(df_traffic['is_attack']==1).sum():,})")
    print(f"Security audit sessions: {len(df_security):,}")
    print(f"Correlated session-flows: {len(df_corr):,}")

    # Feature definitions (pure side-channel observable ESP & kernel features, no identifiers)
    feature_cols = [
        "flow_duration_sec",
        "packet_count",
        "total_bytes",
        "byte_rate_Bps",
        "bit_rate_bps",
        "mean_packet_length",
        "std_packet_length",
        "min_packet_length",
        "max_packet_length",
        "mean_iat_sec",
        "std_iat_sec",
        "outbound_bytes_ratio",
        "ebpf_event_count",
        "socket_buffer_drops",
        "tcp_retrans_count",
    ]

    # Verify features exist
    available_features = [c for c in feature_cols if c in df_traffic.columns]
    print(f"Using {len(available_features)} side-channel / eBPF features: {available_features}")

    # Session-aware train/test split to prevent data leakage between sessions
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(df_traffic, groups=df_traffic["session_id"]))
    
    train_traffic = df_traffic.iloc[train_idx].copy()
    test_traffic = df_traffic.iloc[test_idx].copy()

    train_sessions = set(train_traffic["session_id"])
    test_sessions = set(test_traffic["session_id"])
    assert len(train_sessions.intersection(test_sessions)) == 0, "Group leakage detected!"
    print(f"Session-aware Split: {len(train_sessions)} train sessions ({len(train_traffic)} flows), {len(test_sessions)} test sessions ({len(test_traffic)} flows). Group leakage: 0.")

    # =========================================================================
    # TASK 1: Encrypted Application Classification (Benign Traffic Only)
    # =========================================================================
    print_banner("Task 1: Encrypted Application Traffic Classification (Benign Only)")
    benign_train = train_traffic[train_traffic["is_attack"] == 0]
    benign_test = test_traffic[test_traffic["is_attack"] == 0]

    X_train_app = benign_train[available_features]
    y_train_app = benign_train["traffic_type"]
    X_test_app = benign_test[available_features]
    y_test_app = benign_test["traffic_type"]

    classes_app = sorted(y_train_app.unique())
    label_map_app = {c: i for i, c in enumerate(classes_app)}
    inv_label_map_app = {i: c for c, i in label_map_app.items()}

    print(f"Benign training samples: {len(X_train_app)}, test samples: {len(X_test_app)}")
    print(f"Classes ({len(classes_app)}): {classes_app}")

    # Random Forest for App Classification
    rf_app = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_app.fit(X_train_app, y_train_app)
    rf_app_preds = rf_app.predict(X_test_app)
    rf_app_acc = accuracy_score(y_test_app, rf_app_preds)
    rf_app_f1 = f1_score(y_test_app, rf_app_preds, average="macro")

    print(f"\n[Random Forest - App Classification]")
    print(f"Accuracy: {rf_app_acc:.4f} | Macro F1: {rf_app_f1:.4f}")

    # XGBoost for App Classification
    xgb_app = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1)
    xgb_app.fit(X_train_app, y_train_app.map(label_map_app))
    xgb_app_preds_num = xgb_app.predict(X_test_app)
    xgb_app_preds = [inv_label_map_app[i] for i in xgb_app_preds_num]
    xgb_app_acc = accuracy_score(y_test_app, xgb_app_preds)
    xgb_app_f1 = f1_score(y_test_app, xgb_app_preds, average="macro")

    print(f"\n[XGBoost - App Classification]")
    print(f"Accuracy: {xgb_app_acc:.4f} | Macro F1: {xgb_app_f1:.4f}")
    print("\nClassification Report (XGBoost):")
    print(classification_report(y_test_app, xgb_app_preds, digits=4))

    # Top Feature Importances
    fi_app = pd.Series(xgb_app.feature_importances_, index=available_features).sort_values(ascending=False)
    print("Top 5 Indicative Features for App Classification:")
    for feat, imp in fi_app.head(5).items():
        print(f"  - {feat:25s}: {imp:.4f}")

    # =========================================================================
    # TASK 2: Multi-Class Attack Detection & Attribution
    # =========================================================================
    print_banner("Task 2: Multi-Class Attack Detection & Attribution")
    X_train_atk = train_traffic[available_features]
    y_train_atk = train_traffic["attack_type"]
    X_test_atk = test_traffic[available_features]
    y_test_atk = test_traffic["attack_type"]

    classes_atk = sorted(y_train_atk.unique())
    label_map_atk = {c: i for i, c in enumerate(classes_atk)}
    inv_label_map_atk = {i: c for c, i in label_map_atk.items()}

    print(f"Attack classes ({len(classes_atk)}): {classes_atk}")

    # XGBoost for Attack Detection
    xgb_atk = XGBClassifier(n_estimators=120, max_depth=7, learning_rate=0.08, random_state=42, n_jobs=-1)
    xgb_atk.fit(X_train_atk, y_train_atk.map(label_map_atk))
    xgb_atk_preds_num = xgb_atk.predict(X_test_atk)
    xgb_atk_preds = [inv_label_map_atk[i] for i in xgb_atk_preds_num]

    atk_acc = accuracy_score(y_test_atk, xgb_atk_preds)
    atk_f1 = f1_score(y_test_atk, xgb_atk_preds, average="macro")
    print(f"\n[XGBoost - Attack Classifier]")
    print(f"Accuracy: {atk_acc:.4f} | Macro F1: {atk_f1:.4f}")
    print("\nDetailed Attack Classification Report:")
    print(classification_report(y_test_atk, xgb_atk_preds, digits=4))

    # Binary Attack Detection Metrics (Benign vs Malicious)
    binary_true = (y_test_atk != "BENIGN").astype(int)
    binary_pred = (pd.Series(xgb_atk_preds) != "BENIGN").astype(int)
    bin_acc = accuracy_score(binary_true, binary_pred)
    bin_f1 = f1_score(binary_true, binary_pred)
    print(f"Binary Attack Detection (Is Malicious): Accuracy = {bin_acc:.4f}, F1-Score = {bin_f1:.4f}")

    # =========================================================================
    # TASK 3: Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
    # =========================================================================
    print_banner("Task 3: Unsupervised Zero-Day Anomaly Detection (Isolation Forest)")
    print("Training Isolation Forest EXCLUSIVELY on Benign Traffic...")
    iso_forest = IsolationForest(n_estimators=150, contamination=0.08, random_state=42, n_jobs=-1)
    iso_forest.fit(X_train_app)  # Trained only on normal flows

    # Evaluate on test set (both benign and attacks)
    iso_preds_raw = iso_forest.predict(X_test_atk)  # 1: Normal, -1: Anomaly
    iso_is_anomaly = (iso_preds_raw == -1).astype(int)
    
    test_eval_df = test_traffic.copy()
    test_eval_df["anomaly_detected"] = iso_is_anomaly

    print("\nZero-Day Anomaly Detection Recall across Attack Vectors (Trained on 0 attack samples):")
    for atk in classes_atk:
        subset = test_eval_df[test_eval_df["attack_type"] == atk]
        detected = subset["anomaly_detected"].sum()
        total = len(subset)
        pct = (detected / total) * 100 if total > 0 else 0
        role = "Normal Baseline" if atk == "BENIGN" else "Attack Vector"
        print(f"  - {atk:20s} ({role:15s}): {detected:3d}/{total:3d} flagged ({pct:5.1f}%)")

    # =========================================================================
    # TASK 4: VISTA Correlation Engine & Composite Risk Scoring
    # =========================================================================
    print_banner("Task 4: Multi-Layer Correlation & Composite Threat Assessment")
    
    # Take a sample test session with both traffic and security metadata
    sample_corr = df_corr.groupby("session_id").filter(lambda g: (g["is_attack"] == 1).any()).iloc[0:8]
    sample_session = sample_corr["session_id"].iloc[0]
    sec_row = df_security[df_security["session_id"] == sample_session].iloc[0]
    
    print(f"Analyzing Correlated Session: {sample_session} (SPI: {sec_row['spi']})")
    print("-" * 70)
    print(f"[Tier C - Security Posture Engine]")
    print(f"  - IKE/IPsec Config : IKEv{sec_row['ike_version']}, {sec_row['encryption_algo']}, HMAC: {sec_row['auth_algo']}, DH: Group {sec_row['dh_group']}")
    print(f"  - PFS / Anti-Replay: PFS={'Enabled' if sec_row['pfs_enabled'] else 'DISABLED'}, Anti-Replay={'Enabled' if sec_row['anti_replay'] else 'DISABLED'}")
    print(f"  - Rule Posture Risk: {sec_row['risk_score']} / 100 ({sec_row['compliance_status']})")
    print(f"  - Findings         : {sec_row['vulnerabilities_detected']}")

    session_flows = df_corr[df_corr["session_id"] == sample_session]
    X_sess = session_flows[available_features]
    
    # Model predictions
    flow_atk_preds = [inv_label_map_atk[i] for i in xgb_atk.predict(X_sess)]
    flow_app_preds = [inv_label_map_app[i] for i in xgb_app.predict(X_sess)]
    flow_anomalies = iso_forest.predict(X_sess)

    print(f"\n[Tier A & B - Traffic & Attack Inference Across {len(session_flows)} Flows]")
    for idx, (_, flow) in enumerate(session_flows.iterrows()):
        f_id = flow["flow_id"]
        pred_atk = flow_atk_preds[idx]
        pred_app = flow_app_preds[idx]
        is_anom = "ANOMALY" if flow_anomalies[idx] == -1 else "NORMAL"
        bytes_val = flow["total_bytes"]
        rate_val = flow["bit_rate_bps"]
        true_atk = flow["attack_type"]
        
        print(f"  Flow {f_id} | True: {true_atk:17s} -> Detected: {pred_atk:17s} (App: {pred_app:15s}, Side-Channel: {is_anom}, Rate: {rate_val:10.1f} bps)")

    # Composite Threat Score Calculation
    # Formula: 0.4 * Posture_Risk + 0.6 * Max_Attack_Severity
    has_critical_attack = any(a in ["DOS_FLOOD", "DATA_EXFILTRATION", "PORT_SCAN"] for a in flow_atk_preds)
    attack_penalty = 60 if has_critical_attack else (30 if any(a != "BENIGN" for a in flow_atk_preds) else 0)
    composite_score = min(100, int(0.4 * sec_row["risk_score"] + attack_penalty))
    
    print("\n[VISTA Correlation Synthesis]")
    print(f"  - Composite Session Threat Score: {composite_score} / 100")
    if composite_score >= 70:
        print("  - Actionable Threat Level: CRITICAL - Automated mitigation recommendation generated.")
    elif composite_score >= 40:
        print("  - Actionable Threat Level: ELEVATED - Monitored telemetry alert.")
    else:
        print("  - Actionable Threat Level: LOW / NORMAL - Compliant.")

    # Explainability (SHAP attribution)
    print("\n[Explainable AI - Fast SHAP Summary]")
    explainer = shap.TreeExplainer(xgb_atk)
    shap_vals = explainer(X_sess.iloc[0:1])
    if len(shap_vals.values.shape) == 3:
        top_feat_idx = int(np.argmax(np.abs(shap_vals.values[0]).sum(axis=1)))
    else:
        top_feat_idx = int(np.argmax(np.abs(shap_vals.values[0])))
    top_feature = available_features[top_feat_idx]
    print(f"SHAP attribution calculated successfully for flow {session_flows['flow_id'].iloc[0]}. Top contributing feature: {top_feature}")

    print_banner("All Model Tests Completed Successfully")

if __name__ == "__main__":
    main()
