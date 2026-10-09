#!/usr/bin/env python3
"""Export repository dataset summaries and evaluation reports for the dashboard."""

import json
from pathlib import Path
import pandas as pd

WORKSPACE_ROOT = Path("c:/vista")
DASHBOARD_DATA_DIR = WORKSPACE_ROOT / "vista-dashboard" / "src" / "data"
DASHBOARD_DATA_DIR.mkdir(parents=True, exist_ok=True)

# 1. Process ipsec_traffic_classification_v2.csv
print("[*] Reading ipsec_traffic_classification_v2.csv...")
df_flows = pd.read_csv(WORKSPACE_ROOT / "DATASET" / "ipsec_traffic_classification_v2.csv")
print(f"    Loaded {len(df_flows)} flows.")

flows_list = []

for i, row in df_flows.iterrows():
    flows_list.append({
        "id": str(row["flow_id"]),
        "sessionId": str(row["session_id"]),
        "spi": str(row["esp_spi"]),
        "duration": round(float(row["flow_duration_sec"]), 2),
        "packets": int(row["packet_count"]),
        "bytes": int(row["total_bytes"]),
        "byteRateBps": round(float(row["byte_rate_Bps"]), 2),
        "bitRateBps": round(float(row["bit_rate_bps"]), 2),
        "meanPacketLen": round(float(row["mean_packet_length"]), 1),
        "stdPacketLen": round(float(row["std_packet_length"]), 1),
        "minPacketLen": int(row["min_packet_length"]),
        "maxPacketLen": int(row["max_packet_length"]),
        "meanIat": round(float(row["mean_iat_sec"]), 5),
        "stdIat": round(float(row["std_iat_sec"]), 5),
        "outboundRatio": round(float(row["outbound_bytes_ratio"]), 3),
        "trafficType": str(row["traffic_type"]),
        "attackType": str(row["attack_type"]),
        "isAttack": int(row["is_attack"]),
        "ebpfEvents": int(row["ebpf_event_count"]),
        "socketDrops": int(row["socket_buffer_drops"]),
        "tcpRetrans": int(row["tcp_retrans_count"]),
    })

flows_json_path = DASHBOARD_DATA_DIR / "realFlows.json"
with open(flows_json_path, "w", encoding="utf-8") as f:
    json.dump(flows_list, f, indent=2)
print(f"[+] Saved {len(flows_list)} flows to {flows_json_path}")

# 2. Process ipsec_security_audit_v2.csv
print("[*] Reading ipsec_security_audit_v2.csv...")
df_audit = pd.read_csv(WORKSPACE_ROOT / "DATASET" / "ipsec_security_audit_v2.csv")
print(f"    Loaded {len(df_audit)} audit sessions.")

audit_list = []
for _, row in df_audit.iterrows():
    vuln_str = str(row.get("vulnerabilities_detected", ""))
    vulns = [v.strip() for v in vuln_str.split("|") if v.strip() and v.strip() != "No_Vulnerabilities"]
    
    audit_list.append({
        "sessionId": str(row["session_id"]),
        "spi": str(row["spi"]),
        "ipVersion": str(row["ip_version"]),
        "ikeVersion": int(row["ike_version"]),
        "mode": str(row["ipsec_mode"]),
        "encryption": str(row["encryption_algo"]),
        "auth": str(row["auth_algo"]),
        "dhGroup": int(row["dh_group"]),
        "pfs": int(row["pfs_enabled"]) == 1,
        "antiReplay": int(row["anti_replay"]) == 1,
        "lifetime": int(row["key_lifetime_sec"]),
        "riskScore": int(row["risk_score"]),
        "compliance": str(row["compliance_status"]).replace("_", " "),
        "vulnerabilities": vulns
    })

audit_json_path = DASHBOARD_DATA_DIR / "realAudits.json"
with open(audit_json_path, "w", encoding="utf-8") as f:
    json.dump(audit_list, f, indent=2)
print(f"[+] Saved {len(audit_list)} audit records to {audit_json_path}")

# 3. Read real ML model evaluation summaries from reports/metrics
print("[*] Reading vista-ml model evaluation summaries...")
model_summary_file = WORKSPACE_ROOT / "vista-ml" / "reports" / "metrics" / "model_summary.json"
anomaly_file = WORKSPACE_ROOT / "vista-ml" / "reports" / "metrics" / "anomaly_results.json"
shap_file = WORKSPACE_ROOT / "vista-ml" / "reports" / "shap" / "top_features.json"

with open(model_summary_file, "r", encoding="utf-8") as f:
    model_summary = json.load(f)

with open(anomaly_file, "r", encoding="utf-8") as f:
    anomaly_results = json.load(f)

with open(shap_file, "r", encoding="utf-8") as f:
    shap_data = json.load(f)

ml_metrics = {
    "randomForest": model_summary.get("random_forest", {}),
    "xgboost": model_summary.get("xgboost", {}),
    "isolationForest": anomaly_results,
    "topShapFeatures": shap_data.get("top_features", [])
}

ml_metrics_path = DASHBOARD_DATA_DIR / "realMlMetrics.json"
with open(ml_metrics_path, "w", encoding="utf-8") as f:
    json.dump(ml_metrics, f, indent=2)
print(f"[+] Saved ML evaluation metrics to {ml_metrics_path}")

# 4. Compute comprehensive aggregate statistics
print("[*] Computing real aggregate statistics...")

# Packet length stats
mean_pkt_len = float(df_flows["mean_packet_length"].mean())
std_pkt_len = float(df_flows["std_packet_length"].mean())

pkt_sub200 = int((df_flows["mean_packet_length"] <= 200).sum())
pkt_200_800 = int(((df_flows["mean_packet_length"] > 200) & (df_flows["mean_packet_length"] <= 800)).sum())
pkt_800_1200 = int(((df_flows["mean_packet_length"] > 800) & (df_flows["mean_packet_length"] <= 1200)).sum())
pkt_mtu = int((df_flows["mean_packet_length"] > 1200).sum())
total_flw = len(df_flows)

# IAT stats
median_iat_ms = float(df_flows["mean_iat_sec"].median() * 1000.0)
mean_iat_ms = float(df_flows["mean_iat_sec"].mean() * 1000.0)

iat_sub1ms = int((df_flows["mean_iat_sec"] < 0.001).sum())
iat_1_50ms = int(((df_flows["mean_iat_sec"] >= 0.001) & (df_flows["mean_iat_sec"] <= 0.050)).sum())
iat_50_500ms = int(((df_flows["mean_iat_sec"] > 0.050) & (df_flows["mean_iat_sec"] <= 0.500)).sum())
iat_beacon = int((df_flows["mean_iat_sec"] > 0.500).sum())

# Directionality
mean_outbound_ratio = float(df_flows["outbound_bytes_ratio"].mean())

# Attack vs Benign
attack_counts = df_flows["attack_type"].value_counts().to_dict()
traffic_counts = df_flows["traffic_type"].value_counts().to_dict()

# Audit stats
audit_compliance_counts = df_audit["compliance_status"].value_counts().to_dict()
audit_encryption_counts = df_audit["encryption_algo"].value_counts().to_dict()
audit_auth_counts = df_audit["auth_algo"].value_counts().to_dict()
audit_dh_counts = df_audit["dh_group"].value_counts().to_dict()

# Vulns detected
all_vulns = []
for v in df_audit["vulnerabilities_detected"].dropna():
    if v != "No_Vulnerabilities":
        all_vulns.extend([x.strip() for x in v.split("|") if x.strip()])
vuln_series = pd.Series(all_vulns).value_counts().to_dict()

summary_data = {
    "totalFlows": total_flw,
    "totalSessions": len(df_audit),
    "benignCount": int((df_flows["is_attack"] == 0).sum()),
    "attackCount": int((df_flows["is_attack"] == 1).sum()),
    "attackTypes": {str(k): int(v) for k, v in attack_counts.items()},
    "trafficTypes": {str(k): int(v) for k, v in traffic_counts.items()},
    "packetSize": {
        "meanBytes": round(mean_pkt_len, 1),
        "stdBytes": round(std_pkt_len, 1),
        "bucket_64_200": {"count": pkt_sub200, "pct": round(pkt_sub200 / total_flw * 100, 1)},
        "bucket_200_800": {"count": pkt_200_800, "pct": round(pkt_200_800 / total_flw * 100, 1)},
        "bucket_800_1200": {"count": pkt_800_1200, "pct": round(pkt_800_1200 / total_flw * 100, 1)},
        "bucket_1200_1500": {"count": pkt_mtu, "pct": round(pkt_mtu / total_flw * 100, 1)},
    },
    "iat": {
        "medianMs": round(median_iat_ms, 2),
        "meanMs": round(mean_iat_ms, 2),
        "bucket_sub1ms": {"count": iat_sub1ms, "pct": round(iat_sub1ms / total_flw * 100, 1)},
        "bucket_1_50ms": {"count": iat_1_50ms, "pct": round(iat_1_50ms / total_flw * 100, 1)},
        "bucket_50_500ms": {"count": iat_50_500ms, "pct": round(iat_50_500ms / total_flw * 100, 1)},
        "bucket_beacon": {"count": iat_beacon, "pct": round(iat_beacon / total_flw * 100, 1)},
    },
    "directionality": {
        "meanOutbound": round(mean_outbound_ratio, 3),
        "outboundPct": round(mean_outbound_ratio * 100, 1),
        "inboundPct": round((1.0 - mean_outbound_ratio) * 100, 1)
    },
    "auditSummary": {
        "compliance": {str(k): int(v) for k, v in audit_compliance_counts.items()},
        "encryption": {str(k): int(v) for k, v in audit_encryption_counts.items()},
        "auth": {str(k): int(v) for k, v in audit_auth_counts.items()},
        "dhGroups": {str(k): int(v) for k, v in audit_dh_counts.items()},
        "vulnerabilities": {str(k): int(v) for k, v in vuln_series.items()}
    }
}

summary_json_path = DASHBOARD_DATA_DIR / "realDatasetSummary.json"
with open(summary_json_path, "w", encoding="utf-8") as f:
    json.dump(summary_data, f, indent=2)
print(f"[+] Saved summary statistics to {summary_json_path}")
print("[✓] All real dataset JSON files created successfully!")
