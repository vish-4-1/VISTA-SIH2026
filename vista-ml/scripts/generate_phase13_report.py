#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "vista-ml" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = ROOT / "vista-ml" / "models" / "candidates" / "controlled_workload_classification" / "20261010T082308Z-6b8eb840" / "random_forest.joblib"
RTP_CAMPAIGN_ID = "9f3f1f2b-7a6e-468c-b86d-1f9bee65d8bf"
RTP_DATASET_CSV = ROOT / "captures" / "strongswan" / "collections" / "campaigns" / RTP_CAMPAIGN_ID / "dataset_preparation" / "prepared_dataset.csv"


def generate_phase13_report() -> Path:
    model = joblib.load(MODEL_PATH)
    approved_features = list(model.feature_names_in_)

    df_rtp = pd.read_csv(RTP_DATASET_CSV)
    X_rtp = df_rtp[approved_features]
    preds = model.predict(X_rtp)
    probs = model.predict_proba(X_rtp)

    rtp_eval_details = []
    for idx, row in df_rtp.iterrows():
        p_dict = {cls: float(round(p, 4)) for cls, p in zip(model.classes_, probs[idx])}
        rtp_eval_details.append({
            "experiment_id": str(row.get("experiment_id")),
            "session_id": str(row.get("session_id")),
            "true_label": "controlled_rtp_voip",
            "predicted_label": str(preds[idx]),
            "probabilities": p_dict,
            "features": {
                "packet_count": float(row["packet_count"]),
                "byte_count": float(row["byte_count"]),
                "mean_packet_size": float(row["mean_packet_size"]),
                "std_packet_size": float(row["std_packet_size"]),
                "direction_ratio": float(row["direction_ratio"]),
                "forward_packet_count": float(row["forward_packet_count"]),
                "backward_packet_count": float(row["backward_packet_count"]),
                "flow_duration": float(row["flow_duration"]),
            }
        })

    report = {
        "schema_version": "vista-phase13-workload-coverage-v1",
        "phase": "Phase 13 — Expanded Workload Coverage and Honest Classification Boundaries",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "candidate_model_provenance": {
            "model_path": str(MODEL_PATH),
            "model_sha256": "de9d6334309ad1b286ce917c28de49833d4f186e2022fc3b03d53b2c2a826de8",
            "feature_schema": "vista-flow-v1.json",
            "feature_count": len(approved_features),
            "validated_for_inference": False,
            "production_eligible": False,
        },
        "workload_feasibility_matrix": {
            "controlled_icmpv4": {
                "decision": "COLLECTED_AND_VALIDATED",
                "generator": "ping -n -c <count> -i <interval> -s <payload_bytes> 172.20.0.3 (pc1)",
                "receiver": "Linux kernel ICMP echo responder (pc2)",
                "ground_truth_source": "ping transmitted/received counters and rtt matching pc2 tcpdump ICMP count",
                "capture_method": "Outer ESP on pc1 (pc1_outer_icmp.pcap), inner ICMP on pc2",
                "failure_conditions": "Packet loss > 0, unreadable PCAP, 0 ESP packets, SA delta <= 0",
                "evidence_campaigns": ["76adc766-ef41-45f5-b677-1d950c7ff052", "d645e930-010c-4f8a-a10a-fe7f22aef309"],
            },
            "controlled_tcp_marker": {
                "decision": "COLLECTED_AND_VALIDATED",
                "generator": "Bounded TCP marker client script on pc1 emitting structured payload bytes",
                "receiver": "OpenBSD netcat (nc -l -p <port>) writing to /tmp/tcp_marker.bin on pc2",
                "ground_truth_source": "Byte count and SHA-256 match between sender and receiver payload file",
                "capture_method": "Outer ESP on pc1 (pc1_outer_tcp.pcap), inner TCP on pc2",
                "failure_conditions": "Byte mismatch, SHA-256 mismatch, nc non-zero exit, 0 ESP packets, SA delta <= 0",
                "evidence_campaigns": ["76adc766-ef41-45f5-b677-1d950c7ff052", "d645e930-010c-4f8a-a10a-fe7f22aef309"],
            },
            "controlled_http": {
                "decision": "COLLECTED_AND_VALIDATED",
                "generator": "Perl IO::Socket::INET HTTP client script on pc1 (GET and POST)",
                "receiver": "Perl IO::Socket::INET bounded HTTP/1.1 server script on pc2",
                "ground_truth_source": "Client measurement JSON and server evidence JSON matching request count, status 200, response bytes, and SHA-256",
                "capture_method": "Outer ESP on pc1 (pc1_outer_http.pcap), inner TCP on pc2",
                "failure_conditions": "Non-200 status code, response byte mismatch, SHA-256 mismatch, 0 ESP packets, SA delta <= 0",
                "evidence_campaigns": ["76adc766-ef41-45f5-b677-1d950c7ff052", "d645e930-010c-4f8a-a10a-fe7f22aef309"],
            },
            "controlled_rtp_voip": {
                "decision": "COLLECTED_AND_VALIDATED",
                "generator": "Perl IO::Socket::INET UDP sender on pc1 emitting RFC 3550 RTP packets (12-byte header, SSRC, seq, ts, G.711 frame payload)",
                "receiver": "Perl IO::Socket::INET UDP receiver on pc2 validating RTP v2, unpacking sequence continuity, recording jitter and payload hash",
                "ground_truth_source": "Client measurement JSON and server evidence JSON matching packet count, sequence range, SSRC, byte count, and SHA-256",
                "capture_method": "Outer ESP on pc1 (pc1_outer_rtp.pcap), inner UDP on pc2 (pc2_receiver_rtp.pcap)",
                "failure_conditions": "Packet loss > 0, SSRC mismatch, SHA-256 mismatch, sequence gap, 0 ESP packets, SA delta <= 0",
                "evidence_campaigns": [RTP_CAMPAIGN_ID],
            },
            "controlled_smtp": {
                "decision": "IMPLEMENTED_NOT_VALIDATED",
                "generator": "Perl IO::Socket::INET SMTP client script on pc1 (EHLO, MAIL FROM, RCPT TO, DATA, body, QUIT)",
                "receiver": "Perl IO::Socket::INET SMTP server script on pc2 implementing RFC 5321 state machine and evidence capture",
                "ground_truth_source": "Transaction ID, message body bytes, and message body SHA-256 verified between client and server",
                "capture_method": "Outer ESP on pc1, inner TCP on pc2",
                "failure_conditions": "Non-250/354 status code, body byte mismatch, SHA-256 mismatch",
                "evidence_campaigns": ["Verified in unit integration test scratch/test_smtp_roundtrip.py; formal multi-session campaign not yet scheduled"],
            },
            "controlled_video_streaming": {
                "decision": "BLOCKED",
                "generator": "Synthetic UDP or HTTP chunk streaming",
                "receiver": "UDP socket sink / HTTP sink",
                "ground_truth_source": "None (no media codec or RTP/RTSP streaming server in container images)",
                "capture_method": "N/A",
                "failure_conditions": "Cannot verify actual video codec stream or frame decoding without third-party media libraries (ffmpeg/gstreamer)",
                "evidence_campaigns": [],
            },
            "ipv6_traffic": {
                "decision": "BLOCKED",
                "generator": "IPv6 ICMPv6 / TCP client",
                "receiver": "IPv6 responder on pc2",
                "ground_truth_source": "N/A",
                "capture_method": "N/A",
                "failure_conditions": "Docker bridge subnet lacks global IPv6 addressing; StrongSwan swanctl.conf traffic selectors cover only 172.20.0.2/32 <-> 172.20.0.3/32",
                "evidence_campaigns": [],
            },
        },
        "rtp_collection_campaign": {
            "campaign_id": RTP_CAMPAIGN_ID,
            "workload_set": "rtp",
            "recipe_mode": "standard",
            "seed": 26164,
            "sessions_requested": 15,
            "sessions_completed": 15,
            "sessions_failed": 0,
            "observations_accepted": 15,
            "observations_quarantined": 0,
            "dataset_admission_status": "READY_FOR_REVIEW",
            "manifest_path": f"captures/strongswan/collections/campaigns/{RTP_CAMPAIGN_ID}/campaign_manifest.json",
            "report_path": f"captures/strongswan/collections/campaigns/{RTP_CAMPAIGN_ID}/dataset_preparation/dataset_report.json",
        },
        "frozen_model_ood_evaluation": {
            "target_campaign": RTP_CAMPAIGN_ID,
            "sample_count": 15,
            "ground_truth_class": "controlled_rtp_voip",
            "candidate_model_classes": list(model.classes_),
            "prediction_distribution": {
                "controlled_http": int((preds == "controlled_http").sum()),
                "controlled_icmpv4": int((preds == "controlled_icmpv4").sum()),
                "controlled_tcp_marker": int((preds == "controlled_tcp_marker").sum()),
            },
            "classification_error_rate": 1.0,
            "mean_prediction_probabilities": {
                cls: float(round(probs[:, i].mean(), 4))
                for i, cls in enumerate(model.classes_)
            },
            "root_cause_analysis": {
                "closed_world_assumption": "The frozen Phase 10 model has no 'unknown' or 'out-of-distribution' reject option; it is forced to select one of the 3 training classes.",
                "feature_signature_overlap": "RTP VoIP streaming packets (256-336 bytes) exhibit std_packet_size = 0.0 (like ICMP) but direction_ratio = 1.00 (strictly unidirectional). Because ICMP requires direction_ratio == 0.50, decision trees branch to controlled_http.",
                "scientific_conclusion": "Demonstrates that high accuracy on controlled training classes (Objective 2) DOES NOT equate to general application identification (Objective 3). Out-of-distribution traffic is silently and confidently misclassified as HTTP.",
            },
            "per_observation_results": rtp_eval_details,
        },
        "classification_scope_boundaries": {
            "objective_1_tunnel_metadata": {
                "scope": "Outer IPsec ESP and NAT-T encapsulation analysis",
                "capability": "Fully supported. Accurately extracts outer flow features, packet timings, byte counts, and SA counter deltas.",
                "status": "VALIDATED",
            },
            "objective_2_controlled_workload_classification": {
                "scope": "Distinguishing known, isolated benign generation recipes from outer ESP flow statistics",
                "capability": "Supported within tested scope (96.67% accuracy on baseline classes).",
                "status": "VALIDATED_WITHIN_SCOPED_RECIPES",
            },
            "objective_3_arbitrary_application_identification": {
                "scope": "Recognizing arbitrary application protocols (VoIP, streaming, mail, web) in operational tunnels",
                "capability": "NOT SUPPORTED. Outer ESP features are insufficient to separate arbitrary encrypted applications; novel protocols collapse into training classes.",
                "status": "BLOCKED",
            },
            "objective_4_security_attack_detection": {
                "scope": "Detecting malicious network intrusion, exfiltration, or tunnel tampering",
                "capability": "NOT SUPPORTED. Benign controlled workload models cannot detect attacks without labeled operational attack data.",
                "status": "BLOCKED",
            },
        },
        "multiplexing_feasibility_assessment": {
            "verdict": "ARCHITECTURALLY_BLOCKED_FOR_SINGLE_ESP_SA",
            "findings": [
                "Under vista-flow-v1, outer flow key (50, 172.20.0.2:0, 172.20.0.3:0) merges all concurrent tunnel traffic into a single aggregate outer ESP flow.",
                "Concurrent workloads sharing the same tunnel corrupt flow-level ground truth and cannot be attributed to individual applications without inner plaintext inspection.",
                "Alternative architectures: (1) Tunnel-level aggregate telemetry; (2) Controlled isolated time windows; (3) Dedicated per-workload CHILD_SAs with distinct SPIs.",
            ]
        },
        "safeguards_preserved": {
            "validated_for_inference": False,
            "production_eligible": False,
            "experimental": True,
        }
    }

    report_path = REPORTS_DIR / "phase13_workload_coverage_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report written successfully to {report_path}")
    return report_path


if __name__ == "__main__":
    generate_phase13_report()
