from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import ESP
from scapy.utils import PcapReader
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.data.schema import ALL_FEATURE_COLUMNS
from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.explainability.shap_analysis import explain_xgboost
from vista_ml.features.pcap_features import extract_flow_features
from vista_ml.models.random_forest import save_model_bundle, train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle as save_xgboost_bundle
from vista_ml.models.xgboost_model import train_xgboost_classifier


CLIENT_CONTAINER = "vista-client"
GATEWAY_CONTAINER = "vista-gateway"
SERVER_CONTAINER = "vista-server"
SERVER_IP = "172.22.0.10"
GATEWAY_INNER_IP = "172.22.0.2"
TCP_PORT = 18080


def _docker_path() -> str:
    docker = shutil.which("docker")
    if docker:
        return docker
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    if candidate.is_file():
        return str(candidate)
    raise FileNotFoundError("Docker Desktop CLI was not found on PATH or in its standard per-user install directory.")


def _docker(*args: str, check: bool = True, capture_output: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_docker_path(), *args],
        check=check,
        capture_output=capture_output,
        text=True,
    )


def _ensure_runtime() -> None:
    nat_command = (
        "if ! command -v iptables >/dev/null 2>&1; then "
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables; fi; "
        "iptables -t nat -C POSTROUTING -s 172.20.0.2/32 -d 172.22.0.10/32 -o eth1 "
        "-j SNAT --to-source 172.22.0.2 2>/dev/null || "
        "iptables -t nat -A POSTROUTING -s 172.20.0.2/32 -d 172.22.0.10/32 -o eth1 "
        "-j SNAT --to-source 172.22.0.2"
    )
    _docker("exec", "vista-gateway", "sh", "-lc", nat_command)

    for container, package, tool in [
        ("vista-gateway", "tcpdump", "tcpdump"),
        (SERVER_CONTAINER, "netcat-openbsd", "nc"),
        (CLIENT_CONTAINER, "netcat-openbsd", "nc"),
    ]:
        command = (
            f"command -v {tool} >/dev/null 2>&1 || "
            f"(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {package})"
        )
        _docker("exec", container, "sh", "-lc", command)

    _docker("exec", CLIENT_CONTAINER, "ping", "-c", "1", "-W", "2", SERVER_IP)


def _capture_packets(experiment_id: str, label: str, index: int, capture_path: Path) -> None:
    remote_path = f"/tmp/{experiment_id}.pcap"
    tcpdump_filter = "(ip proto 50) or (udp port 4500 and udp[8:4] != 0)"
    packet_limit = "12" if label == "ICMP_NORMAL" else "5"
    capture = subprocess.Popen(
        [
            _docker_path(), "exec", GATEWAY_CONTAINER, "tcpdump", "-n", "-i", "eth0",
            "-c", packet_limit, "-U", "-w", remote_path, tcpdump_filter,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        ready_line = capture.stderr.readline()
        if "listening on" not in ready_line:
            stdout, stderr = capture.communicate(timeout=5)
            raise RuntimeError(f"tcpdump did not start for {experiment_id}: {ready_line}{stderr or stdout}")

        if label == "ICMP_NORMAL":
            _docker("exec", CLIENT_CONTAINER, "ping", "-c", "6", "-i", "0.2", "-W", "2", SERVER_IP)
        else:
            receive_path = f"/tmp/{experiment_id}-received.txt"
            _docker("exec", "-d", SERVER_CONTAINER, "sh", "-lc", f"nc -l -p {TCP_PORT} > {receive_path}")
            marker = f"VISTA-NORMAL-{experiment_id}"
            _docker(
                "exec", "-i", CLIENT_CONTAINER, "sh", "-lc",
                f"printf '%s\\n' '{marker}' | nc -w 3 {SERVER_IP} {TCP_PORT}",
            )
            received = _docker("exec", SERVER_CONTAINER, "cat", receive_path).stdout.strip()
            if received != marker:
                raise RuntimeError(f"TCP marker was not received for {experiment_id}.")

        stdout, stderr = capture.communicate(timeout=20)
        if capture.returncode != 0:
            raise RuntimeError(f"tcpdump failed for {experiment_id}: {stderr or stdout}")
        _docker("cp", f"{GATEWAY_CONTAINER}:{remote_path}", str(capture_path))
    except Exception:
        _docker("exec", GATEWAY_CONTAINER, "pkill", "-INT", "tcpdump", check=False)
        capture.kill()
        capture.communicate()
        raise


def _packet_table(pcap_path: Path, experiment_id: str) -> pd.DataFrame:
    packets = []
    for packet in PcapReader(str(pcap_path)):
        if IP not in packet:
            continue
        ip = packet[IP]
        if ESP in packet or int(ip.proto) == 50:
            protocol = "ESP"
        elif UDP in packet and 4500 in {int(packet[UDP].sport), int(packet[UDP].dport)}:
            udp_payload = bytes(packet[UDP].payload)
            if len(udp_payload) < 8 or udp_payload[:4] == b"\x00\x00\x00\x00":
                continue
            protocol = "ESP_UDP"
        else:
            continue

        endpoints = sorted((ip.src, ip.dst))
        flow_id = f"{protocol}|{endpoints[0]}|{endpoints[1]}"
        packets.append({
            "timestamp": datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat(),
            "packet_length": int(ip.len or len(ip)),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": 0,
            "dst_port": 0,
            "protocol": protocol,
            "flow_id": flow_id,
            "direction": "forward" if ip.src == endpoints[0] else "backward",
        })

    if not packets:
        raise ValueError(f"No IPv4 TCP/UDP/ICMP packets found in {pcap_path}.")
    return pd.DataFrame(packets)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture and classify benign ICMP versus TCP traffic through the VISTA StrongSwan tunnel."
    )
    parser.add_argument("--repetitions", type=int, default=10, help="Independent sessions per benign traffic class.")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if args.repetitions < 4:
        raise ValueError("Use at least 4 independent captures per class for a meaningful pipeline smoke test.")
    if not 0.1 <= args.test_size <= 0.5:
        raise ValueError("test-size must be between 0.1 and 0.5")

    _ensure_runtime()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    capture_dir = ROOT.parent / "captures" / "strongswan" / "normal" / run_id
    packet_dir = ROOT / "data" / "processed" / "strongswan" / run_id / "packets"
    report_dir = ROOT / "reports" / "strongswan_testbed_normal" / run_id
    model_dir = ROOT / "models" / "strongswan_testbed_normal" / run_id
    for directory in (capture_dir, packet_dir, report_dir, model_dir):
        directory.mkdir(parents=True, exist_ok=True)

    feature_rows = []
    for label in ("ICMP_NORMAL", "TCP_NORMAL"):
        for index in range(args.repetitions):
            experiment_id = f"{label.lower()}_{index:02d}"
            pcap_path = capture_dir / f"{experiment_id}.pcap"
            _capture_packets(experiment_id, label, index, pcap_path)
            packet_frame = _packet_table(pcap_path, experiment_id)
            packet_csv = packet_dir / f"{experiment_id}.csv"
            packet_frame.to_csv(packet_csv, index=False)
            flow = extract_flow_features(packet_csv)
            if len(flow) != 1:
                raise ValueError(f"Expected one flow for {experiment_id}, found {len(flow)}.")
            flow.loc[:, "experiment_id"] = experiment_id
            flow.loc[:, "scenario_id"] = label.lower()
            flow.loc[:, "traffic_type"] = "benign_controlled"
            flow.loc[:, "attack_type"] = "none"
            flow.loc[:, "label"] = label
            flow.loc[:, "ipsec_mode"] = "tunnel"
            flow.loc[:, "ike_version"] = "2"
            flow.loc[:, "cipher"] = "AES_CBC_256_HMAC_SHA2_256"
            flow.loc[:, "integrity_algorithm"] = "HMAC_SHA2_256_128"
            flow.loc[:, "dh_group"] = "MODP_2048"
            flow["pfs_enabled"] = pd.Series([pd.NA], dtype="boolean")
            feature_rows.append(flow)

    dataset = pd.concat(feature_rows, ignore_index=True)
    feature_columns = [
        column for column in ALL_FEATURE_COLUMNS
        if column in dataset.columns and dataset[column].notna().any()
    ]
    X = dataset[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = dataset["label"].astype(str)
    groups = dataset["experiment_id"].astype(str)
    group_labels = dataset[["experiment_id", "label"]].drop_duplicates().set_index("experiment_id")["label"]
    train_groups, test_groups = train_test_split(
        group_labels.index.to_numpy(),
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=group_labels.to_numpy(),
    )
    train_mask = groups.isin(train_groups)
    test_mask = groups.isin(test_groups)
    if set(groups[train_mask]) & set(groups[test_mask]):
        raise RuntimeError("Experiment leakage detected between train and test groups.")

    dataset_path = ROOT / "data" / "processed" / "strongswan" / run_id / "normal_traffic_features.parquet"
    dataset.to_parquet(dataset_path, index=False)
    labels = sorted(y.unique())
    summary = {
        "dataset_category": "VISTA-generated StrongSwan testbed, benign controlled traffic only",
        "tasks": {"ICMP_NORMAL": "controlled ping traffic", "TCP_NORMAL": "controlled TCP marker traffic"},
        "dataset_reference": "Custom dataset collected from the controlled VISTA StrongSwan Docker testbed.",
        "reference_sources": [
            {"id": "RFC 7296", "url": "https://www.rfc-editor.org/rfc/rfc7296", "scope": "IKEv2 negotiation and SA establishment"},
            {"id": "RFC 4301", "url": "https://www.rfc-editor.org/rfc/rfc4301", "scope": "IPsec architecture, SAs, and tunnel/transport modes"},
            {"id": "RFC 4303", "url": "https://www.rfc-editor.org/rfc/rfc4303", "scope": "ESP packet format and processing"},
            {"id": "strongSwan swanctl.conf documentation", "url": "https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html", "scope": "Ground-truth connection/proposal configuration"},
            {"id": "SIH 2026 PS 26160", "url": "https://sih.gov.in/sih2026PS", "scope": "Project requirements"},
        ],
        "ipsec_configuration_ground_truth": {
            "ike_version": "IKEv2",
            "ike_proposal": "AES-CBC-256 / HMAC-SHA2-256-128 / PRF-HMAC-SHA2-256 / MODP-2048",
            "esp_proposal": "AES-CBC-256 / HMAC-SHA2-256-128",
            "mode": "tunnel",
            "child_sa_pfs": "no separate DH/PFS proposal configured",
            "configuration_variants_collected": 1,
        },
        "limitations": [
            "No attack traffic or attack labels were generated.",
            "No eBPF telemetry was collected.",
            "The model input contains outer ESP packet sizes/timing/direction only; it does not contain decrypted inner protocol headers.",
            "This dataset distinguishes benign ICMP from benign TCP, not VPN attacks or cryptographic settings.",
            "Only one IPsec configuration was collected, so IKE version, cipher, DH/PFS, and mode inference cannot be trained or evaluated from this run.",
            "Each independent capture session is one experiment group; the small test set is for pipeline validation only.",
        ],
        "capture_point": "vista-gateway eth0; outer encrypted ESP packet headers before decryption",
        "model_input_scope": "outer ESP sizes, timing, rates, and direction only; no inner IP/TCP/ICMP headers or payload",
        "capture_dir": str(capture_dir),
        "feature_dataset": str(dataset_path),
        "rows": len(dataset),
        "source_features": feature_columns,
        "class_distribution": y.value_counts().to_dict(),
        "train_experiments": sorted(map(str, train_groups)),
        "test_experiments": sorted(map(str, test_groups)),
        "results": {},
    }

    for model_name, trainer, model_path in (
        ("random_forest", train_random_forest_classifier, model_dir / "random_forest.joblib"),
        ("xgboost", train_xgboost_classifier, model_dir / "xgboost.joblib"),
    ):
        model = trainer(X.loc[train_mask], y.loc[train_mask], random_state=args.random_state)
        metadata = {
            "dataset_category": summary["dataset_category"],
            "task": "benign ICMP versus benign TCP classification",
            "feature_columns": feature_columns,
            "capture_point": summary["capture_point"],
            "ipsec_configuration_ground_truth": summary["ipsec_configuration_ground_truth"],
            "reference_sources": summary["reference_sources"],
            "attack_detection_claim": False,
            "ebpf_collected": False,
        }
        if model_name == "xgboost":
            save_xgboost_bundle(model, model_path, metadata)
        else:
            save_model_bundle(model, model_path, metadata)
        metrics = evaluate_classifier(
            model,
            X.loc[test_mask],
            y.loc[test_mask],
            labels,
            report_dir / model_name,
        )
        summary["results"][model_name] = {
            key: metrics[key] for key in ("accuracy", "macro_f1", "macro_precision", "macro_recall")
        }
        if model_name == "xgboost":
            summary["shap"] = explain_xgboost(
                model,
                X.loc[test_mask],
                output_dir=report_dir / "shap",
                max_samples=len(X.loc[test_mask]),
            )

    with (report_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, default=str)
    print(f"Captured {len(dataset)} independent benign flows from {capture_dir}")
    print(f"Experiment-group split: {len(train_groups)} train / {len(test_groups)} test")
    for model_name, metrics in summary["results"].items():
        print(f"{model_name}: accuracy={metrics['accuracy']:.3f}, macro_f1={metrics['macro_f1']:.3f}")
    print(f"Summary: {report_dir / 'summary.json'}")
    print("These are controlled benign-traffic pipeline checks, not attack-detection results.")


if __name__ == "__main__":
    main()