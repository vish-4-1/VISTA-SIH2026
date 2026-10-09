from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.evaluation.evaluate import evaluate_classifier
from vista_ml.explainability.shap_analysis import explain_xgboost
from vista_ml.models.random_forest import save_model_bundle, train_random_forest_classifier
from vista_ml.models.xgboost_model import save_model_bundle as save_xgboost_bundle
from vista_ml.models.xgboost_model import train_xgboost_classifier


PC1 = "pc1"
PC2 = "pc2"
GROUP_PROPOSALS = {
    "MODP_2048": "aes256-sha256-modp2048",
    "MODP_3072": "aes256-sha256-modp3072",
    "ECP_256": "aes256-sha256-ecp256",
}
CONFIG_PATH = "/etc/swanctl/swanctl.conf"

REFERENCES = [
    {
        "id": "RFC 7296 sections 1.2, 2.7, 3.3 and 3.4",
        "url": "https://www.rfc-editor.org/rfc/rfc7296",
        "use": "IKE_SA_INIT exchange, transform negotiation and KE payload/DH group",
    },
    {
        "id": "strongSwan swanctl.conf documentation",
        "url": "https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html",
        "use": "IKE proposals and StrongSwan connection configuration",
    },
    {
        "id": "SIH 2026 PS 26160",
        "url": "https://sih.gov.in/sih2026PS",
        "use": "Project requirements",
    },
]


def _docker_path() -> str:
    docker = shutil.which("docker")
    if docker:
        return docker
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    if candidate.is_file():
        return str(candidate)
    raise FileNotFoundError("Docker Desktop CLI was not found on PATH or in its standard per-user install directory.")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_docker_path(), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _ensure_tcpdump() -> None:
    _docker(
        "exec", PC1, "sh", "-lc",
        "command -v tcpdump >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump)",
    )


def _terminate_connection() -> None:
    for container in (PC1, PC2):
        _docker("exec", container, "swanctl", "--terminate", "--ike", "pc1-pc2", check=False)


def _load_variant(group: str) -> None:
    proposal = GROUP_PROPOSALS[group]
    for container in (PC1, PC2):
        variant_path = f"/tmp/vista-swanctl-{group.lower()}.conf"
        load_variant = (
            f"sed 's|^[[:space:]]*proposals = .*|        proposals = {proposal}|' "
            f"{CONFIG_PATH} > {variant_path} && "
            f"swanctl --load-conns --file {variant_path} && "
            f"rm -f {variant_path}"
        )
        _docker("exec", container, "sh", "-lc", load_variant)


def _restore_configs() -> None:
    _terminate_connection()
    for container in (PC1, PC2):
        _docker("exec", container, "swanctl", "--load-conns")
    status = _docker("exec", PC1, "swanctl", "--list-sas", check=False).stdout
    if "ESTABLISHED" not in status:
        _docker("exec", PC1, "swanctl", "--initiate", "--child", "pc-tunnel")


def _capture_handshake(group: str, repetition: int, capture_path: Path) -> dict[str, float | int | str]:
    remote_path = f"/tmp/ike-init-{group.lower()}-{repetition:02d}.pcap"
    capture = subprocess.Popen(
        [
            _docker_path(), "exec", PC1, "tcpdump", "-n", "-i", "eth0",
            "-c", "2", "-U", "-w", remote_path, "udp port 500 or udp port 4500",
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
            raise RuntimeError(f"tcpdump did not start for {group}/{repetition}: {ready_line}{stderr or stdout}")

        _docker("exec", PC1, "swanctl", "--initiate", "--child", "pc-tunnel")
        stdout, stderr = capture.communicate(timeout=20)
        if capture.returncode != 0:
            raise RuntimeError(f"IKE_SA_INIT capture failed: {stderr or stdout}")
        _docker("cp", f"{PC1}:{remote_path}", str(capture_path))
    except Exception:
        _docker("exec", PC1, "pkill", "-INT", "tcpdump", check=False)
        capture.kill()
        capture.communicate()
        raise

    messages = []
    for packet in PcapReader(str(capture_path)):
        if IP not in packet or UDP not in packet:
            continue
        payload = bytes(packet[UDP].payload)
        if 4500 in {int(packet[UDP].sport), int(packet[UDP].dport)}:
            if payload[:4] != b"\x00\x00\x00\x00":
                continue
            payload = payload[4:]
        if len(payload) < 28:
            continue
        if payload[17] >> 4 != 2 or payload[18] != 34:
            continue
        if int.from_bytes(payload[20:24], "big") != 0:
            continue
        is_response = bool(payload[19] & 0x20)
        messages.append({
            "timestamp": float(packet.time),
            "response": is_response,
            "ip_length": int(packet[IP].len or len(packet[IP])),
            "ike_length": int.from_bytes(payload[24:28], "big"),
        })

    requests = [message for message in messages if not message["response"]]
    responses = [message for message in messages if message["response"]]
    if not requests or not responses:
        raise RuntimeError(f"Did not capture both IKE_SA_INIT request and response for {group}/{repetition}.")
    request = requests[0]
    response = responses[0]
    return {
        "initiator_init_ip_bytes": request["ip_length"],
        "responder_init_ip_bytes": response["ip_length"],
        "initiator_init_ike_bytes": request["ike_length"],
        "responder_init_ike_bytes": response["ike_length"],
        "ike_init_total_bytes": request["ip_length"] + response["ip_length"],
        "request_response_size_delta": abs(request["ip_length"] - response["ip_length"]),
        "request_response_delay_ms": max(0.0, (response["timestamp"] - request["timestamp"]) * 1000.0),
        "ike_init_datagram_count": len(messages),
    }


def _negotiated_dh_group() -> str:
    output = _docker("exec", PC1, "swanctl", "--list-sas").stdout
    matches = re.findall(r"\b(MODP_2048|MODP_3072|ECP_256)\b", output)
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise RuntimeError(f"Expected one negotiated IKE DH group, found {unique} in SA output.")
    return unique[0]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture IKE_SA_INIT packet observables and train a DH-group classifier on the StrongSwan testbed."
    )
    parser.add_argument("--repetitions", type=int, default=12, help="Fresh handshakes per DH group.")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if args.repetitions < 4:
        raise ValueError("Use at least four independent handshakes per DH group.")
    if not 0.1 <= args.test_size <= 0.5:
        raise ValueError("test-size must be between 0.1 and 0.5")

    _ensure_tcpdump()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    capture_dir = ROOT.parent / "captures" / "strongswan" / "ike_dh_inference" / run_id
    report_dir = ROOT / "reports" / "strongswan_ike_dh" / run_id
    model_dir = ROOT / "models" / "strongswan_ike_dh" / run_id
    for directory in (capture_dir, report_dir, model_dir):
        directory.mkdir(parents=True, exist_ok=True)

    rows = []
    try:
        for group, proposal in GROUP_PROPOSALS.items():
            for repetition in range(args.repetitions):
                _terminate_connection()
                _load_variant(group)
                experiment_id = f"ike_{group.lower()}_{repetition:02d}"
                capture_path = capture_dir / f"{experiment_id}.pcap"
                observed = _capture_handshake(group, repetition, capture_path)
                negotiated = _negotiated_dh_group()
                if negotiated != group:
                    raise RuntimeError(
                        f"Requested {group} but StrongSwan negotiated {negotiated}; refusing mislabeled sample."
                    )
                rows.append({
                    "experiment_id": experiment_id,
                    "scenario_id": f"ike_dh_{group.lower()}",
                    "label": group,
                    "requested_ike_proposal": proposal,
                    "negotiated_ike_dh_group": negotiated,
                    "ike_version": 2,
                    "esp_proposal": "aes256-sha256",
                    "mode": "tunnel",
                    "child_sa_pfs": "not configured",
                    **observed,
                })
    finally:
        _restore_configs()

    dataset = pd.DataFrame(rows)
    label_names = sorted(GROUP_PROPOSALS)
    expected_per_class = args.repetitions
    if dataset["label"].value_counts().to_dict() != {label: expected_per_class for label in label_names}:
        raise RuntimeError("Captured data are not class-balanced; refusing to train.")

    feature_columns = [
        "initiator_init_ip_bytes",
        "responder_init_ip_bytes",
        "initiator_init_ike_bytes",
        "responder_init_ike_bytes",
        "ike_init_total_bytes",
        "request_response_size_delta",
        "request_response_delay_ms",
        "ike_init_datagram_count",
    ]
    X = dataset[feature_columns].astype(float)
    y = dataset["label"].astype(str)
    train_idx, test_idx = train_test_split(
        np.arange(len(dataset)),
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )
    train_df = dataset.iloc[train_idx]
    test_df = dataset.iloc[test_idx]
    overlap = set(train_df["experiment_id"]) & set(test_df["experiment_id"])
    if overlap:
        raise RuntimeError(f"Handshake leakage detected: {sorted(overlap)}")

    dataset_path = ROOT / "data" / "processed" / "strongswan_ike_dh" / run_id / "ike_init_features.parquet"
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_parquet(dataset_path, index=False)
    report = {
        "dataset_category": "VISTA-generated StrongSwan testbed, controlled configuration-inference experiment",
        "task": "classify IKE DH group from IKE_SA_INIT packet lengths/timing only",
        "capture_point": "pc1 eth0; IKE_SA_INIT UDP port 500",
        "model_features": feature_columns,
        "labels": label_names,
        "class_distribution": dataset["label"].value_counts().to_dict(),
        "configuration_ground_truth": {
            "varying_factor": "IKE DH group",
            "groups": label_names,
            "fixed_ike_encryption": "AES-CBC-256",
            "fixed_ike_integrity_prf": "HMAC-SHA2-256",
            "fixed_esp_proposal": "AES-CBC-256 / HMAC-SHA2-256-128",
            "fixed_mode": "tunnel",
            "child_sa_pfs": "disabled/not configured",
            "verification": "Negotiated group checked from swanctl --list-sas for every capture; mismatch aborts the run.",
        },
        "split": {
            "strategy": "stratified by label; one row per fresh IKE handshake",
            "train_handshakes": len(train_idx),
            "test_handshakes": len(test_idx),
            "random_state": args.random_state,
            "experiment_overlap": sorted(overlap),
        },
        "references": REFERENCES,
        "limitations": [
            "IKE_SA_INIT proposal/KE fields are protocol-visible; packet lengths are a proxy signal, not a substitute for a standards-compliant parser.",
            "Only DH group varies. This run does not validate cipher, PFS, transport mode, attack detection, or eBPF inference.",
            "Small controlled laboratory results are not production performance or security guarantees.",
        ],
        "results": {},
    }

    for model_name, trainer, saver in (
        ("random_forest", train_random_forest_classifier, save_model_bundle),
        ("xgboost", train_xgboost_classifier, save_xgboost_bundle),
    ):
        model = trainer(X.iloc[train_idx], y.iloc[train_idx], random_state=args.random_state)
        saver(model, model_dir / f"{model_name}.joblib", {
            "dataset": "StrongSwan testbed IKE_SA_INIT capture",
            "task": report["task"],
            "feature_columns": feature_columns,
            "configuration_ground_truth": report["configuration_ground_truth"],
            "references": REFERENCES,
        })
        metrics = evaluate_classifier(
            model,
            X.iloc[test_idx],
            y.iloc[test_idx],
            label_names,
            report_dir / model_name,
        )
        report["results"][model_name] = {
            key: metrics[key] for key in ("accuracy", "macro_f1", "macro_precision", "macro_recall")
        }
        if model_name == "xgboost":
            report["shap"] = explain_xgboost(
                model,
                X.iloc[test_idx],
                output_dir=report_dir / "shap",
                max_samples=len(test_idx),
            )

    with (report_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    print(f"Captured {len(dataset)} fresh IKE_SA_INIT handshakes: {dataset['label'].value_counts().to_dict()}")
    for model_name, metrics in report["results"].items():
        print(f"{model_name}: accuracy={metrics['accuracy']:.3f}, macro_f1={metrics['macro_f1']:.3f}")
    print(f"Dataset: {dataset_path}")
    print(f"Summary: {report_dir / 'summary.json'}")
    print("Only IKE DH-group inference was evaluated; do not generalize to other SIH tasks.")


if __name__ == "__main__":
    main()