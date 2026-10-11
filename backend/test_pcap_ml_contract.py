from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from backend.services.model_service import FEATURE_COLUMNS, model_service
from backend.services.pcap_analyzer import PcapAnalyzer
from vista_ml.features.pcap_features import extract_flow_features


def test_outer_esp_and_ike_are_preserved_but_not_sent_to_application_models(tmp_path: Path) -> None:
    ike = bytearray(28)
    ike[17] = 0x20
    ike_packets = [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=500, dport=500) / Raw(load=bytes(ike)),
        Ether() / IP(src="192.0.2.2", dst="192.0.2.1") / UDP(sport=500, dport=500) / Raw(load=bytes(ike)),
    ]
    esp_packets = [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ESP(spi=0x12345678, seq=1) / Raw(load=b"a" * 16),
        Ether() / IP(src="192.0.2.2", dst="192.0.2.1") / ESP(spi=0x87654321, seq=1) / Raw(load=b"b" * 16),
    ]
    capture = tmp_path / "ike-esp.pcap"
    wrpcap(str(capture), ike_packets + esp_packets)

    with (
        patch.object(model_service, "prepare_feature_dataframe", side_effect=AssertionError("must not infer outer IPsec")),
        patch.object(model_service, "predict_traffic", side_effect=AssertionError("must not classify outer IPsec")),
        patch.object(model_service, "predict_threat", side_effect=AssertionError("must not detect attacks from outer IPsec")),
    ):
        result = PcapAnalyzer().analyze_file(capture)

    assert result["totalPackets"] == 4
    assert len(result["flows"]) == 2
    assert {flow["protocolFamily"] for flow in result["flows"]} == {"ESP", "IKE"}
    assert {flow["analysisId"] for flow in result["flows"]} == {result["analysisId"]}
    for flow in result["flows"]:
        assert flow["trafficPrediction"]["status"] == "out_of_distribution"
        assert flow["threatPrediction"]["status"] == "out_of_distribution"
        assert flow["trafficPrediction"]["label"] is None
        assert flow["threatPrediction"]["label"] is None
        assert flow["isAttack"] is None

    repeated = PcapAnalyzer().analyze_file(capture)
    assert repeated["analysisId"] != result["analysisId"]


def test_udp_flow_key_includes_both_transport_ports(tmp_path: Path) -> None:
    packets = [
        Ether() / IP(src="198.51.100.1", dst="198.51.100.2") / UDP(sport=12345, dport=53) / Raw(load=b"a"),
        Ether() / IP(src="198.51.100.1", dst="198.51.100.2") / UDP(sport=12346, dport=53) / Raw(load=b"b"),
    ]
    capture = tmp_path / "udp-tuples.pcap"
    wrpcap(str(capture), packets)

    def insufficient(features):
        return [{
            "status": "insufficient_data",
            "predictedClass": None,
            "missingFeatures": ["mean_inter_arrival_time"],
        } for _ in range(len(features))]

    with (
        patch.object(model_service, "predict_traffic", side_effect=insufficient),
        patch.object(model_service, "predict_threat", side_effect=insufficient),
        patch.object(model_service, "predict_anomaly", side_effect=insufficient),
    ):
        result = PcapAnalyzer().analyze_file(capture)

    assert len(result["flows"]) == 2
    assert {flow["protocolFamily"] for flow in result["flows"]} == {"UDP"}
    assert {flow["srcPort"] for flow in result["flows"]} == {12345, 12346}
    assert all(flow["predictionStatus"] == "insufficient_data" for flow in result["flows"])


def test_batch_packet_extractor_matches_backend_vista_flow_v1_features(tmp_path: Path) -> None:
    source_packets = []
    timestamps = [1_700_000_000.0, 1_700_000_000.125, 1_700_000_000.5, 1_700_000_000.7]
    for index, payload_size in enumerate((4, 8, 16, 2)):
        src, dst = (
            ("192.0.2.1", "192.0.2.2")
            if index % 2 == 0
            else ("192.0.2.2", "192.0.2.1")
        )
        packet = Ether() / IP(src=src, dst=dst) / ICMP() / Raw(load=b"x" * payload_size)
        packet.time = timestamps[index]
        source_packets.append(packet)

    capture = tmp_path / "feature-contract.pcap"
    wrpcap(str(capture), source_packets)

    packet_rows = []
    for packet in source_packets:
        packet_rows.append(
            {
                "timestamp": datetime.fromtimestamp(
                    float(packet.time), tz=timezone.utc
                ).isoformat(),
                "packet_length": len(bytes(packet[IP])),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ICMP",
                "flow_id": "ICMP|192.0.2.1:0|192.0.2.2:0",
                "direction": "forward" if packet[IP].src < packet[IP].dst else "backward",
            }
        )
    offline = extract_flow_features(pd.DataFrame(packet_rows))
    runtime_frames = []

    def record_runtime_features(features):
        runtime_frames.append(features.copy())
        return [
            {"status": "insufficient_data", "predictedClass": None}
            for _ in range(len(features))
        ]

    with (
        patch.object(model_service, "predict_traffic", side_effect=record_runtime_features),
        patch.object(
            model_service,
            "predict_threat",
            side_effect=lambda features: record_runtime_features(features),
        ),
        patch.object(
            model_service,
            "predict_anomaly",
            side_effect=lambda features: record_runtime_features(features),
        ),
    ):
        result = PcapAnalyzer().analyze_file(capture)

    assert len(result["flows"]) == 1
    assert result["flows"][0]["protocolFamily"] == "ICMP"
    assert runtime_frames
    np.testing.assert_allclose(
        runtime_frames[0].iloc[0].to_numpy(dtype=float),
        offline.loc[0, FEATURE_COLUMNS].to_numpy(dtype=float),
        rtol=0,
        atol=1e-8,
        equal_nan=True,
    )
