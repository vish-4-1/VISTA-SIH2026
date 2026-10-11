"""
VISTA PCAP & Live Traffic Analyzer
Parses libpcap (.pcap) and pcapng files using Scapy.
Extracts IPsec ESP SPIs and IKE negotiation headers, then invokes the ModelService only
when the complete recorded feature schema can be formed from the capture.
"""

from __future__ import annotations

import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader

from backend.services.model_service import model_service
from backend.services.posture_engine import posture_engine

logger = logging.getLogger(__name__)


def _format_spi(spi_val: int) -> str:
    """Formats an integer SPI into standard 8-character hex format 0x12345678."""
    return f"0x{spi_val & 0xFFFFFFFF:08x}"


class PcapAnalyzer:
    def parse_pcap_bytes(
        self,
        pcap_bytes: bytes,
        filename: str = "capture.pcap",
        model_name: str = "xgboost",
    ) -> Dict[str, Any]:
        """
        Saves bytes to a temporary file and analyzes it.
        """
        suffix = Path(filename).suffix or ".pcap"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_file.write(pcap_bytes)
            tmp_path = Path(tmp_file.name)

        try:
            return self.analyze_file(tmp_path, filename=filename, model_name=model_name)
        finally:
            if tmp_path.exists():
                try:
                    os.unlink(tmp_path)
                except OSError:
                    logger.exception("Unable to remove temporary PCAP file %s.", tmp_path)

    def analyze_file(
        self,
        file_path: Path | str,
        filename: Optional[str] = None,
        model_name: str = "xgboost",
    ) -> Dict[str, Any]:
        """
        Parses PCAP file, aggregates flows, and runs ML inference.
        """
        path_obj = Path(file_path)
        name = filename or path_obj.name
        analysis_id = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        packets_data: List[Dict[str, Any]] = []
        ike_negotiations: List[Dict[str, Any]] = []
        total_raw_packets = 0
        total_raw_bytes = 0

        try:
            reader = PcapReader(str(path_obj))
        except Exception as err:
            raise ValueError(f"Unable to read PCAP format: {err}")

        for pkt in reader:
            total_raw_packets += 1
            pkt_time = float(getattr(pkt, "time", 0.0))
            pkt_len = len(pkt)
            total_raw_bytes += pkt_len

            # IP Resolution
            src_ip = None
            dst_ip = None
            ip_proto = 0
            is_ipv6 = False

            if IP in pkt:
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
                ip_proto = int(pkt[IP].proto)
                pkt_len = int(pkt[IP].len or len(pkt[IP]))
            elif IPv6 in pkt:
                src_ip = str(pkt[IPv6].src)
                dst_ip = str(pkt[IPv6].dst)
                ip_proto = int(pkt[IPv6].nh)
                is_ipv6 = True

            proto_label = "OTHER"
            protocol_family = "OTHER"
            spi_hex = None
            src_port = 0
            dst_port = 0

            # 1. ESP Packet Analysis (Protocol 50)
            if ESP in pkt or ip_proto == 50:
                proto_label = "ESP (50)"
                protocol_family = "ESP"
                if ESP in pkt:
                    spi_hex = _format_spi(int(pkt[ESP].spi))
                else:
                    # Raw ESP has no decoded Scapy layer; its payload starts with the SPI.
                    network_layer = pkt[IPv6] if is_ipv6 else pkt[IP] if IP in pkt else None
                    if network_layer is not None:
                        raw_payload = bytes(network_layer.payload)
                        if len(raw_payload) >= 4:
                            spi_int = int.from_bytes(raw_payload[:4], byteorder="big")
                            spi_hex = _format_spi(spi_int)

            # 2. UDP Ports 500 / 4500 (IKE and NAT-T ESP)
            elif UDP in pkt:
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                udp_payload = bytes(pkt[UDP].payload)
                protocol_family = "UDP"
                proto_label = "UDP"

                if src_port == 500 or dst_port == 500:
                    protocol_family = "IKE"
                    proto_label = "IKE (UDP 500)"
                    # Parse ISAKMP Header
                    if len(udp_payload) >= 28:
                        init_spi = udp_payload[:8].hex()
                        resp_spi = udp_payload[8:16].hex()
                        next_payload = udp_payload[16]
                        v_byte = udp_payload[17]
                        major_v = (v_byte >> 4) & 0x0F
                        minor_v = v_byte & 0x0F
                        exch_type = udp_payload[18]
                        proto_label = f"IKEv{major_v} (UDP 500)"
                        spi_hex = f"0x{init_spi[:8]}"

                        ike_negotiations.append({
                            "timestamp": pkt_time,
                            "ikeVersion": f"IKEv{major_v}.{minor_v}",
                            "majorVersion": major_v,
                            "initiatorSpi": f"0x{init_spi}",
                            "responderSpi": f"0x{resp_spi}",
                            "exchangeType": exch_type,
                            "src": f"{src_ip}:{src_port}",
                            "dst": f"{dst_ip}:{dst_port}",
                        })

                elif src_port == 4500 or dst_port == 4500:
                    if len(udp_payload) >= 4:
                        # Non-ESP marker check (\x00\x00\x00\x00)
                        if udp_payload[:4] == b"\x00\x00\x00\x00":
                            protocol_family = "IKE"
                            proto_label = "NAT-T IKE (UDP 4500)"
                            if len(udp_payload) >= 32:
                                v_byte = udp_payload[21]
                                major_v = (v_byte >> 4) & 0x0F
                                proto_label = f"NAT-T IKEv{major_v}"
                        else:
                            # Encapsulated ESP! First 4 bytes are the SPI
                            protocol_family = "ESP"
                            proto_label = "NAT-T ESP (UDP 4500)"
                            spi_int = int.from_bytes(udp_payload[:4], byteorder="big")
                            spi_hex = _format_spi(spi_int)

            elif TCP in pkt:
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                protocol_family = "TCP"
                proto_label = "TCP"
            elif ICMP in pkt:
                protocol_family = "ICMP"
                proto_label = "ICMP"
            elif is_ipv6 and ip_proto == 58:
                protocol_family = "ICMPv6"
                proto_label = "ICMPv6"

            # Endpoints and flow key
            port_aware = protocol_family in {"TCP", "UDP", "IKE"} or bool(src_port or dst_port)
            src_endpoint = (src_ip, src_port if port_aware else 0)
            dst_endpoint = (dst_ip, dst_port if port_aware else 0)
            endpoints = sorted((src_endpoint, dst_endpoint), key=lambda item: (item[0] or "", item[1]))
            flow_key = f"{protocol_family}|{endpoints[0][0]}:{endpoints[0][1]}|{endpoints[1][0]}:{endpoints[1][1]}"
            direction = "forward" if src_endpoint == endpoints[0] else "backward"

            packets_data.append({
                "time": pkt_time,
                "length": pkt_len,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_label,
                "protocol_family": protocol_family,
                "spi": spi_hex,
                "flow_key": flow_key,
                "direction": direction,
                "is_ipv6": is_ipv6,
            })

        reader.close()

        if not packets_data:
            return {
                "analysisId": analysis_id,
                "filename": name,
                "totalPackets": 0,
                "totalBytes": 0,
                "flows": [],
                "summary": {},
                "ikeNegotiations": [],
                "mlInference": {
                    "status": "insufficient_data",
                    "model": model_name,
                    "predictedFlows": 0,
                    "insufficientDataFlows": 0,
                    "unavailableFlows": 0,
                },
            }

        # Flow Aggregation
        df_pkts = pd.DataFrame(packets_data)
        flows_list: List[Dict[str, Any]] = []
        flow_idx = 1

        for f_key, group in df_pkts.groupby("flow_key"):
            pkts_count = len(group)
            total_bytes = int(group["length"].sum())
            t_min = float(group["time"].min())
            t_max = float(group["time"].max())
            duration = round(t_max - t_min, 4)

            # Length stats
            lens = group["length"].values
            mean_len = round(float(np.mean(lens)), 1)
            std_len = round(float(np.std(lens)), 1) if pkts_count > 1 else 0.0
            min_len = int(np.min(lens))
            max_len = int(np.max(lens))

            # Inter-arrival times
            if pkts_count > 1:
                times_sorted = np.sort(group["time"].values)
                iats = np.diff(times_sorted)
                mean_iat = round(float(np.mean(iats)), 5)
                std_iat = round(float(np.std(iats)), 5)
                min_iat = round(float(np.min(iats)), 5)
                max_iat = round(float(np.max(iats)), 5)
            else:
                mean_iat = None
                std_iat = None
                min_iat = None
                max_iat = None

            # Direction ratio
            fwd_count = int((group["direction"] == "forward").sum())
            bwd_count = int((group["direction"] == "backward").sum())
            outbound_ratio = round(fwd_count / pkts_count, 3)

            byte_rate = round(total_bytes / duration, 2) if duration > 0 else None
            bit_rate = round((total_bytes * 8) / duration, 2) if duration > 0 else None
            pps = round(pkts_count / duration, 2) if duration > 0 else None

            # Dominant SPI and IP endpoints
            spi_values = group["spi"].dropna()
            most_frequent_spi = spi_values.mode()[0] if not spi_values.empty else None
            first_row = group.iloc[0]

            iso_time = datetime.fromtimestamp(t_min, tz=timezone.utc).strftime("%H:%M:%S")

            flow_rec = {
                "id": f"FLW-{flow_idx:07d}",
                "flowId": f"FLW-{flow_idx:07d}",
                "analysisId": analysis_id,
                "spi": most_frequent_spi,
                "time": iso_time,
                "src": first_row["src_ip"],
                "dst": first_row["dst_ip"],
                "proto": first_row["protocol"],
                "protocolFamily": first_row["protocol_family"],
                "srcPort": int(first_row["src_port"]),
                "dstPort": int(first_row["dst_port"]),
                "isIPv6": bool(first_row["is_ipv6"]),
                "duration": duration,
                "packets": pkts_count,
                "bytes": total_bytes,
                "byteRateBps": byte_rate,
                "bitRateBps": bit_rate,
                "packetsPerSecond": pps,
                "meanPacketLen": mean_len,
                "stdPacketLen": std_len,
                "minPacketLen": min_len,
                "maxPacketLen": max_len,
                "meanIat": mean_iat,
                "stdIat": std_iat,
                "minIat": min_iat,
                "maxIat": max_iat,
                "outboundRatio": outbound_ratio,
                "forward_packet_count": fwd_count,
                "backward_packet_count": bwd_count,
                "forward_bytes": int(group.loc[group["direction"] == "forward", "length"].sum()),
                "backward_bytes": int(group.loc[group["direction"] == "backward", "length"].sum()),
            }
            flows_list.append(flow_rec)
            flow_idx += 1

        # Live outer ESP and IKE control-plane records are not compatible with
        # the current application/attack model training distributions.
        inference_error = None
        inference_indices = [
            index for index, flow in enumerate(flows_list)
            if flow.get("protocolFamily") not in {"ESP", "IKE"}
        ]
        feature_frame = None
        if inference_indices:
            try:
                feature_frame = model_service.prepare_feature_dataframe(
                    [flows_list[index] for index in inference_indices]
                )
            except Exception as err:
                inference_error = str(err)
                logger.exception("Unable to prepare PCAP flow features.")

        def unavailable_result(task: str, error: Optional[str] = None) -> Dict[str, Any]:
            return {
                "status": "unavailable" if error else "unsupported_input",
                "source": "ml_model",
                "predictedClass": None,
                "modelUsed": task,
                "modelArtifact": (
                    "traffic_classifier.joblib" if task == "traffic_classifier"
                    else "attack_classifier.joblib"
                ),
                "probability": None,
                "probabilityType": None,
                "confidence": None,
                "confidenceValue": None,
                "probabilities": None,
                "isAttack": None,
                "isAnomaly": None,
                "anomalyScore": None,
                "missingFeatures": [],
                **({"error": error} if error else {}),
            }

        task_results: Dict[str, List[Dict[str, Any]]] = {
            "traffic": [unavailable_result("traffic_classifier") for _ in flows_list],
            "threat": [unavailable_result("attack_classifier") for _ in flows_list],
            "anomaly": [unavailable_result("isolation_forest") for _ in flows_list],
        }
        for index, flow in enumerate(flows_list):
            if flow.get("protocolFamily") in {"ESP", "IKE"}:
                plane = "control-plane IKE" if flow["protocolFamily"] == "IKE" else "outer encrypted ESP"
                reason = (
                    f"Observed {plane} does not contain labeled inner application/attack flow records. "
                    "The available models have no validated IPsec capture evaluation for this input."
                )
                for task, model_name in (
                    ("traffic", "traffic_classifier"),
                    ("threat", "attack_classifier"),
                    ("anomaly", "isolation_forest"),
                ):
                    task_results[task][index] = {
                        **unavailable_result(model_name),
                        "status": "out_of_distribution",
                        "source": "unsupported_input",
                        "isOutOfDistribution": True,
                        "outOfDistributionReason": reason,
                    }

        if feature_frame is not None:
            for task, predictor in (
                ("traffic", model_service.predict_traffic),
                ("threat", model_service.predict_threat),
                ("anomaly", model_service.predict_anomaly),
            ):
                try:
                    outputs = predictor(feature_frame)
                    if len(outputs) != len(inference_indices):
                        raise RuntimeError(
                            f"{task} predictor returned {len(outputs)} results for "
                            f"{len(inference_indices)} flows."
                        )
                    for index, output in zip(inference_indices, outputs):
                        task_results[task][index] = output
                except Exception as err:
                    logger.exception("%s inference failed.", task)
                    inference_error = f"{task}: {err}"
                    for index in inference_indices:
                        task_results[task][index] = unavailable_result(
                            {
                                "traffic": "traffic_classifier",
                                "threat": "attack_classifier",
                                "anomaly": "isolation_forest",
                            }[task],
                            str(err),
                        )

        for index, flow in enumerate(flows_list):
            traffic_result = task_results["traffic"][index]
            threat_result = task_results["threat"][index]
            anomaly_result = task_results["anomaly"][index]
            flow["trafficPrediction"] = {
                "status": traffic_result.get("status"),
                "source": traffic_result.get("source"),
                "label": traffic_result.get("predictedClass"),
                "model": traffic_result.get("modelUsed"),
                "modelArtifact": traffic_result.get("modelArtifact"),
                "modelVersion": traffic_result.get("modelVersion"),
                "featureSchemaVersion": traffic_result.get("featureSchemaVersion"),
                "predictionTask": traffic_result.get("modelTask"),
                "probability": traffic_result.get("probability"),
                "probabilityType": traffic_result.get("probabilityType"),
                "probabilities": traffic_result.get("probabilities"),
                "isOutOfDistribution": traffic_result.get("isOutOfDistribution", False),
                "outOfDistributionReason": traffic_result.get("outOfDistributionReason"),
                "missingFeatures": traffic_result.get("missingFeatures", []),
                "error": traffic_result.get("error"),
                "analysisId": analysis_id,
                "flowId": flow["flowId"],
            }
            flow["anomalyPrediction"] = {
                "status": anomaly_result.get("status"),
                "source": anomaly_result.get("source"),
                "label": anomaly_result.get("predictedClass"),
                "isAnomaly": anomaly_result.get("isAnomaly"),
                "anomalyScore": anomaly_result.get("anomalyScore"),
                "scoreConvention": anomaly_result.get("scoreConvention"),
                "decisionThreshold": anomaly_result.get("decisionThreshold"),
                "modelArtifact": anomaly_result.get("modelArtifact"),
                "modelVersion": anomaly_result.get("modelVersion"),
                "featureSchemaVersion": anomaly_result.get("featureSchemaVersion"),
                "validationStatus": anomaly_result.get("validationStatus"),
                "error": anomaly_result.get("error"),
                "analysisId": analysis_id,
                "flowId": flow["flowId"],
            }
            flow["trafficType"] = (
                traffic_result.get("predictedClass")
                if traffic_result.get("status") == "success"
                else "Out of scope"
                if traffic_result.get("status") == "out_of_distribution"
                else "Insufficient Data"
                if traffic_result.get("status") == "insufficient_data"
                else "Prediction Unavailable"
            )
            flow["threatPrediction"] = {
                "status": threat_result.get("status"),
                "source": threat_result.get("source"),
                "label": threat_result.get("predictedClass"),
                "model": threat_result.get("modelUsed"),
                "modelArtifact": threat_result.get("modelArtifact"),
                "modelVersion": threat_result.get("modelVersion"),
                "featureSchemaVersion": threat_result.get("featureSchemaVersion"),
                "predictionTask": threat_result.get("modelTask"),
                "probability": threat_result.get("probability"),
                "probabilityType": threat_result.get("probabilityType"),
                "probabilities": threat_result.get("probabilities"),
                "missingFeatures": threat_result.get("missingFeatures", []),
                "error": threat_result.get("error"),
                "analysisId": analysis_id,
                "flowId": flow["flowId"],
            }
            flow["mlPrediction"] = flow["threatPrediction"]
            flow["predictionStatus"] = threat_result.get("status")
            flow["attackType"] = (
                threat_result.get("predictedClass")
                if threat_result.get("status") == "success"
                else "Insufficient Data"
                if threat_result.get("status") == "insufficient_data"
                else "Out of scope"
                if threat_result.get("status") == "out_of_distribution"
                else "Prediction Unavailable"
            )
            flow["isAttack"] = threat_result.get("isAttack")
            flow["confidence"] = threat_result.get("confidence")
            flow["confidenceValue"] = threat_result.get("confidenceValue")
            flow["probabilities"] = threat_result.get("probabilities")
            flow["isAnomaly"] = anomaly_result.get("isAnomaly")
            flow["anomalyScore"] = anomaly_result.get("anomalyScore")
            flow["inferenceEngine"] = threat_result.get("modelUsed")
            flow["model_used"] = threat_result.get("modelUsed")
            if threat_result.get("error"):
                flow["predictionError"] = threat_result["error"]
            elif threat_result.get("status") == "insufficient_data":
                flow["predictionError"] = (
                    "Required model features are missing: "
                    + ", ".join(threat_result.get("missingFeatures", []))
                )

        # High-level Summary
        predicted_flows = [f for f in flows_list if f["predictionStatus"] == "success"]
        attack_count = sum(1 for f in predicted_flows if f["isAttack"] == 1)
        esp_count = sum(1 for f in flows_list if "ESP" in f["proto"])
        ike_count = sum(1 for f in flows_list if "IKE" in f["proto"])
        insufficient_count = sum(1 for f in flows_list if f["predictionStatus"] == "insufficient_data")
        unavailable_count = sum(1 for f in flows_list if f["predictionStatus"] == "unavailable")
        unsupported_count = sum(1 for f in flows_list if f["predictionStatus"] == "unsupported_input")
        out_of_distribution_count = sum(1 for f in flows_list if f["predictionStatus"] == "out_of_distribution")

        all_models_info = model_service.get_info().get("models", {})
        threat_model_info = all_models_info.get("attack_classifier", {})
        traffic_model_info = all_models_info.get("traffic_classifier", {})
        anomaly_model_info = all_models_info.get("isolation_forest", {})

        summary = {
            "totalFlows": len(flows_list),
            "totalPackets": total_raw_packets,
            "totalBytes": total_raw_bytes,
            "benignFlows": sum(1 for f in predicted_flows if f["isAttack"] == 0),
            "attackFlows": attack_count,
            "predictedFlows": len(predicted_flows),
            "insufficientDataFlows": insufficient_count,
            "unavailablePredictionFlows": unavailable_count,
            "unsupportedInputFlows": unsupported_count,
            "outOfDistributionFlows": out_of_distribution_count,
            "espFlows": esp_count,
            "ikeFlows": ike_count,
            "detectedIkeNegotiations": len(ike_negotiations),
            "threatRatio": (
                round(attack_count / len(predicted_flows), 3)
                if predicted_flows else None
            ),
        }
        inference_status = (
            "success" if predicted_flows
            else "out_of_distribution" if out_of_distribution_count == len(flows_list)
            else "unsupported_input" if unsupported_count
            else "insufficient_data" if insufficient_count
            else "unavailable" if unavailable_count
            else "insufficient_data"
        )
        ml_inference = {
            "status": inference_status,
            "source": "ml_model",
            "analysisId": analysis_id,
            "model": "attack_classifier",
            "modelArtifact": "attack_classifier.joblib",
            "modelTask": threat_model_info.get("predictionTask"),
            "modelVersion": threat_model_info.get("modelVersion"),
            "featureSchemaVersion": threat_model_info.get("featureSchemaVersion"),
            "validationStatus": threat_model_info.get("validationStatus"),
            "trainingDataScope": threat_model_info.get("trainingDataScope"),
            "trainingDataset": threat_model_info.get("trainingDataset"),
            "evaluationScope": threat_model_info.get("evaluationScope"),
            "classes": threat_model_info.get("classes", []),
            "features": threat_model_info.get("features", []),
            "predictedFlows": len(predicted_flows),
            "insufficientDataFlows": insufficient_count,
            "unavailableFlows": unavailable_count,
            "unsupportedInputFlows": unsupported_count,
            "outOfDistributionFlows": out_of_distribution_count,
            "trafficModel": {
                "name": "traffic_classifier",
                "modelArtifact": "traffic_classifier.joblib",
                "predictionTask": traffic_model_info.get("predictionTask"),
                "modelVersion": traffic_model_info.get("modelVersion"),
                "featureSchemaVersion": traffic_model_info.get("featureSchemaVersion"),
                "validationStatus": traffic_model_info.get("validationStatus"),
                "inferenceEnabled": traffic_model_info.get("inferenceEnabled"),
                "classes": traffic_model_info.get("classes", []),
                "features": traffic_model_info.get("features", []),
                "trainingDataset": traffic_model_info.get("trainingDataset"),
                "trainingDataScope": traffic_model_info.get("trainingDataScope"),
            },
            "threatModel": {
                "name": "attack_classifier",
                "modelArtifact": "attack_classifier.joblib",
                "predictionTask": threat_model_info.get("predictionTask"),
                "modelVersion": threat_model_info.get("modelVersion"),
                "featureSchemaVersion": threat_model_info.get("featureSchemaVersion"),
                "validationStatus": threat_model_info.get("validationStatus"),
                "inferenceEnabled": threat_model_info.get("inferenceEnabled"),
                "classes": threat_model_info.get("classes", []),
                "features": threat_model_info.get("features", []),
                "trainingDataset": threat_model_info.get("trainingDataset"),
                "trainingDataScope": threat_model_info.get("trainingDataScope"),
            },
            "anomalyModel": {
                "name": "isolation_forest",
                "modelArtifact": "isolation_forest.joblib",
                "predictionTask": anomaly_model_info.get("predictionTask"),
                "modelVersion": anomaly_model_info.get("modelVersion"),
                "featureSchemaVersion": anomaly_model_info.get("featureSchemaVersion"),
                "validationStatus": anomaly_model_info.get("validationStatus"),
                "inferenceEnabled": anomaly_model_info.get("inferenceEnabled"),
                "trainingDataset": anomaly_model_info.get("trainingDataset"),
                "trainingDataScope": anomaly_model_info.get("trainingDataScope"),
            },
        }
        if inference_error:
            ml_inference["error"] = inference_error

        # Build predictions schema with provenance
        predictions = {
            "protocol": {
                "value": "IKEv2/ESP" if esp_count > 0 and ike_count > 0 else "ESP" if esp_count > 0 else "IKE" if ike_count > 0 else "Other",
                "source": "Observed",
                "confidence": None
            },
            "ikeVersion": {
                "value": ike_negotiations[0]["majorVersion"] if ike_negotiations else None,
                "source": "Observed" if ike_negotiations else "Insufficient Data",
                "confidence": None
            },
            "encryption": { "value": None, "source": "Not supported by the current model", "confidence": None },
            "auth": { "value": None, "source": "Not supported by the current model", "confidence": None },
            "dhGroup": { "value": None, "source": "Not supported by the current model", "confidence": None },
            "pfs": { "value": None, "source": "Not supported by the current model", "confidence": None },
            "antiReplay": { "value": None, "source": "Not supported by the current model", "confidence": None },
            "lifetime": { "value": None, "source": "Not supported by the current model", "confidence": None },
        }

        # Pass to posture engine
        session_for_eval = {
            "encryption": predictions["encryption"]["value"],
            "auth": predictions["auth"]["value"],
            "dhGroup": predictions["dhGroup"]["value"],
            "pfs": predictions["pfs"]["value"],
            "antiReplay": predictions["antiReplay"]["value"],
            "lifetime": predictions["lifetime"]["value"],
            "ikeVersion": predictions["ikeVersion"]["value"],
        }
        assessment = posture_engine.evaluate_session(session_for_eval)

        analyzed_at = datetime.now(timezone.utc).isoformat()

        return {
            "analysisId": analysis_id,
            "filename": name,
            "dataMode": "pcap",
            "analyzedAt": analyzed_at,
            "totalPackets": total_raw_packets,
            "totalBytes": total_raw_bytes,
            "flows": flows_list,
            "summary": summary,
            "ikeNegotiations": ike_negotiations,
            "predictions": predictions,
            "assessment": assessment,
            "mlInference": ml_inference,
        }


# Global singleton instance
pcap_analyzer = PcapAnalyzer()
