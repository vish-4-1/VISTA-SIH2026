"""
VISTA PCAP & Live Traffic Analyzer
Parses libpcap (.pcap) and pcapng files using Scapy.
Extracts IPsec ESP SPIs and IKE negotiation headers, then invokes the ModelService only
when the complete recorded feature schema can be formed from the capture.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
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
            spi_hex = None
            src_port = 0
            dst_port = 0

            # 1. ESP Packet Analysis (Protocol 50)
            if ESP in pkt or ip_proto == 50:
                proto_label = "ESP (50)"
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

                if src_port == 500 or dst_port == 500:
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
                            proto_label = "NAT-T IKE (UDP 4500)"
                            if len(udp_payload) >= 32:
                                v_byte = udp_payload[21]
                                major_v = (v_byte >> 4) & 0x0F
                                proto_label = f"NAT-T IKEv{major_v}"
                        else:
                            # Encapsulated ESP! First 4 bytes are the SPI
                            proto_label = "NAT-T ESP (UDP 4500)"
                            spi_int = int.from_bytes(udp_payload[:4], byteorder="big")
                            spi_hex = _format_spi(spi_int)

            elif TCP in pkt:
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                proto_label = "TCP"
            elif ICMP in pkt:
                proto_label = "ICMP"

            # Endpoints and flow key
            endpoints = sorted((src_ip, dst_ip))
            flow_key = f"{proto_label}|{endpoints[0]}|{endpoints[1]}"
            direction = "forward" if src_ip == endpoints[0] else "backward"

            packets_data.append({
                "time": pkt_time,
                "length": pkt_len,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_label,
                "spi": spi_hex,
                "flow_key": flow_key,
                "direction": direction,
                "is_ipv6": is_ipv6,
            })

        reader.close()

        if not packets_data:
            return {
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
                "spi": most_frequent_spi,
                "time": iso_time,
                "src": first_row["src_ip"],
                "dst": first_row["dst_ip"],
                "proto": first_row["protocol"],
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

        # Run Live Machine Learning Inference on Extracted Flows
        inference_error = None
        try:
            features_df = model_service.prepare_feature_dataframe(flows_list)
            traffic_predictions = model_service.predict_traffic(features_df)
            threat_predictions = model_service.predict_threat(features_df, model_name=model_name)

            for i, flow in enumerate(flows_list):
                t_pred = traffic_predictions[i]
                th_pred = threat_predictions[i]

                # 1. Traffic Classification (AI Analysis / Encrypted Application Profile)
                is_ike_flow = "IKE" in str(flow.get("proto", "")).upper()
                if is_ike_flow:
                    flow["trafficPrediction"] = {
                        "status": "out_of_distribution",
                        "source": "unsupported_input",
                        "label": "IKE Control Plane",
                        "model": t_pred["modelUsed"],
                        "modelArtifact": t_pred["modelArtifact"],
                        "modelVersion": t_pred.get("modelVersion"),
                        "trainingDataScope": t_pred.get("trainingDataScope"),
                        "predictionTask": "encrypted application traffic classification",
                        "probability": None,
                        "probabilityType": None,
                        "probabilities": None,
                        "isOutOfDistribution": True,
                        "outOfDistributionReason": (
                            "IKE control-plane negotiation; traffic classifier is trained on encapsulated "
                            "data-plane application payloads, not key-exchange signaling."
                        ),
                        "missingFeatures": [],
                    }
                    flow["trafficType"] = "IKE Control Plane (Out of scope)"
                else:
                    flow["trafficPrediction"] = {
                        "status": t_pred["status"],
                        "source": t_pred["source"],
                        "label": t_pred["predictedClass"],
                        "model": t_pred["modelUsed"],
                        "modelArtifact": t_pred["modelArtifact"],
                        "modelVersion": t_pred.get("modelVersion"),
                        "trainingDataScope": t_pred.get("trainingDataScope"),
                        "predictionTask": t_pred.get("predictionTask"),
                        "probability": t_pred["probability"],
                        "probabilityType": t_pred["probabilityType"],
                        "probabilities": t_pred["probabilities"],
                        "isOutOfDistribution": False,
                        "missingFeatures": t_pred["missingFeatures"],
                    }
                    flow["trafficType"] = (
                        t_pred["predictedClass"]
                        if t_pred["status"] == "success"
                        else "Insufficient Data"
                        if t_pred["status"] == "insufficient_data"
                        else "Prediction Unavailable"
                    )

                # 2. Threat Classification (Threat Intelligence / Attack Detection)
                flow["threatPrediction"] = {
                    "status": th_pred["status"],
                    "source": th_pred["source"],
                    "label": th_pred["predictedClass"],
                    "model": th_pred["modelUsed"],
                    "modelArtifact": th_pred["modelArtifact"],
                    "modelVersion": th_pred.get("modelVersion"),
                    "trainingDataScope": th_pred.get("trainingDataScope"),
                    "predictionTask": th_pred.get("predictionTask"),
                    "probability": th_pred["probability"],
                    "probabilityType": th_pred["probabilityType"],
                    "probabilities": th_pred["probabilities"],
                    "missingFeatures": th_pred["missingFeatures"],
                }

                # Backward-compatible fields
                flow["mlPrediction"] = flow["threatPrediction"]
                flow["predictionStatus"] = th_pred["status"]
                flow["attackType"] = (
                    th_pred["predictedClass"]
                    if th_pred["status"] == "success"
                    else "Insufficient Data"
                    if th_pred["status"] == "insufficient_data"
                    else "Prediction Unavailable"
                )
                flow["isAttack"] = th_pred["isAttack"]
                flow["confidence"] = th_pred["confidence"]
                flow["confidenceValue"] = th_pred["confidenceValue"]
                flow["probabilities"] = th_pred["probabilities"]
                flow["isAnomaly"] = th_pred["isAnomaly"]
                flow["anomalyScore"] = th_pred["anomalyScore"]
                flow["inferenceEngine"] = th_pred["modelUsed"]
                flow["model_used"] = th_pred["modelUsed"]
                if th_pred["status"] == "insufficient_data":
                    flow["predictionError"] = (
                        "Required model features are missing: "
                        + ", ".join(th_pred["missingFeatures"])
                    )
        except Exception as e:
            logger.exception("ML inference failed: %s", e)
            inference_error = str(e)
            for flow in flows_list:
                flow["trafficPrediction"] = {
                    "status": "unavailable",
                    "source": "traffic_classifier",
                    "label": None,
                    "model": "traffic_classifier",
                    "probability": None,
                    "probabilityType": None,
                    "probabilities": None,
                }
                flow["threatPrediction"] = {
                    "status": "unavailable",
                    "source": "attack_classifier",
                    "label": None,
                    "model": model_name,
                    "probability": None,
                    "probabilityType": None,
                    "probabilities": None,
                }
                flow["mlPrediction"] = flow["threatPrediction"]
                flow["predictionStatus"] = "unavailable"
                flow["attackType"] = "Prediction Unavailable"
                flow["isAttack"] = None
                flow["trafficType"] = "Prediction Unavailable"
                flow["confidence"] = None
                flow["confidenceValue"] = None
                flow["probabilities"] = None
                flow["isAnomaly"] = None
                flow["anomalyScore"] = None
                flow["inferenceEngine"] = "Prediction Unavailable"
                flow["predictionError"] = inference_error

        # High-level Summary
        predicted_flows = [f for f in flows_list if f["predictionStatus"] == "success"]
        attack_count = sum(1 for f in predicted_flows if f["isAttack"] == 1)
        esp_count = sum(1 for f in flows_list if "ESP" in f["proto"])
        ike_count = sum(1 for f in flows_list if "IKE" in f["proto"])
        insufficient_count = sum(1 for f in flows_list if f["predictionStatus"] == "insufficient_data")
        unavailable_count = sum(1 for f in flows_list if f["predictionStatus"] == "unavailable")

        all_models_info = model_service.get_info().get("models", {})
        threat_model_info = all_models_info.get(model_name, {})
        traffic_model_info = all_models_info.get("traffic_classifier", {})

        summary = {
            "totalFlows": len(flows_list),
            "totalPackets": total_raw_packets,
            "totalBytes": total_raw_bytes,
            "benignFlows": sum(1 for f in predicted_flows if f["isAttack"] == 0),
            "attackFlows": attack_count,
            "predictedFlows": len(predicted_flows),
            "insufficientDataFlows": insufficient_count,
            "unavailablePredictionFlows": unavailable_count,
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
            else "insufficient_data" if insufficient_count and not unavailable_count
            else "unavailable" if unavailable_count
            else "insufficient_data"
        )
        ml_inference = {
            "status": inference_status,
            "source": "ml_model",
            "model": model_name,
            "modelArtifact": (
                "attack_classifier.joblib" if model_name in ("attack_classifier", "xgboost")
                else "random_forest_baseline.joblib"
            ),
            "modelTask": threat_model_info.get("predictionTask"),
            "trainingDataScope": threat_model_info.get("trainingDataScope"),
            "trainingDataset": threat_model_info.get("trainingDataset"),
            "evaluationScope": threat_model_info.get("evaluationScope"),
            "classes": threat_model_info.get("classes", []),
            "features": threat_model_info.get("features", []),
            "predictedFlows": len(predicted_flows),
            "insufficientDataFlows": insufficient_count,
            "unavailableFlows": unavailable_count,
            "trafficModel": {
                "name": "traffic_classifier",
                "modelArtifact": "traffic_classifier.joblib",
                "predictionTask": traffic_model_info.get("predictionTask"),
                "classes": traffic_model_info.get("classes", []),
                "features": traffic_model_info.get("features", []),
                "trainingDataset": traffic_model_info.get("trainingDataset"),
                "trainingDataScope": traffic_model_info.get("trainingDataScope"),
            },
            "threatModel": {
                "name": model_name,
                "modelArtifact": (
                    "attack_classifier.joblib" if model_name in ("attack_classifier", "xgboost")
                    else "random_forest_baseline.joblib"
                ),
                "predictionTask": threat_model_info.get("predictionTask"),
                "classes": threat_model_info.get("classes", []),
                "features": threat_model_info.get("features", []),
                "trainingDataset": threat_model_info.get("trainingDataset"),
                "trainingDataScope": threat_model_info.get("trainingDataScope"),
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
        digest_src = f"{name}:{total_raw_packets}:{total_raw_bytes}:{len(flows_list)}"
        analysis_id = f"ANL-{hashlib.sha256(digest_src.encode('utf-8')).hexdigest()[:10].upper()}"

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
