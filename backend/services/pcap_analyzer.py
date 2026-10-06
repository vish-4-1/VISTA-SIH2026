"""
VISTA PCAP & Live Traffic Analyzer
Parses libpcap (.pcap) and pcapng files using Scapy.
Extracts IPsec ESP SPIs, IKEv1/v2 negotiation headers (ISAKMP), flow statistical metrics,
and invokes the ModelService for live AI classification.
"""

from __future__ import annotations

import io
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader

from backend.services.model_service import model_service


def _format_spi(spi_val: int) -> str:
    """Formats an integer SPI into standard 8-character hex format 0x12345678."""
    return f"0x{spi_val & 0xFFFFFFFF:08x}"


class PcapAnalyzer:
    def __init__(self) -> None:
        pass

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
                except Exception:
                    pass

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
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
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
            spi_hex = "0x00000000"
            src_port = 0
            dst_port = 0

            # 1. ESP Packet Analysis (Protocol 50)
            if ESP in pkt or ip_proto == 50:
                proto_label = "ESP (50)"
                if ESP in pkt:
                    spi_hex = _format_spi(int(pkt[ESP].spi))
                else:
                    # Raw parse first 4 bytes of IP payload
                    try:
                        raw_payload = bytes(pkt[IP].payload)
                        if len(raw_payload) >= 4:
                            spi_int = int.from_bytes(raw_payload[:4], byteorder="big")
                            spi_hex = _format_spi(spi_int)
                    except Exception:
                        pass

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

        if not packets_data:
            return {
                "filename": name,
                "totalPackets": 0,
                "totalBytes": 0,
                "flows": [],
                "summary": {},
                "ikeNegotiations": [],
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
            duration = max(0.001, round(t_max - t_min, 4))

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
                mean_iat = 0.0
                std_iat = 0.0
                min_iat = 0.0
                max_iat = 0.0

            # Direction ratio
            fwd_count = int((group["direction"] == "forward").sum())
            bwd_count = int((group["direction"] == "backward").sum())
            outbound_ratio = round(fwd_count / pkts_count, 3)

            byte_rate = round(total_bytes / duration, 2)
            bit_rate = round((total_bytes * 8) / duration, 2)
            pps = round(pkts_count / duration, 2)

            # Dominant SPI and IP endpoints
            most_frequent_spi = group["spi"].mode()[0] if not group["spi"].empty else "0x00000000"
            first_row = group.iloc[0]

            iso_time = datetime.fromtimestamp(t_min, tz=timezone.utc).strftime("%H:%M:%S")

            flow_rec = {
                "id": f"FLW-{flow_idx:07d}",
                "sessionId": f"VPN-SES-{((flow_idx - 1) // 5) + 1:05d}",
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
                "forward_bytes": round(fwd_count * mean_len, 2),
                "backward_bytes": round(bwd_count * mean_len, 2),
                "ebpfEvents": max(1, int(pkts_count * 2.8)),
                "socketDrops": 0,
                "tcpRetrans": 0,
            }
            flows_list.append(flow_rec)
            flow_idx += 1

        # Run Live Machine Learning Inference on Extracted Flows
        features_df = model_service.prepare_feature_dataframe(flows_list)
        predictions = model_service.predict(features_df, model_name=model_name)

        # Merge Predictions into Flows
        for i, flow in enumerate(flows_list):
            pred = predictions[i]
            flow["attackType"] = pred["predictedClass"]
            flow["isAttack"] = pred["isAttack"]
            flow["trafficType"] = "Benign" if pred["isAttack"] == 0 else "Attack"
            flow["confidence"] = pred["confidence"]
            flow["confidenceValue"] = pred["confidenceValue"]
            flow["probabilities"] = pred["probabilities"]
            flow["isAnomaly"] = pred["isAnomaly"]
            flow["anomalyScore"] = pred["anomalyScore"]
            flow["inferenceEngine"] = f"{pred['modelUsed']} (Live Model)"

        # High-level Summary
        attack_count = sum(1 for f in flows_list if f["isAttack"] == 1)
        esp_count = sum(1 for f in flows_list if "ESP" in f["proto"])
        ike_count = sum(1 for f in flows_list if "IKE" in f["proto"])

        summary = {
            "totalFlows": len(flows_list),
            "totalPackets": total_raw_packets,
            "totalBytes": total_raw_bytes,
            "benignFlows": len(flows_list) - attack_count,
            "attackFlows": attack_count,
            "espFlows": esp_count,
            "ikeFlows": ike_count,
            "detectedIkeNegotiations": len(ike_negotiations),
            "threatRatio": round(attack_count / max(1, len(flows_list)), 3),
        }

        return {
            "filename": name,
            "totalPackets": total_raw_packets,
            "totalBytes": total_raw_bytes,
            "flows": flows_list,
            "summary": summary,
            "ikeNegotiations": ike_negotiations,
        }


# Global singleton instance
pcap_analyzer = PcapAnalyzer()
