"""
VISTA eBPF Service Bridge
Exposes live eBPF ring buffer events and integrates with the ML fusion pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import pandas as pd

from ebpf.vista_ebpf_agent import ebpf_agent
from vista_ml.features.ebpf_features import aggregate_ebpf_features
from vista_ml.features.fusion import fuse_pcap_ebpf


class EbpfService:
    def __init__(self) -> None:
        pass

    def get_live_events(self, limit: int = 12) -> List[Dict[str, Any]]:
        """Returns the most recent eBPF kernel events."""
        return ebpf_agent.get_recent_events(limit=limit)

    def get_status(self) -> Dict[str, Any]:
        """Returns probe and ring buffer status."""
        return ebpf_agent.get_status()

    def fuse_with_ebpf(self, flow_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fuses flow records with recent eBPF events using the vista_ml.features.fusion logic.
        """
        if not flow_records:
            return []

        df_pcap = pd.DataFrame(flow_records)
        df_ebpf = ebpf_agent.export_events_dataframe(limit=100)

        try:
            merged = fuse_pcap_ebpf(df_pcap, df_ebpf, join_on_flow_id=False)
            sanitized = merged.astype(object).where(pd.notnull(merged), None)
            return sanitized.to_dict(orient="records")
        except Exception as err:
            print(f"[EbpfService] Fusion note: {err}")
            return flow_records


ebpf_service = EbpfService()
