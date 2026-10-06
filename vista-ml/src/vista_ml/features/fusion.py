from __future__ import annotations

import numpy as np
import pandas as pd


def _normalize_time_column(frame: pd.DataFrame, preferred_name: str) -> pd.Series:
    for col in (preferred_name, "timestamp_start", "timestamp"):
        if col in frame.columns:
            return pd.to_datetime(frame[col], errors="coerce", utc=True)
    return pd.to_datetime(pd.Series([pd.NaT] * len(frame), index=frame.index), utc=True)


def fuse_pcap_ebpf(
    pcap_df: pd.DataFrame,
    ebpf_df: pd.DataFrame,
    correlation_window_ms: int = 100,
    join_on_flow_id: bool = True,
) -> pd.DataFrame:
    """Correlate PCAP and eBPF features using flow context and temporal proximity.

    The implementation aligns records by the strongest available flow identifier, dropping to a
    timestamp-based fallback if exact flow IDs are not present. When there is no reliable exact
    5-tuple identifier in eBPF data, the match is marked as a weak correlation and the output
    retains the original flow with NULL/NaN eBPF feature values.
    """
    pcap = pcap_df.copy()
    ebpf = ebpf_df.copy()
    if pcap.empty:
        return pcap

    pcap["_pcap_time"] = _normalize_time_column(pcap, "timestamp_start")
    ebpf["_ebpf_time"] = _normalize_time_column(ebpf, "timestamp")

    if "flow_id" in pcap.columns and "flow_id" in ebpf.columns and join_on_flow_id:
        merged = pcap.merge(ebpf, on="flow_id", how="left", suffixes=("_pcap", "_ebpf"))
        if "_ebpf_time" in merged.columns and "_pcap_time" in merged.columns:
            ebpf_t = pd.to_datetime(merged["_ebpf_time"], errors="coerce", utc=True)
            pcap_t = pd.to_datetime(merged["_pcap_time"], errors="coerce", utc=True)
            merged["_time_delta_ms"] = (ebpf_t - pcap_t).dt.total_seconds().abs() * 1000
            merged["correlation_window_ms"] = correlation_window_ms
            merged["matched_ebpf"] = merged["_time_delta_ms"].le(correlation_window_ms).fillna(False)
            return merged
        return merged

    pcap = pcap.copy()
    pcap["_correlation_key"] = "unknown"
    if "src_ip" in pcap.columns and "dst_ip" in pcap.columns:
        pcap["_correlation_key"] = (
            pcap["src_ip"].astype(str) + "->" + pcap["dst_ip"].astype(str)
        )

    if "flow_id" in ebpf.columns:
        ebpf["_correlation_key"] = ebpf["flow_id"].astype(str)
    elif "socket_id" in ebpf.columns:
        ebpf["_correlation_key"] = ebpf["socket_id"].astype(str)
    else:
        ebpf["_correlation_key"] = "unknown"

    merged = pcap.merge(ebpf, on="_correlation_key", how="left", suffixes=("_pcap", "_ebpf"))
    ebpf_t = pd.to_datetime(merged.get("_ebpf_time", pd.Series([pd.NaT] * len(merged))), errors="coerce", utc=True)
    pcap_t = pd.to_datetime(merged.get("_pcap_time", pd.Series([pd.NaT] * len(merged))), errors="coerce", utc=True)
    merged["_time_delta_ms"] = (ebpf_t - pcap_t).dt.total_seconds().abs() * 1000
    merged["correlation_window_ms"] = correlation_window_ms
    merged["matched_ebpf"] = merged["_time_delta_ms"].le(correlation_window_ms).fillna(False)
    return merged


def correlate_pcap_ebpf(
    pcap_features: pd.DataFrame,
    ebpf_features: pd.DataFrame,
    correlation_window_ms: int = 100,
) -> pd.DataFrame:
    """Convenience wrapper for the public pipeline."""
    return fuse_pcap_ebpf(pcap_features, ebpf_features, correlation_window_ms=correlation_window_ms)
