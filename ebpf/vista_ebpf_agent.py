"""
VISTA eBPF Userspace Telemetry Collector Agent
SIH26160 · NTRO · Smart India Hackathon 2026

This backend-side agent polls the Docker Linux collector API. If the collector or
its eBPF probes are unavailable, it reports UNAVAILABLE and returns no events.
"""

from __future__ import annotations

import collections
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.request import urlopen

import pandas as pd

from ebpf.event_window import select_recent_events


class VistaEbpfAgent:
    """Reads events and status from the privileged Linux collector API."""

    def __init__(self, max_buffer_size: int = 500) -> None:
        self.max_buffer_size = max_buffer_size
        self.event_buffer: collections.deque[Dict[str, Any]] = collections.deque(maxlen=max_buffer_size)
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.collector_url = os.environ.get(
            "VISTA_EBPF_COLLECTOR_URL", "http://127.0.0.1:8765"
        ).rstrip("/")
        self._collector_status: Dict[str, Any] = {}
        self._collector_error: Optional[str] = None
        self._collector_last_success = 0.0
        self._event_mode = "UNAVAILABLE"

    def start(self) -> None:
        """Starts polling the collector without synthesizing events when unavailable."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stops the collection thread."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _worker_loop(self) -> None:
        """Polls the Linux collector; unavailable collection never creates events."""
        while self.is_running:
            try:
                self._poll_collector()
            except Exception as err:
                self._collector_error = str(err)
                self._collector_status = {
                    "status": "ERROR",
                    "mode": "UNAVAILABLE",
                    "probes": [],
                    "error": self._collector_error,
                }
                self._set_event_mode("UNAVAILABLE")
            time.sleep(0.5)

    def _get_collector_json(self, path: str) -> Dict[str, Any]:
        with urlopen(f"{self.collector_url}{path}", timeout=1.5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _poll_collector(self) -> None:
        """Refreshes status and events from the privileged collector container."""
        status = self._get_collector_json("/status")
        self._collector_status = status
        if status.get("mode") != "NATIVE_KERNEL_EBPF":
            self._collector_last_success = time.monotonic()
            self._set_event_mode("UNAVAILABLE")
            self._collector_error = status.get("error") or "Native eBPF probes are unavailable."
            return

        payload = self._get_collector_json("/events?limit=500")
        self._collector_error = None
        self._collector_last_success = time.monotonic()
        self._set_event_mode(status["mode"])
        known_ids = {event.get("id") for event in self.event_buffer}
        for event in payload.get("events", []):
            if event.get("id") not in known_ids:
                self.event_buffer.append(event)
                known_ids.add(event.get("id"))

    def _set_event_mode(self, mode: str) -> None:
        if self._event_mode != mode:
            self.event_buffer.clear()
            self._event_mode = mode

    def _collector_is_native(self) -> bool:
        return (
            self._collector_status.get("mode") == "NATIVE_KERNEL_EBPF"
            and time.monotonic() - self._collector_last_success <= 3.0
        )

    def get_recent_events(self, limit: int = 12) -> List[Dict[str, Any]]:
        """Returns the most recent events."""
        return select_recent_events(self.event_buffer, limit)

    def export_events_dataframe(self, limit: int = 200) -> pd.DataFrame:
        """
        Exports buffered events as a DataFrame strictly matching the
        schema in vista_ml.features.ebpf_features.
        """
        events = self.get_recent_events(limit=limit)
        df = pd.DataFrame(events)
        columns = [
            "timestamp",
            "flow_id",
            "pid",
            "process_name",
            "event_type",
            "socket_id",
            "bytes",
            "packets",
        ]
        if df.empty:
            return pd.DataFrame(columns=columns)
        for col in columns:
            if col not in df.columns:
                df[col] = None
        df["event_type"] = df["eventType"]
        return df[columns]

    def get_status(self) -> Dict[str, Any]:
        """Returns eBPF subsystem status."""
        live_mode = self._collector_status.get("mode", "UNAVAILABLE")
        probes = self._collector_status.get("probes", [])
        collector_status = self._collector_status.get("status", "UNAVAILABLE")
        if live_mode == "NATIVE_KERNEL_EBPF" and not self._collector_is_native():
            live_mode = "UNAVAILABLE"
            collector_status = "ERROR"
            probes = [{**probe, "status": "STALE"} for probe in probes]
        return {
            "status": "RUNNING" if self.is_running else "STOPPED",
            "mode": live_mode,
            "collectorUrl": self.collector_url,
            "collectorStatus": collector_status,
            "bpfError": self._collector_status.get("error") or self._collector_error,
            "probes": probes,
            "bufferedEventsCount": len(self.event_buffer),
            "transport": self._collector_status.get("transport"),
            "ringBufferCapacityBytes": self._collector_status.get("ringBufferCapacityBytes", 0),
            "ringBufferDroppedEvents": self._collector_status.get("ringBufferDroppedEvents", 0),
            "hookHits": self._collector_status.get("hookHits", {}),
            "ringEventsSeen": self._collector_status.get("ringEventsSeen", 0),
            "activeSpiCount": self._collector_status.get("activeSpiCount", 0),
        }


# Global singleton agent instance, auto-started
ebpf_agent = VistaEbpfAgent()
ebpf_agent.start()
