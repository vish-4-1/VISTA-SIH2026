"""CO-RE libbpf collector with a read-only HTTP event/status API."""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from event_window import select_recent_events


ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = Path("/run/vista")
BTF_PATH = Path("/sys/kernel/btf/vmlinux")
EVENT_TYPES = {1: "XFRM_OUT", 2: "XFRM_IN", 3: "SOCK_SEND"}
FUNCTION_MAP = {
    "XFRM_OUT": "xfrm_output()",
    "XFRM_IN": "xfrm_input()",
    "SOCK_SEND": "sock_sendmsg()",
}
CAPABILITY_BITS = {"CAP_PERFMON": 38, "CAP_BPF": 39}


class KernelCollector:
    def __init__(self, capacity: int = 1000) -> None:
        self.events: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._probe_status = [
            {"name": "kprobe:xfrm_output", "target": "Linux XFRM outbound", "status": "UNAVAILABLE"},
            {"name": "kprobe:xfrm_input", "target": "Linux XFRM inbound", "status": "UNAVAILABLE"},
            {"name": "kprobe:sock_sendmsg", "target": "Socket transmission", "status": "UNAVAILABLE"},
            {"name": "kprobe:udp_sendmsg", "target": "UDP transmission", "status": "UNAVAILABLE"},
            {"name": "kprobe:__sys_sendto", "target": "Socket send syscall", "status": "UNAVAILABLE"},
        ]
        self._error: str | None = None
        self._mode = "UNAVAILABLE"
        self._status = "ERROR"
        self._hook_hits: dict[str, int] = {}
        self._ring_reserve_failures = 0
        self._ring_events_seen = 0
        self._malformed_ring_events = 0
        self._start_libbpf_loader()

    @staticmethod
    def _effective_capabilities() -> int:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
        raise RuntimeError("could not read CapEff from /proc/self/status")

    def _validate_environment(self) -> None:
        if not BTF_PATH.is_file() or not os.access(BTF_PATH, os.R_OK):
            raise RuntimeError(f"kernel BTF is unavailable or unreadable: {BTF_PATH}")

        capabilities = self._effective_capabilities()
        missing = [
            name
            for name, bit in CAPABILITY_BITS.items()
            if not capabilities & (1 << bit)
        ]
        if missing:
            raise RuntimeError(
                "missing effective capabilities required for BPF tracing: "
                + ", ".join(missing)
            )

    def _build_core_object(self) -> Path:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        vmlinux_header = RUNTIME_DIR / "vmlinux.h"
        bpf_object = RUNTIME_DIR / "vista_ipsec_monitor.bpf.o"
        with vmlinux_header.open("w", encoding="utf-8") as header:
            result = subprocess.run(
                ["bpftool", "btf", "dump", "file", str(BTF_PATH), "format", "c"],
                check=False,
                stdout=header,
                stderr=subprocess.PIPE,
                text=True,
            )
        if result.returncode:
            raise RuntimeError(f"bpftool could not generate vmlinux.h: {result.stderr.strip()}")

        machine = os.uname().machine
        target_arch = {"x86_64": "x86", "aarch64": "arm64"}.get(machine)
        if target_arch is None:
            raise RuntimeError(f"unsupported BPF target architecture: {machine}")

        result = subprocess.run(
            [
                "clang",
                "-target", "bpf",
                f"-D__TARGET_ARCH_{target_arch}",
                "-O2", "-g", "-Wall", "-Werror",
                "-I", str(RUNTIME_DIR),
                "-c", str(ROOT / "vista_ipsec_monitor.bpf.c"),
                "-o", str(bpf_object),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(f"clang CO-RE compilation failed: {result.stderr.strip()}")
        return bpf_object

    def _start_libbpf_loader(self) -> None:
        try:
            self._validate_environment()
            bpf_object = self._build_core_object()
            self._process = subprocess.Popen(
                [str(ROOT / "vista_libbpf_loader"), str(bpf_object)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            assert self._process.stdout is not None
            ready, _, _ = select.select([self._process.stdout], [], [], 15)
            if not ready:
                raise RuntimeError("libbpf loader did not report startup status within 15 seconds")

            first_line = self._process.stdout.readline()
            if not first_line:
                error_output = self._process.stderr.read() if self._process.stderr else ""
                raise RuntimeError(
                    f"libbpf loader exited without status (exit={self._process.poll()}): "
                    f"{error_output.strip() or 'no diagnostic output'}"
                )
            loader_status = json.loads(first_line)
            if loader_status.get("kind") != "status":
                raise RuntimeError(f"unexpected libbpf loader startup message: {first_line.strip()}")
            self._mode = loader_status.get("mode", "UNAVAILABLE")
            self._status = loader_status.get("status", "ERROR")
            self._error = loader_status.get("error")
            self._probe_status = loader_status.get("probes", self._probe_status)

            if self._mode != "NATIVE_KERNEL_EBPF":
                if self._process.poll() is None:
                    self._process.terminate()
                return

            threading.Thread(target=self._read_events, daemon=True).start()
            threading.Thread(target=self._read_stderr, daemon=True).start()
        except Exception as exc:
            self._error = str(exc)
            self._mode = "UNAVAILABLE"
            self._status = "ERROR"
            if self._process and self._process.poll() is None:
                self._process.terminate()

    def _read_events(self) -> None:
        if self._process is None or self._process.stdout is None:
            return
        try:
            for line in self._process.stdout:
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if message.get("kind") == "event":
                    self._append_event(message)
                elif message.get("kind") == "stats":
                    self._hook_hits = message.get("hookHits", {})
                    self._ring_reserve_failures = int(message.get("ringReserveFailures", 0))
                    self._ring_events_seen = int(message.get("ringEventsSeen", 0))
                    self._malformed_ring_events = int(message.get("malformedRingEvents", 0))
        finally:
            if self._process.poll() is not None:
                self._mode = "UNAVAILABLE"
                self._status = "ERROR"
                self._error = (
                    f"libbpf loader exited unexpectedly with code {self._process.returncode}"
                )
                for probe in self._probe_status:
                    probe["status"] = "DETACHED"

    def _read_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return
        for line in self._process.stderr:
            message = line.strip()
            if message:
                self._error = message

    def _append_event(self, event: dict[str, Any]) -> None:
        now_ns = int(event.get("timestamp_ns", 0))
        event_type = event.get("eventType", "UNKNOWN")
        timestamp = (
            datetime.fromtimestamp(now_ns / 1_000_000_000, tz=timezone.utc).isoformat()
            if now_ns
            else datetime.now(timezone.utc).isoformat()
        )
        pid = int(event.get("pid", 0))
        process_name = str(event.get("process_name", ""))
        event.update({
            "timestamp": timestamp,
            "fn": FUNCTION_MAP.get(event_type, "unknown()"),
            "target": f"PID {pid} ({process_name})",
            "spi": event.get("spi"),
            "seq": None,
            "bytes": event.get("bytes"),
            "flow_id": None,
            "socket_id": None,
        })
        with self._lock:
            self.events.append(event)

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            buffered = len(self.events)
        return {
            "status": self._status,
            "mode": self._mode,
            "probes": self._probe_status,
            "error": self._error,
            "btf": {
                "path": str(BTF_PATH),
                "available": BTF_PATH.is_file() and os.access(BTF_PATH, os.R_OK),
            },
            "bufferedEventsCount": buffered,
            "hookHits": self._hook_hits,
            "ringReserveFailures": self._ring_reserve_failures,
            "ringEventsSeen": self._ring_events_seen,
            "malformedRingEvents": self._malformed_ring_events,
            "transport": "LIBBPF_RING_BUFFER" if self._mode == "NATIVE_KERNEL_EBPF" else None,
            "ringBufferCapacityBytes": 1 << 20 if self._mode == "NATIVE_KERNEL_EBPF" else 0,
            "ringBufferDroppedEvents": self._ring_reserve_failures,
            "activeSpiCount": 0,
        }

    def get_events(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return select_recent_events(self.events, limit)


def make_handler(collector: KernelCollector) -> type[BaseHTTPRequestHandler]:
    class CollectorHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/status":
                payload = collector.get_status()
            elif parsed.path == "/events":
                try:
                    limit = int(parse_qs(parsed.query).get("limit", ["12"])[0])
                except ValueError:
                    self.send_error(400, "limit must be an integer")
                    return
                payload = {"events": collector.get_events(max(1, min(limit, 500)))}
            else:
                self.send_error(404)
                return

            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"[collector-api] {format % args}")

    return CollectorHandler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    collector = KernelCollector()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(collector))
    print(
        f"VISTA eBPF collector status={collector.get_status()['mode']} "
        f"listening on {args.host}:{args.port}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if collector._process and collector._process.poll() is None:
            collector._process.terminate()


if __name__ == "__main__":
    main()
