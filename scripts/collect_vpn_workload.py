#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.workload_collection import (
    collect_http_workload,
    collect_icmp_workload,
    collect_tcp_marker_workload,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect a bounded, live ICMPv4/TCP/HTTP testbed workload with PCAP and independent receiver evidence."
    )
    parser.add_argument(
        "--profiles",
        required=True,
        help='JSON array, e.g. \'[{"count":5,"interval_seconds":0.2,"payload_bytes":64}]\'',
    )
    parser.add_argument(
        "--workload",
        default="icmpv4",
        choices=["icmpv4", "tcp_marker", "http"],
        help="Use count as echo packets for icmpv4, marker messages for tcp_marker, or requests for http.",
    )
    parser.add_argument("--experiment-id", help="Optional opaque UUIDv4; generated when omitted.")
    parser.add_argument("--session-id", help="Optional opaque UUIDv4 shared by a collection session.")
    args = parser.parse_args()
    try:
        profiles = json.loads(args.profiles)
    except json.JSONDecodeError as exc:
        parser.error(f"--profiles is not valid JSON: {exc}")
    configuration = {"profiles": profiles}
    if args.experiment_id:
        configuration["experimentId"] = args.experiment_id
    if args.session_id:
        configuration["sessionId"] = args.session_id
    if args.workload == "http":
        collector = collect_http_workload
    elif args.workload == "tcp_marker":
        collector = collect_tcp_marker_workload
    else:
        collector = collect_icmp_workload

    result = collector(configuration)
    print(json.dumps(result, indent=2))
    if result.get("status") != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
