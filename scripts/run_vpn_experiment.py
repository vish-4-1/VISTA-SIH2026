#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.vpn_testbed import run_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate, apply, and verify a StrongSwan VPN experiment configuration.")
    parser.add_argument("--mode", default="tunnel", choices=["tunnel", "transport"])
    parser.add_argument(
        "--cipher",
        default="aes256gcm16",
        choices=["aes128", "aes256", "aes128gcm", "aes256gcm", "aes128gcm16", "aes256gcm16"],
    )
    parser.add_argument("--dh-group", type=int, default=14)
    parser.add_argument("--pfs", action="store_true", default=True)
    parser.add_argument("--no-pfs", dest="pfs", action="store_false")
    parser.add_argument("--ip-version", default="IPv4", choices=["IPv4", "IPv6"])
    parser.add_argument(
        "--traffic-type",
        default="icmpv4",
        choices=["icmpv4", "icmpv6", "udp_rtp", "http", "https", "smtp", "video", "whatsapp"],
    )
    args = parser.parse_args()

    payload = {
        "mode": args.mode,
        "cipher": args.cipher,
        "dhGroup": args.dh_group,
        "pfs": args.pfs,
        "ipVersion": args.ip_version,
        "trafficType": args.traffic_type,
    }
    result = run_experiment(payload)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
