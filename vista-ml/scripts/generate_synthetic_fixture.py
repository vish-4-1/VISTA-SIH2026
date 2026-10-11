from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.datasets.synthetic_fixture import write_synthetic_fixture  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a clearly synthetic, deterministic software-test fixture."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=26160)
    parser.add_argument(
        "--class-counts",
        type=json.loads,
        default={"ICMP": 4, "PORT_SCAN": 4},
        help='JSON mapping, e.g. {"ICMP":4,"PORT_SCAN":4}; class names are case-sensitive.',
    )
    args = parser.parse_args()
    manifest = write_synthetic_fixture(
        args.output_dir, seed=args.seed, class_counts=args.class_counts
    )
    print(json.dumps({
        "status": manifest["admissionStatus"],
        "originType": manifest["originType"],
        "rowCount": manifest["rowCount"],
        "datasetManifest": str(args.output_dir / "dataset_manifest.json"),
    }, indent=2))


if __name__ == "__main__":
    main()
