from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.datasets.generator import generate_sample_dataset


def main() -> None:
    output_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    df = generate_sample_dataset(output_path=output_path, n_experiments=50, flows_per_experiment=15, seed=42)
    print(f"Generated synthetic dataset at {output_path}")
    print(f"Rows={len(df)}, columns={len(df.columns)}")


if __name__ == "__main__":
    main()
