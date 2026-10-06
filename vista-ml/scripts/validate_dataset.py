from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vista_ml.data.loader import load_dataset


def main() -> None:
    sample_path = ROOT / "data" / "sample" / "synthetic_vista_dataset.parquet"
    if not sample_path.exists():
        raise FileNotFoundError(f"Synthetic dataset missing: {sample_path}. Run scripts/generate_sample_dataset.py first.")
    df = load_dataset(sample_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Experiment count: {df['experiment_id'].nunique()}")
    print(f"Label distribution:\n{df['label'].value_counts().to_string()}")


if __name__ == "__main__":
    main()
