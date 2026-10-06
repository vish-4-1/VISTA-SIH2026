from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from vista_ml.data.schema import validate_dataset


SUPPORTED_EXTENSIONS = {".csv", ".json", ".parquet", ".pq"}


def load_dataset(path: str | Path | pd.DataFrame) -> pd.DataFrame:
    if isinstance(path, pd.DataFrame):
        return validate_dataset(path.copy())

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        df = pd.read_csv(file_path)
    elif suffix in {".parquet", ".pq"}:
        df = pd.read_parquet(file_path)
    elif suffix == ".json":
        df = pd.read_json(file_path)
    else:
        raise ValueError(f"Unsupported dataset format: {suffix}. Use CSV, JSON, or Parquet.")

    return validate_dataset(df)


def load_dataset_config(path: str | Path) -> dict[str, Any]:
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}
