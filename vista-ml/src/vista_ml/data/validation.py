from __future__ import annotations

import pandas as pd

from vista_ml.data.schema import REQUIRED_COLUMNS, ALL_FEATURE_COLUMNS


def validate_row_count(df: pd.DataFrame) -> None:
    if df.empty:
        raise ValueError("Dataset is empty.")


def check_missing_required_columns(df: pd.DataFrame) -> list[str]:
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    return missing


def validate_flow_schema(df: pd.DataFrame) -> pd.DataFrame:
    validate_row_count(df)
    missing = check_missing_required_columns(df)
    if missing:
        raise ValueError(f"Missing required schema columns: {missing}")

    numeric_cols = [
        col for col in ALL_FEATURE_COLUMNS if col in df.columns
    ] + ["packet_count", "byte_count", "flow_duration", "direction_ratio"]
    for column in numeric_cols:
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce")
    return df


def validate_public_dataset(df: pd.DataFrame, label_column: str = "label") -> pd.DataFrame:
    if label_column not in df.columns:
        raise ValueError(f"Public dataset is missing label column: {label_column}")
    return validate_flow_schema(df)
