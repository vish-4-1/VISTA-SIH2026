from __future__ import annotations

import pandas as pd


def check_group_leakage(train_df: pd.DataFrame, test_df: pd.DataFrame, group_col: str = "experiment_id") -> None:
    if group_col not in train_df.columns or group_col not in test_df.columns:
        raise ValueError(f"Leakage check requires the '{group_col}' column in both train and test data.")

    overlap = set(train_df[group_col].astype(str)) & set(test_df[group_col].astype(str))
    if overlap:
        raise ValueError(f"Data leakage detected: experiment overlap {sorted(list(overlap))[:10]}")

    return None
