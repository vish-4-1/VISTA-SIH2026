from __future__ import annotations

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


def experiment_aware_split(
    df: pd.DataFrame,
    group_col: str = "experiment_id",
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if group_col not in df.columns:
        raise ValueError(f"Grouping column '{group_col}' not found in dataset.")
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(df, groups=df[group_col]))
    return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()


def scenario_aware_split(
    df: pd.DataFrame,
    group_col: str = "experiment_id",
    target_col: str = "label",
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if df.empty:
        raise ValueError("Dataset is empty.")
    if group_col not in df.columns:
        raise ValueError(f"Grouping column '{group_col}' not found in dataset.")
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataset.")

    grouped = df.groupby(group_col)[target_col].agg(lambda s: s.mode().iloc[0])
    unique_experiments = grouped.index.tolist()
    if len(unique_experiments) < 2:
        raise ValueError("At least two experiments are required for a split.")
    train_experiments, test_experiments = experiment_aware_split(
        pd.DataFrame({group_col: unique_experiments}),
        group_col=group_col,
        test_size=test_size,
        random_state=random_state,
    )
    train_experiments = train_experiments[group_col].tolist()
    test_experiments = test_experiments[group_col].tolist()
    train_df = df[df[group_col].isin(train_experiments)].copy()
    test_df = df[df[group_col].isin(test_experiments)].copy()
    return train_df, test_df


def check_group_leakage(train_df: pd.DataFrame, test_df: pd.DataFrame, group_col: str = "experiment_id") -> None:
    if group_col not in train_df.columns or group_col not in test_df.columns:
        raise ValueError(f"Grouping column '{group_col}' not found in train/test data.")
    train_groups = set(train_df[group_col].astype(str))
    test_groups = set(test_df[group_col].astype(str))
    overlap = train_groups & test_groups
    if overlap:
        raise ValueError(f"Experiment leakage detected: {sorted(list(overlap))[:10]}")
