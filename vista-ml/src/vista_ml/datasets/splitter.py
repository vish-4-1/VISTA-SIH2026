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


def grouped_train_validation_test_split(
    df: pd.DataFrame,
    group_col: str,
    target_col: str,
    validation_size: float = 0.2,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if df.empty:
        raise ValueError("Dataset is empty.")
    if group_col not in df.columns or target_col not in df.columns:
        raise ValueError(f"Dataset must include grouping column {group_col!r} and target {target_col!r}.")
    if df[group_col].isna().any():
        raise ValueError(f"Grouping column {group_col!r} contains missing values.")
    if df[group_col].nunique() < 3:
        raise ValueError("At least three independent groups are required for train/validation/test splits.")
    if not 0 < validation_size < 1 or not 0 < test_size < 1 or validation_size + test_size >= 1:
        raise ValueError("Validation and test fractions must be positive and sum to less than one.")

    groups = df[group_col].astype(str)
    if group_col.lower() in {"row_id", "row_number", "index"}:
        raise ValueError(
            f"Grouping column {group_col!r} is a row identifier, not an independent capture/session group."
        )
    if groups.nunique() < 5:
        raise ValueError("At least five independent groups are required for the requested three-way split.")

    outer = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_validation_idx, test_idx = next(outer.split(df, groups=groups))
    train_validation = df.iloc[train_validation_idx]
    relative_validation_size = validation_size / (1.0 - test_size)
    inner = GroupShuffleSplit(
        n_splits=1,
        test_size=relative_validation_size,
        random_state=random_state + 1,
    )
    train_idx, validation_idx = next(
        inner.split(train_validation, groups=groups.iloc[train_validation_idx])
    )
    train = train_validation.iloc[train_idx].copy()
    validation = train_validation.iloc[validation_idx].copy()
    test = df.iloc[test_idx].copy()

    train_groups = set(train[group_col].astype(str))
    validation_groups = set(validation[group_col].astype(str))
    test_groups = set(test[group_col].astype(str))
    if (
        train_groups & validation_groups
        or train_groups & test_groups
        or validation_groups & test_groups
    ):
        raise ValueError("Group leakage detected across train, validation, and test splits.")
    return train, validation, test


def check_group_leakage(train_df: pd.DataFrame, test_df: pd.DataFrame, group_col: str = "experiment_id") -> None:
    if group_col not in train_df.columns or group_col not in test_df.columns:
        raise ValueError(f"Grouping column '{group_col}' not found in train/test data.")
    train_groups = set(train_df[group_col].astype(str))
    test_groups = set(test_df[group_col].astype(str))
    overlap = train_groups & test_groups
    if overlap:
        raise ValueError(f"Experiment leakage detected: {sorted(list(overlap))[:10]}")
