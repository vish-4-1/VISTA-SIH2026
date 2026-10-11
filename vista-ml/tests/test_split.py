from __future__ import annotations

import pandas as pd

import pytest

from vista_ml.datasets.splitter import (
    check_group_leakage,
    experiment_aware_split,
    grouped_train_validation_test_split,
)


def test_experiment_aware_split_keeps_groups_separate() -> None:
    df = pd.DataFrame(
        {
            "experiment_id": ["exp1", "exp1", "exp2", "exp2", "exp3", "exp3"],
            "label": ["NORMAL", "NORMAL", "PORT_SCAN", "PORT_SCAN", "DOS", "DOS"],
            "feature_a": [1, 2, 3, 4, 5, 6],
        }
    )
    train_df, test_df = experiment_aware_split(df, test_size=0.33, random_state=42)
    assert not set(train_df["experiment_id"]) & set(test_df["experiment_id"])
    check_group_leakage(train_df, test_df)


def test_three_way_grouped_split_keeps_capture_groups_separate() -> None:
    df = pd.DataFrame(
        [
            {"capture_id": f"capture-{group}", "label": label, "feature": group + row}
            for group in range(20)
            for row, label in enumerate(("APP_A", "APP_B"))
        ]
    )
    train, validation, test = grouped_train_validation_test_split(
        df, "capture_id", "label", random_state=7
    )
    group_sets = [set(part["capture_id"]) for part in (train, validation, test)]
    assert not group_sets[0] & group_sets[1]
    assert not group_sets[0] & group_sets[2]
    assert not group_sets[1] & group_sets[2]
    assert all(set(part["label"]) == {"APP_A", "APP_B"} for part in (train, validation, test))


def test_three_way_grouped_split_rejects_explicit_row_identifiers() -> None:
    df = pd.DataFrame(
        {"row_id": range(12), "label": ["A", "B"] * 6, "feature": range(12)}
    )
    with pytest.raises(ValueError, match="row identifier"):
        grouped_train_validation_test_split(df, "row_id", "label")


def test_three_way_grouped_split_accepts_one_record_per_real_capture() -> None:
    df = pd.DataFrame(
        [
            {"capture_id": f"capture-{index}", "label": "A" if index % 2 else "B", "feature": index}
            for index in range(20)
        ]
    )
    train, validation, test = grouped_train_validation_test_split(
        df, "capture_id", "label", random_state=11
    )
    group_sets = [set(part["capture_id"]) for part in (train, validation, test)]
    assert not group_sets[0] & group_sets[1]
    assert not group_sets[0] & group_sets[2]
    assert not group_sets[1] & group_sets[2]


def test_three_way_grouped_split_requires_independent_groups() -> None:
    df = pd.DataFrame(
        {"capture_id": ["same"] * 10, "label": ["A", "B"] * 5, "feature": range(10)}
    )
    with pytest.raises(ValueError, match="At least three independent groups"):
        grouped_train_validation_test_split(df, "capture_id", "label")
