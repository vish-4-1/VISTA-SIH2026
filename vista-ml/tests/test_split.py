from __future__ import annotations

import pandas as pd

from vista_ml.datasets.splitter import check_group_leakage, experiment_aware_split


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
