from __future__ import annotations

import pandas as pd
import pytest

from vista_ml.data.adapters.iscxvpn2016_adapter import adapt_iscxvpn2016
from vista_ml.utils.artifacts import create_candidate_run_dirs


def test_adapter_uses_source_labels_without_fabricating_capture_metadata() -> None:
    source = pd.DataFrame(
        {
            "feature_a": [1.0, 2.0],
            "Label": ["VPN-CHAT", "CHAT"],
        }
    )
    adapted = adapt_iscxvpn2016(source)

    assert adapted["label"].tolist() == ["VPN-CHAT", "CHAT"]
    assert adapted["traffic_type"].tolist() == ["vpn", "nonvpn"]
    assert "experiment_id" not in adapted.columns
    assert "scenario_id" not in adapted.columns
    assert "attack_type" not in adapted.columns


def test_adapter_rejects_missing_source_labels() -> None:
    source = pd.DataFrame({"feature_a": [1.0, 2.0], "Label": ["CHAT", None]})
    with pytest.raises(ValueError, match="missing or empty labels"):
        adapt_iscxvpn2016(source)


def test_candidate_artifacts_use_new_nonproduction_paths(tmp_path) -> None:
    first_model_dir, first_report_dir = create_candidate_run_dirs(tmp_path, "unit-task")
    second_model_dir, second_report_dir = create_candidate_run_dirs(tmp_path, "unit-task")

    assert first_model_dir != second_model_dir
    assert first_report_dir != second_report_dir
    assert first_model_dir.is_dir()
    assert first_report_dir.is_dir()
    assert second_model_dir.is_dir()
    assert second_report_dir.is_dir()
    assert "candidates" in first_model_dir.parts
    assert "candidates" in first_report_dir.parts
