from __future__ import annotations

import json
from pathlib import Path

from vista_ml.data.schema import ALL_FEATURE_COLUMNS


ROOT = Path(__file__).resolve().parents[1]


def test_historical_and_runtime_feature_contracts_are_distinct_and_ordered() -> None:
    historical_schema = json.loads(
        (ROOT / "schemas" / "vista-testbed-extractor-v1.json").read_text(encoding="utf-8")
    )
    assert historical_schema["schema_version"] == "vista-testbed-extractor-v1"
    assert historical_schema["runtime_compatible"] is False

    runtime_schema = json.loads(
        (ROOT / "schemas" / "vista-flow-v1.json").read_text(encoding="utf-8")
    )
    feature_names = [feature["name"] for feature in runtime_schema["features"]]
    assert runtime_schema["schema_version"] == "vista-flow-v1"
    assert runtime_schema["runtime_feature_compatible"] is True
    assert feature_names == ALL_FEATURE_COLUMNS[:18]
    assert [feature["order"] for feature in runtime_schema["features"]] == list(range(18))
    assert len(feature_names) == len(set(feature_names))
    assert all(
        {"type", "units", "definition", "aggregation"} <= set(feature)
        for feature in runtime_schema["features"]
    )
    assert "Reject" in runtime_schema["missing_value_policy"]
