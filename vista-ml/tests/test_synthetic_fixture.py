from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from vista_ml.datasets.synthetic_fixture import (
    generate_fixture_rows,
    validate_fixture_artifacts,
    validate_fixture_frame,
    write_synthetic_fixture,
)


def test_seed_and_configuration_produce_deterministic_rows():
    left = generate_fixture_rows(26160, {"ICMP": 3, "PORT_SCAN": 3})
    right = generate_fixture_rows(26160, {"PORT_SCAN": 3, "ICMP": 3})
    pd.testing.assert_frame_equal(left, right)


def test_fixture_schema_relationships_and_class_counts_are_valid():
    frame = generate_fixture_rows(7, {"VoIP": 2, "PORT_SCAN": 2})
    validate_fixture_frame(frame)
    assert set(frame["label"]) == {"VoIP", "PORT_SCAN"}
    assert set(frame["origin_type"]) == {"synthetic_fixture"}
    assert (frame["forward_packet_count"] + frame["backward_packet_count"] == frame["packet_count"]).all()
    assert (frame["forward_bytes"] + frame["backward_bytes"] == frame["byte_count"]).all()


@pytest.mark.parametrize(
    "seed,counts",
    [
        (True, {"ICMP": 1}),
        (-1, {"ICMP": 1}),
        (1, {}),
        (1, {"OUTSIDE": 1}),
        (1, {"ICMP": 0}),
        (1, {"ICMP": True}),
        (1, {"ICMP": 10001}),
    ],
)
def test_invalid_fixture_parameters_are_rejected(seed, counts):
    with pytest.raises(ValueError):
        generate_fixture_rows(seed, counts)


def test_missing_and_infinite_features_are_rejected():
    frame = generate_fixture_rows(1, {"ICMP": 2})
    frame.loc[0, "flow_duration"] = np.inf
    with pytest.raises(ValueError, match="non-finite"):
        validate_fixture_frame(frame)

    frame = generate_fixture_rows(1, {"ICMP": 2})
    frame.loc[0, "packet_count"] = np.nan
    with pytest.raises(ValueError, match="missing or non-finite"):
        validate_fixture_frame(frame)


@pytest.mark.parametrize("column", ["experiment_id", "scenario_id", "flow_id"])
def test_duplicate_identifiers_are_rejected(column):
    frame = generate_fixture_rows(5, {"ICMP": 2})
    frame.loc[1, column] = frame.loc[0, column]
    with pytest.raises(ValueError, match="duplicate identifiers"):
        validate_fixture_frame(frame)


def test_inconsistent_session_spi_and_timestamps_are_rejected():
    frame = generate_fixture_rows(8, {"ICMP": 2})
    frame.loc[1, "session_id"] = frame.loc[0, "session_id"]
    with pytest.raises(ValueError, match="inconsistent SPI"):
        validate_fixture_frame(frame)

    frame = generate_fixture_rows(8, {"ICMP": 1})
    frame.loc[0, "timestamp_end"] = frame.loc[0, "timestamp_start"]
    with pytest.raises(ValueError, match="timestamps"):
        validate_fixture_frame(frame)


def test_manifest_hashes_origin_and_no_overwrite(tmp_path):
    output = tmp_path / "fixture"
    manifest = write_synthetic_fixture(
        output, seed=26160, class_counts={"ICMP": 2, "PORT_SCAN": 2}
    )
    assert manifest["originType"] == "synthetic_fixture"
    assert manifest["admissionStatus"] == "SYNTHETIC_FIXTURE"
    report = validate_fixture_artifacts(output / "dataset_manifest.json")
    assert report["status"] == "SYNTHETIC_FIXTURE"
    with pytest.raises(FileExistsError):
        write_synthetic_fixture(
            output, seed=26160, class_counts={"ICMP": 2, "PORT_SCAN": 2}
        )

    data_path = output / "flows.csv"
    data_path.write_text(data_path.read_text(encoding="utf-8") + "", encoding="utf-8")
    data_path.write_text(data_path.read_text(encoding="utf-8").replace("synthetic_fixture", "testbed_collected", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        validate_fixture_artifacts(output / "dataset_manifest.json")


def test_synthetic_and_collected_rows_cannot_be_mixed():
    frame = generate_fixture_rows(9, {"ICMP": 2})
    frame.loc[0, "origin_type"] = "testbed_collected"
    with pytest.raises(ValueError, match="origin_type"):
        validate_fixture_frame(frame)


def test_fixture_manifest_json_is_versioned(tmp_path):
    output = tmp_path / "fixture"
    write_synthetic_fixture(output, seed=11, class_counts={"ICMP": 1})
    manifest = json.loads((output / "dataset_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schemaVersion"] == "vista-synthetic-flow-fixture-v1"
    assert "no network traffic was generated" in manifest["labelSemantics"]
