import json
import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.services import workload_collection


def test_rtp_profile_validation_accepts_valid():
    valid = [
        {"count": 10, "interval_seconds": 0.02, "payload_bytes": 160, "ssrc": 0x12345678, "payload_type": 0, "start_sequence": 1000},
        {"count": 20, "interval_seconds": 0.04, "payload_bytes": 320, "ssrc": 0x87654321, "payload_type": 8, "start_sequence": 2000},
    ]
    res = workload_collection.validate_rtp_profiles(valid)
    assert len(res) == 2
    assert res[0]["count"] == 10
    assert res[0]["interval_seconds"] == 0.02
    assert res[0]["payload_bytes"] == 160
    assert res[1]["payload_type"] == 8


@pytest.mark.parametrize(
    "invalid_profile",
    [
        {"count": 0, "interval_seconds": 0.02, "payload_bytes": 160},
        {"count": 10, "interval_seconds": 0.001, "payload_bytes": 160},
        {"count": 10, "interval_seconds": 0.02, "payload_bytes": 1500},
        {"count": 10, "interval_seconds": 0.02, "payload_bytes": 160, "ssrc": -1},
        {"count": 10, "interval_seconds": 0.02, "payload_bytes": 160, "payload_type": 128},
        {"count": 10, "interval_seconds": 0.02, "payload_bytes": 160, "start_sequence": 70000},
        {"count": True, "interval_seconds": 0.02, "payload_bytes": 160},
    ]
)
def test_rtp_profile_validation_rejects_invalid(invalid_profile):
    with pytest.raises(ValueError):
        workload_collection.validate_rtp_profiles([invalid_profile])


def test_manifest_v2_schema_accepts_rtp_voip():
    schema_path = Path("vista-ml/schemas/strongswan-experiment-manifest-v2.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    workload_type_enum = schema["$defs"]["observation"]["properties"]["workload"]["properties"]["type"]["enum"]
    assert "rtp_voip" in workload_type_enum
    assert "icmpv4_echo" in workload_type_enum
    assert "tcp_marker" in workload_type_enum
    assert "http_traffic" in workload_type_enum


def test_target_label_schema_v2_definition():
    schema_path = Path("vista-ml/schemas/vista-target-label-schema-v2.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert "controlled_rtp_voip" in schema["target_classes"]
    assert schema["workload_subtype_mapping"]["rtp_voip"] == "controlled_rtp_voip"


def test_phase13_report_content_and_verdicts():
    report_path = Path("vista-ml/reports/phase13_workload_coverage_report.json")
    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))

    assert data["schema_version"] == "vista-phase13-workload-coverage-v1"
    matrix = data["workload_feasibility_matrix"]
    assert matrix["controlled_icmpv4"]["decision"] == "COLLECTED_AND_VALIDATED"
    assert matrix["controlled_tcp_marker"]["decision"] == "COLLECTED_AND_VALIDATED"
    assert matrix["controlled_http"]["decision"] == "COLLECTED_AND_VALIDATED"
    assert matrix["controlled_rtp_voip"]["decision"] == "COLLECTED_AND_VALIDATED"
    assert matrix["controlled_smtp"]["decision"] == "IMPLEMENTED_NOT_VALIDATED"
    assert matrix["controlled_video_streaming"]["decision"] == "BLOCKED"
    assert matrix["ipv6_traffic"]["decision"] == "BLOCKED"

    ood = data["frozen_model_ood_evaluation"]
    assert ood["sample_count"] == 15
    assert ood["classification_error_rate"] == 1.0
    assert ood["prediction_distribution"]["controlled_http"] == 15

    safeguards = data["safeguards_preserved"]
    assert safeguards["validated_for_inference"] is False
    assert safeguards["production_eligible"] is False
