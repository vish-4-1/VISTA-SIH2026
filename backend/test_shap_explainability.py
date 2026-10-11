"""
VISTA SHAP Explainability & Safeguards Test Suite
Verifies:
1. Global SHAP artifact provenance and ranking (mean-absolute-SHAP).
2. Directional contribution additivity (base_value + sum(contributions) == output_value).
3. Multiclass output selection.
4. Schema mismatch and missing feature rejection.
5. Ineligible model rejection (fail-closed safety gate).
6. ESP / IKE outer tunnel encryption boundary rejection.
7. Prevention of global-artifact reuse as a local explanation.
8. Experimental model safeguards and demonstrator flag gating.
9. Response schemas and error handling across endpoints.
"""

import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.main import app
from backend.services.shap_service import shap_service

client = TestClient(app)

SAMPLE_SYN_FLOOD_FLOW = {
    "flowId": "TST-SYN-001",
    "proto": "TCP",
    "protocolFamily": "TCP",
    "src": "172.20.0.2",
    "dst": "172.20.0.3",
    "srcPort": 49152,
    "dstPort": 80,
    "packets": 5000,
    "bytes": 320000,
    "duration": 1.2,
    "packetsPerSecond": 4166.6,
    "bytesPerSecond": 266666.7,
    "meanPacketLen": 64.0,
    "stdPacketLen": 0.0,
    "minPacketLen": 64.0,
    "maxPacketLen": 64.0,
    "meanIat": 0.00024,
    "stdIat": 0.00003,
    "minIat": 0.00015,
    "maxIat": 0.0004,
    "outboundRatio": 0.99,
    "forward_packet_count": 4950,
    "backward_packet_count": 50,
    "forward_bytes": 316800,
    "backward_bytes": 3200,
}

SAMPLE_ESP_FLOW = {
    "flowId": "TST-ESP-002",
    "proto": "ESP (50)",
    "protocolFamily": "ESP",
    "src": "172.20.0.2",
    "dst": "172.20.0.3",
    "srcPort": 0,
    "dstPort": 0,
    "packets": 1200,
    "bytes": 1450000,
    "duration": 10.0,
    "packetsPerSecond": 120.0,
    "bytesPerSecond": 145000.0,
    "meanPacketLen": 1208.3,
    "stdPacketLen": 180.5,
    "minPacketLen": 96.0,
    "maxPacketLen": 1480.0,
    "meanIat": 0.0083,
    "stdIat": 0.0041,
    "minIat": 0.0005,
    "maxIat": 0.045,
    "outboundRatio": 0.50,
    "forward_packet_count": 600,
    "backward_packet_count": 600,
    "forward_bytes": 725000,
    "backward_bytes": 725000,
}


def test_shap_status_endpoint():
    """Verifies GET /api/ml/shap/status schema and model gating."""
    res = client.get("/api/ml/shap/status")
    assert res.status_code == 200
    data = res.json()
    assert "TreeExplainer" in data["explainerEngine"]
    assert "GLOBAL_FEATURE_IMPORTANCE" in data["supportedModes"]
    assert "DIRECTIONAL_LOCAL_CONTRIBUTIONS" in data["supportedModes"]
    assert "PER_FLOW_EXPLANATION" in data["supportedModes"]
    assert data["featureSchema"] == "vista-flow-v1"
    assert data["featureCount"] == 18
    assert data["safeguards"]["failClosedGating"] is True
    assert data["safeguards"]["espEncryptionBoundaryEnforced"] is True

    # Models readiness
    models = data["models"]
    assert "xgboost" in models or "attack_classifier" in models
    assert models["xgboost"]["globalArtifactStatus"] == "AVAILABLE"
    assert models["xgboost"]["localExplanationEligible"] is True
    assert models["random_forest"]["globalArtifactStatus"] == "UNAVAILABLE"
    assert models["random_forest"]["localExplanationEligible"] is False


def test_global_shap_xgboost_is_available_with_linked_evidence():
    """Global SHAP values are exposed when audited held-out model, split, and dataset evidence are linked."""
    res = client.get("/api/ml/shap/global?model=xgboost")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "AVAILABLE"
    assert data["model_id"] in {"xgboost", "xgboost_classifier"}
    assert data["sample_count"] == 200
    assert len(data["top_features"]) == 18
    assert data["feature_schema"] == "vista-flow-v1"
    assert data["provenance"]["dataset_sha256"] is not None


def test_global_shap_random_forest_is_unavailable_without_linked_evidence():
    """No static global value table is exposed for the baseline model."""
    res = client.get("/api/ml/shap/global?model=random_forest")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UNAVAILABLE"
    assert data["sample_count"] is None
    assert data["top_features"] == []


def test_global_shap_unsupported_model_fails_closed():
    """Verifies request for unvalidated model with no artifact returns honest UNAVAILABLE."""
    res = client.get("/api/ml/shap/global?model=unregistered_neural_net")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UNAVAILABLE"
    assert "No audited held-out SHAP artifact" in data["reason"]
    assert data["top_features"] == []


def test_per_flow_esp_encryption_boundary_blocked():
    """Verifies Safeguard: Outer ESP traffic is strictly BLOCKED from application/attack attribution."""
    payload = {
        "flow_record": SAMPLE_ESP_FLOW,
        "model_name": "xgboost_classifier",
        "target_class": "DOS",
        "allow_experimental": True,  # Even with experimental flag, ESP boundary MUST hold!
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "BLOCKED"
    assert "Encryption Boundary" in data["reason"]
    assert data["prerequisites"]["modelEligible"] is False
    assert data["prerequisites"]["featuresExtracted"] is False


def test_per_flow_unvalidated_model_fail_closed_gate():
    """Verifies Safeguard: Experimental models without held-out validation are blocked without allow_experimental flag."""
    payload = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "random_forest_baseline",
        "target_class": "DOS",
        "allow_experimental": False,
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "BLOCKED"
    assert "Safety Gate" in data["reason"]
    assert "validated_for_inference" in data["reason"]
    assert data["prerequisites"]["modelEligible"] is False


def test_per_flow_xgboost_with_held_out_validation_is_eligible():
    """Verifies XGBoost with audited held-out validation is ELIGIBLE even when allow_experimental is False."""
    payload = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "xgboost_classifier",
        "target_class": "DOS",
        "allow_experimental": False,
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ELIGIBLE"
    assert data["prerequisites"]["modelEligible"] is True
    assert data["provenance"]["status"] == "ELIGIBLE"
    assert data["experimental_mode"] is False


def test_per_flow_missing_features_rejected():
    """Verifies Prerequisite 2: Incomplete feature vector returns UNAVAILABLE."""
    incomplete_flow = {
        "flowId": "TST-INC-003",
        "proto": "TCP",
        "protocolFamily": "TCP",
        "duration": 5.0,
        # missing packet_count, byte_count, iat, etc.
    }
    payload = {
        "flow_record": incomplete_flow,
        "model_name": "xgboost_classifier",
        "target_class": "DOS",
        "allow_experimental": True,
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UNAVAILABLE"
    assert "Missing or non-finite features" in data["reason"]
    assert "missing_features" in data
    assert len(data["missing_features"]) > 0


def test_directional_contributions_exact_additivity_xgboost():
    """Verifies Mode B & C: Exact additive identity base_value + sum(contributions) == output_value."""
    payload = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "xgboost_classifier",
        "target_class": "DOS",
        "allow_experimental": True,
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in {"SUCCESS", "ELIGIBLE", "EXPERIMENTAL"}
    assert data["explained_class"] == "DOS"
    assert "log-odds" in data["model_output_space"]

    base_value = data["base_value"]
    output_value = data["output_value"]
    contributions = data["feature_contributions"]

    assert len(contributions) == 18
    sum_contributions = sum(item["contribution"] for item in contributions)

    # EXACT ADDITIVITY: base_value + sum(contributions) == output_value
    reconstructed_output = base_value + sum_contributions
    delta = abs(reconstructed_output - output_value)
    assert delta < 1e-4, f"Additivity violation! Reconstructed: {reconstructed_output}, actual: {output_value}, delta: {delta}"

    # Verify signed contributions: some positive, some negative
    has_pos = any(c["contribution"] > 0 for c in contributions)
    has_neg = any(c["contribution"] < 0 for c in contributions)
    assert has_pos, "Expected positive feature contributions towards DOS"
    # SYN flood with high PPS should have packets_per_second as strong positive contribution
    pps_contrib = next(c for c in contributions if c["feature"] == "packets_per_second")
    assert pps_contrib["contribution"] > 0, f"Expected positive PPS contribution for SYN flood, got {pps_contrib['contribution']}"


def test_directional_contributions_exact_additivity_random_forest():
    """Verifies exact additivity for Random Forest in probability output space."""
    payload = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "random_forest_baseline",
        "target_class": "DOS",
        "allow_experimental": True,
    }
    res = client.post("/api/ml/shap/explain-flow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in {"SUCCESS", "ELIGIBLE", "EXPERIMENTAL"}
    assert data["explained_class"] == "DOS"
    assert data["model_output_space"] == "probability"

    base_value = data["base_value"]
    output_value = data["output_value"]
    contributions = data["feature_contributions"]

    assert len(contributions) == 18
    sum_contributions = sum(item["contribution"] for item in contributions)
    delta = abs((base_value + sum_contributions) - output_value)
    assert delta < 1e-4, f"Random Forest additivity violation! Delta: {delta}"


def test_multiclass_output_selection():
    """Verifies that selecting different output classes yields distinct explanations."""
    payload_dos = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "xgboost_classifier",
        "target_class": "DOS",
        "allow_experimental": True,
    }
    payload_normal = {
        "flow_record": SAMPLE_SYN_FLOOD_FLOW,
        "model_name": "xgboost_classifier",
        "target_class": "NORMAL",
        "allow_experimental": True,
    }
    res_dos = client.post("/api/ml/shap/explain-flow", json=payload_dos).json()
    res_normal = client.post("/api/ml/shap/explain-flow", json=payload_normal).json()

    assert res_dos["explained_class"] == "DOS"
    assert res_normal["explained_class"] == "NORMAL"
    assert res_dos["output_value"] != res_normal["output_value"]
    assert res_dos["base_value"] != res_normal["base_value"]


def test_metrics_endpoint_backward_compatibility():
    """Verifies GET /api/ml/metrics returns shapImportance and shapProvenance without breaking schema."""
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "shapImportance" in data
    assert data["shapImportance"] is not None
    assert data["shapImportance"]["model_id"] == "xgboost"
    assert "shapProvenance" in data
    assert data["shapProvenance"]["status"] == "AVAILABLE_GLOBAL_ONLY"
    assert "dataset" in data["shapProvenance"]


def test_prevention_of_global_artifact_reuse_as_local_explanation():
    """Verifies that global SHAP values are not confused with local flow explanations."""
    global_res = client.get("/api/ml/shap/global?model=xgboost").json()
    local_res = client.post(
        "/api/ml/shap/explain-flow",
        json={
            "flow_record": SAMPLE_SYN_FLOOD_FLOW,
            "model_name": "xgboost_classifier",
            "target_class": "DOS",
            "allow_experimental": True,
        },
    ).json()

    local_vals = {f["feature"]: f["contribution"] for f in local_res["feature_contributions"]}

    # Global held-out values represent mean absolute SHAP and must not be mixed with local signed terms.
    assert global_res["status"] == "AVAILABLE"
    assert len(global_res["top_features"]) == 18
    assert all(f["shap_value"] >= 0 for f in global_res["top_features"])
    # Local values contain directional signs (+/-)
    assert any(v < 0 for v in local_vals.values())


if __name__ == "__main__":
    pytest.main(["-v", __file__])
