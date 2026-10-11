from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from backend.services.model_service import ModelService


class FakeClassifier:
    classes_ = np.asarray(["BENIGN", "DOS"])
    feature_names_in_ = np.asarray(["packet_count", "byte_count"])

    def __init__(self, label: str = "DOS") -> None:
        self.label = label
        self.calls = 0

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        self.calls += 1
        assert list(features.columns) == list(self.feature_names_in_)
        return np.asarray([self.label] * len(features))

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray([[0.2, 0.8]] * len(features))


class FakeIsolationForest:
    feature_names_in_ = np.asarray(["packet_count", "byte_count"])

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        assert list(features.columns) == list(self.feature_names_in_)
        return np.asarray([1, -1][:len(features)])

    def decision_function(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray([0.2, -0.1][:len(features)])


def configured_service(
    classifier: FakeClassifier | None,
    metadata: dict | None = None,
    xgboost: FakeClassifier | None = None,
) -> ModelService:
    service = ModelService.__new__(ModelService)
    service.traffic_model = None
    service.traffic_metadata = {}
    service.attack_model = classifier
    service.attack_metadata = metadata or {}
    service.xgb_model = xgboost
    service.xgb_metadata = {
        "prediction_task": "encrypted application traffic classification",
        "feature_columns": ["packet_count", "byte_count"],
        "validated_for_inference": True,
        "feature_schema_version": "vista-flow-v1",
    }
    service.iso_model = None
    service.iso_metadata = {}
    service.rf_model = None
    service.rf_metadata = {}
    service.load_errors = {}
    return service


VALID_ATTACK_METADATA = {
    "prediction_task": "flow attack detection and attribution",
    "feature_columns": ["packet_count", "byte_count"],
    "validated_for_inference": True,
    "feature_schema_version": "vista-flow-v1",
    "validation_status": "held_out_verified",
    "model_version": "test-1",
}


def test_missing_and_nonfinite_features_are_insufficient_data() -> None:
    service = configured_service(FakeClassifier(), VALID_ATTACK_METADATA)

    missing_column = service.predict(pd.DataFrame({"packet_count": [1]}), "attack_classifier")[0]
    assert missing_column["status"] == "insufficient_data"
    assert missing_column["missingFeatures"] == ["byte_count"]

    nonfinite_value = service.predict(
        pd.DataFrame({"byte_count": [20], "packet_count": [np.nan]}),
        "attack_classifier",
    )[0]
    assert nonfinite_value["status"] == "insufficient_data"
    assert nonfinite_value["missingFeatures"] == ["packet_count"]


def test_reordered_features_are_aligned_to_the_fitted_feature_order() -> None:
    model = FakeClassifier()
    service = configured_service(model, VALID_ATTACK_METADATA)

    result = service.predict(
        pd.DataFrame({"byte_count": [200], "packet_count": [4]}),
        "attack_classifier",
    )[0]

    assert result["status"] == "success"
    assert result["predictedClass"] == "DOS"
    assert result["isAttack"] == 1
    assert result["probability"] == 0.8
    assert result["modelVersion"] == "test-1"
    assert model.calls == 1


def test_unvalidated_artifact_does_not_produce_a_prediction() -> None:
    model = FakeClassifier()
    service = configured_service(model, {
        **VALID_ATTACK_METADATA,
        "validated_for_inference": False,
    })

    result = service.predict(
        pd.DataFrame({"packet_count": [4], "byte_count": [200]}),
        "attack_classifier",
    )[0]

    assert result["status"] == "unsupported_input"
    assert result["predictedClass"] is None
    assert result["probabilities"] is None
    assert model.calls == 0


def test_attack_model_never_falls_back_to_the_xgboost_traffic_artifact() -> None:
    service = configured_service(None, {}, xgboost=FakeClassifier(label="BENIGN"))

    with pytest.raises(RuntimeError, match="not loaded"):
        service.predict(
            pd.DataFrame({"packet_count": [4], "byte_count": [200]}),
            "attack_classifier",
        )


def test_traffic_predictions_do_not_claim_attack_semantics() -> None:
    traffic_model = FakeClassifier(label="DOS")
    traffic_model.classes_ = np.asarray(["BENIGN", "DOS"])
    service = configured_service(
        FakeClassifier(label="DOS"),
        VALID_ATTACK_METADATA,
        xgboost=traffic_model,
    )

    result = service.predict(
        pd.DataFrame({"packet_count": [4], "byte_count": [200]}),
        "xgboost",
    )[0]
    assert result["predictedClass"] == "DOS"
    assert result["isAttack"] is None


def test_threat_prediction_uses_only_the_dedicated_attack_artifact() -> None:
    attack_model = FakeClassifier(label="DOS")
    traffic_model = FakeClassifier(label="BENIGN")
    service = configured_service(attack_model, VALID_ATTACK_METADATA, traffic_model)

    result = service.predict_threat(
        pd.DataFrame({"packet_count": [4], "byte_count": [200]}),
        model_name="xgboost",
    )[0]
    assert result["predictedClass"] == "DOS"
    assert attack_model.calls == 1
    assert traffic_model.calls == 0


def test_isolation_forest_score_uses_negative_decision_function_as_outlier() -> None:
    service = configured_service(None)
    service.iso_model = FakeIsolationForest()
    service.iso_metadata = {
        "feature_columns": ["packet_count", "byte_count"],
        "validated_for_inference": True,
        "feature_schema_version": "vista-flow-v1",
        "score_convention": "decision_function; negative is outlier",
    }

    results = service.predict_anomaly(
        pd.DataFrame({"byte_count": [200, 300], "packet_count": [4, 5]})
    )
    assert [item["isAnomaly"] for item in results] == [False, True]
    assert [item["anomalyScore"] for item in results] == [0.2, -0.1]
    assert all(item["decisionThreshold"] == 0.0 for item in results)


def test_isolation_forest_without_threshold_provenance_is_not_used() -> None:
    service = configured_service(None)
    service.iso_model = FakeIsolationForest()
    service.iso_metadata = {
        "feature_columns": ["packet_count", "byte_count"],
        "validated_for_inference": True,
        "feature_schema_version": "vista-flow-v1",
    }

    result = service.predict_anomaly(
        pd.DataFrame({"packet_count": [4], "byte_count": [200]})
    )[0]
    assert result["status"] == "unsupported_input"
    assert result["isAnomaly"] is None
    assert result["anomalyScore"] is None
