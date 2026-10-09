"""
VISTA ML Model Service
Loads checked-in VISTA models and performs schema-checked inference.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT_DIR / "vista-ml" / "models"
VISTA_ML_SRC = ROOT_DIR / "vista-ml" / "src"
if str(VISTA_ML_SRC) not in sys.path and VISTA_ML_SRC.exists():
    sys.path.insert(0, str(VISTA_ML_SRC))

logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "mean_inter_arrival_time",
    "std_inter_arrival_time",
    "min_inter_arrival_time",
    "max_inter_arrival_time",
    "packets_per_second",
    "bytes_per_second",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "direction_ratio",
]

CANONICAL_FEATURE_SCHEMA: List[Dict[str, Any]] = [
    {
        "name": "packet_count",
        "group": "NETWORK_BASIC",
        "type": "integer",
        "unit": "packets",
        "description": "Total observed packets in the bidirectional flow",
    },
    {
        "name": "byte_count",
        "group": "NETWORK_BASIC",
        "type": "integer",
        "unit": "bytes",
        "description": "Total observed payload and header bytes in the flow",
    },
    {
        "name": "flow_duration",
        "group": "NETWORK_BASIC",
        "type": "float",
        "unit": "seconds",
        "description": "Total elapsed duration from first to last packet in the flow",
    },
    {
        "name": "mean_packet_size",
        "group": "PACKET_SIZE",
        "type": "float",
        "unit": "bytes",
        "description": "Arithmetic mean of all packet lengths in the flow",
    },
    {
        "name": "std_packet_size",
        "group": "PACKET_SIZE",
        "type": "float",
        "unit": "bytes",
        "description": "Standard deviation of packet lengths in the flow",
    },
    {
        "name": "min_packet_size",
        "group": "PACKET_SIZE",
        "type": "float",
        "unit": "bytes",
        "description": "Minimum observed packet length in the flow",
    },
    {
        "name": "max_packet_size",
        "group": "PACKET_SIZE",
        "type": "float",
        "unit": "bytes",
        "description": "Maximum observed packet length in the flow",
    },
    {
        "name": "mean_inter_arrival_time",
        "group": "TIMING",
        "type": "float",
        "unit": "seconds",
        "description": "Mean time delta between consecutive packets (IAT)",
    },
    {
        "name": "std_inter_arrival_time",
        "group": "TIMING",
        "type": "float",
        "unit": "seconds",
        "description": "Standard deviation of inter-arrival times (jitter)",
    },
    {
        "name": "min_inter_arrival_time",
        "group": "TIMING",
        "type": "float",
        "unit": "seconds",
        "description": "Minimum observed time delta between consecutive packets",
    },
    {
        "name": "max_inter_arrival_time",
        "group": "TIMING",
        "type": "float",
        "unit": "seconds",
        "description": "Maximum observed time delta between consecutive packets",
    },
    {
        "name": "packets_per_second",
        "group": "RATE",
        "type": "float",
        "unit": "packets/s",
        "description": "Average packet transmission rate over the flow duration",
    },
    {
        "name": "bytes_per_second",
        "group": "RATE",
        "type": "float",
        "unit": "bytes/s",
        "description": "Average byte throughput rate over the flow duration",
    },
    {
        "name": "forward_packet_count",
        "group": "DIRECTION",
        "type": "integer",
        "unit": "packets",
        "description": "Number of packets sent in the forward direction",
    },
    {
        "name": "backward_packet_count",
        "group": "DIRECTION",
        "type": "integer",
        "unit": "packets",
        "description": "Number of packets received in the reverse direction",
    },
    {
        "name": "forward_bytes",
        "group": "DIRECTION",
        "type": "integer",
        "unit": "bytes",
        "description": "Cumulative bytes transmitted in the forward direction",
    },
    {
        "name": "backward_bytes",
        "group": "DIRECTION",
        "type": "integer",
        "unit": "bytes",
        "description": "Cumulative bytes transmitted in the reverse direction",
    },
    {
        "name": "direction_ratio",
        "group": "DIRECTION",
        "type": "float",
        "unit": "ratio (0–1)",
        "description": "Ratio of forward bytes to total flow bytes (asymmetry)",
    },
]

FEATURE_SCHEMA_BY_NAME = {item["name"]: item for item in CANONICAL_FEATURE_SCHEMA}


class ModelService:
    def __init__(self) -> None:
        self.traffic_model = None
        self.attack_model = None
        self.xgb_model = None
        self.rf_model = None
        self.iso_model = None
        self.traffic_metadata: Dict[str, Any] = {}
        self.attack_metadata: Dict[str, Any] = {}
        self.xgb_metadata: Dict[str, Any] = {}
        self.rf_metadata: Dict[str, Any] = {}
        self.iso_metadata: Dict[str, Any] = {}
        self.load_errors: Dict[str, str] = {}
        self.is_loaded = False
        self._load_models()

    def _load_models(self) -> None:
        """Loads serialized models from disk."""
        traffic_path = MODELS_DIR / "traffic_classifier.joblib"
        attack_path = MODELS_DIR / "attack_classifier.joblib"
        xgb_path = MODELS_DIR / "xgboost_classifier.joblib"
        rf_path = MODELS_DIR / "random_forest_baseline.joblib"
        iso_path = MODELS_DIR / "isolation_forest.joblib"

        if traffic_path.exists():
            try:
                self.traffic_model = joblib.load(traffic_path)
                meta_file = MODELS_DIR / "traffic_classifier.metadata.json"
                if meta_file.exists():
                    self.traffic_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                self.load_errors["traffic_classifier"] = str(err)
                logger.exception("Failed to load traffic classifier model.")

        if attack_path.exists():
            try:
                self.attack_model = joblib.load(attack_path)
                meta_file = MODELS_DIR / "attack_classifier.metadata.json"
                if meta_file.exists():
                    self.attack_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                self.load_errors["attack_classifier"] = str(err)
                logger.exception("Failed to load attack classifier model.")

        if xgb_path.exists():
            try:
                self.xgb_model = joblib.load(xgb_path)
                meta_file = MODELS_DIR / "xgboost_classifier.metadata.json"
                if meta_file.exists():
                    self.xgb_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                self.load_errors["xgboost"] = str(err)
                logger.exception("Failed to load XGBoost model.")

        # If attack_model not explicitly loaded, fall back to xgb_model
        if self.attack_model is None and self.xgb_model is not None:
            self.attack_model = self.xgb_model
            self.attack_metadata = self.xgb_metadata

        if rf_path.exists():
            try:
                self.rf_model = joblib.load(rf_path)
                meta_file = MODELS_DIR / "random_forest_baseline.metadata.json"
                if meta_file.exists():
                    self.rf_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                self.load_errors["random_forest"] = str(err)
                logger.exception("Failed to load Random Forest model.")

        if iso_path.exists():
            try:
                self.iso_model = joblib.load(iso_path)
                meta_file = MODELS_DIR / "isolation_forest.metadata.json"
                if meta_file.exists():
                    self.iso_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                self.load_errors["isolation_forest"] = str(err)
                logger.exception("Failed to load Isolation Forest model.")

        self.is_loaded = (
            self.traffic_model is not None
            or self.attack_model is not None
            or self.xgb_model is not None
            or self.rf_model is not None
        )

    @staticmethod
    def _feature_columns(model: Any, metadata: Dict[str, Any]) -> List[str]:
        configured_columns = metadata.get("feature_columns")
        if isinstance(configured_columns, list) and configured_columns:
            return [str(column) for column in configured_columns]
        model_columns = getattr(model, "feature_names_in_", None)
        return list(model_columns) if model_columns is not None else FEATURE_COLUMNS

    @classmethod
    def _model_info(
        cls,
        model: Any,
        metadata: Dict[str, Any],
        load_error: Optional[str] = None,
    ) -> Dict[str, Any]:
        model_type = metadata.get("model")
        is_classifier = (
            getattr(model, "classes_", None) is not None
            if model is not None
            else isinstance(model_type, str) and "Classifier" in model_type
        )
        has_artifact_metadata = model is not None or bool(metadata)
        feature_cols = cls._feature_columns(model, metadata)
        info: Dict[str, Any] = {
            "loaded": model is not None,
            "classes": [str(label) for label in getattr(model, "classes_", [])] if model is not None else [],
            "features": feature_cols,
            "featureSchema": [
                FEATURE_SCHEMA_BY_NAME.get(col, {
                    "name": col,
                    "group": "GENERAL",
                    "type": "float",
                    "unit": "—",
                    "description": f"Observed {col} flow property",
                })
                for col in feature_cols
            ],
            "metadata": metadata,
            "predictionTask": metadata.get(
                "prediction_task",
                "flow traffic-label classification"
                if is_classifier
                else "flow anomaly detection"
                if model is not None or model_type == "IsolationForest"
                else "Not available",
            ),
            "trainingDataScope": metadata.get("training_data_scope") or (
                "synthetic development dataset" if has_artifact_metadata else None
            ),
            "trainingDataset": metadata.get("training_dataset") or (
                "data/sample/synthetic_vista_dataset.parquet" if has_artifact_metadata else None
            ),
            "evaluationScope": metadata.get("evaluation_scope") or (
                "synthetic-data evaluation; not validated for real-world attack detection"
                if has_artifact_metadata else None
            ),
            "probabilitiesAvailable": bool(
                model is not None and hasattr(model, "predict_proba")
            ),
            "probabilityCalibration": metadata.get("probability_calibration") or (
                "not evaluated" if is_classifier else None
            ),
        }
        if load_error:
            info["loadError"] = load_error
        return info

    def get_info(self) -> Dict[str, Any]:
        """Returns loaded model classes, metadata, and input feature requirements."""
        return {
            "status": "online" if self.is_loaded else "degraded",
            "canonicalFeatureSchema": CANONICAL_FEATURE_SCHEMA,
            "models": {
                "traffic_classifier": self._model_info(
                    self.traffic_model, self.traffic_metadata, self.load_errors.get("traffic_classifier"),
                ),
                "attack_classifier": self._model_info(
                    self.attack_model or self.xgb_model, self.attack_metadata or self.xgb_metadata, self.load_errors.get("attack_classifier") or self.load_errors.get("xgboost"),
                ),
                "xgboost": self._model_info(
                    self.xgb_model or self.attack_model, self.xgb_metadata or self.attack_metadata, self.load_errors.get("xgboost") or self.load_errors.get("attack_classifier"),
                ),
                "random_forest": self._model_info(
                    self.rf_model, self.rf_metadata, self.load_errors.get("random_forest"),
                ),
                "isolation_forest": self._model_info(
                    self.iso_model, self.iso_metadata, self.load_errors.get("isolation_forest"),
                ),
            },
        }

    def prepare_feature_dataframe(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Aligns observed numeric features to the model schema without imputing missing data."""
        df = pd.DataFrame(records)

        # Mapping variations of column names
        aliases = {
            "packets": "packet_count",
            "bytes": "byte_count",
            "duration": "flow_duration",
            "meanPacketLen": "mean_packet_size",
            "stdPacketLen": "std_packet_size",
            "minPacketLen": "min_packet_size",
            "maxPacketLen": "max_packet_size",
            "meanIat": "mean_inter_arrival_time",
            "stdIat": "std_inter_arrival_time",
            "minIat": "min_inter_arrival_time",
            "maxIat": "max_inter_arrival_time",
            "outboundRatio": "direction_ratio",
        }
        for src, dst in aliases.items():
            if src in df.columns and dst not in df.columns:
                df[dst] = df[src]

        # Rates are derived only when their complete inputs and a positive duration exist.
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = np.nan
        duration = pd.to_numeric(df["flow_duration"], errors="coerce")
        packet_rate = np.where(
            duration > 0,
            pd.to_numeric(df["packet_count"], errors="coerce") / duration,
            np.nan,
        )
        byte_rate = np.where(
            duration > 0,
            pd.to_numeric(df["byte_count"], errors="coerce") / duration,
            np.nan,
        )
        df["packets_per_second"] = pd.to_numeric(
            df["packets_per_second"], errors="coerce",
        ).fillna(pd.Series(packet_rate, index=df.index))
        df["bytes_per_second"] = pd.to_numeric(
            df["bytes_per_second"], errors="coerce",
        ).fillna(pd.Series(byte_rate, index=df.index))

        return df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")

    def predict(
        self,
        features_df: pd.DataFrame,
        model_name: str = "xgboost",
    ) -> List[Dict[str, Any]]:
        """
        Runs inference and returns model probability estimates where supported.
        """
        model_choices = {
            "traffic_classifier": (
                self.traffic_model,
                self.traffic_metadata,
                "traffic_classifier.joblib",
                "TrafficClassifier (XGBoost)",
            ),
            "traffic": (
                self.traffic_model,
                self.traffic_metadata,
                "traffic_classifier.joblib",
                "TrafficClassifier (XGBoost)",
            ),
            "attack_classifier": (
                self.attack_model or self.xgb_model,
                self.attack_metadata or self.xgb_metadata,
                "attack_classifier.joblib",
                "AttackClassifier (XGBoost)",
            ),
            "attack": (
                self.attack_model or self.xgb_model,
                self.attack_metadata or self.xgb_metadata,
                "attack_classifier.joblib",
                "AttackClassifier (XGBoost)",
            ),
            "xgboost": (
                self.xgb_model or self.attack_model,
                self.xgb_metadata or self.attack_metadata,
                "xgboost_classifier.joblib",
                "XGBoost",
            ),
            "random_forest": (
                self.rf_model,
                self.rf_metadata,
                "random_forest_baseline.joblib",
                "RandomForest",
            ),
        }
        if model_name not in model_choices:
            raise ValueError(f"Unsupported classifier model: {model_name}.")
        model, metadata, artifact, model_label = model_choices[model_name]
        if model is None:
            raise RuntimeError(
                self.load_errors.get(model_name, f"The requested {model_name} model is not loaded.")
            )

        classes = [str(label) for label in getattr(model, "classes_", [])]
        if not classes:
            raise RuntimeError(f"The loaded {model_name} model does not expose its supported classes.")
        expected_columns = self._feature_columns(model, metadata)
        absent_columns = [column for column in expected_columns if column not in features_df.columns]
        if absent_columns:
            raise ValueError(f"Missing model input columns: {', '.join(absent_columns)}.")
        inputs = features_df[expected_columns]

        results: List[Dict[str, Any]] = []
        valid_positions: List[int] = []
        for position, (_, row) in enumerate(inputs.iterrows()):
            missing = [column for column, value in row.items() if not np.isfinite(value)]
            if missing:
                results.append({
                    "status": "insufficient_data",
                    "source": "ml_model",
                    "predictedClass": None,
                    "modelUsed": model_label,
                    "modelArtifact": artifact,
                    "modelTask": metadata.get("prediction_task") or "classification",
                    "trainingDataScope": metadata.get("training_data_scope")
                    or "synthetic development dataset",
                    "probability": None,
                    "probabilityType": None,
                    "confidence": None,
                    "confidenceValue": None,
                    "probabilities": None,
                    "isAttack": None,
                    "isAnomaly": None,
                    "anomalyScore": None,
                    "missingFeatures": missing,
                })
            else:
                results.append({})
                valid_positions.append(position)

        if not valid_positions:
            return results

        valid_features = inputs.iloc[valid_positions]
        raw_preds = model.predict(valid_features)

        probas = None
        if hasattr(model, "predict_proba"):
            try:
                probas = model.predict_proba(valid_features)
            except Exception:
                logger.exception("Model probability calculation failed; confidence is unavailable.")

        # Isolation forest anomaly detection
        anomalies = None
        anomaly_scores = None
        if self.iso_model is not None:
            try:
                anomalies = self.iso_model.predict(valid_features)
                anomaly_scores = self.iso_model.score_samples(valid_features)
            except Exception:
                logger.exception("Isolation Forest inference failed; anomaly results are unavailable.")
                anomalies = None
                anomaly_scores = None

        for prediction_index, row_position in enumerate(valid_positions):
            pred_class = str(raw_preds[prediction_index])
            proba_dict: Dict[str, float] = {}
            predicted_probability = None

            if probas is not None:
                p_row = probas[prediction_index]
                for c_idx, c_name in enumerate(classes):
                    proba_dict[str(c_name)] = round(float(p_row[c_idx]), 4)
                if pred_class in classes:
                    predicted_probability = round(float(p_row[classes.index(pred_class)]), 4)

            is_anomaly = None
            anomaly_score = None
            if anomalies is not None:
                is_anomaly = bool(anomalies[prediction_index] == -1)
                anomaly_score = round(float(anomaly_scores[prediction_index]), 4)

            is_attack = None
            if "BENIGN" in classes:
                is_attack = 0 if pred_class == "BENIGN" else 1
            elif "NORMAL" in classes:
                is_attack = 0 if pred_class == "NORMAL" else 1
            elif metadata.get("prediction_task") == "encrypted application traffic classification":
                is_attack = 0

            results[row_position] = {
                "status": "success",
                "source": "ml_model",
                "predictedClass": pred_class,
                "isAttack": is_attack,
                "probability": predicted_probability,
                "probabilityType": (
                    "predict_proba model probability; calibration not evaluated"
                    if predicted_probability is not None else None
                ),
                "confidence": (
                    f"{predicted_probability * 100:.1f}%"
                    if predicted_probability is not None else None
                ),
                "confidenceValue": (
                    round(predicted_probability * 100, 1)
                    if predicted_probability is not None else None
                ),
                "probabilities": proba_dict,
                "isAnomaly": is_anomaly,
                "anomalyScore": anomaly_score,
                "modelUsed": model_label,
                "modelArtifact": artifact,
                "modelTask": metadata.get("prediction_task") or "classification",
                "modelVersion": metadata.get("model_version") or metadata.get("version"),
                "trainingDataScope": metadata.get("training_data_scope")
                or "synthetic development dataset",
                "missingFeatures": [],
            }

        return results

    def predict_traffic(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Runs inference using the dedicated AI Analysis traffic classifier."""
        return self.predict(features_df, model_name="traffic_classifier")

    def predict_threat(
        self, features_df: pd.DataFrame, model_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Runs inference using the dedicated Threat Intelligence attack detection model."""
        target_model = model_name if model_name in ("random_forest", "xgboost") else "attack_classifier"
        return self.predict(features_df, model_name=target_model)


# Global singleton instance
model_service = ModelService()
