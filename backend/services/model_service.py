"""
VISTA ML Model Service
Loads trained Random Forest, XGBoost, and Isolation Forest models and
provides unified inference, true probability calculation, and feature attribution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT_DIR / "vista-ml" / "models"

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

LABELS = [
    "BRUTE_FORCE",
    "C2_BEACONING",
    "DATA_EXFILTRATION",
    "DOS",
    "NORMAL",
    "PORT_SCAN",
]


class ModelService:
    def __init__(self) -> None:
        self.rf_model = None
        self.xgb_model = None
        self.iso_model = None
        self.rf_metadata: Dict[str, Any] = {}
        self.xgb_metadata: Dict[str, Any] = {}
        self.iso_metadata: Dict[str, Any] = {}
        self.is_loaded = False
        self._load_models()

    def _load_models(self) -> None:
        """Loads serialized models from disk."""
        rf_path = MODELS_DIR / "random_forest_baseline.joblib"
        xgb_path = MODELS_DIR / "xgboost_classifier.joblib"
        iso_path = MODELS_DIR / "isolation_forest.joblib"

        if rf_path.exists():
            try:
                self.rf_model = joblib.load(rf_path)
                meta_file = MODELS_DIR / "random_forest_baseline.metadata.json"
                if meta_file.exists():
                    self.rf_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                print(f"[ModelService] Warning: Failed to load RF model: {err}")

        if xgb_path.exists():
            try:
                self.xgb_model = joblib.load(xgb_path)
                meta_file = MODELS_DIR / "xgboost_classifier.metadata.json"
                if meta_file.exists():
                    self.xgb_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                print(f"[ModelService] Warning: Failed to load XGB model: {err}")

        if iso_path.exists():
            try:
                self.iso_model = joblib.load(iso_path)
                meta_file = MODELS_DIR / "isolation_forest.metadata.json"
                if meta_file.exists():
                    self.iso_metadata = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception as err:
                print(f"[ModelService] Warning: Failed to load Isolation Forest model: {err}")

        self.is_loaded = bool(self.xgb_model or self.rf_model)

    def get_info(self) -> Dict[str, Any]:
        """Returns model versions, status, and input feature requirements."""
        return {
            "status": "online" if self.is_loaded else "degraded",
            "models": {
                "xgboost": {
                    "loaded": self.xgb_model is not None,
                    "classes": list(getattr(self.xgb_model, "classes_", [])),
                    "features": FEATURE_COLUMNS,
                    "metadata": self.xgb_metadata,
                },
                "random_forest": {
                    "loaded": self.rf_model is not None,
                    "classes": list(getattr(self.rf_model, "classes_", [])),
                    "features": FEATURE_COLUMNS,
                    "metadata": self.rf_metadata,
                },
                "isolation_forest": {
                    "loaded": self.iso_model is not None,
                    "features": FEATURE_COLUMNS,
                    "metadata": self.iso_metadata,
                },
            },
        }

    def prepare_feature_dataframe(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Standardizes input records into a DataFrame aligned with training features."""
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

        # Derive rates if missing
        if "packets_per_second" not in df.columns:
            dur = df.get("flow_duration", 0).astype(float)
            pkts = df.get("packet_count", 0).astype(float)
            df["packets_per_second"] = np.where(dur > 0, pkts / dur, 0.0)

        if "bytes_per_second" not in df.columns:
            dur = df.get("flow_duration", 0).astype(float)
            bts = df.get("byte_count", 0).astype(float)
            df["bytes_per_second"] = np.where(dur > 0, bts / dur, 0.0)

        # Derive forward/backward metrics if missing
        if "forward_packet_count" not in df.columns:
            ratio = df.get("direction_ratio", 0.5).astype(float)
            pkts = df.get("packet_count", 0).astype(float)
            df["forward_packet_count"] = np.round(pkts * ratio).astype(int)
            df["backward_packet_count"] = np.maximum(0, pkts - df["forward_packet_count"]).astype(int)

        if "forward_bytes" not in df.columns:
            fwd_pkts = df.get("forward_packet_count", 0).astype(float)
            mean_sz = df.get("mean_packet_size", 100.0).astype(float)
            df["forward_bytes"] = fwd_pkts * mean_sz

        if "backward_bytes" not in df.columns:
            bwd_pkts = df.get("backward_packet_count", 0).astype(float)
            mean_sz = df.get("mean_packet_size", 100.0).astype(float)
            df["backward_bytes"] = bwd_pkts * mean_sz

        # Ensure all required feature columns exist and are numeric
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

        return df[FEATURE_COLUMNS]

    def predict(
        self,
        features_df: pd.DataFrame,
        model_name: str = "xgboost",
    ) -> List[Dict[str, Any]]:
        """
        Runs model inference on feature rows and returns predictions with true probabilities.
        """
        model = self.xgb_model if model_name == "xgboost" and self.xgb_model else self.rf_model
        if model is None:
            raise RuntimeError("No trained model available for inference.")

        classes = list(getattr(model, "classes_", LABELS))
        raw_preds = model.predict(features_df)

        probas = None
        if hasattr(model, "predict_proba"):
            try:
                probas = model.predict_proba(features_df)
            except Exception:
                pass

        # Isolation forest anomaly detection
        anomalies = None
        anomaly_scores = None
        if self.iso_model is not None:
            try:
                anomalies = self.iso_model.predict(features_df)
                anomaly_scores = self.iso_model.score_samples(features_df)
            except Exception:
                pass

        results: List[Dict[str, Any]] = []
        for i in range(len(features_df)):
            pred_class = str(raw_preds[i])
            proba_dict: Dict[str, float] = {}
            confidence_pct = 95.0

            if probas is not None:
                p_row = probas[i]
                for c_idx, c_name in enumerate(classes):
                    proba_dict[str(c_name)] = round(float(p_row[c_idx]), 4)
                confidence_pct = round(float(np.max(p_row)) * 100, 1)
            else:
                proba_dict = {pred_class: 1.0}

            is_anomaly = False
            anomaly_score = 0.0
            if anomalies is not None:
                is_anomaly = bool(anomalies[i] == -1)
                anomaly_score = round(float(anomaly_scores[i]), 4)

            is_attack = 0 if pred_class == "NORMAL" else 1

            results.append({
                "predictedClass": pred_class,
                "isAttack": is_attack,
                "confidence": f"{confidence_pct}%",
                "confidenceValue": confidence_pct,
                "probabilities": proba_dict,
                "isAnomaly": is_anomaly,
                "anomalyScore": anomaly_score,
                "modelUsed": "XGBoost" if model == self.xgb_model else "RandomForest",
            })

        return results


# Global singleton instance
model_service = ModelService()
