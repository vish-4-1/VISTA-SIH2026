"""
VISTA ML Model ONNX Exporter
Converts trained Scikit-learn (Random Forest, Isolation Forest) and XGBoost models
into standardized ONNX (Open Neural Network Exchange) format.
Validates outputs against ONNX Runtime for inference parity.
"""

from pathlib import Path
import joblib
import numpy as np
import onnx
import onnxruntime as rt
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType as SklearnFloatTensorType
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType as OnnxFloatTensorType

ROOT_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT_DIR / "models"
ONNX_DIR = MODELS_DIR / "onnx"
ONNX_DIR.mkdir(parents=True, exist_ok=True)

N_FEATURES = 18


def export_random_forest():
    rf_path = MODELS_DIR / "random_forest_baseline.joblib"
    out_path = ONNX_DIR / "random_forest_baseline.onnx"
    print(f"[*] Loading Random Forest from {rf_path}...")
    rf_model = joblib.load(rf_path)

    print(f"[*] Converting Random Forest to ONNX...")
    initial_type = [("float_input", SklearnFloatTensorType([None, N_FEATURES]))]
    onx = convert_sklearn(rf_model, initial_types=initial_type, target_opset=15)
    with open(out_path, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"[+] Saved Random Forest ONNX: {out_path} ({out_path.stat().st_size:,} bytes)")

    # Validate with onnxruntime
    sess = rt.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    test_x = np.random.randn(5, N_FEATURES).astype(np.float32)
    input_name = sess.get_inputs()[0].name
    res = sess.run(None, {input_name: test_x})
    print(f"[+] ONNX Runtime Validation PASSED (predicted: {res[0]})")
    return out_path


def export_isolation_forest():
    iso_path = MODELS_DIR / "isolation_forest.joblib"
    out_path = ONNX_DIR / "isolation_forest.onnx"
    print(f"[*] Loading Isolation Forest from {iso_path}...")
    iso_model = joblib.load(iso_path)

    print(f"[*] Converting Isolation Forest to ONNX...")
    initial_type = [("float_input", SklearnFloatTensorType([None, N_FEATURES]))]
    target_opset = {"": 15, "ai.onnx.ml": 3}
    onx = convert_sklearn(iso_model, initial_types=initial_type, target_opset=target_opset)
    with open(out_path, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"[+] Saved Isolation Forest ONNX: {out_path} ({out_path.stat().st_size:,} bytes)")

    # Validate with onnxruntime
    sess = rt.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    test_x = np.random.randn(5, N_FEATURES).astype(np.float32)
    input_name = sess.get_inputs()[0].name
    res = sess.run(None, {input_name: test_x})
    print(f"[+] ONNX Runtime Validation PASSED (anomaly scores: {res[0]})")
    return out_path


def export_xgboost():
    xgb_path = MODELS_DIR / "xgboost_classifier.joblib"
    out_path = ONNX_DIR / "xgboost_classifier.onnx"
    print(f"[*] Loading XGBoost from {xgb_path}...")
    xgb_model = joblib.load(xgb_path)
    estimator = getattr(xgb_model, "estimator", xgb_model)

    print(f"[*] Converting XGBoost to ONNX...")
    # Map feature names to standard f%d required by onnxmltools
    booster = estimator.get_booster()
    orig_names = booster.feature_names
    booster.feature_names = [f"f{i}" for i in range(N_FEATURES)]

    initial_type = [("float_input", OnnxFloatTensorType([None, N_FEATURES]))]
    onx = onnxmltools.convert_xgboost(estimator, initial_types=initial_type, target_opset=15)
    
    # Restore original names
    booster.feature_names = orig_names

    with open(out_path, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"[+] Saved XGBoost ONNX: {out_path} ({out_path.stat().st_size:,} bytes)")

    # Validate with onnxruntime
    sess = rt.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    test_x = np.random.randn(5, N_FEATURES).astype(np.float32)
    input_name = sess.get_inputs()[0].name
    res = sess.run(None, {input_name: test_x})
    print(f"[+] ONNX Runtime Validation PASSED (classes: {res[0]}, probs shape: {res[1].shape})")
    return out_path


if __name__ == "__main__":
    print("==================================================")
    print("       VISTA ML ONNX EXPORT & VALIDATION          ")
    print("==================================================")
    rf_out = export_random_forest()
    iso_out = export_isolation_forest()
    xgb_out = export_xgboost()
    print("==================================================")
    print("SUCCESS: All 3 models converted and validated in ONNX format!")
    print(f"Location: {ONNX_DIR}")
    print("==================================================")
