"""
VISTA AI-Powered IPsec Protocol Analyzer & Security Assessment Framework
Backend API Service — FastAPI
Smart India Hackathon 2026 · Problem Statement SIH26160 (NTRO)
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from backend.services.model_service import model_service
from backend.services.pcap_analyzer import pcap_analyzer
from backend.services.posture_engine import posture_engine
from backend.services.soc_service import soc_service
from backend.services.ebpf_service import ebpf_service

ROOT_DIR = Path(__file__).resolve().parents[1]
METRICS_PATH = ROOT_DIR / "vista-ml" / "reports" / "metrics" / "model_summary.json"
SHAP_PATH = ROOT_DIR / "vista-ml" / "reports" / "shap" / "top_features.json"
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VISTA AI Core API",
    description="Live AI-Powered IPsec VPN Protocol Analyzer and Security Assessment API (SIH26160 / NTRO)",
    version="2.0.0",
)

# Enable CORS for local development and Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "service": "VISTA AI Core API",
        "problemStatement": "SIH26160",
        "organization": "National Technical Research Organisation (NTRO)",
        "status": "ONLINE",
        "docsUrl": "/docs",
    }


@app.get("/api/status")
def get_system_status():
    """Returns engine health, loaded model metadata, and feature configuration."""
    model_info = model_service.get_info()
    soc_summary = soc_service.get_soc_status()
    return {
        "status": "ONLINE",
        "backend": "FastAPI / Uvicorn",
        "models": model_info["models"],
        "system": soc_summary,
    }


@app.post("/api/analyze/pcap")
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    model: str = Query("xgboost", pattern="^(xgboost|random_forest|attack_classifier|traffic_classifier)$"),
):
    """
    Accepts uploaded .pcap or .pcapng file, decodes IPsec ESP SPIs and IKE headers,
    extracts flow metadata, and returns predictions where complete model inputs are available.
    """
    filename = file.filename or "uploaded.pcap"
    try:
        content = await file.read()
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        result = pcap_analyzer.parse_pcap_bytes(
            pcap_bytes=content,
            filename=filename,
            model_name=model,
        )
        return result
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {str(err)}")


@app.post("/api/analyze/csv")
async def analyze_csv_upload(
    file: UploadFile = File(...),
    model: str = Query("xgboost", pattern="^(xgboost|random_forest|attack_classifier|traffic_classifier)$"),
):
    """
    Accepts uploaded flow CSV and preserves input records when model inference is unavailable.
    """
    try:
        content = await file.read()
        df_raw = pd.read_csv(io.BytesIO(content))
        if df_raw.empty:
            raise HTTPException(status_code=400, detail="Uploaded CSV has no records.")

        records = df_raw.to_dict(orient="records")
        try:
            features_df = model_service.prepare_feature_dataframe(records)
            predictions = model_service.predict(features_df, model_name=model)
        except Exception as err:
            logger.exception("CSV ML inference failed.")
            predictions = [{
                "status": "unavailable",
                "source": "ml_model",
                "predictedClass": None,
                "isAttack": None,
                "confidence": None,
                "confidenceValue": None,
                "probability": None,
                "probabilityType": None,
                "probabilities": None,
                "isAnomaly": None,
                "anomalyScore": None,
                "modelUsed": model,
                "missingFeatures": [],
                "error": str(err),
            } for _ in records]

        for i, rec in enumerate(records):
            pred = predictions[i]
            rec["predictionStatus"] = pred["status"]
            rec["mlPrediction"] = {
                "status": pred["status"],
                "source": pred["source"],
                "label": pred["predictedClass"],
                "model": pred["modelUsed"],
                "probability": pred.get("probability"),
                "probabilityType": pred.get("probabilityType"),
                "probabilities": pred.get("probabilities"),
                "missingFeatures": pred.get("missingFeatures", []),
                "trainingDataScope": pred.get("trainingDataScope"),
            }
            if pred.get("modelArtifact"):
                rec["mlPrediction"]["modelArtifact"] = pred["modelArtifact"]
            if pred.get("modelVersion"):
                rec["mlPrediction"]["modelVersion"] = pred["modelVersion"]
            if pred.get("error"):
                rec["mlPrediction"]["error"] = pred["error"]
            rec["attackType"] = (
                pred["predictedClass"]
                if pred["status"] == "success"
                else "Insufficient Data"
                if pred["status"] == "insufficient_data"
                else "Prediction Unavailable"
            )
            rec["isAttack"] = pred["isAttack"]
            rec["trafficType"] = (
                "Benign" if pred["isAttack"] == 0
                else "Attack" if pred["isAttack"] == 1
                else pred["status"].replace("_", " ").title()
            )
            rec["confidence"] = pred["confidence"]
            rec["confidenceValue"] = pred["confidenceValue"]
            rec["probabilities"] = pred["probabilities"]
            rec["isAnomaly"] = pred["isAnomaly"]
            rec["anomalyScore"] = pred["anomalyScore"]
            rec["inferenceEngine"] = pred["modelUsed"]
            if pred["status"] == "insufficient_data":
                rec["predictionError"] = (
                    "Required model features are missing: "
                    + ", ".join(pred["missingFeatures"])
                )
            elif pred.get("error"):
                rec["predictionError"] = pred["error"]

        model_metadata = model_service.get_info()["models"][model]
        return {
            "filename": file.filename,
            "totalFlows": len(records),
            "flows": records,
            "mlInference": {
                "status": (
                    "success" if any(pred["status"] == "success" for pred in predictions)
                    else "insufficient_data" if any(
                        pred["status"] == "insufficient_data" for pred in predictions
                    )
                    else "unavailable"
                ),
                "source": "ml_model",
                "model": model,
                "modelArtifact": (
                    "xgboost_classifier.joblib" if model == "xgboost"
                    else "random_forest_baseline.joblib"
                ),
                "modelTask": model_metadata.get("predictionTask"),
                "trainingDataScope": model_metadata.get("trainingDataScope"),
                "trainingDataset": model_metadata.get("trainingDataset"),
                "evaluationScope": model_metadata.get("evaluationScope"),
                "predictedFlows": sum(pred["status"] == "success" for pred in predictions),
                "insufficientDataFlows": sum(
                    pred["status"] == "insufficient_data" for pred in predictions
                ),
                "unavailableFlows": sum(pred["status"] == "unavailable" for pred in predictions),
                **({"error": next(
                    (pred["error"] for pred in predictions if pred.get("error")),
                    None,
                )} if any(pred.get("error") for pred in predictions) else {}),
            },
        }
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"CSV analysis failed: {str(err)}")


@app.get("/api/captures/samples")
def list_sample_captures():
    """Returns available sample PCAPs in the captures directory for quick evaluation."""
    captures_dir = ROOT_DIR / "captures"
    samples = []
    if captures_dir.exists():
        for p in sorted(captures_dir.glob("*.pcap*")):
            samples.append({
                "name": p.name,
                "sizeBytes": p.stat().st_size,
            })
    return samples


@app.get("/api/captures/samples/{filename}")
def get_sample_capture(filename: str):
    """Returns a sample capture file for testing and analysis."""
    safe_name = Path(filename).name
    pcap_path = ROOT_DIR / "captures" / safe_name
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail="Sample capture not found.")
    return FileResponse(pcap_path, media_type="application/octet-stream", filename=safe_name)


@app.get("/api/audit/sessions")
def get_audit_sessions(
    compliance: Optional[str] = None,
    limit: int = Query(500, ge=1, le=2000),
):
    """
    Returns operational IPsec sessions evaluated against NIST SP 800-77.
    Generated scenario audit records are not exposed as operational assessments.
    """
    sessions = posture_engine.evaluate_sessions(posture_engine.get_audit_sessions())
    if compliance:
        sessions = [s for s in sessions if str(s.get("compliance", "")).lower() == compliance.lower()]
    return sessions[:limit]


@app.get("/api/audit/summary")
def get_audit_summary():
    """
    Returns aggregate cryptographic compliance statistics and overall security posture score.
    """
    return posture_engine.compute_summary_posture()


@app.get("/api/ml/metrics")
def get_ml_metrics():
    """
    Returns evaluated model performance metrics and SHAP feature importance.
    """
    metrics_data = {}
    if METRICS_PATH.exists():
        metrics_data = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    shap_data = {}
    if SHAP_PATH.exists():
        shap_data = json.loads(SHAP_PATH.read_text(encoding="utf-8"))

    return {
        "metrics": metrics_data,
        "shapImportance": shap_data,
        "evaluationProvenance": {
            "dataset": "Synthetic VISTA development dataset",
            "method": "Experiment-aware group holdout; offline evaluation, not current-capture accuracy.",
            "limitations": (
                "Synthetic labels and label-conditioned features do not establish real-world attack-detection performance."
            ),
            "trafficDataset": "IPsec Encrypted Traffic Classification & Attack Attribution Dataset (v2)",
            "trafficMethod": "Session-isolated GroupShuffleSplit (80/20 train/test holdout); 0% session overlap.",
            "attackDataset": "IPsec Encrypted Traffic Classification & Attack Attribution Dataset (v2)",
            "attackMethod": "Session-isolated GroupShuffleSplit (80/20 train/test holdout); 0% session overlap.",
        },
        "shapProvenance": {
            "dataset": "IPsec Encrypted Traffic Classification & Attack Attribution Dataset (v2)",
            "scope": "Global TreeExplainer SHAP importance evaluated on held-out test flows; reflects side-channel timing/length features.",
        },
    }


@app.get("/api/soc/status")
def get_soc_status():
    """
    Returns observed flow totals and aggregates only successful model predictions.
    """
    return soc_service.get_soc_status()


@app.get("/api/soc/threats")
def get_soc_threats():
    """
    Returns threat detections dynamically mapped to MITRE ATT&CK techniques.
    """
    return soc_service.get_threat_matrix()


@app.post("/api/soc/threats")
def get_analysis_threats(request: Dict[str, Any]):
    """Maps successful unverified ML class predictions from uploaded flows to MITRE."""
    flows = request.get("flows")
    if not isinstance(flows, list):
        raise HTTPException(status_code=400, detail="Request must include a flows array.")
    return soc_service.get_threat_matrix(flows=flows)


@app.get("/api/ebpf/events")
def get_ebpf_events(limit: int = Query(12, ge=1, le=500)):
    """
    Returns actual Linux kernel events; the list is empty when collection is unavailable.
    """
    status = ebpf_service.get_status()
    return {
        "status": status["mode"],
        "events": ebpf_service.get_live_events(limit=limit),
    }


@app.get("/api/ebpf/status")
def get_ebpf_status():
    """
    Returns collector mode and the actual Linux probe attachment state.
    """
    return ebpf_service.get_status()


@app.post("/api/ebpf/fuse")
def fuse_flows_with_ebpf(request: Dict[str, Any]):
    """
    Runs the VISTA fusion pipeline against available collector events.
    """
    flows = request.get("flows", [])
    if not flows:
        raise HTTPException(status_code=400, detail="No flows provided for fusion.")
    fused = ebpf_service.fuse_with_ebpf(flows)
    return {
        "fusedFlowCount": len(fused),
        "flows": fused,
    }


@app.post("/api/reports/generate")
def generate_audit_report(request: Dict[str, Any]):
    """Generates a report from available audit data and optional uploaded analysis flows."""
    report_type = request.get("reportType", "Technical Assessment")
    flows = request.get("flows")
    if flows is not None and not isinstance(flows, list):
        raise HTTPException(status_code=400, detail="The flows field must be an array.")

    posture = posture_engine.compute_summary_posture()
    soc = soc_service.get_soc_status(custom_flows=flows) if flows is not None else soc_service.get_soc_status()
    audits = posture_engine.get_audit_sessions()
    score = posture.get("overallScore")
    score_text = f"{score}/100" if score is not None else "Not available"
    compliance = posture.get("compliancePercentage")
    compliance_text = f"{compliance}%" if compliance is not None else "Not available"
    assessed_sessions = posture.get("assessedSessions", 0)
    assessed_sessions_text = str(assessed_sessions) if assessed_sessions else "Not available"
    high_risk_text = str(posture.get("highRiskCount", 0)) if assessed_sessions else "Not available"
    ai_confidence = soc.get("aiConfidence")
    successful_predictions = [
        flow for flow in (flows or [])
        if flow.get("predictionStatus") == "success"
    ]
    predicted_classes: Dict[str, int] = {}
    for flow in successful_predictions:
        label = (flow.get("mlPrediction") or {}).get("label") or flow.get("attackType")
        if label:
            predicted_classes[str(label)] = predicted_classes.get(str(label), 0) + 1
    prediction_summary = (
        "\n".join(f"- {label}: {count} ML predictions" for label, count in sorted(predicted_classes.items()))
        if predicted_classes else "- No successful ML predictions are available."
    )
    insufficient_count = sum(
        flow.get("predictionStatus") == "insufficient_data" for flow in (flows or [])
    )
    unavailable_count = sum(
        flow.get("predictionStatus") == "unavailable" for flow in (flows or [])
    )
    prediction_status_line = (
        f"- Prediction status counts: {len(successful_predictions)} successful, "
        f"{insufficient_count} insufficient data, {unavailable_count} unavailable\n"
        if flows is not None else ""
    )
    prediction_model = next(
        ((flow.get("mlPrediction") or {}).get("model") for flow in successful_predictions
         if (flow.get("mlPrediction") or {}).get("model")),
        None,
    )
    prediction_artifact = next(
        ((flow.get("mlPrediction") or {}).get("modelArtifact") for flow in successful_predictions
         if (flow.get("mlPrediction") or {}).get("modelArtifact")),
        None,
    )
    model_version = next(
        ((flow.get("mlPrediction") or {}).get("modelVersion") for flow in successful_predictions
         if (flow.get("mlPrediction") or {}).get("modelVersion")),
        None,
    )
    training_data_scope = next(
        ((flow.get("mlPrediction") or {}).get("trainingDataScope") for flow in successful_predictions
         if (flow.get("mlPrediction") or {}).get("trainingDataScope")),
        None,
    )
    probability_line = (
        f"- Mean predicted-class model probability (uncalibrated): {ai_confidence}%\n"
        if flows is not None and ai_confidence is not None else ""
    )
    model_line = (
        f"- Prediction model: {prediction_model}"
        + (f" ({prediction_artifact})" if prediction_artifact else "")
        + (f" (version {model_version})" if model_version else "")
        + "\n"
        if prediction_model else ""
    )
    training_line = (
        f"- Training data scope: {training_data_scope}\n"
        if training_data_scope else ""
    )
    observed_protocols = sorted({
        str(flow["proto"]) for flow in flows or [] if flow.get("proto")
    })
    observed_line = (
        f"- Observed flow protocols: {', '.join(observed_protocols) if observed_protocols else 'Not available'}\n"
        if flows is not None else ""
    )
    vulnerability_counts: Dict[str, int] = {}
    for session in audits:
        for vulnerability in session.get("vulnerabilities", []):
            vulnerability_counts[vulnerability] = vulnerability_counts.get(vulnerability, 0) + 1
    top_findings = sorted(vulnerability_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    finding_lines = (
        "\n".join(f"- {name}: {count} audited sessions" for name, count in top_findings)
        if top_findings else "- No audited vulnerability records available."
    )

    md = f"""# VISTA IPsec Security Assessment Report
**Document Type:** {report_type}
**Data source:** {"Uploaded PCAP/CSV analysis and available operational audit records" if flows is not None else "Available repository flow records and operational audit records"}

## Assessment summary
- Overall posture score: {score_text}
- Assessed audit sessions: {assessed_sessions_text}
- Compliance rate: {compliance_text}
- High-risk sessions: {high_risk_text}
- Flow records: {soc.get('totalFlows', 0)}
- Flows predicted as non-normal by ML (unverified): {soc.get('threatsDetectedCount', 0) if flows is not None else "Not available"}
{observed_line}{model_line}{training_line}{prediction_status_line}{probability_line}
## Uploaded flow-class ML predictions
These are model predictions, not confirmed incidents or verified IPsec configuration.
The loaded classifier's scope is limited to its documented training and evaluation data; its output is not proof of a real-world threat.
{prediction_summary if flows is not None else "- No uploaded analysis predictions were supplied."}
## Available cryptographic posture
- AEAD cipher adoption: {posture.get('aeadAdoptionRate') if posture.get('aeadAdoptionRate') is not None else "Not available"}
- PFS adoption: {posture.get('pfsAdoptionRate') if posture.get('pfsAdoptionRate') is not None else "Not available"}
- Anti-replay enforcement: {posture.get('antiReplayEnforcedRate') if posture.get('antiReplayEnforcedRate') is not None else "Not available"}
- Strong DH groups: {posture.get('strongDhRate') if posture.get('strongDhRate') is not None else "Not available"}

## Most frequent recorded findings
{finding_lines}

This report includes repository audit records and flow classifications. It does not claim live tunnel state or live packet telemetry.
"""
    return {
        "reportType": report_type,
        "format": "markdown",
        "content": md,
        "score": score,
        "source": soc["source"],
    }
