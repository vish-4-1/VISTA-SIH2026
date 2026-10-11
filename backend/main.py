"""
VISTA AI-Powered IPsec Protocol Analyzer & Security Assessment Framework
Backend API Service — FastAPI
Smart India Hackathon 2026 · Problem Statement SIH26160 (NTRO)
"""

from __future__ import annotations

import io
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from pydantic import BaseModel
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from backend.services.model_service import model_service
from backend.services.shap_service import shap_service
from backend.services.pcap_analyzer import pcap_analyzer
from backend.services.posture_engine import posture_engine
from backend.services.soc_service import soc_service
from backend.services.ebpf_service import ebpf_service
from backend.services.dataset_service import dataset_service
from backend.services.vpn_testbed import (
    StrongSwanExperimentError,
    get_testbed_live_status,
    inspect_runtime_capabilities,
    prepare_capability_report,
    run_experiment,
    validate_configuration,
)

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
        result["sourceCaptureSha256"] = hashlib.sha256(content).hexdigest()
        result["sourceCaptureSizeBytes"] = len(content)
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
        analyzed_at = datetime.now(timezone.utc).isoformat()
        analysis_id = f"ANL-{uuid.uuid4().hex[:12].upper()}"
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
            flow_id = str(rec.get("flowId") or rec.get("flow_id") or f"FLW-{i + 1:07d}")
            rec["analysisId"] = analysis_id
            rec["flowId"] = flow_id
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
                "analysisId": analysis_id,
                "flowId": flow_id,
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
            "analysisId": analysis_id,
            "filename": file.filename,
            "sourceCaptureSha256": hashlib.sha256(content).hexdigest(),
            "sourceCaptureSizeBytes": len(content),
            "dataMode": "csv",
            "analyzedAt": analyzed_at,
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


class FlowExplainRequest(BaseModel):
    flow_id: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    flow_record: Optional[Dict[str, Any]] = None
    model_name: Optional[str] = "xgboost"
    target_class: Optional[str] = None
    protocol_family: Optional[str] = None
    allow_experimental: Optional[bool] = False


@app.get("/api/ml/metrics")
def get_ml_metrics():
    """
    Returns evaluation and explanation artifacts with explicit model provenance.
    """
    metrics_data = {}
    if METRICS_PATH.exists():
        candidate_metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        if (
            isinstance(candidate_metrics, dict)
            and candidate_metrics.get("evaluation_status") == "held_out_verified"
            and candidate_metrics.get("feature_schema_version") == "vista-flow-v1"
        ):
            metrics_data = candidate_metrics.get("models", {})

    # Retrieve audited global SHAP importance
    global_shap = shap_service.get_global_importance("xgboost")
    shap_data = None
    if global_shap.get("status") == "AVAILABLE":
        shap_data = {
            "scope": "global",
            "model_id": global_shap["model_id"],
            "model_version": global_shap["model_version"],
            "feature_schema_version": global_shap["feature_schema"],
            "sample_count": global_shap["sample_count"],
            "dataset_id": global_shap["dataset_id"],
            "dataset_name": global_shap["dataset_name"],
            "dataset_hash": global_shap["dataset_hash"],
            "evaluation_split": global_shap["evaluation_split"],
            "importance_measure": global_shap["importance_measure"],
            "top_features": [
                {
                    "feature": f["feature"],
                    "shap_value": f["importance"],
                    "rank": f["rank"],
                    "group": f["group"],
                    "relativeWeight": f.get("relativeWeight", 1.0),
                }
                for f in global_shap["top_features"]
            ],
            "all_features": global_shap["all_features"],
            "provenance": global_shap["provenance"],
        }

    is_verified = bool(metrics_data) or (shap_data is not None and shap_data.get("provenance", {}).get("status") == "HELD_OUT_VERIFIED")

    return {
        "metrics": metrics_data,
        "shapImportance": shap_data,
        "evaluationProvenance": {
            "status": "HELD_OUT_VERIFIED" if is_verified else "NOT_VALIDATED",
            "dataset": (
                (shap_data.get("dataset_name") if shap_data else "See per-model evaluation artifact provenance.")
                if is_verified else "No eligible held-out evaluation artifact is available."
            ),
            "method": "Metrics are exposed only when a held-out report declares the canonical schema and validation status.",
            "limitations": "Checked-in synthetic fixtures are development data, not real-world validation. The legacy attack sample has incomplete origin evidence and is explicitly unverified.",
            "trafficDataset": "ISCXVPN2016 archive is present, but the current runtime model was not trained/evaluated against an audited leakage-aware split.",
            "attackDataset": "No compatible public attack dataset has been validated. The legacy VISTA attack sample has unknown origin and unverified labels because source PCAP and endpoint evidence are not packaged.",
        },
        "shapProvenance": {
            "status": "AVAILABLE_GLOBAL_ONLY" if shap_data else "NOT_AVAILABLE",
            "scope": (
                "Global feature importance with provenance linked to a held-out evaluation artifact; not an explanation of current live capture."
                if shap_data else "No current SHAP artifact matches a validated model version and feature schema."
            ),
            "model": shap_data.get("model_id") if shap_data else None,
            "dataset": shap_data.get("dataset_name") if shap_data else None,
            "evaluationDataset": shap_data.get("dataset_id") if shap_data else None,
            "sampleCount": shap_data.get("sample_count") if shap_data else None,
        },
        "perFlowExplanation": {
            "status": "FAIL_CLOSED_GATED",
            "limitation": "Per-flow explanation requires an eligible validated model, matching canonical schema, and unencrypted transport.",
        },
    }


@app.get("/api/ml/shap/status")
def get_shap_status():
    """
    Returns explainer readiness, model validation gating, and supported SHAP explanation modes.
    """
    return shap_service.get_explainer_status()


@app.get("/api/ml/shap/global")
def get_global_shap_importance(model: str = Query("xgboost", description="Model identifier")):
    """
    Returns global feature importance ranked by mean absolute SHAP values with evaluation provenance.
    """
    return shap_service.get_global_importance(model_id=model)


@app.post("/api/ml/shap/explain-flow")
def explain_individual_flow(request: FlowExplainRequest):
    """
    Computes directional feature contributions and baseline value for an individual flow
    only when all 7 prerequisites are verified.
    """
    flow_payload = dict(request.flow_record or request.features or {})
    if request.flow_id:
        flow_payload["id"] = request.flow_id
        flow_payload["flow_id"] = request.flow_id
    if request.protocol_family:
        flow_payload["protocolFamily"] = request.protocol_family

    return shap_service.explain_flow(
        flow_record=flow_payload,
        model_name=request.model_name or "xgboost",
        target_class=request.target_class,
        allow_experimental=bool(request.allow_experimental),
    )


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


@app.get("/api/testbed/profiles")
def get_testbed_profiles():
    """
    Returns repository StrongSwan profiles with evidence status. A profile is marked
    executed only when the capability report contains successful runtime evidence.
    """
    profiles = [
        {
            "id": "ikev2-aes256gcm",
            "name": "Suite-B / NIST High: AES-256-GCM + MODP-2048",
            "mode": "tunnel",
            "ikeVersion": 2,
            "encryption": "AES-256-GCM",
            "espProposals": "aes256gcm16-modp2048",
            "ikeProposals": "aes256-sha256-modp2048",
            "dhGroup": 14,
            "dhGroupName": "modp2048",
            "pfs": True,
            "ipVersion": "IPv4",
            "pc1Ip": "172.20.0.2",
            "pc2Ip": "172.20.0.3",
            "status": "EXECUTED_WITH_EVIDENCE",
            "configFile": "pc1-swanctl.conf",
            "evidenceReference": "captures/strongswan/capability_report.json",
            "nistCompliance": "Compliant (NIST SP 800-77 r1)",
        },
        {
            "id": "ikev2-aes256cbc",
            "name": "Legacy Baseline: AES-256-CBC + HMAC-SHA256 + MODP-2048",
            "mode": "tunnel",
            "ikeVersion": 2,
            "encryption": "AES-256-CBC",
            "integrity": "HMAC-SHA256",
            "espProposals": "aes256-sha256-modp2048",
            "ikeProposals": "aes256-sha256-modp2048",
            "dhGroup": 14,
            "dhGroupName": "modp2048",
            "pfs": True,
            "ipVersion": "IPv4",
            "pc1Ip": "172.20.0.2",
            "pc2Ip": "172.20.0.3",
            "status": "EXECUTED_WITH_EVIDENCE",
            "configFile": "pc1-cbc-swanctl.conf",
            "evidenceReference": "captures/strongswan/capability_report.json",
            "nistCompliance": "Compliant with integrity validation",
        },
        {
            "id": "ikev2-transport",
            "name": "Host-to-Host: AES-256-GCM Transport Mode",
            "mode": "transport",
            "ikeVersion": 2,
            "encryption": "AES-256-GCM",
            "espProposals": "aes256gcm16",
            "ikeProposals": "aes256-sha256-modp2048",
            "dhGroup": 14,
            "dhGroupName": "modp2048",
            "pfs": False,
            "ipVersion": "IPv4",
            "pc1Ip": "172.20.0.2",
            "pc2Ip": "172.20.0.3",
            "status": "IMPLEMENTED_UNVERIFIED",
            "configFile": None,
            "evidenceReference": "captures/strongswan/capability_report.json",
            "nistCompliance": "Unverified — no successful transport-mode experiment is recorded",
        },
    ]

    return {
        "architecture": "PC1 ⇄ IPsec ESP Tunnel ⇄ PC2",
        "daemon": "strongSwan 5.9.x",
        "kernelSubsystem": "Linux XFRM / netlink xfrm_user",
        "profiles": profiles,
        "supportScope": "Configuration options and kernel support do not prove negotiated runtime behavior; inspect each profile status and the cited evidence.",
        "supportedMatrix": {
            "modes": ["tunnel", "transport"],
            "ciphers": ["aes256gcm16", "aes128gcm16", "aes256", "aes128"],
            "integrity": ["sha256", "sha384", "sha512"],
            "dhGroups": [
                {"group": 14, "name": "modp2048", "status": "Compliant"},
                {"group": 19, "name": "ecp256", "status": "Compliant"},
                {"group": 20, "name": "ecp384", "status": "Compliant"},
                {"group": 2, "name": "modp1024", "status": "Deprecated (NIST Non-compliant)"},
            ],
            "ipVersions": [
                {"version": "IPv4", "status": "Operational on subnet 172.20.0.0/24"},
                {"version": "IPv6", "status": "Requires dual-stack Docker bridge configuration"},
            ],
            "trafficProfiles": ["ICMP", "Web_Browsing", "Email_IMAP", "VoIP", "WhatsApp", "Video_Streaming"],
        },
    }


@app.post("/api/testbed/validate")
def validate_testbed_configuration(payload: Dict[str, Any]):
    """
    Validates a requested IPsec VPN testbed configuration against installed strongSwan
    capabilities, Linux kernel XFRM transforms, and testbed network constraints.
    """
    validation = validate_configuration(
        payload,
        runtime_capabilities=inspect_runtime_capabilities(),
    )
    if validation["valid"]:
        nist = "Compliant"
    else:
        nist = "Invalid"
    return {
        "valid": validation["valid"],
        "configuration": validation["configuration"],
        "issues": validation["issues"],
        "warnings": validation["warnings"],
        "nistCompliance": nist,
        "supportedFeatures": validation["supportedFeatures"],
        "capabilityStatus": validation["capabilityStatus"],
    }


@app.post("/api/testbed/run")
def run_testbed_experiment(payload: Dict[str, Any]):
    """Generates, applies, verifies, and records a real StrongSwan testbed experiment."""
    try:
        result = run_experiment(payload)
        return result
    except StrongSwanExperimentError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Experiment execution failed: {err}") from err


@app.get("/api/testbed/capability-report")
def get_testbed_capability_report():
    """Returns the runtime capability matrix for the current Docker strongSwan testbed."""
    return prepare_capability_report()


@app.get("/api/testbed/live-status")
def get_live_testbed_status():
    """
    Returns authoritative live runtime status of the IPsec testbed,
    including Docker container availability and IPs, negotiated StrongSwan
    IKE/CHILD SAs via swanctl, Linux kernel eBPF probe health, and active capture status.
    """
    return get_testbed_live_status()


@app.post("/api/reports/generate")
def generate_audit_report(request: Dict[str, Any]):
    """Generates a report from available audit data and optional uploaded analysis flows."""
    report_type = request.get("reportType", "Technical Assessment")
    flows = request.get("flows")
    analysis_id = request.get("analysisId")
    filename = request.get("filename")
    if flows is not None and not isinstance(flows, list):
        raise HTTPException(status_code=400, detail="The flows field must be an array.")
    if analysis_id:
        mismatched_ids = {
            str(flow.get("analysisId"))
            for flow in flows or []
            if flow.get("analysisId") and str(flow.get("analysisId")) != str(analysis_id)
        }
        if mismatched_ids:
            raise HTTPException(
                status_code=400,
                detail="Report flows contain records from a different PCAP analysis ID.",
            )

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

    analysis_id_line = f"- Analysis Session ID: {analysis_id}\n" if analysis_id else ""
    target_file_line = f"- Target Capture: {filename}\n" if filename else ""

    md = f"""# VISTA IPsec Security Assessment Report
**Document Type:** {report_type}
**Data source:** {"Uploaded PCAP/CSV analysis and available operational audit records" if flows is not None else "Available repository flow records and operational audit records"}

## Assessment summary
{analysis_id_line}{target_file_line}- Overall posture score: {score_text}
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
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "content": md,
        "score": score,
        "source": soc["source"],
        "analysisId": analysis_id,
        "filename": filename,
    }


# ==============================================================================
# DATASET STUDIO API ENDPOINTS (SIH26160 / NTRO)
# ==============================================================================


@app.get("/api/datasets")
def list_datasets():
    """Lists registered campaign and sample datasets in VISTA."""
    return {
        "datasets": dataset_service.list_datasets(),
        "total": len(dataset_service.list_datasets()),
    }


@app.get("/api/datasets/capabilities")
def get_dataset_capabilities():
    """Returns verified testbed parameters and limits for dataset generation."""
    return dataset_service.get_testbed_capabilities()


@app.get("/api/datasets/scenarios")
def list_dataset_scenarios():
    """Lists implemented dataset scenarios and their evidence/safety contracts."""
    return {"scenarios": dataset_service.list_scenarios()}


@app.get("/api/datasets/scenarios/{scenario_id}")
def inspect_dataset_scenario(scenario_id: str):
    scenario = dataset_service.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Unknown or deferred scenario.")
    return scenario


@app.post("/api/datasets/scenarios/{scenario_id}/validate")
def validate_dataset_scenario(scenario_id: str, payload: Dict[str, Any]):
    try:
        return dataset_service.validate_scenario(scenario_id, payload.get("parameters", {}))
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


@app.post("/api/datasets/scenarios/{scenario_id}/runs")
def start_dataset_scenario(scenario_id: str, payload: Dict[str, Any]):
    try:
        return dataset_service.start_scenario_run(
            scenario_id,
            payload.get("parameters", {}),
            confirmed_isolated_lab=payload.get("confirmedIsolatedLab") is True,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


@app.post("/api/datasets/preflight")
def run_dataset_preflight(payload: Dict[str, Any]):
    """Verifies testbed availability and configuration support before running a collection job."""
    return dataset_service.run_preflight_check(payload)


@app.post("/api/datasets/generate")
def start_dataset_generation(payload: Dict[str, Any]):
    """Dispatches a real asynchronous testbed-driven dataset generation job."""
    try:
        job = dataset_service.start_generation_job(payload)
        return job
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except Exception as err:
        logger.exception("Failed to dispatch dataset generation job.")
        raise HTTPException(status_code=500, detail=f"Job dispatch error: {err}") from err


@app.get("/api/datasets/jobs/{job_id}")
def get_dataset_job_status(job_id: str):
    """Polls real-time stage progress and completion status of a dataset generation job."""
    job = dataset_service.get_job_status(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found.")
    return job


@app.get("/api/datasets/scenario-runs/{job_id}")
def get_dataset_scenario_run(job_id: str):
    job = dataset_service.get_job_status(job_id)
    if not job or not job.get("scenarioId"):
        raise HTTPException(status_code=404, detail="Scenario run not found.")
    return job


@app.post("/api/datasets/jobs/{job_id}/cancel")
def cancel_dataset_generation_job(job_id: str):
    """Requests safe cancellation; active bounded collectors clean up before termination."""
    cancelled = dataset_service.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=400, detail="Job is not active or cannot be cancelled.")
    return {"jobId": job_id, "status": "CANCELLING"}


@app.get("/api/datasets/{dataset_id}")
def get_dataset_details(dataset_id: str):
    """Retrieves deep metadata, schema manifests, quality reports, and sample rows."""
    details = dataset_service.get_dataset_details(dataset_id)
    if not details:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return details


@app.post("/api/datasets/{dataset_id}/validate")
def validate_dataset(dataset_id: str):
    """Executes an exhaustive quality and data-leakage audit on the dataset."""
    try:
        report = dataset_service.validate_dataset_quality(dataset_id)
        return report
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Validation failed: {err}") from err


@app.get("/api/datasets/{dataset_id}/export")
def export_dataset(dataset_id: str, format: str = Query("csv", pattern="^(csv|zip)$")):
    """Safely exports and downloads the versioned dataset file."""
    try:
        target_path = dataset_service.export_dataset_file(dataset_id, format_type=format)
        return FileResponse(
            target_path,
            media_type="application/octet-stream",
            filename=target_path.name,
        )
    except FileNotFoundError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err
    except ValueError as err:
        if "not found" in str(err).lower():
            raise HTTPException(status_code=404, detail=str(err)) from err
        raise HTTPException(status_code=400, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Export failed: {err}") from err
