"""Test script to verify all backend endpoints"""
import sys
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from starlette.testclient import TestClient
from backend.main import app
from backend.services.model_service import model_service
from backend.services.posture_engine import posture_engine

def run_tests():
    client = TestClient(app)
    
    # 1. Health check
    res = client.get("/")
    assert res.status_code == 200, f"Root failed: {res.text}"
    print("[PASS] GET / passed:", res.json()["status"])

    # 2. Status
    res = client.get("/api/status")
    assert res.status_code == 200, f"Status failed: {res.text}"
    data = res.json()
    assert data["status"] == "ONLINE"
    assert data["models"]["xgboost"]["loaded"] is True
    assert data["models"]["xgboost"]["predictionTask"] == "flow traffic-label classification"
    assert data["models"]["xgboost"]["trainingDataScope"] == "synthetic development dataset"
    print("[PASS] GET /api/status passed (XGBoost loaded:", data["models"]["xgboost"]["loaded"], ")")

    # 3. Audit Summary
    res = client.get("/api/audit/summary")
    assert res.status_code == 200, f"Audit summary failed: {res.text}"
    audit_summary = res.json()
    assert audit_summary["overallScore"] is None
    assert audit_summary["assessedSessions"] == 0
    assert audit_summary["source"] == "No operational audit source configured"
    print("[PASS] GET /api/audit/summary reports no operational audit source")

    complete_session = {
        "encryption": "AES-CBC-128",
        "auth": "SHA1",
        "dhGroup": 19,
        "pfs": True,
        "antiReplay": True,
        "lifetime": 1800,
        "ikeVersion": 2,
        "riskScore": 0,
        "compliance": "Secure Compliant",
        "vulnerabilities": [],
    }
    evaluated = posture_engine.evaluate_session(complete_session)
    assert evaluated["riskScore"] == 50
    assert evaluated["compliance"] == "Medium Risk"
    supplied_summary = posture_engine.compute_summary_posture([complete_session])
    assert supplied_summary["overallScore"] == 50
    assert supplied_summary["mediumRiskCount"] == 1

    incomplete_summary = posture_engine.compute_summary_posture([
        {**complete_session, "antiReplay": None},
    ])
    assert incomplete_summary["overallScore"] is None
    assert incomplete_summary["assessedSessions"] == 0
    assert incomplete_summary["insufficientDataCount"] == 1
    print("[PASS] Posture engine recalculates supplied inputs and rejects incomplete sessions")

    # 4. Audit Sessions
    res = client.get("/api/audit/sessions?limit=5")
    assert res.status_code == 200, f"Audit sessions failed: {res.text}"
    assert res.json() == []
    print("[PASS] GET /api/audit/sessions excludes generated scenario records")

    # 5. ML Metrics
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200, f"Metrics failed: {res.text}"
    assert res.json()["evaluationProvenance"]["dataset"] == "Synthetic VISTA development dataset"
    assert "xgboost" in res.json()["metrics"]
    assert res.json()["shapProvenance"]["scope"]
    print("[PASS] GET /api/ml/metrics passed")

    # 6. SOC Status
    res = client.get("/api/soc/status")
    assert res.status_code == 200, f"SOC status failed: {res.text}"
    assert res.json()["securityScore"] is None
    print("[PASS] GET /api/soc/status passed: packets =", res.json()["rawPacketsCount"])

    # 7. PCAP Upload & Live Inference
    probe_pcap = ROOT / "captures" / "vista-outer-esp-probe.pcap"
    if probe_pcap.exists():
        with open(probe_pcap, "rb") as f:
            res = client.post(
                "/api/analyze/pcap?model=xgboost",
                files={"file": ("vista-outer-esp-probe.pcap", f, "application/octet-stream")},
            )
        assert res.status_code == 200, f"PCAP analysis failed: {res.text}"
        res_data = res.json()
        assert len(res_data["flows"]) > 0
        flow0 = res_data["flows"][0]
        assert flow0["predictionStatus"] in {"success", "insufficient_data", "unavailable"}
        assert res_data["totalPackets"] > 0
        if flow0["predictionStatus"] == "success":
            model_classes = data["models"]["xgboost"]["classes"]
            assert flow0["mlPrediction"]["label"] in model_classes
            assert flow0["mlPrediction"]["source"] == "ml_model"
            probability = flow0["mlPrediction"]["probability"]
            assert probability is None or 0 <= probability <= 1
            if probability is not None:
                assert probability == flow0["mlPrediction"]["probabilities"][flow0["mlPrediction"]["label"]]
                assert "calibration not evaluated" in flow0["mlPrediction"]["probabilityType"]
        print(f"[PASS] POST /api/analyze/pcap preserved observations; inference status: "
              f"{flow0['predictionStatus']}, SPI: {flow0['spi']}")

    capture = (
        ROOT / "captures" / "strongswan" / "normal" / "20261005T152919Z"
        / "icmp_normal_00.pcap"
    )
    if capture.exists():
        with open(capture, "rb") as f:
            res = client.post(
                "/api/analyze/pcap?model=xgboost",
                files={"file": (capture.name, f, "application/octet-stream")},
            )
        assert res.status_code == 200, f"Observed capture analysis failed: {res.text}"
        result = res.json()
        assert result["totalPackets"] > 0
        assert result["mlInference"]["status"] in {"success", "insufficient_data"}
        for flow in result["flows"]:
            assert flow["predictionStatus"] == "success"
            assert flow["mlPrediction"]["label"] in data["models"]["xgboost"]["classes"]
            probability = flow["mlPrediction"]["probability"]
            assert probability is None or 0 <= probability <= 1
            if probability is not None:
                assert probability == flow["mlPrediction"]["probabilities"][flow["mlPrediction"]["label"]]
        print("[PASS] Observed StrongSwan capture produced supported model outputs")

        with patch.object(model_service, "predict", side_effect=RuntimeError("test inference failure")):
            with open(capture, "rb") as f:
                failed_prediction = client.post(
                    "/api/analyze/pcap?model=xgboost",
                    files={"file": (capture.name, f, "application/octet-stream")},
                )
        assert failed_prediction.status_code == 200
        failed_result = failed_prediction.json()
        assert failed_result["totalPackets"] > 0
        assert failed_result["mlInference"]["status"] == "unavailable"
        assert "test inference failure" in failed_result["mlInference"]["error"]
        print("[PASS] PCAP observations remain available when model inference fails")

    incomplete = model_service.prepare_feature_dataframe([{
        "packets": 1,
        "bytes": 100,
        "duration": 0,
        "meanPacketLen": 100,
        "stdPacketLen": 0,
        "minPacketLen": 100,
        "maxPacketLen": 100,
        "forward_packet_count": 1,
        "backward_packet_count": 0,
        "forward_bytes": 100,
        "backward_bytes": 0,
        "outboundRatio": 1,
    }])
    missing_result = model_service.predict(incomplete)[0]
    assert missing_result["status"] == "insufficient_data"
    assert "mean_inter_arrival_time" in missing_result["missingFeatures"]
    print("[PASS] Missing model features return Insufficient Data instead of imputed values")

    csv_res = client.post(
        "/api/analyze/csv?model=xgboost",
        files={"file": ("incomplete.csv", "packets,bytes,duration\n1,100,0\n", "text/csv")},
    )
    assert csv_res.status_code == 200
    assert csv_res.json()["flows"][0]["predictionStatus"] == "insufficient_data"
    assert csv_res.json()["mlInference"]["status"] == "insufficient_data"
    print("[PASS] CSV observations are returned with an explicit insufficient-data result")

    # 8. Report Generation
    res = client.post("/api/reports/generate", json={"reportType": "Technical Assessment"})
    assert res.status_code == 200
    assert "Overall posture score: Not available" in res.json()["content"]
    assert "Assessed audit sessions: Not available" in res.json()["content"]
    print("[PASS] POST /api/reports/generate passed")

    if capture.exists():
        report_res = client.post(
            "/api/reports/generate",
            json={"reportType": "Technical Assessment", "flows": result["flows"]},
        )
        assert report_res.status_code == 200
        assert "Uploaded flow-class ML predictions" in report_res.json()["content"]
        assert "Prediction model: XGBoost (xgboost_classifier.joblib)" in report_res.json()["content"]
        assert "not confirmed incidents" in report_res.json()["content"]
        assert "Training data scope: synthetic development dataset" in report_res.json()["content"]
        print("[PASS] Uploaded model predictions and artifact provenance appear in reports")

        threats_res = client.post("/api/soc/threats", json={"flows": result["flows"]})
        assert threats_res.status_code == 200
        assert all(
            threat["verificationStatus"] == "Unverified model prediction"
            for threat in threats_res.json()
        )

    # 9. eBPF Kernel Event Stream
    res = client.get("/api/ebpf/events?limit=6")
    assert res.status_code == 200
    ebpf_data = res.json()
    assert ebpf_data["status"] in {
        "NATIVE_KERNEL_EBPF",
        "UNAVAILABLE",
    }
    assert isinstance(ebpf_data["events"], list)
    print(f"[PASS] GET /api/ebpf/events passed (mode: {ebpf_data['status']})")

    # 10. eBPF Subsystem Status
    res = client.get("/api/ebpf/status")
    assert res.status_code == 200
    status_data = res.json()
    assert status_data["status"] == "RUNNING"
    print(f"[PASS] GET /api/ebpf/status passed (mode: {status_data['mode']}, probes: {len(status_data['probes'])})")

    # 11. PCAP + eBPF Flow Fusion
    dummy_flows = [{
        "flow_id": "ESP|172.20.0.2|172.20.0.3",
        "spi": "0xc6dd300d",
        "timestamp_start": "2026-10-06T19:30:00Z",
        "packet_count": 12,
        "byte_count": 1872
    }]
    res = client.post("/api/ebpf/fuse", json={"flows": dummy_flows})
    assert res.status_code == 200
    fused_data = res.json()
    assert fused_data["fusedFlowCount"] == 1
    print("[PASS] POST /api/ebpf/fuse passed (correlated PCAP with live eBPF telemetry)")

    # 12. Separated ML Pipelines (AI Analysis & Threat Intelligence)
    res = client.get("/api/status")
    status_models = res.json()["models"]
    assert status_models["traffic_classifier"]["loaded"] is True
    assert status_models["attack_classifier"]["loaded"] is True
    assert "VoIP" in status_models["traffic_classifier"]["classes"]
    assert "DOS_FLOOD" in status_models["attack_classifier"]["classes"]
    print("[PASS] Separated model architectures validated: traffic_classifier & attack_classifier loaded")

    # Verify live PCAP returns both traffic and threat predictions
    if probe_pcap.exists():
        with open(probe_pcap, "rb") as f:
            res = client.post(
                "/api/analyze/pcap?model=attack_classifier",
                files={"file": ("vista-outer-esp-probe.pcap", f, "application/octet-stream")},
            )
        assert res.status_code == 200
        pcap_data = res.json()
        assert len(pcap_data["flows"]) > 0
        f0 = pcap_data["flows"][0]
        assert "trafficPrediction" in f0
        assert "threatPrediction" in f0
        assert f0["trafficPrediction"]["status"] in {"success", "insufficient_data"}
        assert f0["threatPrediction"]["status"] in {"success", "insufficient_data"}
        assert "trafficModel" in pcap_data["mlInference"]
        assert "threatModel" in pcap_data["mlInference"]
        print("[PASS] PCAP analysis outputs separate trafficPrediction (AI Analysis) and threatPrediction (Threat Intel)")

    print("\nALL BACKEND API TESTS (INCLUDING EBPF & SEPARATED ML) PASSED SUCCESSFULLY! [OK]")

if __name__ == "__main__":
    run_tests()
