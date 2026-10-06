"""Test script to verify all backend endpoints"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from starlette.testclient import TestClient
from backend.main import app

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
    print("[PASS] GET /api/status passed (XGBoost loaded:", data["models"]["xgboost"]["loaded"], ")")

    # 3. Audit Summary
    res = client.get("/api/audit/summary")
    assert res.status_code == 200, f"Audit summary failed: {res.text}"
    print("[PASS] GET /api/audit/summary passed: overallScore =", res.json()["overallScore"])

    # 4. Audit Sessions
    res = client.get("/api/audit/sessions?limit=5")
    assert res.status_code == 200, f"Audit sessions failed: {res.text}"
    assert len(res.json()) == 5
    print("[PASS] GET /api/audit/sessions passed (retrieved 5 sessions)")

    # 5. ML Metrics
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200, f"Metrics failed: {res.text}"
    print("[PASS] GET /api/ml/metrics passed")

    # 6. SOC Status
    res = client.get("/api/soc/status")
    assert res.status_code == 200, f"SOC status failed: {res.text}"
    print("[PASS] GET /api/soc/status passed: packets =", res.json()["packetsAnalyzed"])

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
        print(f"[PASS] POST /api/analyze/pcap passed! Flows: {len(res_data['flows'])}, "
              f"Pred: {flow0['attackType']}, Conf: {flow0['confidence']}, SPI: {flow0['spi']}")

    # 8. Report Generation
    res = client.post("/api/reports/generate", json={"reportType": "Technical Assessment"})
    assert res.status_code == 200
    print("[PASS] POST /api/reports/generate passed")

    # 9. eBPF Kernel Event Stream
    res = client.get("/api/ebpf/events?limit=6")
    assert res.status_code == 200
    ebpf_data = res.json()
    assert ebpf_data["status"] == "STREAMING"
    assert len(ebpf_data["events"]) > 0
    print(f"[PASS] GET /api/ebpf/events passed ({len(ebpf_data['events'])} events from ring buffer)")

    # 10. eBPF Subsystem Status
    res = client.get("/api/ebpf/status")
    assert res.status_code == 200
    status_data = res.json()
    assert status_data["status"] == "RUNNING"
    print(f"[PASS] GET /api/ebpf/status passed (mode: {status_data['mode']}, probes: {len(status_data['probes'])})")

    # 11. PCAP + eBPF Flow Fusion
    dummy_flows = [{
        "flow_id": "ESP|172.20.0.2|172.20.0.10",
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

    print("\nALL BACKEND API TESTS (INCLUDING EBPF) PASSED SUCCESSFULLY! [OK]")

if __name__ == "__main__":
    run_tests()
