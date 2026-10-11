import hashlib
import sys
from pathlib import Path

from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.main import app  # noqa: E402


def test_uploaded_csv_response_carries_the_hash_of_its_source_bytes():
    content = b"packets,bytes,duration\n1,100,0\n"
    response = TestClient(app).post(
        "/api/analyze/csv?model=xgboost",
        files={"file": ("fixture.csv", content, "text/csv")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["sourceCaptureSha256"] == hashlib.sha256(content).hexdigest()
    assert body["sourceCaptureSizeBytes"] == len(content)


def test_generated_report_includes_backend_creation_timestamp():
    response = TestClient(app).post("/api/reports/generate", json={"reportType": "Technical Assessment"})

    assert response.status_code == 200
    assert response.json()["createdAt"]
