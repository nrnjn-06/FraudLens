"""Tests for API contracts, schema validation, and error handling."""

import io
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

ALLOWED_CLASSIFICATIONS = {"HIGH RISK", "MEDIUM RISK", "LOW RISK", "UNABLE TO VERIFY"}


def test_url_contract_valid():
    """Verify POST /analyze-url complies with schema and unified classifications."""
    payload = {"url": "https://secure-login-update-account.com/verify?token=123"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["target_url"] == payload["url"]
    assert data["classification"] in ALLOWED_CLASSIFICATIONS
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["model_name"] == "RandomForest_URL_v1"
    assert "confidence" in data["model_prediction"]
    assert data["forensics"]["hostname"] == "secure-login-update-account.com"
    assert data["forensics"]["query_params"] == {"token": "123"}
    assert isinstance(data["evidence"], list)
    assert isinstance(data["recommendations"], list)
    assert "timestamp" in data


def test_url_contract_invalid_empty():
    """Verify POST /analyze-url rejects empty strings."""
    response = client.post("/analyze-url", json={"url": "   "})
    assert response.status_code == 422


def test_url_contract_dangerous_scheme():
    """Verify POST /analyze-url rejects javascript: pseudo-URLs."""
    response = client.post("/analyze-url", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422


def test_message_contract_valid():
    """Verify POST /analyze-message complies with schema, performs entity extraction, and routes URLs."""
    payload = {
        "message_text": "URGENT: Your bank account is locked. Update KYC at https://fakebank.xyz or call 9876543210. Pay via support@icici."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["original_text"] == payload["message_text"]
    assert data["classification"] in ALLOWED_CLASSIFICATIONS
    assert data["classification"] in {"HIGH RISK", "MEDIUM RISK"}
    assert data["status"] in {"ANALYSIS_ACTIVE", "STAGE_3_ANALYSIS_ACTIVE"}
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["is_scam"] is True
    assert data["model_prediction"]["model_name"] == "LogisticRegression_TFIDF_v1"

    # Verify entity extraction
    entities = data["extracted_entities"]
    assert any("fakebank.xyz" in u for u in entities["urls"])
    assert len(entities["phone_numbers"]) >= 1
    assert "support@icici" in entities["upi_ids"]

    # Verify embedded URL was routed into the internal URL detector
    assert len(data["embedded_url_analyses"]) >= 1
    assert data["embedded_url_analyses"][0]["classification"] in ALLOWED_CLASSIFICATIONS


def test_message_contract_invalid_empty():
    """Verify POST /analyze-message rejects empty message strings."""
    response = client.post("/analyze-message", json={"message_text": "   "})
    assert response.status_code == 422


def test_qr_contract_valid_image():
    """Verify POST /analyze-qr accepts valid image headers and returns contract."""
    # 1x1 transparent PNG magic bytes
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    files = {"file": ("test.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] in ALLOWED_CLASSIFICATIONS
    assert data["classification"] == "UNABLE TO VERIFY"
    assert data["status"] in {"NO_QR_DETECTED", "ANALYSIS_ACTIVE", "STAGE_6_NO_QR_DETECTED", "STAGE_6_ANALYSIS_ACTIVE"}
    assert data["destination_preview"] is not None
    assert data["upi_inspection"] is not None


def test_qr_contract_empty_file():
    """Verify POST /analyze-qr rejects empty files."""
    files = {"file": ("empty.png", io.BytesIO(b""), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 400


def test_qr_contract_invalid_format():
    """Verify POST /analyze-qr rejects non-image text files."""
    files = {"file": ("not_an_image.txt", io.BytesIO(b"Hello world text file"), "text/plain")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 415
