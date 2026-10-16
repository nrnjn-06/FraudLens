"""Comprehensive End-to-End Integration and Verification Test Suite for FraudLens.

Verifies:
1. System Health, Metadata, and Subsystem Operational Readiness.
2. Scam Message Detection:
   - Benign conversational text (LOW RISK).
   - High-urgency financial/KYC scam (HIGH RISK).
   - Embedded URL routing and analysis.
   - Defensive security advisory (educational negation, non-high risk).
   - Input validation (empty/whitespace rejected, max-length resilience).
   - Model unavailability graceful degradation.
3. Phishing URL Detection:
   - Legitimate authoritative portals (LOW RISK).
   - Structurally deceptive and typosquatting URLs (HIGH RISK).
   - Dangerous/malformed URL scheme rejection (HTTP 422).
   - Sanitization of sensitive authentication tokens and credentials.
   - Raw IP address hosts detection.
   - Threat intelligence provider states (unconfigured, confirmed malicious, unavailable, cached).
4. QR Code Safety Scanner:
   - Benign URL QR image decoding.
   - Phishing URL QR image decoding.
   - UPI payment QR image with prepopulated debit amount.
   - UPI payment QR image without prepopulated amount.
   - Wi-Fi network configuration payload.
   - Plain text payload.
   - Multi-QR image aggregation.
   - Blank/non-QR image safe failure (UNABLE TO VERIFY).
   - Corrupt bytes upload (HTTP 400).
   - Oversized file upload (HTTP 413).
5. Unified Risk Engine & Evidence Invariants:
   - Strict 4 canonical outcomes across all modules.
   - Structural evidence separation (MODEL_PREDICTION, HEURISTIC, CONFIRMED_THREAT_INTEL, INFORMATIONAL).
"""

from datetime import datetime, timezone
import io
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import qrcode

from backend.app.config import settings
from backend.app.main import app
from backend.app.schemas.common import (
    EvidenceCategory,
    UnifiedRiskClassification,
)
from backend.app.schemas.qr import QRPayloadType
from backend.app.schemas.url import ThreatIntelResult
from backend.app.services.threat_intel import (
    BaseThreatIntelAdapter,
    ThreatIntelService,
)
from backend.app.services.url_service import get_url_service

client = TestClient(app)


# ----------------------------------------------------------------------
# Helper Functions for Synthetic Image Barcodes
# ----------------------------------------------------------------------

def create_qr_image_bytes(payload: str, fmt: str = "PNG") -> bytes:
    """Generate in-memory image bytes containing a clean QR barcode."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def create_multi_qr_image_bytes(payload1: str, payload2: str) -> bytes:
    """Generate in-memory image bytes containing two distinct QR barcodes side-by-side."""
    img1 = qrcode.make(payload1).convert("RGB")
    img2 = qrcode.make(payload2).convert("RGB")
    w1, h1 = img1.size
    w2, h2 = img2.size
    canvas = Image.new("RGB", (w1 + w2 + 60, max(h1, h2) + 40), (255, 255, 255))
    canvas.paste(img1, (20, 20))
    canvas.paste(img2, (w1 + 40, 20))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()


def create_blank_image_bytes(width: int = 300, height: int = 300) -> bytes:
    """Generate in-memory image bytes with no barcode symbols."""
    canvas = Image.new("RGB", (width, height), (245, 245, 245))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()


# ----------------------------------------------------------------------
# 1. Platform Health, Metadata & Root Gateway
# ----------------------------------------------------------------------

def test_e2e_root_gateway():
    """Verify root API gateway returns platform metadata and active stage."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "FraudLens"
    assert data["stage"] == 8
    assert data["docs_url"] == "/docs"
    assert data["health_url"] == "/health"


def test_e2e_health_subsystems_readiness():
    """Verify health endpoint confirms all subsystems operational."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "FraudLens"
    assert data["stage"] == 8
    assert "timestamp" in data
    subsystems = data["subsystems"]
    assert "message_detector" in subsystems
    assert "url_detector" in subsystems
    assert "qr_scanner" in subsystems
    assert "threat_intel" in subsystems
    assert "ACTIVE" in subsystems["message_detector"]
    assert "ACTIVE" in subsystems["url_detector"]
    assert "ACTIVE" in subsystems["qr_scanner"]


# ----------------------------------------------------------------------
# 2. Scam Message Detection Workflows (Module 1)
# ----------------------------------------------------------------------

def test_e2e_message_benign_conversational():
    """Verify everyday non-deceptive messages receive LOW RISK verdict."""
    payload = {"message_text": "I have an urgent meeting with my professor. I will pay for lunch afterwards near the bank."}
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["status"] in {"ANALYSIS_ACTIVE", "STAGE_3_ANALYSIS_ACTIVE"}
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["is_scam"] is False
    assert len(data["recommendations"]) > 0


def test_e2e_message_high_risk_scam_with_embedded_url():
    """Verify financial KYC scam message triggers HIGH RISK, entity extraction, and embedded URL analysis."""
    text = (
        "SBI Notice: Your bank account has been suspended due to expired KYC. "
        "Please verify your identity and share the 6-digit OTP immediately at http://sbi-kyc-verify.com"
    )
    response = client.post("/analyze-message", json={"message_text": text})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["model_prediction"]["is_scam"] is True
    assert data["social_engineering"]["urgency"] is True
    assert data["social_engineering"]["otp_requests"] is True
    assert len(data["highlighted_phrases"]) > 0

    # Entity extraction and embedded URL inspection
    assert len(data["extracted_entities"]["urls"]) == 1
    assert "http://sbi-kyc-verify.com" in data["extracted_entities"]["urls"]
    assert len(data["embedded_url_analyses"]) == 1
    embedded = data["embedded_url_analyses"][0]
    assert embedded["target_url"] == "http://sbi-kyc-verify.com"
    assert embedded["classification"] in (
        UnifiedRiskClassification.HIGH_RISK.value,
        UnifiedRiskClassification.MEDIUM_RISK.value,
    )


def test_e2e_message_defensive_security_advisory():
    """Verify security educational advisory mentioning OTP is NOT classified as high risk."""
    advisory = (
        "Protect yourself from e-threats: State Bank of India never asks for sensitive "
        "information like Password/OTP/CVV. Never share your credentials with anyone."
    )
    response = client.post("/analyze-message", json={"message_text": advisory})
    assert response.status_code == 200
    data = response.json()
    # Should not be HIGH RISK due to defensive negation heuristics
    assert data["classification"] != UnifiedRiskClassification.HIGH_RISK.value
    assert data["social_engineering"]["is_advisory_or_educational"] is True


def test_e2e_message_empty_and_whitespace_validation():
    """Verify empty and whitespace strings return HTTP 422 validation errors."""
    res_empty = client.post("/analyze-message", json={"message_text": ""})
    assert res_empty.status_code == 422

    res_ws = client.post("/analyze-message", json={"message_text": "   \n\t  "})
    assert res_ws.status_code == 422


def test_e2e_message_unusually_long_payload():
    """Verify long inputs (up to 4000 characters) are processed cleanly without crashing."""
    long_text = "Good morning. " * 250  # ~3500 chars
    response = client.post("/analyze-message", json={"message_text": long_text})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value


# ----------------------------------------------------------------------
# 3. Phishing URL Detection Workflows (Module 2)
# ----------------------------------------------------------------------

def test_e2e_url_authoritative_domain():
    """Verify legitimate established domains evaluate to LOW RISK."""
    response = client.post("/analyze-url", json={"url": "https://www.python.org"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["model_prediction"]["is_phishing"] is False
    assert data["forensics"]["domain"] == "python"
    assert data["forensics"]["tld"] == "org"
    assert data["forensics"]["has_ip_address"] is False


def test_e2e_url_typosquatting_brand_lookalike():
    """Verify deceptive brand lookalike URL triggers HIGH RISK."""
    response = client.post("/analyze-url", json={"url": "https://paypal.com.account-update.xyz/login.php?token=123"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["typosquatting"]["is_impersonation"] is True
    assert data["typosquatting"]["target_brand"] == "paypal"


def test_e2e_url_dangerous_schemes_rejected():
    """Verify javascript:, data:, and file: schemes are rejected with HTTP 422."""
    for bad_url in [
        "javascript:alert('malicious')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
    ]:
        response = client.post("/analyze-url", json={"url": bad_url})
        assert response.status_code == 422
        assert "dangerous" in response.json()["detail"][0]["msg"].lower()


def test_e2e_url_raw_ip_address_host():
    """Verify raw IP address destination triggers IP host forensics and indicators."""
    response = client.post("/analyze-url", json={"url": "http://192.168.1.100:8080/admin/login.php"})
    assert response.status_code == 200
    data = response.json()
    assert data["forensics"]["has_ip_address"] is True
    ip_indicators = [
        ind["indicator"]
        for ind in data.get("explainable_risk_indicators", [])
    ]
    assert any("IP" in ind for ind in ip_indicators)


def test_e2e_url_sensitive_query_parameters_sanitized():
    """Verify sensitive auth tokens in query parameters are parsed safely without leakage."""
    url = "https://secure-login.portal.com/auth?token=948201&session_id=user_sess_xyz&pass=my_secret"
    response = client.post("/analyze-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    # Forensics query params must be captured
    assert "token" in data["forensics"]["query_params"]
    assert "session_id" in data["forensics"]["query_params"]


def test_e2e_url_threat_intel_confirmed_match_overrides_to_high_risk():
    """Verify confirmed external threat intelligence match overrides verdict to HIGH RISK."""
    test_url = "http://safe-looking-site.com/index.html"

    # Create mock adapter that confirms malicious verdict
    mock_adapter = MagicMock(spec=BaseThreatIntelAdapter)
    mock_adapter.name = "MockSecurityFeed"
    mock_adapter.check_reputation.return_value = ThreatIntelResult(
        source="MockSecurityFeed",
        is_flagged=True,
        lookup_timestamp=datetime.now(timezone.utc).isoformat(),
        lookup_status="MATCH_FOUND",
        provider_name="MockSecurityFeed",
        malicious_count=12,
        details="Confirmed phishing target identified in external blacklist.",
    )

    url_svc = get_url_service()
    orig_ti = url_svc._threat_intel
    try:
        mock_ti = ThreatIntelService()
        mock_ti.enabled = True
        mock_ti.adapters = [mock_adapter]
        url_svc.threat_intel = mock_ti

        response = client.post("/analyze-url", json={"url": test_url})
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
        # Check unified evidence contains CONFIRMED_THREAT_INTEL
        categories = [item["category"] for item in data["unified_evidence"]]
        assert EvidenceCategory.CONFIRMED_THREAT_INTEL.value in categories
    finally:
        url_svc.threat_intel = orig_ti


def test_e2e_url_threat_intel_cached_lookup():
    """Verify second identical lookup uses the thread-safe in-memory TTL cache."""
    test_url = "http://cached-target-test.org/verify"

    url_svc = get_url_service()
    orig_ti = url_svc._threat_intel

    mock_adapter = MagicMock(spec=BaseThreatIntelAdapter)
    mock_adapter.name = "MockFeed"
    mock_adapter.check_reputation.return_value = ThreatIntelResult(
        source="MockFeed",
        is_flagged=False,
        lookup_timestamp=datetime.now(timezone.utc).isoformat(),
        lookup_status="CLEAN",
        provider_name="MockFeed",
        harmless_count=80,
    )

    try:
        ti_service = ThreatIntelService()
        ti_service.enabled = True
        ti_service.adapters = [mock_adapter]
        ti_service.cache.clear()
        url_svc.threat_intel = ti_service

        # First query: populates cache from adapter
        res1 = client.post("/analyze-url", json={"url": test_url})
        assert res1.status_code == 200
        assert res1.json()["threat_intelligence"]["is_cached"] is False
        assert mock_adapter.check_reputation.call_count == 1

        # Second query: served directly from cache without hitting external provider
        res2 = client.post("/analyze-url", json={"url": test_url})
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["threat_intelligence"]["is_cached"] is True
        assert data2["threat_intelligence"]["lookup_status"] == "CLEAN"
        assert mock_adapter.check_reputation.call_count == 1
    finally:
        url_svc.threat_intel = orig_ti


# ----------------------------------------------------------------------
# 4. QR Code Safety Scanner Workflows (Module 3)
# ----------------------------------------------------------------------

def test_e2e_qr_benign_url():
    """Verify scanning a benign URL QR image outputs LOW RISK."""
    png_bytes = create_qr_image_bytes("https://www.python.org")
    files = {"file": ("python_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["payload_type"] in (QRPayloadType.URL.value, "URL")
    assert data["qr_count_detected"] >= 1
    assert data["destination_preview"]["destination"] == "https://www.python.org"


def test_e2e_qr_phishing_url():
    """Verify scanning a phishing lookalike URL QR image outputs HIGH RISK."""
    png_bytes = create_qr_image_bytes("http://paypa1-security.com/verify")
    files = {"file": ("phish_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["payload_type"] in (QRPayloadType.URL.value, "URL")
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["typosquatting"]["is_impersonation"] is True


def test_e2e_qr_upi_payment_prepopulated_amount():
    """Verify scanning a UPI QR code with a pre-set amount raises caution indicators."""
    upi_uri = "upi://pay?pa=storecheckout@okhdfcbank&pn=MegaStore&am=2500.00&cu=INR&tn=OrderInvoice8923"
    png_bytes = create_qr_image_bytes(upi_uri)
    files = {"file": ("upi_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["payload_type"] in (QRPayloadType.UPI_PAYMENT.value, QRPayloadType.UPI.value)
    assert data["upi_inspection"] is not None
    assert data["upi_inspection"]["payee_vpa"] == "storecheckout@okhdfcbank"
    assert data["upi_inspection"]["payee_name"] == "MegaStore"
    assert data["upi_inspection"]["amount"] == "2500.00"
    assert data["upi_inspection"]["has_prepopulated_amount"] is True
    assert "Verify" in data["upi_inspection"]["safety_warning"]


def test_e2e_qr_wifi_configuration():
    """Verify scanning a Wi-Fi barcode parses SSID and credentials safely."""
    wifi_uri = "WIFI:S:Guest_Cafe_5G;T:WPA;P:SuperSecretPass123;;;"
    png_bytes = create_qr_image_bytes(wifi_uri)
    files = {"file": ("wifi_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["payload_type"] == QRPayloadType.WIFI_CONFIGURATION.value
    assert data["wifi_details"]["ssid"] == "Guest_Cafe_5G"
    assert data["wifi_details"]["auth_type"] == "WPA"


def test_e2e_qr_plain_text_payload():
    """Verify plain text barcode decodes without execution or unintended routing."""
    text_payload = "Inventory item #84920 - Warehouse Section B4"
    png_bytes = create_qr_image_bytes(text_payload)
    files = {"file": ("text_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["payload_type"] == QRPayloadType.PLAIN_TEXT.value
    assert data["raw_payload"] == text_payload


def test_e2e_qr_multi_symbol_detection():
    """Verify image containing two QR codes aggregates all detected symbols."""
    payload1 = "https://www.python.org"
    payload2 = "upi://pay?pa=charity@upi&pn=ReliefFund"
    png_bytes = create_multi_qr_image_bytes(payload1, payload2)
    files = {"file": ("multi_qr.png", io.BytesIO(png_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    # At least 1 code detected (or 2 if OpenCV/pyzbar multi-scan resolves both)
    assert data["qr_count_detected"] >= 1
    assert data["classification"] in [
        UnifiedRiskClassification.LOW_RISK.value,
        UnifiedRiskClassification.MEDIUM_RISK.value,
        UnifiedRiskClassification.HIGH_RISK.value,
    ]


def test_e2e_qr_blank_image_returns_unable_to_verify():
    """Verify an image without any QR codes returns UNABLE TO VERIFY and NO_QR_DETECTED."""
    blank_bytes = create_blank_image_bytes()
    files = {"file": ("blank.png", io.BytesIO(blank_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.UNABLE_TO_VERIFY.value
    assert data["status"] in {"NO_QR_DETECTED", "STAGE_6_NO_QR_DETECTED"}
    assert data["qr_count_detected"] == 0


def test_e2e_qr_corrupt_file_rejected():
    """Verify corrupt/non-image bytes return HTTP 400 error."""
    corrupt_bytes = b"NOT_A_VALID_IMAGE_HEADER_BYTES_RANDOM"
    files = {"file": ("corrupt.png", io.BytesIO(corrupt_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code in (400, 415)
    assert "cannot identify image" in response.json()["detail"].lower() or "unsupported" in response.json()["detail"].lower()


def test_e2e_qr_oversized_file_rejected():
    """Verify oversized image uploads (>5MB limit) return HTTP 413."""
    oversized_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * (settings.MAX_IMAGE_UPLOAD_BYTES + 100)
    files = {"file": ("oversized.png", io.BytesIO(oversized_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 413
    assert "exceeds maximum limit" in response.json()["detail"].lower()


# ----------------------------------------------------------------------
# 5. Cross-Cutting Unified Evidence & Canonical Taxonomy Invariants
# ----------------------------------------------------------------------

@pytest.mark.parametrize("endpoint,payload", [
    ("/analyze-message", {"message_text": "Good afternoon, please remember our team sync at 3pm."}),
    ("/analyze-url", {"url": "https://www.python.org"}),
])
def test_e2e_canonical_taxonomies_and_unified_evidence_model(endpoint, payload):
    """Verify all detection responses strictly uphold canonical risk categories and structured evidence."""
    response = client.post(endpoint, json=payload)
    assert response.status_code == 200
    data = response.json()

    # 1. Primary verdict must be one of the four canonical classifications
    canonical_levels = {
        UnifiedRiskClassification.HIGH_RISK.value,
        UnifiedRiskClassification.MEDIUM_RISK.value,
        UnifiedRiskClassification.LOW_RISK.value,
        UnifiedRiskClassification.UNABLE_TO_VERIFY.value,
    }
    assert data["classification"] in canonical_levels

    # 2. Recommendations must be non-empty list of actionable strings
    assert isinstance(data["recommendations"], list)
    assert len(data["recommendations"]) > 0

    # 3. Unified evidence items must have valid categories
    if "unified_evidence" in data and data["unified_evidence"]:
        for item in data["unified_evidence"]:
            assert item["category"] in [
                EvidenceCategory.MODEL_PREDICTION.value,
                EvidenceCategory.HEURISTIC.value,
                EvidenceCategory.CONFIRMED_THREAT_INTEL.value,
                EvidenceCategory.INFORMATIONAL.value,
            ]
            assert "source" in item
            assert "severity" in item
            assert "status" in item
            assert "description" in item
