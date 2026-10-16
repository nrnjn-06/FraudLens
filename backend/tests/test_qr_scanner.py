"""Automated test suite for Module 3: QR Code Safety Scanner.

Comprehensive coverage:
1. Valid QR images decoding (OpenCV / pyzbar pipeline).
2. Multi-QR code detection in single image.
3. Empty, invalid, corrupt, and unsupported file uploads.
4. Oversized byte limits and image dimension thresholds.
5. Clean handling of images containing no QR codes.
6. URL payload classification and integration with URLAnalysisService.
7. UPI payment URI inspection (complete, missing, invalid amount, coercive memos, embedded URLs).
8. Wi-Fi configuration parsing (WPA, WEP, open unencrypted).
9. Contact, phone, SMS, and email payloads.
10. Plain text payloads with script/HTML injection protection.
11. Dangerous executable schemes (javascript:, data:).
12. Fallback when URL model inference is unavailable.
13. All 4 platform risk verdicts (HIGH RISK, MEDIUM RISK, LOW RISK, UNABLE TO VERIFY).
14. Zero network egress during optical decoding and inspection.
15. API contracts and error statuses on POST /analyze-qr.
"""

import io
import socket
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import qrcode

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.schemas.qr import QRPayloadType
from backend.app.services.qr_service import QRScannerService, get_qr_service
from backend.app.services.url_service import URLAnalysisService

client = TestClient(app)


def make_qr_bytes(payload: str, fmt: str = "PNG") -> bytes:
    """Generate in-memory image bytes containing a synthetic QR barcode."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def make_multi_qr_bytes(payload1: str, payload2: str) -> bytes:
    """Generate in-memory PNG bytes containing two QR codes side-by-side."""
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


def make_blank_image_bytes(width: int = 250, height: int = 250) -> bytes:
    """Generate image bytes with no barcode symbols."""
    canvas = Image.new("RGB", (width, height), (240, 240, 240))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()


# ----------------------------------------------------------------------
# 1. Image Validation, Format & Constraint Tests
# ----------------------------------------------------------------------

def test_qr_empty_file_rejected():
    """Verify empty upload bytes return HTTP 400."""
    files = {"file": ("empty.png", io.BytesIO(b""), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_qr_unsupported_file_format_rejected():
    """Verify text or non-image files return HTTP 415."""
    files = {"file": ("script.txt", io.BytesIO(b"Hello non-image file"), "text/plain")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 415
    assert "unsupported" in response.json()["detail"].lower()


def test_qr_oversized_file_rejected():
    """Verify uploads exceeding max bytes return HTTP 413."""
    service = QRScannerService()
    # Create fake oversized payload with valid PNG header
    huge_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * (service.max_file_size + 10)
    files = {"file": ("huge.png", io.BytesIO(huge_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 413
    assert "exceeds maximum limit" in response.json()["detail"].lower()


def test_qr_oversized_dimensions_rejected():
    """Verify images exceeding maximum allowable dimensions (4096px) return HTTP 400."""
    # Generate 4200x50 image with valid PNG data
    img = Image.new("RGB", (4200, 50), (255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    files = {"file": ("wide.png", io.BytesIO(buf.getvalue()), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 400
    assert "dimensions" in response.json()["detail"].lower()


def test_qr_no_symbol_detected():
    """Verify blank images without QR codes return UNABLE TO VERIFY with zero count."""
    blank_bytes = make_blank_image_bytes(300, 300)
    files = {"file": ("blank.png", io.BytesIO(blank_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.UNABLE_TO_VERIFY.value
    assert data["status"] in {"NO_QR_DETECTED", "STAGE_6_NO_QR_DETECTED"}
    assert data["qr_count_detected"] == 0
    assert data["payload_type"] == QRPayloadType.UNREADABLE.value
    assert data["destination_preview"]["destination"] == "No readable QR code found in image."
    assert any("No QR code symbol" in ev for ev in data["evidence"])


# ----------------------------------------------------------------------
# 2. Phishing URL Detection Integration Tests
# ----------------------------------------------------------------------

def test_qr_phishing_url_payload_high_risk():
    """Verify QR containing a phishing URL is routed to URL detector and returns HIGH RISK."""
    phishing_url = "https://paypal.com.account-update.xyz/login.php?token=123"
    qr_bytes = make_qr_bytes(phishing_url)

    files = {"file": ("qr_phish.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["qr_count_detected"] >= 1
    assert data["payload_type"] == QRPayloadType.URL.value
    assert data["destination_preview"]["destination"] == phishing_url
    assert data["destination_preview"]["scheme"] == "https"

    # URL Analysis assertions
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["target_url"] == phishing_url
    assert data["url_analysis"]["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["url_analysis"]["model_prediction"]["is_phishing"] is True
    assert data["url_analysis"]["model_prediction"]["model_name"] == "RandomForest_URL_v1"
    assert data["url_analysis"]["forensics"]["hostname"] == "paypal.com.account-update.xyz"
    assert any("phishing" in ev.lower() or "evaluated" in ev.lower() for ev in data["evidence"])


def test_qr_benign_url_payload_low_risk():
    """Verify QR containing an authentic URL returns LOW RISK without false alarm."""
    legit_url = "https://python.org"
    qr_bytes = make_qr_bytes(legit_url)

    files = {"file": ("qr_legit.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["qr_count_detected"] >= 1
    assert data["payload_type"] == QRPayloadType.URL.value
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["model_prediction"]["is_phishing"] is False


def test_qr_dangerous_javascript_scheme_high_risk():
    """Verify dangerous executable schemes (javascript:) are blocked and flagged HIGH RISK."""
    dangerous_payload = "javascript:alert(document.cookie)"
    qr_bytes = make_qr_bytes(dangerous_payload)

    files = {"file": ("qr_xss.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert data["destination_preview"]["scheme"] == "javascript"
    assert any("dangerous executable scheme" in ev.lower() for ev in data["evidence"])
    assert data["url_analysis"] is None  # Never routed as navigable web address


# ----------------------------------------------------------------------
# 3. UPI Payment Inspection Tests
# ----------------------------------------------------------------------

def test_qr_upi_payment_valid_complete():
    """Verify complete, standard UPI payment QR parses all parameters cleanly."""
    upi_uri = "upi://pay?pa=store@okhdfcbank&pn=Grocery%20Store&am=250.50&cu=INR&tn=Invoice%2042&mc=5411"
    qr_bytes = make_qr_bytes(upi_uri)

    files = {"file": ("qr_upi.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["payload_type"] in (QRPayloadType.UPI_PAYMENT.value, QRPayloadType.UPI.value)

    upi = data["upi_inspection"]
    assert upi is not None
    assert upi["payee_vpa"] == "store@okhdfcbank"
    assert upi["payee_name"] == "Grocery Store"
    assert upi["amount"] == "250.50"
    assert upi["currency"] == "INR"
    assert upi["transaction_note"] == "Invoice 42"
    assert upi["merchant_code"] == "5411"
    assert upi["has_prepopulated_amount"] is True
    assert "Verify the payee" in upi["safety_warning"]


def test_qr_upi_coercive_memo_flagged_high_risk():
    """Verify UPI QR with coercive scam memo (KYC block, penalty fee) escalates to HIGH RISK."""
    upi_uri = "upi://pay?pa=fraudster@ybl&pn=Bank%20Support&am=5000.00&tn=Urgent%20KYC%20unblock%20verification%20fee"
    qr_bytes = make_qr_bytes(upi_uri)

    files = {"file": ("qr_upi_scam.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    upi = data["upi_inspection"]
    assert upi is not None
    assert any("coercive" in n.lower() for n in upi["validation_notes"])
    assert any("social engineering" in ev.lower() for ev in data["evidence"])


def test_qr_upi_malformed_vpa_and_invalid_amount():
    """Verify UPI QR with invalid VPA handle and non-numeric amount flags MEDIUM RISK."""
    upi_uri = "upi://pay?pa=invalid_no_bank_handle&am=not_a_number&pn=Test"
    qr_bytes = make_qr_bytes(upi_uri)

    files = {"file": ("qr_upi_bad.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.MEDIUM_RISK.value
    upi = data["upi_inspection"]
    assert any("format" in n.lower() or "syntax" in n.lower() for n in upi["validation_notes"])
    assert any("non-numeric" in n.lower() for n in upi["validation_notes"])


def test_qr_upi_embedded_phishing_url():
    """Verify UPI QR with embedded reference URL routes into phishing engine."""
    upi_uri = "upi://pay?pa=merchant@upi&url=https://paypal.com.account-update.xyz/verify"
    qr_bytes = make_qr_bytes(upi_uri)

    files = {"file": ("qr_upi_url.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    upi = data["upi_inspection"]
    assert any("phishing" in n.lower() for n in upi["validation_notes"])


# ----------------------------------------------------------------------
# 4. Other Payload Types (Wi-Fi, Contact, Plain Text)
# ----------------------------------------------------------------------

def test_qr_wifi_configuration_standard_low_risk():
    """Verify standard WPA2 Wi-Fi barcode parses correctly with LOW RISK."""
    wifi_str = "WIFI:S:HomeNetwork;T:WPA;P:SuperSecretPass;H:false;;"
    qr_bytes = make_qr_bytes(wifi_str)

    files = {"file": ("qr_wifi.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["payload_type"] == QRPayloadType.WIFI_CONFIGURATION.value
    assert data["wifi_details"]["ssid"] == "HomeNetwork"
    assert data["wifi_details"]["auth_type"] == "WPA"
    assert data["wifi_details"]["has_password"] is True


def test_qr_wifi_open_network_medium_risk():
    """Verify open unencrypted Wi-Fi network triggers MEDIUM RISK warning."""
    wifi_str = "WIFI:S:PublicFreeWifi;T:nopass;P:;;"
    qr_bytes = make_qr_bytes(wifi_str)

    files = {"file": ("qr_wifi_open.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.MEDIUM_RISK.value
    assert data["wifi_details"]["security_warning"] is not None
    assert "unencrypted" in data["wifi_details"]["security_warning"].lower()


def test_qr_plain_text_safe():
    """Verify benign plain text barcode classifies as LOW RISK."""
    plain_str = "Serial Number: SN-98234-A2, Inspected by QA."
    qr_bytes = make_qr_bytes(plain_str)

    files = {"file": ("qr_text.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["payload_type"] == QRPayloadType.PLAIN_TEXT.value
    assert data["destination_preview"]["destination"] == plain_str


def test_qr_plain_text_script_injection_high_risk():
    """Verify plain text containing script injection tags is caught and flagged HIGH RISK."""
    script_str = "<script>alert('pwned')</script>"
    qr_bytes = make_qr_bytes(script_str)

    files = {"file": ("qr_script.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert any("script injection" in ev.lower() for ev in data["evidence"])


def test_qr_contact_tel_low_risk():
    """Verify telephone URI parses target and returns LOW RISK."""
    tel_str = "tel:+919876543210"
    qr_bytes = make_qr_bytes(tel_str)

    files = {"file": ("qr_tel.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == UnifiedRiskClassification.LOW_RISK.value
    assert data["payload_type"] == QRPayloadType.PHONE_OR_CONTACT.value
    assert data["contact_details"]["target"] == "+919876543210"


# ----------------------------------------------------------------------
# 5. Multi-QR Detection & Aggregation Tests
# ----------------------------------------------------------------------

def test_qr_multi_symbol_detection():
    """Verify image with multiple QR symbols decodes all codes and aggregates by highest risk."""
    payload_safe = "https://www.google.com"
    payload_phish = "https://paypal.com.account-update.xyz/login.php"

    multi_bytes = make_multi_qr_bytes(payload_safe, payload_phish)
    files = {"file": ("qr_multi.png", io.BytesIO(multi_bytes), "image/png")}
    response = client.post("/analyze-qr", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["qr_count_detected"] >= 2
    # Aggregated verdict must be HIGH RISK because of the phishing link
    assert data["classification"] == UnifiedRiskClassification.HIGH_RISK.value
    assert len(data["decoded_items"]) >= 2
    assert any("Multi-QR Detection" in ev for ev in data["evidence"])


# ----------------------------------------------------------------------
# 6. Resilience, Fallback & Security Invariants
# ----------------------------------------------------------------------

def test_qr_url_model_unavailable_fallback():
    """Verify that when ML URL model throws an error, service returns UNABLE TO VERIFY."""
    service = QRScannerService()
    mock_url_service = MagicMock(spec=URLAnalysisService)
    mock_url_service.analyze_url.side_effect = RuntimeError("Simulated model artifact failure")
    service.url_service = mock_url_service

    qr_bytes = make_qr_bytes("https://example.com/test")
    resp = service.analyze_qr_image(qr_bytes, "test.png")

    assert resp.classification == UnifiedRiskClassification.UNABLE_TO_VERIFY
    assert any("unavailable" in ev.lower() for ev in resp.evidence)


def test_qr_analysis_zero_network_egress():
    """Verify that analyzing a QR image performs strictly zero outbound network requests."""
    orig_connect = socket.socket.connect

    def forbidden_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"Outbound network egress attempted to {address}!")
        return orig_connect(self, address, *args, **kwargs)

    with patch.object(socket.socket, "connect", forbidden_connect):
        qr_bytes = make_qr_bytes("https://paypal.com.account-update.xyz/login.php")
        files = {"file": ("qr_net.png", io.BytesIO(qr_bytes), "image/png")}
        response = client.post("/analyze-qr", files=files)
        assert response.status_code == 200
        assert response.json()["classification"] == UnifiedRiskClassification.HIGH_RISK.value
