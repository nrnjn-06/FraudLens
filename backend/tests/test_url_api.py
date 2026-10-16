"""API integration tests for POST /analyze-url and end-to-end URL classification."""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.url_model_loader import URLModelLoader
from backend.app.services.url_service import URLAnalysisService, get_url_service

client = TestClient(app)


def test_api_analyze_url_high_risk_phishing():
    """Verify phishing URL with brand impersonation and sensitive tokens is classified HIGH RISK."""
    payload = {"url": "https://paypal.com.account-update.xyz/login.php?token=123"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["target_url"] == payload["url"]
    assert data["classification"] == "HIGH RISK"
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["is_phishing"] is True
    assert data["typosquatting"]["is_impersonation"] is True
    assert len(data["explainable_risk_indicators"]) > 0
    assert len(data["evidence"]) > 0


def test_api_analyze_url_high_risk_ip_address():
    """Verify raw IP address hosting authentication page is classified HIGH RISK."""
    payload = {"url": "http://192.168.1.100:8080/admin/login.php"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "HIGH RISK"
    assert data["forensics"]["has_ip_address"] is True


def test_api_analyze_url_low_risk_authoritative():
    """Verify legitimate authoritative domain is classified LOW RISK with transparent explanation."""
    payload = {"url": "https://www.google.com/search?q=fraudlens"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "LOW RISK"
    assert data["forensics"]["hostname"] == "www.google.com"
    assert data["forensics"]["domain"] == "google"


def test_api_analyze_url_medium_risk_anomalous():
    """Verify anomalous structure with suspicious keyword is classified MEDIUM RISK."""
    payload = {"url": "https://sub.portal.sbi.co.in/banking"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] in ["MEDIUM RISK", "LOW RISK"]
    assert data["forensics"]["subdomain"] == "sub.portal"


def test_api_analyze_url_rejects_empty():
    """Verify empty URL input is rejected with 422."""
    response = client.post("/analyze-url", json={"url": "   "})
    assert response.status_code == 422


def test_api_analyze_url_rejects_dangerous_scheme():
    """Verify dangerous non-web schemes are rejected with 422."""
    response = client.post("/analyze-url", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422

    response = client.post("/analyze-url", json={"url": "data:text/html,<script>bad</script>"})
    assert response.status_code == 422


def test_api_fallback_when_model_unavailable(monkeypatch):
    """Verify UNABLE TO VERIFY is returned when model loader reports model unavailable."""
    class DummyUnavailableLoader:
        is_available = False
        def predict(self, url):
            return None

    dummy_service = URLAnalysisService(model_loader=DummyUnavailableLoader())
    app.dependency_overrides[get_url_service] = lambda: dummy_service

    try:
        response = client.post("/analyze-url", json={"url": "https://some-unverified-site.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "UNABLE TO VERIFY"
        assert data["status"] == "MODEL_UNAVAILABLE"
    finally:
        app.dependency_overrides.clear()


def test_message_service_regression_with_url_analysis():
    """Verify that MessageAnalysisService still properly executes embedded URL analysis."""
    payload = {"message_text": "URGENT: Your account is suspended. Verify immediately at https://paypal.com.account-update.xyz/login"}
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "HIGH RISK"
    assert "embedded_url_analyses" in data
    assert len(data["embedded_url_analyses"]) == 1
    embedded = data["embedded_url_analyses"][0]
    assert embedded["classification"] == "HIGH RISK"
    assert embedded["model_prediction"]["is_phishing"] is True


def test_api_academic_domain_vit_ac_in_low_risk():
    """Verify vtop.vit.ac.in is classified LOW RISK due to academic exemption from typosquatting."""
    payload = {"url": "https://vtop.vit.ac.in"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "LOW RISK"
    assert data["typosquatting"]["is_impersonation"] is False
    assert data["forensics"]["domain"] == "vit"
    assert data["forensics"]["tld"] == "ac.in"

