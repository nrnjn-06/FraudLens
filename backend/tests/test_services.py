"""Unit tests for reusable services."""

from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.message_service import MessageAnalysisService
from backend.app.services.threat_intel import ThreatIntelService
from backend.app.services.url_service import URLAnalysisService


def test_url_service_forensics_parsing():
    """Verify URL forensics parser extracts correct components and detects IPs."""
    service = URLAnalysisService()

    # Normal domain
    res1 = service.parse_forensics("https://sub.portal.example.com/path/to/resource?auth=1&user=bob")
    assert res1.hostname == "sub.portal.example.com"
    assert res1.subdomain == "sub.portal"
    assert res1.domain == "example"
    assert res1.tld == "com"
    assert res1.path == "/path/to/resource"
    assert res1.query_params["auth"] == "1"
    assert res1.query_params["user"] == "bob"
    assert res1.has_ip_address is False

    # IP address
    res2 = service.parse_forensics("http://192.168.1.100/admin")
    assert res2.hostname == "192.168.1.100"
    assert res2.has_ip_address is True


def test_message_service_extracts_entities_and_routes_url():
    """Verify MessageAnalysisService invokes URL service for extracted URLs."""
    url_service = URLAnalysisService()
    message_service = MessageAnalysisService(url_service=url_service)

    msg = "Please check https://legit-looking-portal.xyz/login immediately or call 123-456-7890."
    response = message_service.analyze_message(msg)

    assert response.classification in {
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
        UnifiedRiskClassification.LOW_RISK,
    }
    assert response.model_prediction is not None
    assert len(response.extracted_entities.urls) == 1
    assert "https://legit-looking-portal.xyz/login" in response.extracted_entities.urls
    assert len(response.embedded_url_analyses) == 1
    assert response.embedded_url_analyses[0].target_url == "https://legit-looking-portal.xyz/login"


def test_threat_intel_service_graceful_fallback():
    """Verify ThreatIntelService reports unconfigured status without failing."""
    ti_service = ThreatIntelService()
    result = ti_service.check_reputation("https://example.com")
    assert result.lookup_status == "UNCONFIGURED"
    assert result.is_flagged is False
    assert result.details is not None
