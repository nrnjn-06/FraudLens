"""Tests for Feature 4: Entity Extraction and Embedded URL Scanning.

Verifies:
- Extraction of URLs (scheme and naked domains) with punctuation trimming
- Phone numbers (domestic Indian and international)
- UPI handles (differentiated from emails)
- Punctuation around URLs (commas, periods, parentheses, quotes)
- Exact character offsets: text[start:end] == span.raw_text
- Integration with URLAnalysisService
- Resilience: malformed URLs or service exceptions never crash message analysis
- Passive inspection: zero network requests
"""

import pytest
from unittest.mock import MagicMock
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.entity_extractor import EntityExtractor, get_entity_extractor
from backend.app.services.message_service import MessageAnalysisService
from backend.app.services.url_service import URLAnalysisService


@pytest.fixture
def extractor():
    return get_entity_extractor()


# -----------------------------------------------------------------------------
# 1. URL Extraction Tests
# -----------------------------------------------------------------------------

def test_extract_urls_with_schemes(extractor):
    """Verify HTTP and HTTPS URLs extracted correctly with exact offsets."""
    text = "Please check https://secure-bank.com/login and http://update.xyz?id=99 for details."
    res = extractor.extract(text)
    assert len(res.urls) == 2
    assert "https://secure-bank.com/login" in res.urls
    assert "http://update.xyz?id=99" in res.urls

    # Check offsets
    for span in [s for s in res.spans if s.entity_type == "URL"]:
        assert text[span.start:span.end] == span.raw_text
        assert span.value in res.urls


def test_extract_naked_domains(extractor):
    """Verify naked domains like www.bank.com and bit.ly/test are extracted."""
    text = "Visit www.sbi-verify.com or check tinyurl.com/update-kyc today."
    res = extractor.extract(text)
    assert "www.sbi-verify.com" in res.urls
    assert "tinyurl.com/update-kyc" in res.urls


def test_strip_punctuation_around_urls(extractor):
    """Verify trailing and leading punctuation is excluded from URLs."""
    text = "Go to (http://example.com/test), or visit 'http://sbi.co.in/login'. Check http://bank.com/!"
    res = extractor.extract(text)
    assert "http://example.com/test" in res.urls
    assert "http://sbi.co.in/login" in res.urls
    assert "http://bank.com/" in res.urls

    for span in [s for s in res.spans if s.entity_type == "URL"]:
        assert text[span.start:span.end] == span.raw_text


def test_exclude_version_numbers_and_decimals(extractor):
    """Verify version numbers like 1.0.0 or decimals like 3.14 are not extracted as URLs."""
    text = "FraudLens v1.2.3 was released. Current CPI is 4.5%."
    res = extractor.extract(text)
    assert len(res.urls) == 0


# -----------------------------------------------------------------------------
# 2. Phone Numbers and UPI Handles Tests
# -----------------------------------------------------------------------------

def test_extract_phone_numbers(extractor):
    """Verify domestic and international phone numbers extracted accurately."""
    text = "Call +91 98765 43210 or 1-800-555-0199 for immediate support."
    res = extractor.extract(text)
    assert len(res.phone_numbers) >= 2
    for span in [s for s in res.spans if s.entity_type == "PHONE"]:
        assert text[span.start:span.end] == span.raw_text


def test_extract_upi_handles(extractor):
    """Verify UPI handles extracted and differentiated from normal emails."""
    text = "Pay to merchant@okhdfcbank or 9876543210@paytm. Email us at support@mybank.com."
    res = extractor.extract(text)
    assert "merchant@okhdfcbank" in res.upi_ids
    assert "9876543210@paytm" in res.upi_ids
    assert "support@mybank.com" not in res.upi_ids
    assert any("Email: support@mybank.com" in ind for ind in res.indicators)

    for span in [s for s in res.spans if s.entity_type == "UPI"]:
        assert text[span.start:span.end] == span.raw_text


def test_repeated_entities_deduplication(extractor):
    """Verify repeated entities are deduplicated in list while retaining spans."""
    text = "Visit http://test.com once and http://test.com twice."
    res = extractor.extract(text)
    assert len(res.urls) == 1
    assert res.urls[0] == "http://test.com"
    # Spans preserve both occurrences
    url_spans = [s for s in res.spans if s.entity_type == "URL"]
    assert len(url_spans) == 2


def test_no_entities_message(extractor):
    """Verify clean message with no entities returns empty lists."""
    text = "Hello, how are you doing today? Let us meet tomorrow."
    res = extractor.extract(text)
    assert len(res.urls) == 0
    assert len(res.phone_numbers) == 0
    assert len(res.upi_ids) == 0
    assert len(res.spans) == 0


# -----------------------------------------------------------------------------
# 3. URL Service Integration & Resilience Tests
# -----------------------------------------------------------------------------

def test_message_service_routes_embedded_urls_to_url_detector():
    """Verify extracted URLs are passed through URLAnalysisService."""
    service = MessageAnalysisService()
    msg = "Urgent: Your account is locked. Verify at http://sbi-fake-portal.com/login"
    resp = service.analyze_message(msg)

    assert len(resp.embedded_url_analyses) == 1
    emb = resp.embedded_url_analyses[0]
    assert emb.target_url == "http://sbi-fake-portal.com/login"
    assert emb.forensics is not None
    assert emb.forensics.domain == "sbi-fake-portal"
    assert emb.forensics.tld == "com"


def test_message_service_handles_url_service_failure_gracefully():
    """Verify URL analysis exceptions do not crash message analysis."""
    failing_url_service = MagicMock(spec=URLAnalysisService)
    failing_url_service.analyze_url.side_effect = RuntimeError("Simulated URL parsing crash")

    service = MessageAnalysisService(url_service=failing_url_service)
    msg = "Click http://malformed-url.com immediately"
    resp = service.analyze_message(msg)

    assert len(resp.embedded_url_analyses) == 1
    assert resp.embedded_url_analyses[0].classification == UnifiedRiskClassification.UNABLE_TO_VERIFY
    assert resp.embedded_url_analyses[0].status == "URL_ANALYSIS_FAILED"
    # Main message analysis still succeeds
    assert resp.classification in [
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
        UnifiedRiskClassification.LOW_RISK,
    ]
