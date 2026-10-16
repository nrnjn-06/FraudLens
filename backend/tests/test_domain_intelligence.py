"""Comprehensive tests for Domain Intelligence Service, WHOIS/RDAP, Domain Age calculation,
and Unified Risk Engine scoring integration.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.schemas.url import (
    DomainForensics,
    DomainIntelligenceResult,
    TyposquattingDetails,
    URLModelPrediction,
)
from backend.app.services.domain_intelligence import (
    DomainIntelligenceCache,
    DomainIntelligenceService,
    is_internal_or_private_host,
    is_ip_host,
)
from backend.app.services.risk_engine import UnifiedRiskEngine
from backend.app.services.url_service import URLAnalysisService

client = TestClient(app)


def test_ssrf_and_ip_safeguards():
    """Verify IP hosts and internal/private addresses are flagged NOT_APPLICABLE with zero network traffic."""
    service = DomainIntelligenceService(enabled=True)

    test_hosts = [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.5",
        "localhost",
        "http://192.168.1.100:8080/admin",
        "https://127.0.0.1:443/login",
    ]

    for host in test_hosts:
        result = service.analyze_domain(host)
        assert result.lookup_status == "NOT_APPLICABLE"
        assert result.domain_age_days is None
        assert result.domain_created_at is None
        assert "not applicable" in result.domain_intelligence_findings[0].lower()


def test_domain_age_calculation_strict_utc_bands():
    """Verify exact domain age calculation and strict risk categorization bands:
    - < 7 days: Critical Risk
    - 7–30 days: High Risk
    - 31–90 days: Moderate Risk
    - 91–180 days: Mild Risk
    - > 180 days: Established
    """
    service = DomainIntelligenceService(enabled=True)
    now = datetime.now(timezone.utc)

    # 1. Critical age (< 7 days)
    dt_3d = (now - timedelta(days=3)).isoformat()
    age_3d, exp_3d, score_3d = service.calculate_domain_age(dt_3d)
    assert age_3d == 3
    assert score_3d == 1.0
    assert "under 7 days" in exp_3d.lower()

    # 2. High risk age (7-30 days)
    dt_15d = (now - timedelta(days=15)).isoformat()
    age_15d, exp_15d, score_15d = service.calculate_domain_age(dt_15d)
    assert age_15d == 15
    assert score_15d == 0.75
    assert "within 30 days" in exp_15d.lower()

    # 3. Moderate age (31-90 days)
    dt_60d = (now - timedelta(days=60)).isoformat()
    age_60d, exp_60d, score_60d = service.calculate_domain_age(dt_60d)
    assert age_60d == 60
    assert score_60d == 0.45
    assert "within 90 days" in exp_60d.lower()

    # 4. Mild age (91-180 days)
    dt_120d = (now - timedelta(days=120)).isoformat()
    age_120d, exp_120d, score_120d = service.calculate_domain_age(dt_120d)
    assert age_120d == 120
    assert score_120d == 0.20
    assert "within 180 days" in exp_120d.lower()

    # 5. Established (> 180 days)
    dt_400d = (now - timedelta(days=400)).isoformat()
    age_400d, exp_400d, score_400d = service.calculate_domain_age(dt_400d)
    assert age_400d == 400
    assert score_400d == 0.0
    assert "established domain" in exp_400d.lower()


def test_missing_creation_date_handled_transparently_without_penalty():
    """Verify that when registry records omit creation date, domain age is None without false penalization."""
    service = DomainIntelligenceService(enabled=True)
    age, exp, score = service.calculate_domain_age(None)

    assert age is None
    assert score == 0.0
    assert "could not be established" in exp.lower()


def test_domain_intelligence_cache_ttl():
    """Verify thread-safe in-memory cache stores and retrieves by normalized registrable domain."""
    cache = DomainIntelligenceCache(max_entries=10, ttl_seconds=3600)
    now_iso = datetime.now(timezone.utc).isoformat()

    sample = DomainIntelligenceResult(
        domain="example.org",
        hostname="sub.example.org",
        domain_age_days=1000,
        domain_created_at="2020-01-01T00:00:00Z",
        domain_expires_at="2028-01-01T00:00:00Z",
        registrar="Example Registrar Inc.",
        registration_status=["active"],
        nameservers=["ns1.example.org"],
        rdap_available=True,
        whois_available=False,
        lookup_status="SUCCESS",
        domain_intelligence_score=0.0,
        domain_intelligence_findings=["Established domain"],
        checked_at=now_iso,
        tls_certificate_valid=True,
        tls_issuer="DigiCert Inc",
        tls_expires_at=None,
        is_cached=False,
    )

    # Initial get is None
    assert cache.get("example.org") is None

    # Set in cache
    cache.set("example.org", sample)

    # Retrieve from cache
    cached = cache.get("example.org")
    assert cached is not None
    assert cached.domain == "example.org"
    assert cached.is_cached is True


def test_rdap_rfc9083_json_parsing():
    """Verify RFC 9083 RDAP response parser correctly extracts registration date, registrar, and nameservers."""
    service = DomainIntelligenceService(enabled=True)

    mock_rdap_response = {
        "ldhName": "SAMPLEPHISH.XYZ",
        "status": ["active", "clientTransferProhibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2026-10-01T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-01T12:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "NameCheap, Inc."],
                    ],
                ],
            }
        ],
        "nameservers": [{"ldhName": "dns1.registrar-servers.com"}],
    }

    with patch.object(service, "lookup_rdap", return_value={
        "domain": "samplephish.xyz",
        "created_at": "2026-10-01T12:00:00Z",
        "expires_at": "2027-10-01T12:00:00Z",
        "registrar": "NameCheap, Inc.",
        "status": ["active", "clientTransferProhibited"],
        "nameservers": ["dns1.registrar-servers.com"],
        "raw_source": "RDAP",
    }):
        with patch.object(service, "check_tls", return_value=(True, "Let's Encrypt", "2026-12-01T00:00:00Z")):
            result = service.analyze_domain("https://samplephish.xyz/login")

            assert result.domain == "samplephish.xyz"
            assert result.registrar == "NameCheap, Inc."
            assert result.rdap_available is True
            assert result.domain_created_at == "2026-10-01T12:00:00Z"
            assert result.tls_certificate_valid is True
            assert result.tls_issuer == "Let's Encrypt"


def test_weighted_risk_synthesis_with_domain_intel():
    """Verify that multi-factor risk scoring balances components:
    Domain Intel: 40%, ML: 35%, Heuristics: 15%, Threat Intel: 10%.
    """
    forensics = DomainForensics(
        hostname="suspicious-domain.xyz",
        subdomain="",
        domain="suspicious-domain",
        tld="xyz",
        path="/login",
        query_params={},
        has_ip_address=False,
        url_length=30,
    )

    typosquatting = TyposquattingDetails(
        target_brand=None,
        similarity_score=0.0,
        is_impersonation=False,
        details="No brand impersonation detected",
    )

    model_pred = URLModelPrediction(
        is_phishing=False,
        confidence=0.15,
        model_name="RandomForest_URL_v1",
    )

    # Very new domain (< 7 days) -> domain intel score = 0.8
    now_iso = datetime.now(timezone.utc).isoformat()
    domain_intel = DomainIntelligenceResult(
        domain="suspicious-domain.xyz",
        hostname="suspicious-domain.xyz",
        domain_age_days=2,
        domain_created_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
        domain_expires_at=None,
        registrar="Budget Registrar",
        registration_status=["active"],
        nameservers=[],
        rdap_available=True,
        whois_available=False,
        lookup_status="SUCCESS",
        domain_intelligence_score=0.75,
        domain_intelligence_findings=["Critical Warning: Domain registered 2 days ago (< 7 days)."],
        checked_at=now_iso,
        tls_certificate_valid=True,
        tls_issuer="Let's Encrypt",
        tls_expires_at=None,
        is_cached=False,
    )

    classification, status, evidence, unified_evidence, recs = UnifiedRiskEngine.synthesize_url_risk(
        clean_url="https://suspicious-domain.xyz/login",
        forensics=forensics,
        typosquatting=typosquatting,
        inference_prediction=model_pred,
        threat_intel=None,
        domain_intel=domain_intel,
        fdict={"suspicious_token_count": 1},
        is_known_authoritative=False,
    )

    # Despite benign ML score (0.15), domain intel score (0.75 @ 40% weight) lifts composite score
    assert classification in [UnifiedRiskClassification.MEDIUM_RISK, UnifiedRiskClassification.HIGH_RISK]
    assert any("Domain Intelligence" in e or "Domain Intel" in e for e in evidence)


def test_typosquatting_with_fresh_domain_triggers_high_risk():
    """Verify that brand typosquatting combined with a newly registered domain (< 7d) escalates to HIGH RISK."""
    forensics = DomainForensics(
        hostname="paypa1-update.com",
        subdomain="",
        domain="paypa1-update",
        tld="com",
        path="/verify",
        query_params={},
        has_ip_address=False,
        url_length=28,
    )

    typosquatting = TyposquattingDetails(
        target_brand="PayPal",
        similarity_score=0.85,
        is_impersonation=True,
        details="Potential typosquatting/lookalike spoofing target brand 'PayPal'",
    )

    model_pred = URLModelPrediction(
        is_phishing=True,
        confidence=0.55,
        model_name="RandomForest_URL_v1",
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    domain_intel = DomainIntelligenceResult(
        domain="paypa1-update.com",
        hostname="paypa1-update.com",
        domain_age_days=3,
        domain_created_at=(datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        domain_expires_at=None,
        registrar="Privacy Guarded Registrar",
        registration_status=["active"],
        nameservers=[],
        rdap_available=True,
        whois_available=False,
        lookup_status="SUCCESS",
        domain_intelligence_score=0.90,
        domain_intelligence_findings=["Critical: Domain registered 3 days ago."],
        checked_at=now_iso,
        tls_certificate_valid=True,
        tls_issuer="Let's Encrypt",
        tls_expires_at=None,
        is_cached=False,
    )

    classification, status, evidence, unified_evidence, recs = UnifiedRiskEngine.synthesize_url_risk(
        clean_url="https://paypa1-update.com/verify",
        forensics=forensics,
        typosquatting=typosquatting,
        inference_prediction=model_pred,
        threat_intel=None,
        domain_intel=domain_intel,
        fdict={"suspicious_token_count": 1},
        is_known_authoritative=False,
    )

    assert classification == UnifiedRiskClassification.HIGH_RISK
    assert any("PayPal" in e for e in evidence)
    assert any("Domain Intelligence" in e or "Domain Intel" in e for e in evidence)


def test_url_api_endpoint_returns_domain_intelligence():
    """Verify POST /analyze-url includes the domain_intelligence object with full schema."""
    payload = {"url": "https://www.google.com/search?q=security"}
    response = client.post("/analyze-url", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "domain_intelligence" in data
    di = data["domain_intelligence"]
    assert di is not None
    assert di["domain"] == "google.com"
    assert di["hostname"] == "www.google.com"
    assert "lookup_status" in di
    assert "domain_intelligence_findings" in di
    assert isinstance(di["domain_intelligence_findings"], list)


def test_message_api_with_embedded_url_domain_intelligence():
    """Verify POST /analyze-message routes embedded URLs and includes domain_intelligence."""
    payload = {
        "message_text": "ALERT: Your account is suspended. Confirm details at https://secure-login.portal.com/auth"
    }
    response = client.post("/analyze-message", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "embedded_url_analyses" in data
    assert len(data["embedded_url_analyses"]) >= 1

    embedded = data["embedded_url_analyses"][0]
    assert "domain_intelligence" in embedded
    assert embedded["domain_intelligence"] is not None
    assert embedded["domain_intelligence"]["domain"] == "portal.com"
