"""Comprehensive test suite for Context-Aware Security Recommendations,
OfficialDomainRegistry, and RecommendationEngine across URL, Message, and QR subsystems.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.official_registry import (
    OfficialDomainRegistry,
    get_official_registry,
)
from backend.app.services.recommendation_engine import (
    RecommendationEngine,
    get_recommendation_engine,
)
from backend.app.services.url_service import get_url_service
from backend.app.services.message_service import get_message_service

client = TestClient(app)


# =====================================================================
# 1. OfficialDomainRegistry & Lookup Mechanics
# =====================================================================

def test_registry_initialization_and_coverage():
    """Verify registry is seeded with major institutions across diverse sectors."""
    registry = get_official_registry()

    # Banking
    sbi = registry.get_by_brand("sbi")
    assert sbi is not None
    assert sbi.official_domain == "sbi.co.in"
    assert sbi.canonical_url == "https://sbi.co.in/"
    assert "banking" in sbi.category.lower()

    # Courier / Logistics
    fedex = registry.get_by_brand("fedex")
    assert fedex is not None
    assert "fedex.com" in fedex.official_domain

    india_post = registry.get_by_brand("india post")
    assert india_post is not None
    assert india_post.official_domain == "indiapost.gov.in"

    # Government / Tax
    income_tax = registry.get_by_brand("income tax")
    assert income_tax is not None
    assert "incometax.gov.in" in income_tax.official_domain

    # Tech & E-Commerce
    amazon = registry.get_by_brand("amazon")
    assert amazon is not None
    assert "amazon.com" in amazon.official_domain


def test_public_suffix_aware_domain_extraction():
    """Verify public suffix extraction correctly isolates registrable domains."""
    registry = get_official_registry()

    _, reg1 = registry.extract_registrable_domain("sbi.co.in")
    assert reg1 == "sbi.co.in"

    _, reg2 = registry.extract_registrable_domain("portal.sbi.co.in")
    assert reg2 == "sbi.co.in"

    _, reg3 = registry.extract_registrable_domain("sbi-kyc-verify.com")
    assert reg3 == "sbi-kyc-verify.com"

    _, reg4 = registry.extract_registrable_domain("sbi.co.in.attacker.com")
    assert reg4 == "attacker.com"

    _, reg5 = registry.extract_registrable_domain("www.indiapost.gov.in")
    assert reg5 == "indiapost.gov.in"

    _, reg6 = registry.extract_registrable_domain("login.paypal.com")
    assert reg6 == "paypal.com"


# =====================================================================
# 2. Fake SBI / KYC URL Produces Official SBI Link
# =====================================================================

def test_fake_sbi_kyc_url_produces_official_sbi_link():
    """Test Requirement 1: Fake SBI/KYC URL produces official SBI link (https://sbi.co.in/)."""
    url_service = get_url_service()
    fake_sbi_url = "http://sbi-kyc-verify.com"

    response = url_service.analyze_url(fake_sbi_url)

    assert response.classification in (
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    )
    assert response.structured_recommendation is not None

    rec = response.structured_recommendation
    assert rec.is_impersonation_detected is True
    assert rec.organization_name == "State Bank of India (SBI)"
    assert rec.official_url == "https://sbi.co.in/"
    assert rec.official_domain == "sbi.co.in"
    assert rec.official_url_verified is True
    assert rec.official_url_source is not None
    assert len(rec.action_steps) > 0
    assert any("sbi.co.in" in step for step in rec.action_steps)

    # Legacy recommendations list also populated
    assert isinstance(response.recommendations, list)
    assert any("https://sbi.co.in/" in r for r in response.recommendations)


# =====================================================================
# 3. Lookalike Hostname Distinguished from Genuine Official Domain
# =====================================================================

def test_lookalike_distinguished_from_genuine_domain():
    """Test Requirement 2: Subdomain spoofing and typosquatting distinguished from genuine domain."""
    registry = get_official_registry()
    sbi_org = registry.get_by_brand("sbi")
    assert sbi_org is not None

    # Fake 1: typosquat / brand prefix
    is_imp1, reason1 = registry.evaluate_impersonation("http://sbi-kyc-verify.com", sbi_org)
    assert is_imp1 is True
    assert "does not match" in reason1

    # Fake 2: Subdomain deceptive prepending
    is_imp2, reason2 = registry.evaluate_impersonation("http://sbi.co.in.attacker-host.com/login", sbi_org)
    assert is_imp2 is True
    assert "does not match" in reason2

    # Genuine: Official domain
    is_imp3, reason3 = registry.evaluate_impersonation("https://sbi.co.in/portal/login", sbi_org)
    assert is_imp3 is False
    assert "matches the verified official domain" in reason3

    # Genuine: Official subdomain
    is_imp4, reason4 = registry.evaluate_impersonation("https://retail.sbi.co.in/login.htm", sbi_org)
    assert is_imp4 is False
    assert "matches the verified official domain" in reason4


# =====================================================================
# 4. Brand in Path Does Not Make Untrusted Host Official
# =====================================================================

def test_brand_in_path_does_not_make_untrusted_host_official():
    """Test Requirement 3: Brand string in path does not trick engine into validating untrusted host."""
    url_service = get_url_service()
    untrusted_url = "http://evil-attacker-site.com/sbi/verify-account"

    response = url_service.analyze_url(untrusted_url)
    rec = response.structured_recommendation

    assert rec is not None
    # If official_url is populated, it MUST be the genuine official destination (https://sbi.co.in/),
    # and NEVER the untrusted host (evil-attacker-site.com).
    if rec.official_url:
        assert "evil-attacker-site.com" not in rec.official_url
        assert rec.official_url == "https://sbi.co.in/"
    else:
        # If brand was not extracted, no official URL should be fabricated
        assert rec.official_url is None
        assert rec.official_url_verified is False


# =====================================================================
# 5. Unknown Brand Produces No Fabricated Official URL
# =====================================================================

def test_unknown_brand_has_no_fabricated_official_url():
    """Test Requirement 4: Unknown brand has official_url=None and official_url_verified=False."""
    url_service = get_url_service()
    unknown_url = "http://totally-obscure-fake-portal-999.xyz/auth/token?v=1"

    response = url_service.analyze_url(unknown_url)
    rec = response.structured_recommendation

    assert rec is not None
    assert rec.official_url is None
    assert rec.official_url_verified is False
    assert rec.official_domain is None


# =====================================================================
# 6. Legitimate URL Receives Clean Guidance
# =====================================================================

def test_legitimate_url_clean_guidance():
    """Test Requirement 5: Genuine official URL does not receive false impersonation warnings."""
    url_service = get_url_service()
    genuine_url = "https://www.paypal.com/"

    response = url_service.analyze_url(genuine_url)
    rec = response.structured_recommendation

    assert response.classification == UnifiedRiskClassification.LOW_RISK
    assert rec is not None
    assert rec.is_impersonation_detected is False
    assert "Verified Authoritative" in rec.title or "Low Risk" in rec.title


# =====================================================================
# 7. Delivery Scam Recommends Official Tracking Site
# =====================================================================

def test_delivery_scam_recommends_official_tracking_site():
    """Test Requirement 6: Courier / delivery scam recommends verified tracking site."""
    msg_service = get_message_service()

    # FedEx delivery fee scam
    fedex_msg = (
        "FedEx Alert: Your shipment #84729 is held at our depot due to unpaid delivery fee of Rs 49. "
        "Pay immediately within 24 hours at http://fedex-express-delivery.net to release package."
    )
    fedex_resp = msg_service.analyze_message(fedex_msg)
    fedex_rec = fedex_resp.structured_recommendation

    assert fedex_resp.classification in (
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    )
    assert fedex_rec is not None
    assert fedex_rec.is_impersonation_detected is True
    assert fedex_rec.organization_name == "FedEx"
    assert fedex_rec.official_url == "https://www.fedex.com/"
    assert fedex_rec.official_url_verified is True
    assert any("fedex.com" in s for s in fedex_rec.action_steps)

    # India Post address update scam
    post_msg = (
        "India Post: Your parcel has arrived at the distribution terminal but address is incomplete. "
        "Update delivery address within 12h at http://indiapost-update.xyz"
    )
    post_resp = msg_service.analyze_message(post_msg)
    post_rec = post_resp.structured_recommendation

    assert post_rec is not None
    assert post_rec.is_impersonation_detected is True
    assert post_rec.official_url == "https://www.indiapost.gov.in/"
    assert post_rec.official_url_verified is True


# =====================================================================
# 8. Job Scam Recommends Careers Page Only When Confidently Identified
# =====================================================================

def test_job_scam_careers_recommendation():
    """Test Requirement 7: Job scam recommends careers portal only when employer is identified."""
    msg_service = get_message_service()

    # Impersonating known organization (Amazon)
    amazon_job_msg = (
        "Amazon HR Announcement: You are selected for remote operations assistant. "
        "Salary Rs 40,000/month. Register credentials at http://amazon-job-careers.xyz"
    )
    resp_with_brand = msg_service.analyze_message(amazon_job_msg)
    rec_with_brand = resp_with_brand.structured_recommendation

    assert rec_with_brand is not None
    assert rec_with_brand.is_impersonation_detected is True
    assert rec_with_brand.official_url is not None
    assert "amazon" in rec_with_brand.official_url

    # Generic job scam with NO known organization
    generic_job_msg = (
        "Congratulations! Selected for part-time job as HR assistant. "
        "Earn Rs 5000 daily with zero experience. Send registration fee to recruiter immediately."
    )
    resp_generic = msg_service.analyze_message(generic_job_msg)
    rec_generic = resp_generic.structured_recommendation

    assert rec_generic is not None
    # No official URL should be fabricated for generic job scam
    assert rec_generic.official_url is None
    assert rec_generic.official_url_verified is False


# =====================================================================
# 9. Scam Message Without URL Receives Category Advice
# =====================================================================

def test_scam_message_without_url_receives_category_advice():
    """Test Requirement 8: Scam message without URL receives category advice without irrelevant website link."""
    msg_service = get_message_service()
    lottery_msg = (
        "URGENT! You have won Rs 50,000 cash prize in our annual lucky draw! "
        "Transfer registration fee of Rs 200 via UPI to claim your reward before deadline expires today at midnight."
    )

    response = msg_service.analyze_message(lottery_msg)
    rec = response.structured_recommendation

    assert response.classification in (
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    )
    assert rec is not None
    assert rec.official_url is None
    assert rec.official_url_verified is False
    assert any("fee" in step.lower() or "prize" in step.lower() or "pin" in step.lower() for step in rec.action_steps)


# =====================================================================
# 10. Cross-Subsystem Engine Reuse & QR Scanner
# =====================================================================

def test_cross_subsystem_engine_reuse_and_qr():
    """Test Requirement 9: URL, Message, and QR scanner all leverage RecommendationEngine."""
    rec_engine = get_recommendation_engine()
    url_service = get_url_service()

    # 1. URL engine integration
    url_resp = url_service.analyze_url("http://sbi-kyc-verify.com")
    assert url_resp.structured_recommendation is not None
    assert url_resp.structured_recommendation.official_url == "https://sbi.co.in/"
    assert len(url_resp.recommendations) > 0

    # 2. QR with UPI payload
    qr_recs, qr_struct = rec_engine.generate_qr_recommendation(
        classification=UnifiedRiskClassification.MEDIUM_RISK,
        payload_type="UPI",
        decoded_text="upi://pay?pa=scammer@fakebank&pn=FraudMerchant&am=5000",
        upi_details={"payee_name": "FraudMerchant", "payee_vpa": "scammer@fakebank", "amount": "5000"},
    )
    assert qr_struct.title == "UPI Payment QR Code Verification"
    assert "PIN" in qr_struct.action_steps[0]
    assert len(qr_recs) > 0


# =====================================================================
# 11. Ambiguous Brand Guidance Note
# =====================================================================

def test_ambiguous_brand_guidance():
    """Test Requirement 10: Unverified brand triggers explicit independent search guidance."""
    rec_engine = get_recommendation_engine()

    recs, struct = rec_engine.generate_message_recommendation(
        classification=UnifiedRiskClassification.HIGH_RISK,
        original_text="Important message from AcmeRegionalCreditUnion: update your password at http://acme-update.com",
        scam_category="CREDENTIAL_HARVESTING",
        pred_is_scam=True,
        pred_confidence=0.95,
        se_findings=[],
        is_advisory=False,
        is_benign=False,
        embedded_url_analyses=[],
    )

    assert struct.official_url is None
    assert struct.official_url_verified is False
    # Guidance instructs user to not follow unsolicited links and use official app / trusted channel
    assert any("independent" in step.lower() or "unsolicited" in step.lower() or "credentials" in step.lower() for step in struct.action_steps)


# =====================================================================
# 12. Security: Never Use Attacker Domain as Safe Alternative
# =====================================================================

def test_attacker_domain_never_used_as_safe_alternative():
    """Test Requirement 11: Security check ensuring attacker URL is never recommended as official URL."""
    url_service = get_url_service()

    attacker_urls = [
        "http://paypal.com.attacker.com/login",
        "http://sbi-banking-update.xyz",
        "http://dhl-express-tracking.top/parcel",
    ]

    for atk_url in attacker_urls:
        response = url_service.analyze_url(atk_url)
        struct = response.structured_recommendation
        if struct and struct.official_url:
            # Must strictly be HTTPS and belong to verified registry, never the attacker host
            assert struct.official_url.startswith("https://")
            assert atk_url.split("/")[2] not in struct.official_url


# =====================================================================
# 13. API Contracts: /analyze-url and /analyze-message
# =====================================================================

def test_api_contracts_include_recommendations_and_structured_recommendation():
    """Test Requirement 13 & 14: API endpoints return backward-compatible and structured recommendations."""
    # Test /analyze-url
    url_resp = client.post("/analyze-url", json={"url": "http://sbi-kyc-verify.com"})
    assert url_resp.status_code == 200
    url_data = url_resp.json()
    assert "recommendations" in url_data
    assert isinstance(url_data["recommendations"], list)
    assert "structured_recommendation" in url_data
    assert url_data["structured_recommendation"] is not None
    assert url_data["structured_recommendation"]["official_url"] == "https://sbi.co.in/"

    # Test /analyze-message
    msg_resp = client.post(
        "/analyze-message",
        json={"message_text": "SBI Alert: KYC expired. Submit OTP at http://sbi-kyc-verify.com immediately."},
    )
    assert msg_resp.status_code == 200
    msg_data = msg_resp.json()
    assert "recommendations" in msg_data
    assert isinstance(msg_data["recommendations"], list)
    assert "structured_recommendation" in msg_data
    assert msg_data["structured_recommendation"] is not None
    assert msg_data["structured_recommendation"]["official_url"] == "https://sbi.co.in/"
