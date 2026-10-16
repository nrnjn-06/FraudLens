"""End-to-end integration tests for FraudLens Scam Message Detection Module.

Verifies the 10 required real-world scenarios:
1. Message requesting an OTP and threatening account suspension (HIGH RISK, BANK_KYC)
2. Fake delivery fee with a suspicious link (HIGH/MEDIUM RISK, DELIVERY)
3. Unsolicited prize requiring advance payment (HIGH/MEDIUM RISK, PRIZE)
4. Investment offer with guaranteed returns and payment pressure (HIGH/MEDIUM RISK, INVESTMENT)
5. Legitimate bank advisory warning users never to share an OTP (LOW RISK, UNKNOWN, advisory notice)
6. Harmless message discussing an urgent meeting (LOW RISK, UNKNOWN, benign guards)
7. Genuine delivery update with no suspicious indicators (LOW RISK, UNKNOWN)
8. Legitimate job discussion mentioning payment (LOW RISK, UNKNOWN)
9. Message containing a URL but no other suspicious signals (MEDIUM/LOW RISK depending on domain)
10. Message with conflicting indicators or insufficient evidence (Safe fallback, UNKNOWN category)
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.message_service import MessageAnalysisService, get_message_service

client = TestClient(app)


@pytest.fixture
def service():
    return get_message_service()


# -----------------------------------------------------------------------------
# Scenario 1: OTP Request + Account Suspension Threat
# -----------------------------------------------------------------------------
def test_scenario_1_otp_and_suspension_threat(service):
    """Verify critical credential theft + threat triggers HIGH RISK and BANK_KYC."""
    msg = (
        "SBI Notice: Your bank account will be permanently blocked due to suspicious activity. "
        "Please share the 6-digit OTP sent to your phone immediately to verify your account."
    )
    res = service.analyze_message(msg)

    assert res.classification == UnifiedRiskClassification.HIGH_RISK
    assert res.social_engineering.otp_requests is True
    assert res.social_engineering.threats is True
    assert res.scam_type.category == "BANK_KYC"
    assert len(res.highlighted_phrases) >= 2


# -----------------------------------------------------------------------------
# Scenario 2: Fake Delivery Fee + Suspicious Link
# -----------------------------------------------------------------------------
def test_scenario_2_fake_delivery_fee_and_link(service):
    """Verify courier fee extortion with embedded URL triggers DELIVERY scam and URL extraction."""
    msg = (
        "FedEx Alert: Your shipment #84729 is held at depot due to unpaid delivery fee of Rs 49. "
        "Pay immediately within 24 hours at http://fedex-express-delivery.net to release package."
    )
    res = service.analyze_message(msg)

    assert res.classification in [
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    ]
    assert res.scam_type.category == "DELIVERY"
    assert len(res.extracted_entities.urls) == 1
    assert "http://fedex-express-delivery.net" in res.extracted_entities.urls
    assert len(res.embedded_url_analyses) == 1
    assert res.embedded_url_analyses[0].target_url == "http://fedex-express-delivery.net"


# -----------------------------------------------------------------------------
# Scenario 3: Unsolicited Prize + Advance Payment
# -----------------------------------------------------------------------------
def test_scenario_3_unsolicited_prize_advance_payment(service):
    """Verify lottery lure demanding processing fee triggers PRIZE scam category."""
    msg = (
        "Lucky Draw Alert: Congratulations! You have won Rs 50,000 cash prize in our annual lottery. "
        "Transfer processing fee of Rs 200 immediately to claim your prize before deadline expires today at midnight."
    )
    res = service.analyze_message(msg)

    assert res.classification in [
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    ]
    assert res.social_engineering.prize_bait is True
    assert res.social_engineering.payment_demands is True
    assert res.scam_type.category == "PRIZE"


# -----------------------------------------------------------------------------
# Scenario 4: Investment Offer + Guaranteed Returns + Payment Pressure
# -----------------------------------------------------------------------------
def test_scenario_4_investment_guaranteed_returns(service):
    """Verify high-yield crypto doubling triggers INVESTMENT category."""
    msg = (
        "Guaranteed return! Double your money with our automated crypto trading algorithm. "
        "200% return in 24 hours risk-free. Immediate deposit required at http://instant-crypto-returns.biz"
    )
    res = service.analyze_message(msg)

    assert res.classification in [
        UnifiedRiskClassification.HIGH_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    ]
    assert res.scam_type.category == "INVESTMENT"
    assert len(res.extracted_entities.urls) == 1


# -----------------------------------------------------------------------------
# Scenario 5: Legitimate Bank Security Advisory (OTP Warning)
# -----------------------------------------------------------------------------
def test_scenario_5_legitimate_bank_advisory(service):
    """Verify defensive educational bank warning is classified LOW RISK with UNKNOWN category."""
    msg = (
        "Protect yourself from e-threats: State Bank of India never asks for sensitive information "
        "like Password, OTP or CVV. Never share your credentials with anyone."
    )
    res = service.analyze_message(msg)

    assert res.classification == UnifiedRiskClassification.LOW_RISK
    assert res.social_engineering.is_advisory_or_educational is True
    assert res.scam_type.category == "UNKNOWN"
    assert len(res.highlighted_phrases) == 0  # Zero warning phrases flagged on genuine advisory


# -----------------------------------------------------------------------------
# Scenario 6: Harmless Urgent Meeting Context
# -----------------------------------------------------------------------------
def test_scenario_6_harmless_urgent_meeting(service):
    """Verify ordinary conversational urgency & bank mentions are protected by benign guards."""
    msg = "I have an urgent meeting with my professor. I will pay for lunch afterwards near the bank."
    res = service.analyze_message(msg)

    assert res.classification == UnifiedRiskClassification.LOW_RISK
    assert res.social_engineering.urgency is False
    assert res.social_engineering.payment_demands is False
    assert res.scam_type.category == "UNKNOWN"
    assert len(res.highlighted_phrases) == 0


# -----------------------------------------------------------------------------
# Scenario 7: Genuine Delivery Update
# -----------------------------------------------------------------------------
def test_scenario_7_genuine_delivery_update(service):
    """Verify standard delivery status with no coercion is not flagged as scam."""
    msg = "Your order #87654 has been delivered by FedEx to your reception. Thank you for choosing our service."
    res = service.analyze_message(msg)

    assert res.classification == UnifiedRiskClassification.LOW_RISK
    assert res.social_engineering.threats is False
    assert res.social_engineering.payment_demands is False
    assert res.scam_type.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# Scenario 8: Legitimate Job Discussion Mentioning Payment
# -----------------------------------------------------------------------------
def test_scenario_8_legitimate_job_discussion(service):
    """Verify authentic recruitment dialogue without fee extortion is not flagged as JOB scam."""
    msg = "We would like to invite you for a campus interview tomorrow for the software engineering role. Travel reimbursement will be provided."
    res = service.analyze_message(msg)

    assert res.classification == UnifiedRiskClassification.LOW_RISK
    assert res.scam_type.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# Scenario 9: Neutral Message Containing URL Only
# -----------------------------------------------------------------------------
def test_scenario_9_neutral_message_with_url(service):
    """Verify message containing only a URL extracts the URL and routes it without false panic."""
    msg = "Here is the syllabus document for next semester: https://university-portal.edu/syllabus.pdf"
    res = service.analyze_message(msg)

    assert len(res.extracted_entities.urls) == 1
    assert "https://university-portal.edu/syllabus.pdf" in res.extracted_entities.urls
    assert len(res.embedded_url_analyses) == 1
    assert res.social_engineering.otp_requests is False
    assert res.social_engineering.threats is False
    assert res.scam_type.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# Scenario 10: Conflicting or Insufficient Indicators
# -----------------------------------------------------------------------------
def test_scenario_10_conflicting_or_insufficient_evidence(service):
    """Verify ambiguous conversational text with isolated word mentions falls back safely."""
    msg = "Can you send me the investment article link and meet me tomorrow?"
    res = service.analyze_message(msg)

    assert res.classification in [
        UnifiedRiskClassification.LOW_RISK,
        UnifiedRiskClassification.MEDIUM_RISK,
    ]
    assert res.scam_type.category == "UNKNOWN"
    assert res.scam_type.confidence is None


# -----------------------------------------------------------------------------
# 11. API Endpoint Verification
# -----------------------------------------------------------------------------
def test_api_endpoint_end_to_end():
    """Verify FastAPI POST /analyze-message delivers all 5 integrated features."""
    payload = {
        "message_text": (
            "SBI Notice: Your bank account will be permanently blocked due to expired KYC. "
            "Please share the 6-digit OTP immediately at http://sbi-kyc-verify.com or call +91 98765 43210."
        )
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Feature 1
    assert "model_prediction" in data
    assert data["model_prediction"] is not None

    # Feature 2
    assert "social_engineering" in data
    assert data["social_engineering"]["otp_requests"] is True

    # Feature 3
    assert "highlighted_phrases" in data
    assert len(data["highlighted_phrases"]) > 0
    for h in data["highlighted_phrases"]:
        assert payload["message_text"][h["start"]:h["end"]] == h["text"]

    # Feature 4
    assert "extracted_entities" in data
    assert len(data["extracted_entities"]["urls"]) == 1
    assert len(data["extracted_entities"]["phone_numbers"]) >= 1
    assert len(data["embedded_url_analyses"]) == 1

    # Feature 5
    assert "scam_type" in data
    assert data["scam_type"]["category"] == "BANK_KYC"
    assert data["scam_type"]["label"] == "Bank/KYC"

    # Unified risk
    assert data["classification"] == "HIGH RISK"
