"""Automated tests for Feature 2: Social Engineering Detection Engine.

Covers:
- All 7 persuasion categories individually
- Multi-indicator compound messages
- Legitimate bank security advisories (defensive negation filter)
- Legitimate delivery & benign notifications
- Harmless conversational contexts using sensitive words ('urgent meeting', 'pay for lunch', 'walked past bank')
- Empty, whitespace, and unusually long inputs
- Integration with API POST /analyze-message, schema serialization & evidence formatting
"""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.social_engineering import SocialEngineeringDetector

client = TestClient(app)


@pytest.fixture
def detector():
    return SocialEngineeringDetector()


# -----------------------------------------------------------------------------
# 1. Individual Category Unit Tests
# -----------------------------------------------------------------------------

def test_category_1_urgency_deadline(detector):
    """Verify detection of artificial time pressure and explicit deadlines."""
    msg = "Action required within 24 hours. Your request expires today at midnight."
    res = detector.analyze(msg)
    assert res.urgency is True
    assert any(f.category == "urgency" for f in res.findings)
    assert any("within 24 hours" in f.matched_text.lower() for f in res.findings)


def test_category_2_threats_consequences(detector):
    """Verify detection of account blockage and disconnection threats."""
    msg = "Your account will be permanently blocked due to suspicious activity. Legal action will be initiated."
    res = detector.analyze(msg)
    assert res.threats is True
    assert any(f.category == "threats" for f in res.findings)
    assert any(f.severity == "HIGH" for f in res.findings)


def test_category_3_impersonation(detector):
    """Verify detection of institutional authority representation."""
    msg = "Dear Customer, SBI alert: Your bank account requires mandatory PAN card update."
    res = detector.analyze(msg)
    assert res.impersonation is True
    assert any(f.category == "impersonation" for f in res.findings)


def test_category_4_otp_requests(detector):
    """Verify detection of inbound credential and OTP solicitation."""
    msg = "Please share the 6-digit OTP sent to your mobile to verify your transaction."
    res = detector.analyze(msg)
    assert res.otp_requests is True
    assert any(f.category == "otp_requests" for f in res.findings)
    assert any(f.severity == "HIGH" for f in res.findings)


def test_category_5_prize_bait(detector):
    """Verify detection of fabricated winnings, lotteries, and reward bait."""
    msg = "Congratulations! You have won a cash prize of Rs 25,000 in the lucky draw! Claim your reward now."
    res = detector.analyze(msg)
    assert res.prize_bait is True
    assert any(f.category == "prize_bait" for f in res.findings)


def test_category_6_payment_demands(detector):
    """Verify detection of coercive payment demands and fee requirements."""
    msg = "Your electricity bill unpaid. Pay Rs 1500 immediately to avoid power disconnection tonight."
    res = detector.analyze(msg)
    assert res.payment_demands is True
    assert any(f.category == "payment_demands" for f in res.findings)
    assert any(f.severity == "HIGH" for f in res.findings)


def test_category_7_link_click_pressure(detector):
    """Verify detection of directives urging immediate link navigation."""
    msg = "Click the link below immediately to update your profile: https://example.com/verify"
    res = detector.analyze(msg)
    assert res.link_click_pressure is True
    assert any(f.category == "link_click_pressure" for f in res.findings)


# -----------------------------------------------------------------------------
# 2. Defensive Security Advisories (Negation and False-Positive Prevention)
# -----------------------------------------------------------------------------

def test_defensive_advisory_never_share_otp(detector):
    """Verify bank security advisory is recognized and does NOT flag OTP request."""
    msg = "Dear Customer, Never share your OTP, PIN, or password with anyone. Bank staff will never ask for confidential details."
    res = detector.analyze(msg)
    assert res.is_advisory_or_educational is True
    assert res.otp_requests is False  # Suppressed because it advises NOT to share
    assert res.threats is False
    assert any("DEFENSIVE ADVISORY" in s for s in res.signals)


def test_defensive_advisory_sib_security_notice(detector):
    """Verify real-world bank phishing warning is recognized as educational."""
    msg = "Please protect yourself from e-threats. SIB never asks for sensitive information like Password/OTP."
    res = detector.analyze(msg)
    assert res.is_advisory_or_educational is True
    assert res.otp_requests is False


# -----------------------------------------------------------------------------
# 3. Benign & Conversational Context Guard Tests
# -----------------------------------------------------------------------------

def test_benign_conversational_words_not_flagged(detector):
    """Verify harmless words like 'urgent meeting' or 'pay for lunch' are not flagged."""
    msg = "I have an urgent meeting with my professor. I will pay for lunch afterwards near the bank."
    res = detector.analyze(msg)
    assert res.urgency is False
    assert res.payment_demands is False
    assert res.threats is False
    assert res.otp_requests is False
    assert len(res.findings) == 0


def test_benign_delivery_notification(detector):
    """Verify standard legitimate delivery update does not trigger coercive findings."""
    msg = "Your order #87654 has been delivered by FedEx to your reception. Thank you for choosing our service."
    res = detector.analyze(msg)
    assert res.threats is False
    assert res.payment_demands is False
    assert res.otp_requests is False
    assert res.urgency is False


# -----------------------------------------------------------------------------
# 4. Multi-Indicator Compound Scam Message Tests
# -----------------------------------------------------------------------------

def test_compound_electricity_threat_scam(detector):
    """Verify message combining impersonation, threat, urgency, and payment demands."""
    msg = (
        "Dear Customer, Electricity Department alert: Your power will be disconnected tonight "
        "at 9:30 PM due to unpaid bill. Pay immediately within 2 hours to avoid cutoff."
    )
    res = detector.analyze(msg)
    assert res.impersonation is True
    assert res.threats is True
    assert res.urgency is True
    assert res.payment_demands is True
    assert len(res.findings) >= 3


def test_compound_kyc_phishing_scam(detector):
    """Verify message combining bank impersonation, account threat, and link pressure."""
    msg = (
        "SBI Notice: Your bank account has been suspended due to expired KYC. "
        "Click the link immediately to update PAN or account will be permanently blocked."
    )
    res = detector.analyze(msg)
    assert res.impersonation is True
    assert res.threats is True
    assert res.link_click_pressure is True
    assert res.is_advisory_or_educational is False


# -----------------------------------------------------------------------------
# 5. Boundary & Extreme Input Tests
# -----------------------------------------------------------------------------

def test_empty_and_whitespace_input(detector):
    """Verify empty and whitespace strings return empty indicators cleanly."""
    res_empty = detector.analyze("")
    assert res_empty.urgency is False
    assert len(res_empty.findings) == 0

    res_spaces = detector.analyze("     ")
    assert res_spaces.threats is False
    assert len(res_spaces.findings) == 0


def test_unusually_long_input(detector):
    """Verify detector processes long repetitive text without timeout or error."""
    long_text = "Safe conversational text. " * 200 + "Your account will be blocked within 24 hours. " + "End of text. " * 50
    res = detector.analyze(long_text)
    assert res.threats is True
    assert res.urgency is True
    assert len(res.findings) >= 2


# -----------------------------------------------------------------------------
# 6. Integration Tests via POST /analyze-message
# -----------------------------------------------------------------------------

def test_api_integration_security_advisory_classified_low_risk():
    """Verify API classifies legitimate security warning as LOW RISK even with sensitive words."""
    payload = {
        "message_text": "Security Tip from HDFC Bank: Never share your OTP, NetBanking password or UPI PIN with anyone."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "LOW RISK"
    se = data["social_engineering"]
    assert se["is_advisory_or_educational"] is True
    assert se["otp_requests"] is False
    assert any("defensive security advisory" in e.lower() for e in data["evidence"])


def test_api_integration_compound_scam_classified_high_risk():
    """Verify API detects compound coercion and escalates to HIGH RISK."""
    payload = {
        "message_text": (
            "URGENT: Your SBI account is blocked. Update KYC at https://sbi-fake-kyc.com/login "
            "or pay fine of Rs 5000 within 2 hours. Call 9876543210."
        )
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "HIGH RISK"
    se = data["social_engineering"]
    assert se["urgency"] is True
    assert se["threats"] is True
    assert len(se["findings"]) >= 2
    # Verify entity extraction preserved
    assert len(data["extracted_entities"]["urls"]) >= 1
    assert len(data["embedded_url_analyses"]) >= 1


def test_api_integration_ml_and_heuristics_evidence_separation():
    """Verify response evidence clearly distinguishes ML model from heuristic findings."""
    payload = {
        "message_text": "Congratulations! You have won £1,000 cash prize. Call 09061743811 to claim."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    evidence_text = " ".join(data["evidence"])
    # Both evidence types must be present and distinct
    assert "Statistical model prediction" in evidence_text
    assert "Heuristic persuasion tactics" in evidence_text or "PRIZE_BAIT" in str(data["social_engineering"])
