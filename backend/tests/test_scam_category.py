"""Tests for Feature 5: Scam Category Identification.

Verifies:
- BANK_KYC category detection and advisory suppression
- DELIVERY category detection and benign delivery update suppression
- JOB category detection and legitimate interview discussion suppression
- PRIZE category detection and harmless reward points suppression
- INVESTMENT category detection and conversational investment suppression
- UNKNOWN category fallback for ambiguous or benign messages
- Deterministic candidate category handling for multi-signal messages
"""

import pytest
from backend.app.services.scam_category import ScamCategoryClassifier, get_scam_category_classifier
from backend.app.services.social_engineering import SocialEngineeringDetector


@pytest.fixture
def classifier():
    return get_scam_category_classifier()


@pytest.fixture
def se_detector():
    return SocialEngineeringDetector()


# -----------------------------------------------------------------------------
# 1. Bank / KYC Category Tests
# -----------------------------------------------------------------------------

def test_bank_kyc_positive_detection(classifier, se_detector):
    """Verify fraudulent banking/KYC suspension message is categorized as BANK_KYC."""
    msg = "SBI Notice: Your bank account has been suspended due to expired KYC. Update PAN card immediately to avoid permanent deactivation."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "BANK_KYC"
    assert res.label == "Bank/KYC"
    assert res.confidence is not None and res.confidence >= 0.60
    assert len(res.matched_patterns) > 0


def test_bank_advisory_is_not_bank_kyc_scam(classifier, se_detector):
    """Verify legitimate bank security advisories are NOT classified as BANK_KYC scam."""
    msg = "Security Alert: State Bank of India never asks for sensitive information like Password, OTP or CVV. Never share your credentials."
    se = se_detector.analyze(msg)
    assert se.is_advisory_or_educational is True
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"
    assert "advisory" in res.explanation.lower()


def test_benign_conversational_bank_mention(classifier, se_detector):
    """Verify harmless mention of 'near the bank' is NOT classified as BANK_KYC."""
    msg = "I will meet you near the bank of the river after lunch."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# 2. Delivery Fraud Category Tests
# -----------------------------------------------------------------------------

def test_delivery_positive_detection(classifier, se_detector):
    """Verify courier impersonation with unpaid delivery fee is categorized as DELIVERY."""
    msg = "FedEx Alert: Your parcel is held at depot due to unpaid delivery fee of Rs 49. Pay immediately to release package."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "DELIVERY"
    assert res.label == "Delivery"
    assert res.confidence is not None


def test_benign_delivery_notification_suppression(classifier, se_detector):
    """Verify standard legitimate delivery confirmation is NOT flagged as DELIVERY scam."""
    msg = "Your order #87654 has been delivered by FedEx to your reception. Thank you for choosing our service."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# 3. Job Scam Category Tests
# -----------------------------------------------------------------------------

def test_job_scam_positive_detection(classifier, se_detector):
    """Verify work-from-home bait with registration fee demands is categorized as JOB."""
    msg = "Selected for part-time job as HR assistant. Earn Rs 5000 daily with zero experience. Send registration fee to activate account."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "JOB"
    assert res.label == "Job"
    assert res.confidence is not None


def test_benign_job_discussion_suppression(classifier, se_detector):
    """Verify genuine job interview discussion is NOT flagged as JOB scam."""
    msg = "We would like to invite you for a campus interview tomorrow. Looking forward to meeting you."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# 4. Prize / Lottery Category Tests
# -----------------------------------------------------------------------------

def test_prize_scam_positive_detection(classifier, se_detector):
    """Verify unsolicited lottery winnings requiring advance fee is categorized as PRIZE."""
    msg = "Lucky Draw: Congratulations! You have won Rs 50,000 cash prize in our lottery. Transfer registration fee to claim your reward before midnight."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "PRIZE"
    assert res.label == "Prize"
    assert res.confidence is not None


def test_benign_prize_mention_suppression(classifier, se_detector):
    """Verify harmless mention of sports day prize or reward points is NOT flagged as PRIZE scam."""
    msg = "Congratulations, you earned 10 reward points on your grocery purchase today."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# 5. Investment Category Tests
# -----------------------------------------------------------------------------

def test_investment_scam_positive_detection(classifier, se_detector):
    """Verify guaranteed return and crypto doubling scheme is categorized as INVESTMENT."""
    msg = "Guaranteed return! Double your money with our automated crypto trading algorithm. 200% return in 24 hours risk-free."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "INVESTMENT"
    assert res.label == "Investment"
    assert res.confidence is not None


def test_benign_investment_mention_suppression(classifier, se_detector):
    """Verify conversational use of 'investing time' is NOT flagged as INVESTMENT scam."""
    msg = "I am investing my time in studying computer science fundamentals."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"


# -----------------------------------------------------------------------------
# 6. Ambiguous and Multi-Signal Tests
# -----------------------------------------------------------------------------

def test_ambiguous_message_falls_back_to_unknown(classifier, se_detector):
    """Verify ambiguous or ordinary conversational text outputs UNKNOWN."""
    msg = "Can we meet at the library around 4 PM to work on the assignment?"
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    assert res.category == "UNKNOWN"
    assert res.label == "Unknown"
    assert res.confidence is None


def test_multi_signal_message_exposes_candidates(classifier, se_detector):
    """Verify message with both lottery winnings and bank fee demands identifies primary and candidate."""
    msg = "Lucky Draw: You won Rs 50,000 cash prize in annual lottery. Deposit processing fee to SBI bank account to claim your reward."
    se = se_detector.analyze(msg)
    res = classifier.classify(msg, se)
    # Both PRIZE and BANK_KYC have cues; one is primary and other is in candidate_categories
    assert res.category in ["PRIZE", "BANK_KYC"]
    assert len(res.candidate_categories) >= 1
