"""Automated tests for Feature 3: Suspicious-Phrase Highlighting.

Validates:
- Exact character offsets (start inclusive, end exclusive, 0-indexed)
- Invariant: message[start:end] == text == phrase
- Mixed case, punctuation, and Unicode text
- Repeated occurrences of suspicious phrases
- Multiple and overlapping findings
- Protective security advisories (suppression of highlights)
- Benign contextual guards (no false highlights)
- Empty, whitespace, and long messages
- API response integration and backward compatibility
"""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.schemas.message import HighlightedPhrase
from backend.app.services.social_engineering import SocialEngineeringDetector

client = TestClient(app)


@pytest.fixture
def detector():
    return SocialEngineeringDetector()


def test_exact_character_offsets_and_substring_invariants(detector):
    """Verify that original_text[start:end] strictly equals text for every extracted span."""
    message = "URGENT: Your SBI account is suspended. Click the link to update KYC immediately or pay fine within 2 hours."
    spans = detector.extract_highlighted_phrases(message)

    assert len(spans) >= 3
    for span in spans:
        # Check both primary and alias attributes
        assert span.start is not None
        assert span.end is not None
        assert span.text is not None

        # Verify offset invariants
        assert span.start == span.start_idx
        assert span.end == span.end_idx
        assert span.text == span.phrase
        assert span.start < span.end

        # Strict substring identity against original unmodified text
        extracted = message[span.start : span.end]
        assert extracted == span.text
        assert extracted == span.phrase


def test_mixed_case_and_punctuation(detector):
    """Verify phrase highlighting respects mixed case and surrounding punctuation."""
    message = ">>> uRgEnT nOtIcE! <<< Pay Rs 500 immediately to avoid power disconnection tonight!"
    spans = detector.extract_highlighted_phrases(message)

    assert len(spans) >= 2
    for span in spans:
        assert message[span.start : span.end] == span.text
        assert span.text in message


def test_repeated_phrases_produce_distinct_spans(detector):
    """Verify repeated instances of a keyword are extracted at distinct start/end offsets."""
    message = "Call immediately, I repeat please call immediately or take action right now!"
    spans = detector.extract_highlighted_phrases(message)

    # Should find 'immediately' twice at different positions
    immed_spans = [s for s in spans if "immediately" in s.text.lower()]
    assert len(immed_spans) == 2
    assert immed_spans[0].start != immed_spans[1].start
    assert immed_spans[0].end != immed_spans[1].end

    for s in immed_spans:
        assert message[s.start : s.end] == s.text


def test_unicode_and_emojis_offsets(detector):
    """Verify Unicode code points and emojis preserve accurate offsets."""
    message = "⚠️ URGENT: Your account will be permanently blocked! ⚡ Power cut tonight."
    spans = detector.extract_highlighted_phrases(message)

    assert len(spans) >= 2
    for span in spans:
        # Python string indexing on Unicode
        assert message[span.start : span.end] == span.text


def test_multiple_categories_in_compound_message(detector):
    """Verify spans from multiple categories are extracted and categorized properly."""
    message = (
        "Dear Customer, SBI alert: Your bank account will be blocked within 24 hours. "
        "Click the link to verify or share the 6-digit OTP with our agent."
    )
    spans = detector.extract_highlighted_phrases(message)

    categories = {s.category for s in spans}
    assert "impersonation" in categories or "threats" in categories
    assert "urgency" in categories
    assert "otp_requests" in categories

    for s in spans:
        assert message[s.start : s.end] == s.text
        assert len(s.explanation) > 0


def test_security_advisory_suppresses_highlights(detector):
    """Verify defensive educational security warnings produce zero suspicious highlights."""
    msg1 = "Security Tip: SIB never asks for sensitive information like Password/OTP. Beware of fake calls."
    spans1 = detector.extract_highlighted_phrases(msg1)
    assert len(spans1) == 0

    msg2 = "HDFC Bank advisory: Never share your OTP, PIN, or CVV with anyone."
    spans2 = detector.extract_highlighted_phrases(msg2)
    assert len(spans2) == 0


def test_benign_conversational_context_no_highlights(detector):
    """Verify benign contexts like 'pay for lunch' or 'urgent meeting' produce zero highlights."""
    msg = "I have an urgent meeting with my supervisor. Let's pay for lunch together afterwards."
    spans = detector.extract_highlighted_phrases(msg)
    assert len(spans) == 0


def test_empty_and_whitespace_input(detector):
    """Verify empty and whitespace inputs return empty span lists cleanly."""
    assert detector.extract_highlighted_phrases("") == []
    assert detector.extract_highlighted_phrases("   \t\n  ") == []


def test_unusually_long_message_offsets(detector):
    """Verify detector handles long messages accurately."""
    prefix = "Normal filler text for testing purposes. " * 30
    needle = "Your account will be permanently blocked within 24 hours."
    suffix = " More filler text here. " * 30
    message = prefix + needle + suffix

    spans = detector.extract_highlighted_phrases(message)
    assert len(spans) >= 1

    for s in spans:
        assert message[s.start : s.end] == s.text


def test_api_analyze_message_includes_highlighted_phrases():
    """Verify POST /analyze-message returns populated highlighted_phrases in response."""
    payload = {
        "message_text": "URGENT: Your SBI account is blocked. Update KYC at https://fake.bank or pay fine within 2 hours."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "highlighted_phrases" in data
    highlights = data["highlighted_phrases"]
    assert len(highlights) >= 2

    raw_text = payload["message_text"]
    for h in highlights:
        # Check backward compatibility fields
        assert "phrase" in h
        assert "reason" in h
        assert "start_idx" in h
        assert "end_idx" in h

        # Check extended Feature 3 fields
        assert "start" in h
        assert "end" in h
        assert "text" in h
        assert "category" in h
        assert "explanation" in h

        # Verify strict invariant on API response
        assert raw_text[h["start"] : h["end"]] == h["text"]
        assert raw_text[h["start_idx"] : h["end_idx"]] == h["phrase"]


def test_api_advisory_message_has_empty_highlights():
    """Verify defensive security advisory returns empty highlighted_phrases via API."""
    payload = {
        "message_text": "Fraud alert: Never share your OTP or bank password with anyone claiming urgent action."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["highlighted_phrases"] == []
    assert data["classification"] == "LOW RISK"
