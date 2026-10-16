"""Schemas for Module 1: Scam Message Detection."""

from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from backend.app.schemas.common import BaseRiskAssessment
from backend.app.schemas.url import URLAnalysisResponse


class MessageAnalysisRequest(BaseModel):
    """Payload for submitting text (SMS, WhatsApp, email) for scam analysis."""

    message_text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The raw text content to inspect.",
        examples=["URGENT: Your bank account is locked. Click http://secure-bank.xyz to update KYC immediately."],
    )

    @field_validator("message_text")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Message text cannot be empty or solely whitespace.")
        return clean


class HeuristicFinding(BaseModel):
    """Structured detail for an individual detected social engineering signal."""

    category: str = Field(
        ...,
        description="Category: urgency, threats, impersonation, otp_requests, prize_bait, payment_demands, link_click_pressure.",
    )
    explanation: str = Field(
        ...,
        description="Human-readable explanation of why this pattern is suspicious.",
    )
    matched_text: str = Field(
        ...,
        description="Evidence substring or phrase matched.",
    )
    severity: str = Field(
        default="MEDIUM",
        description="Defined severity level (HIGH or MEDIUM).",
    )


class SocialEngineeringIndicators(BaseModel):
    """Signals of manipulative psychology and coercion (Feature 2)."""

    urgency: bool = Field(default=False, description="Artificial time pressure detected.")
    threats: bool = Field(default=False, description="Intimidation, account suspension, or legal threats.")
    impersonation: bool = Field(default=False, description="Impersonation of institutions or authority figures.")
    otp_requests: bool = Field(default=False, description="Solicitation of OTP, passwords, or PINs.")
    prize_bait: bool = Field(default=False, description="Fabricated winnings, lottery, or gift bait.")
    payment_demands: bool = Field(default=False, description="Demands for immediate transfers or gift cards.")
    link_click_pressure: bool = Field(default=False, description="Pressure to click links or navigate immediately.")
    is_advisory_or_educational: bool = Field(
        default=False,
        description="Identifies legitimate security notices warning users against disclosing credentials.",
    )
    is_benign_notification: bool = Field(
        default=False,
        description="Identifies legitimate transactional delivery or job interview notifications.",
    )
    signals: List[str] = Field(default_factory=list, description="Descriptive list of triggered behavioral rules.")
    findings: List[HeuristicFinding] = Field(
        default_factory=list,
        description="Structured details of triggered indicators with matched text and severity.",
    )


class HighlightedPhrase(BaseModel):
    """Warning phrase identified via deterministic explanation heuristics (Feature 3)."""

    phrase: str = Field(..., description="Exact matched phrase in message text.")
    reason: str = Field(..., description="Explanation of why this phrase is suspicious.")
    start_idx: int = Field(..., ge=0, description="Start character offset in raw message (inclusive, 0-indexed).")
    end_idx: int = Field(..., ge=0, description="End character offset in raw message (exclusive, 0-indexed).")

    # Feature 3 extended attributes (matching exact span specifications):
    start: Optional[int] = Field(default=None, description="Inclusive character offset in original message.")
    end: Optional[int] = Field(default=None, description="Exclusive character offset in original message.")
    text: Optional[str] = Field(default=None, description="Exact substring from original message.")
    category: str = Field(default="suspicious_phrase", description="Relevant indicator category.")
    explanation: Optional[str] = Field(default=None, description="Concise reason phrase was flagged.")

    def model_post_init(self, __context: Any) -> None:
        """Synchronize aliases to guarantee message[start:end] == text."""
        if self.start is None:
            self.start = self.start_idx
        if self.end is None:
            self.end = self.end_idx
        if self.text is None:
            self.text = self.phrase
        if self.explanation is None:
            self.explanation = self.reason


class EntitySpan(BaseModel):
    """Detailed entity match with exact character offset and type."""

    entity_type: str = Field(..., description="Type of entity: URL, PHONE, UPI, INDICATOR.")
    value: str = Field(..., description="Extracted entity value.")
    raw_text: str = Field(..., description="Exact raw substring matched in message.")
    start: int = Field(..., ge=0, description="Start offset in original message (inclusive).")
    end: int = Field(..., ge=0, description="End offset in original message (exclusive).")


class ExtractedEntities(BaseModel):
    """Indicators extracted from the message content (Feature 4)."""

    urls: List[str] = Field(default_factory=list, description="Extracted web addresses.")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted telephone numbers.")
    upi_ids: List[str] = Field(default_factory=list, description="Extracted UPI virtual payment addresses.")
    indicators: List[str] = Field(default_factory=list, description="Other detected digital artifacts.")
    spans: List[EntitySpan] = Field(default_factory=list, description="Exact character offsets for extracted entities.")


class ScamTypeClassification(BaseModel):
    """Typology classification for supported fraud categories (Feature 5)."""

    category: str = Field(
        default="UNKNOWN",
        description="Canonical category code: BANK_KYC, DELIVERY, JOB, PRIZE, INVESTMENT, UNKNOWN.",
    )
    label: str = Field(
        default="Unknown",
        description="Human-readable label: Bank/KYC, Delivery, Job, Prize, Investment, Unknown.",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence or support score for this classification.",
    )
    matched_patterns: List[str] = Field(
        default_factory=list,
        description="Supporting indicators, cues, or matched patterns.",
    )
    candidate_categories: List[str] = Field(
        default_factory=list,
        description="Other plausible candidate categories if message is ambiguous.",
    )
    explanation: Optional[str] = Field(
        default=None,
        description="Explanation of the assigned categorization rationale.",
    )


class MessageModelPrediction(BaseModel):
    """Output from the TF-IDF + Logistic Regression scam model (Feature 1)."""

    is_scam: bool = Field(..., description="Binary classification prediction.")
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Diagnostic probability score (never the sole primary verdict).",
    )
    model_name: str = Field(default="LogisticRegression_TFIDF_v1", description="Model architecture tag.")


class MessageAnalysisResponse(BaseRiskAssessment):
    """Comprehensive response contract for scam message analysis."""

    original_text: str = Field(..., description="The message submitted for inspection.")
    model_prediction: Optional[MessageModelPrediction] = Field(
        default=None,
        description="Statistical model prediction.",
    )
    social_engineering: Optional[SocialEngineeringIndicators] = Field(
        default=None,
        description="Psychological coercion findings.",
    )
    highlighted_phrases: List[HighlightedPhrase] = Field(
        default_factory=list,
        description="Phrase highlights and warning explanations.",
    )
    extracted_entities: Optional[ExtractedEntities] = Field(
        default=None,
        description="Extracted URLs, numbers, and indicators.",
    )
    scam_type: Optional[ScamTypeClassification] = Field(
        default=None,
        description="Scam category identification.",
    )
    embedded_url_analyses: List[URLAnalysisResponse] = Field(
        default_factory=list,
        description="Analysis of embedded URLs routed to the phishing engine.",
    )
