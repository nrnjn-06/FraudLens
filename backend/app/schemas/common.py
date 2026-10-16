"""Common schemas, unified risk classifications, and evidence models for FraudLens."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class UnifiedRiskClassification(str, Enum):
    """The four canonical platform-wide fraud-risk classifications."""

    HIGH_RISK = "HIGH RISK"
    MEDIUM_RISK = "MEDIUM RISK"
    LOW_RISK = "LOW RISK"
    UNABLE_TO_VERIFY = "UNABLE TO VERIFY"


class IndicatorContributionType(str, Enum):
    """Origin of a detection indicator for transparency and explainability."""

    MODEL_FEATURE = "MODEL_FEATURE"
    CONFIRMED_EVIDENCE = "CONFIRMED_EVIDENCE"
    HEURISTIC = "HEURISTIC"
    CONFIRMED_THREAT_INTEL = "CONFIRMED_THREAT_INTEL"
    INFORMATIONAL = "INFORMATIONAL"


class ExplainableRiskIndicator(BaseModel):
    """An explainable signal or feature that contributed to an assessment."""

    indicator: str = Field(..., description="Name or identifier of the detected indicator.")
    contribution_type: IndicatorContributionType = Field(
        ...,
        description="Explicit source distinguishing statistical feature, rule, or confirmed threat.",
    )
    description: str = Field(
        ...,
        description="Human-readable explanation of why this indicator was triggered.",
    )


class EvidenceCategory(str, Enum):
    """Classification of an evidence finding to avoid conflating models, rules, and external intel."""

    MODEL_PREDICTION = "MODEL_PREDICTION"
    HEURISTIC = "HEURISTIC"
    CONFIRMED_THREAT_INTEL = "CONFIRMED_THREAT_INTEL"
    INFORMATIONAL = "INFORMATIONAL"


class EvidenceStatus(str, Enum):
    """Verification status of an evidence observation."""

    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class EvidenceSeverity(str, Enum):
    """Severity attribution of an individual evidence signal."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class UnifiedEvidenceItem(BaseModel):
    """Shared structured evidence item across all FraudLens detection modules.

    Guarantees strict separation between statistical model predictions,
    deterministic local heuristics, and confirmed threat intelligence matches.
    """

    category: EvidenceCategory = Field(
        ...,
        description="Origin category: MODEL_PREDICTION, HEURISTIC, CONFIRMED_THREAT_INTEL, or INFORMATIONAL.",
    )
    description: str = Field(
        ...,
        description="Clear, non-technical human-readable explanation of the observed evidence.",
    )
    source: str = Field(
        ...,
        description="Name of the detector or provider (e.g. 'RandomForest_URL_v1', 'UrgencyDetector', 'VirusTotal').",
    )
    severity: EvidenceSeverity = Field(
        default=EvidenceSeverity.INFORMATIONAL,
        description="Assessed severity level of this individual evidence item.",
    )
    status: EvidenceStatus = Field(
        default=EvidenceStatus.CONFIRMED,
        description="Verification state (CONFIRMED, INCONCLUSIVE, STALE, UNAVAILABLE).",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 observation timestamp.",
    )
    provider_lookup_timestamp: Optional[str] = Field(
        default=None,
        description="Timestamp of external provider query if attributable to threat intelligence.",
    )
    indicator_id: Optional[str] = Field(
        default=None,
        description="Machine-readable identifier for categorization and filtering.",
    )
    is_cached: bool = Field(
        default=False,
        description="Whether this observation was served from the local threat intelligence cache.",
    )


class StructuredSecurityRecommendation(BaseModel):
    """Structured, context-aware safety guidance with verified official website references."""

    title: str = Field(..., description="Concise header for the recommended safety response.")
    detected_threat: str = Field(..., description="Summary of what was detected (Section 1).")
    suspicious_reasons: List[str] = Field(
        default_factory=list,
        description="Specific findings explaining why this threat or link is suspicious (Section 2).",
    )
    organization_name: Optional[str] = Field(
        default=None,
        description="Identified target organization or brand name if reliably established.",
    )
    official_url: Optional[str] = Field(
        default=None,
        description="Authoritative canonical HTTPS URL for the legitimate organization (Section 3).",
    )
    official_domain: Optional[str] = Field(
        default=None,
        description="Registrable domain of the official organization.",
    )
    official_url_source: Optional[str] = Field(
        default=None,
        description="Authoritative verification source for the official URL.",
    )
    official_url_verified: bool = Field(
        default=False,
        description="True only if official destination is derived from trusted verified registry.",
    )
    recommended_action: str = Field(..., description="Primary practical next step for the user.")
    action_steps: List[str] = Field(
        default_factory=list,
        description="Itemized checklist of recommended user actions (Section 4).",
    )
    is_impersonation_detected: bool = Field(
        default=False,
        description="True if analysis indicates impersonation of a known organization.",
    )
    scam_category: Optional[str] = Field(
        default=None,
        description="Detected scam category (e.g. 'BANKING_KYC', 'DELIVERY_COURIER', 'LOTTERY_PRIZE', 'JOB_OFFER', 'INVESTMENT_CRYPTO', 'GOVERNMENT_TAX', 'CREDENTIAL_HARVESTING', 'QR_CODE').",
    )


class BaseRiskAssessment(BaseModel):
    """Standard baseline fields across all module analysis responses."""

    classification: UnifiedRiskClassification = Field(
        ...,
        description="Primary user-facing verdict (one of four unified classifications).",
    )
    status: str = Field(
        default="ANALYSIS_ACTIVE",
        description="Execution status indicating pipeline processing state or module availability.",
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="List of detected facts and signals supporting the verdict (human-readable strings).",
    )
    unified_evidence: List[UnifiedEvidenceItem] = Field(
        default_factory=list,
        description="Structured unified evidence items separating model, heuristic, and threat intel findings.",
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable safety guidance for the user.",
    )
    structured_recommendation: Optional[StructuredSecurityRecommendation] = Field(
        default=None,
        description="Comprehensive context-aware safety recommendations with verified official website links.",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of analysis execution.",
    )
