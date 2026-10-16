"""Schemas for Module 2: Phishing URL Detection and reusable URL analysis service."""

import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from backend.app.schemas.common import (
    BaseRiskAssessment,
    ExplainableRiskIndicator,
    UnifiedRiskClassification,
)


class URLAnalysisRequest(BaseModel):
    """Payload for submitting a URL for fraud and phishing inspection."""

    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The target web address to inspect.",
        examples=["https://secure-login-update-account.com/verify"],
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty or whitespace only.")

        lower = clean.lower()
        # Disallow unsupported or dangerous schemes (only http and https are supported)
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", lower)
        if scheme_match:
            scheme = scheme_match.group(1)
            if scheme not in ("http", "https"):
                raise ValueError("Unsupported or dangerous URL scheme. Please enter a valid HTTP or HTTPS URL.")

        return clean


class DomainForensics(BaseModel):
    """Deep structural breakdown of the domain and URL components (Feature 3)."""

    hostname: str = Field(..., description="Full hostname portion of the URL.")
    subdomain: str = Field(default="", description="Extracted subdomain (e.g. 'login.secure').")
    domain: str = Field(..., description="Registered second-level domain (e.g. 'paypal').")
    tld: str = Field(..., description="Top-level domain suffix (e.g. 'com', 'xyz').")
    path: str = Field(default="", description="Path component of the URL.")
    query_params: Dict[str, str] = Field(
        default_factory=dict,
        description="Key-value query string parameters.",
    )
    has_ip_address: bool = Field(
        default=False,
        description="Indicates whether the host is a raw IP address instead of a domain name.",
    )
    url_length: int = Field(..., description="Total character length of the URL.")


class TyposquattingDetails(BaseModel):
    """Detection findings for lookalike domains and brand spoofing (Feature 2)."""

    target_brand: Optional[str] = Field(
        default=None,
        description="Legitimate brand potentially targeted by impersonation.",
    )
    similarity_score: Optional[float] = Field(
        default=None,
        description="String similarity or distance metric against legitimate brand.",
    )
    is_impersonation: bool = Field(
        default=False,
        description="Flag indicating whether typosquatting or brand misuse was detected.",
    )
    details: str = Field(
        default="No brand impersonation detected.",
        description="Diagnostic narrative of typosquatting check.",
    )


class ThreatIntelResult(BaseModel):
    """Reputation and threat intelligence lookup findings (Feature 5)."""

    source: str = Field(default="FraudLens Threat Feed", description="Intelligence provider name.")
    is_flagged: bool = Field(default=False, description="Whether the URL was flagged as malicious.")
    lookup_timestamp: str = Field(..., description="Timestamp of the reputation query.")
    lookup_status: str = Field(
        default="UNCONFIGURED",
        description="Execution status (MATCH_FOUND, CLEAN, INCONCLUSIVE, SERVICE_UNAVAILABLE, RATE_LIMITED, UNCONFIGURED).",
    )
    details: Optional[str] = Field(
        default=None,
        description="Additional context, threat categories, or provider notes.",
    )
    is_cached: bool = Field(
        default=False,
        description="True if result was served from the local threat intelligence cache.",
    )
    cached_timestamp: Optional[str] = Field(
        default=None,
        description="Timestamp when the entry was cached.",
    )
    provider_name: Optional[str] = Field(
        default=None,
        description="Specific provider adapter name (e.g. 'VirusTotal', 'URLScan').",
    )
    malicious_count: Optional[int] = Field(
        default=None,
        description="Count of external security vendors flagging malicious.",
    )
    suspicious_count: Optional[int] = Field(
        default=None,
        description="Count of external security vendors flagging suspicious.",
    )
    harmless_count: Optional[int] = Field(
        default=None,
        description="Count of external security vendors flagging clean or harmless.",
    )


class DomainIntelligenceResult(BaseModel):
    """Domain intelligence and registration forensics (WHOIS/RDAP, Domain Age, TLS)."""

    domain: str = Field(..., description="Registrable second-level domain (e.g. 'example.com').")
    hostname: str = Field(..., description="Full target hostname (e.g. 'sub.example.com').")
    domain_age_days: Optional[int] = Field(
        default=None,
        description="Calculated domain age in days strictly from creation date to current UTC date.",
    )
    domain_created_at: Optional[str] = Field(
        default=None,
        description="Authoritative domain creation/registration date in ISO 8601 format.",
    )
    domain_expires_at: Optional[str] = Field(
        default=None,
        description="Domain registration expiration date in ISO 8601 format.",
    )
    registrar: Optional[str] = Field(
        default=None,
        description="Accredited registrar organization name.",
    )
    registration_status: List[str] = Field(
        default_factory=list,
        description="Domain lifecycle status codes (e.g. 'active', 'clientTransferProhibited').",
    )
    nameservers: List[str] = Field(
        default_factory=list,
        description="Authoritative nameservers serving the domain.",
    )
    rdap_available: bool = Field(
        default=False,
        description="True if registration data was retrieved via authoritative RDAP.",
    )
    whois_available: bool = Field(
        default=False,
        description="True if registration data was retrieved via WHOIS protocol.",
    )
    lookup_status: str = Field(
        default="UNAVAILABLE",
        description="Lookup status: SUCCESS, PARTIAL, UNAVAILABLE, TIMED_OUT, NOT_APPLICABLE, UNCONFIGURED.",
    )
    domain_intelligence_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Normalized domain intelligence risk subscore (0.0=benign, 1.0=high risk).",
    )
    domain_intelligence_findings: List[str] = Field(
        default_factory=list,
        description="Key diagnostic findings and indicators regarding domain age, metadata, and TLS.",
    )
    checked_at: str = Field(
        ...,
        description="ISO 8601 timestamp of domain intelligence inspection.",
    )
    tls_certificate_valid: Optional[bool] = Field(
        default=None,
        description="Whether a valid TLS/HTTPS certificate handshake succeeded.",
    )
    tls_issuer: Optional[str] = Field(
        default=None,
        description="Certificate Authority issuer organization (e.g. 'Let's Encrypt', 'DigiCert').",
    )
    tls_expires_at: Optional[str] = Field(
        default=None,
        description="TLS certificate expiration date in ISO 8601 format.",
    )
    is_cached: bool = Field(
        default=False,
        description="True if registration data was served from the local thread-safe TTL cache.",
    )


class URLModelPrediction(BaseModel):
    """Output from the Random Forest phishing classification model (Feature 1)."""

    is_phishing: bool = Field(..., description="Binary model prediction.")
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Diagnostic probability score (never the sole primary verdict).",
    )
    model_name: str = Field(default="RandomForest_URL_v1", description="Model architecture tag.")


class URLAnalysisResponse(BaseRiskAssessment):
    """Comprehensive response contract for URL analysis."""

    target_url: str = Field(..., description="The URL that was analyzed.")
    model_prediction: Optional[URLModelPrediction] = Field(
        default=None,
        description="Output from ML model.",
    )
    typosquatting: Optional[TyposquattingDetails] = Field(
        default=None,
        description="Brand impersonation and lookalike analysis.",
    )
    forensics: Optional[DomainForensics] = Field(
        default=None,
        description="Structural forensic breakdown (Feature 3).",
    )
    explainable_risk_indicators: List[ExplainableRiskIndicator] = Field(
        default_factory=list,
        description="Transparent list of contributing features and rules (Feature 4).",
    )
    threat_intelligence: Optional[ThreatIntelResult] = Field(
        default=None,
        description="Reputation feed findings.",
    )
    domain_intelligence: Optional[DomainIntelligenceResult] = Field(
        default=None,
        description="Registration data, domain age, and security findings (WHOIS/RDAP & TLS).",
    )
