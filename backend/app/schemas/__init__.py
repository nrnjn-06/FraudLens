"""Pydantic schemas and contracts for FraudLens."""

from backend.app.schemas.common import (
    UnifiedRiskClassification,
    IndicatorContributionType,
    ExplainableRiskIndicator,
)
from backend.app.schemas.url import (
    URLAnalysisRequest,
    URLAnalysisResponse,
    DomainForensics,
    TyposquattingDetails,
    ThreatIntelResult,
)
from backend.app.schemas.message import (
    MessageAnalysisRequest,
    MessageAnalysisResponse,
    SocialEngineeringIndicators,
    HighlightedPhrase,
    ExtractedEntities,
    ScamTypeClassification,
)
from backend.app.schemas.qr import (
    QRPayloadType,
    UPIPaymentDetails,
    DestinationPreview,
    QRAnalysisResponse,
)

__all__ = [
    "UnifiedRiskClassification",
    "IndicatorContributionType",
    "ExplainableRiskIndicator",
    "URLAnalysisRequest",
    "URLAnalysisResponse",
    "DomainForensics",
    "TyposquattingDetails",
    "ThreatIntelResult",
    "MessageAnalysisRequest",
    "MessageAnalysisResponse",
    "SocialEngineeringIndicators",
    "HighlightedPhrase",
    "ExtractedEntities",
    "ScamTypeClassification",
    "QRPayloadType",
    "UPIPaymentDetails",
    "DestinationPreview",
    "QRAnalysisResponse",
]
