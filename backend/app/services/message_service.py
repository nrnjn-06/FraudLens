"""Scam message analysis service for FraudLens.

Orchestrates all 5 message detection features:
1. ML Scam Classification (TF-IDF + Logistic Regression)
2. Social Engineering Detection (7 persuasion heuristic categories & advisory negations)
3. Suspicious-Phrase Highlighting (exact character offset spans)
4. Entity Extraction & Embedded URL Scanning (URLs, phones, UPI handles routed to URL detector)
5. Scam Category Identification (Bank/KYC, Delivery, Job, Prize, Investment, Unknown)
"""

from datetime import datetime, timezone
import logging
from typing import List, Optional

from backend.app.schemas.common import (
    EvidenceCategory,
    EvidenceSeverity,
    EvidenceStatus,
    ExplainableRiskIndicator,
    IndicatorContributionType,
    UnifiedEvidenceItem,
    UnifiedRiskClassification,
)
from backend.app.schemas.message import (
    ExtractedEntities,
    HighlightedPhrase,
    MessageAnalysisResponse,
    ScamTypeClassification,
    SocialEngineeringIndicators,
)
from backend.app.services.recommendation_engine import get_recommendation_engine
from backend.app.services.risk_engine import UnifiedRiskEngine
from backend.app.schemas.url import DomainForensics, URLAnalysisResponse
from backend.app.services.entity_extractor import (
    EntityExtractor,
    get_entity_extractor,
)
from backend.app.services.message_model_loader import (
    MessageModelLoader,
    get_message_model_loader,
)
from backend.app.services.scam_category import (
    ScamCategoryClassifier,
    get_scam_category_classifier,
)
from backend.app.services.social_engineering import (
    SocialEngineeringDetector,
    get_social_engineering_detector,
)
from backend.app.services.url_service import URLAnalysisService, get_url_service

logger = logging.getLogger(__name__)


class MessageAnalysisService:
    """Service orchestrating message fraud detection across all 5 features."""

    def __init__(
        self,
        url_service: Optional[URLAnalysisService] = None,
        model_loader: Optional[MessageModelLoader] = None,
        social_engineering_detector: Optional[SocialEngineeringDetector] = None,
        entity_extractor: Optional[EntityExtractor] = None,
        scam_category_classifier: Optional[ScamCategoryClassifier] = None,
    ):
        self.url_service = url_service or get_url_service()
        self.model_loader = model_loader or get_message_model_loader()
        self.se_detector = social_engineering_detector or get_social_engineering_detector()
        self.entity_extractor = entity_extractor or get_entity_extractor()
        self.scam_classifier = scam_category_classifier or get_scam_category_classifier()

    def extract_entities(self, text: str) -> ExtractedEntities:
        """Extract URLs, phone numbers, and UPI handles with exact character offsets (Feature 4)."""
        return self.entity_extractor.extract(text)

    def analyze_message(self, message_text: str) -> MessageAnalysisResponse:
        """Analyze message for scam indicators, coordinating all 5 features.

        Pipeline steps:
        1. Feature 4: Extract entities (URLs, phones, UPI handles) with exact offsets.
        2. Feature 4: Route embedded URLs to the reusable URLAnalysisService safely.
        3. Feature 1: Execute TF-IDF + Logistic Regression statistical inference.
        4. Feature 2: Execute rule-based Social Engineering heuristic detection.
        5. Feature 3: Extract exact character offset spans for highlighted evidence phrases.
        6. Feature 5: Categorize scam typology into Bank/KYC, Delivery, Job, Prize, Investment, or Unknown.
        7. Multi-evidence risk synthesis mapping to UnifiedRiskClassification without arbitrary formulas.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------------------
        # 1. Feature 4: Entity Extraction
        # -------------------------------------------------------------
        entities = self.extract_entities(message_text)

        # -------------------------------------------------------------
        # 2. Feature 4: Embedded URL Analysis Integration
        # -------------------------------------------------------------
        embedded_analyses: List[URLAnalysisResponse] = []
        for raw_url in entities.urls[:5]:  # Safety cap: analyze up to 5 unique URLs
            try:
                url_resp = self.url_service.analyze_url(raw_url)
                embedded_analyses.append(url_resp)
            except Exception as exc:
                logger.warning("Error analyzing embedded URL '%s': %s", raw_url, exc)
                # Resilient fallback: URL failure never crashes the message analysis
                embedded_analyses.append(
                    URLAnalysisResponse(
                        target_url=raw_url,
                        classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
                        status="URL_ANALYSIS_FAILED",
                        model_prediction=None,
                        forensics=DomainForensics(
                            hostname="unknown",
                            subdomain="",
                            domain="unknown",
                            tld="",
                            path="/",
                            query_params={},
                            has_ip_address=False,
                            url_length=len(raw_url),
                        ),
                        explainable_risk_indicators=[
                            ExplainableRiskIndicator(
                                indicator="ANALYSIS_ERROR",
                                contribution_type=IndicatorContributionType.HEURISTIC,
                                description=f"URL inspection failed: {str(exc)}",
                            )
                        ],
                        evidence=[f"Failed to inspect URL '{raw_url}': {str(exc)}"],
                        recommendations=["Exercise caution with unverified embedded links."],
                        timestamp=now_iso,
                    )
                )

        evidence: List[str] = [
            f"Message length: {len(message_text)} characters.",
            f"Extracted entities: {len(entities.urls)} URL(s), {len(entities.phone_numbers)} phone number(s), {len(entities.upi_ids)} UPI ID(s).",
        ]
        if entities.indicators:
            evidence.append(f"Additional indicators: {', '.join(entities.indicators[:3])}.")

        recommendations: List[str] = [
            "Never share OTPs, passwords, or bank PINs with anyone claiming urgent action.",
            "Verify claims directly through official contact channels, not numbers or links provided in the message.",
        ]

        # -------------------------------------------------------------
        # 3. Feature 2: Social Engineering Heuristic Detection
        # -------------------------------------------------------------
        se_indicators = self.se_detector.analyze(message_text)

        # -------------------------------------------------------------
        # 4. Feature 1: Statistical Model Inference
        # -------------------------------------------------------------
        pred = self.model_loader.predict(message_text)

        # -------------------------------------------------------------
        # 5. Feature 5: Scam Category Identification
        # -------------------------------------------------------------
        scam_type = self.scam_classifier.classify(message_text, se_indicators, entities)

        # -------------------------------------------------------------
        # 6. Multi-Evidence Risk Synthesis via UnifiedRiskEngine
        # -------------------------------------------------------------
        (
            classification,
            status,
            synth_evidence,
            unified_evidence,
            synth_recommendations,
        ) = UnifiedRiskEngine.synthesize_message_risk(
            original_text=message_text,
            is_model_available=pred is not None,
            pred_is_scam=pred.is_scam if pred else False,
            pred_confidence=pred.confidence if pred else 0.0,
            model_name=pred.model_name if pred else "LogisticRegression_TFIDF_v1",
            se_findings=se_indicators.findings,
            is_advisory=se_indicators.is_advisory_or_educational,
            is_benign=se_indicators.is_benign_notification,
            scam_category=scam_type.category,
            embedded_url_analyses=embedded_analyses,
        )

        if pred is None:
            reason = self.model_loader.error_reason or "Scam detection model artifact unavailable."
            evidence.append(f"Model status: {reason}")
        elif se_indicators.is_advisory_or_educational:
            evidence.append(
                "Notice: Identified as a legitimate defensive security advisory or educational alert."
            )

        evidence.extend(synth_evidence)

        # -------------------------------------------------------------
        # 7. Feature 3: Suspicious-Phrase Highlighting
        # -------------------------------------------------------------
        highlighted_phrases = self.se_detector.extract_highlighted_phrases(message_text)
        if highlighted_phrases:
            evidence.append(
                f"Suspicious phrase highlighting (Feature 3): {len(highlighted_phrases)} warning phrase span(s) identified for explanation."
            )
            unified_evidence.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.INFORMATIONAL,
                    description=f"{len(highlighted_phrases)} suspicious phrase span(s) highlighted in message.",
                    source="PhraseHighlighter",
                    severity=EvidenceSeverity.INFORMATIONAL,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="HIGHLIGHTED_PHRASES",
                )
            )

        # Context-aware structured recommendation with verified official links
        rec_strings, structured_rec = get_recommendation_engine().generate_message_recommendation(
            classification=classification,
            original_text=message_text,
            scam_category=scam_type.category,
            pred_is_scam=pred.is_scam if pred else False,
            pred_confidence=pred.confidence if pred else 0.0,
            se_findings=se_indicators.findings,
            is_advisory=se_indicators.is_advisory_or_educational,
            is_benign=se_indicators.is_benign_notification,
            embedded_url_analyses=embedded_analyses,
        )

        return MessageAnalysisResponse(
            original_text=message_text,
            classification=classification,
            status=status,
            model_prediction=pred,
            social_engineering=se_indicators,
            highlighted_phrases=highlighted_phrases,
            extracted_entities=entities,
            scam_type=scam_type,
            embedded_url_analyses=embedded_analyses,
            evidence=evidence,
            unified_evidence=unified_evidence,
            recommendations=rec_strings if rec_strings else synth_recommendations,
            structured_recommendation=structured_rec,
            timestamp=now_iso,
        )


_global_message_service: Optional[MessageAnalysisService] = None


def get_message_service() -> MessageAnalysisService:
    """Dependency injector for MessageAnalysisService singleton."""
    global _global_message_service
    if _global_message_service is None:
        _global_message_service = MessageAnalysisService()
    return _global_message_service
