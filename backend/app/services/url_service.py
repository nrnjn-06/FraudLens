"""Reusable internal URL analysis service for FraudLens.

Integrates:
1. Lexical and structural URL feature extraction (34 offline indicators).
2. Random Forest ML phishing model inference (calibrated threshold t=0.45).
3. Typosquatting and brand-impersonation detection (Levenshtein distance).
4. Domain and URL forensics breakdown.
5. Multi-factor Unified Risk Classification with statistical humility.
"""

from datetime import datetime, timezone
import logging
import re
from typing import List, Optional
from urllib.parse import parse_qs, urlparse
import tldextract

from backend.app.schemas.common import (
    ExplainableRiskIndicator,
    IndicatorContributionType,
    UnifiedRiskClassification,
)
from backend.app.schemas.url import (
    DomainForensics,
    ThreatIntelResult,
    TyposquattingDetails,
    URLAnalysisResponse,
    URLModelPrediction,
)
from backend.app.services.domain_intelligence import (
    DomainIntelligenceService,
    get_domain_intelligence_service,
)
from backend.app.services.recommendation_engine import get_recommendation_engine
from backend.app.services.risk_engine import UnifiedRiskEngine
from backend.app.services.threat_intel import ThreatIntelService, get_threat_intel_service
from backend.app.services.url_features import (
    TARGET_BRANDS,
    check_brand_impersonation,
    extract_url_feature_dict,
    is_exempt_academic_or_gov,
    is_ip_host,
)
from backend.app.services.url_model_loader import (
    URLModelLoader,
    get_url_model_loader,
)

logger = logging.getLogger(__name__)

# Offline TLDExtract instance (strictly zero network egress)
_offline_tld_extract = tldextract.TLDExtract(
    cache_dir="D:/Projects/usability/data/processed/urls/.tld_cache",
    suffix_list_urls=(),
)

# Major authoritative domains to guard against dataset-specific query string bias
AUTHORITATIVE_LEGIT_DOMAINS = {
    "google.com",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "github.com",
    "wikipedia.org",
    "mozilla.org",
    "cloudflare.com",
    "youtube.com",
    "linkedin.com",
    "netflix.com",
    "python.org",
    "gov.in",
    "nic.in",
}


class URLAnalysisService:
    """Internal reusable service for evaluating URL risk and structure."""

    def __init__(
        self,
        threat_intel_service: Optional[ThreatIntelService] = None,
        model_loader: Optional[URLModelLoader] = None,
        domain_intel_service: Optional[DomainIntelligenceService] = None,
    ):
        self._threat_intel = threat_intel_service
        self._domain_intel = domain_intel_service
        self.model_loader = model_loader or get_url_model_loader()

    @property
    def threat_intel(self) -> ThreatIntelService:
        return self._threat_intel or get_threat_intel_service()

    @threat_intel.setter
    def threat_intel(self, value: Optional[ThreatIntelService]) -> None:
        self._threat_intel = value

    @property
    def domain_intel(self) -> DomainIntelligenceService:
        return self._domain_intel or get_domain_intelligence_service()

    @domain_intel.setter
    def domain_intel(self, value: Optional[DomainIntelligenceService]) -> None:
        self._domain_intel = value

    def parse_forensics(self, raw_url: str) -> DomainForensics:
        """Extract structural domain forensics from the URL (Feature 3)."""
        target = (raw_url or "").strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
            target = f"http://{target}"

        try:
            parsed = urlparse(target)
        except Exception:
            parsed = urlparse("http://unknown")

        hostname = parsed.hostname or ""
        has_ip = is_ip_host(hostname)

        # TLD extract offline
        try:
            extracted = _offline_tld_extract(target)
            subdomain = extracted.subdomain
            domain = extracted.domain
            tld = extracted.suffix
        except Exception:
            subdomain, domain, tld = "", "", ""

        # Flatten query parameters safely
        flat_query_params = {}
        try:
            parsed_qs = parse_qs(parsed.query)
            flat_query_params = {k: v[0] if v else "" for k, v in parsed_qs.items()}
        except Exception:
            pass

        return DomainForensics(
            hostname=hostname,
            subdomain=subdomain,
            domain=domain,
            tld=tld,
            path=parsed.path or "/",
            query_params=flat_query_params,
            has_ip_address=has_ip,
            url_length=len(raw_url),
        )

    def analyze_url(self, raw_url: str) -> URLAnalysisResponse:
        """Execute comprehensive URL analysis across ML, heuristics, and forensics."""
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_url = (raw_url or "").strip()

        # 1. Structural domain forensics
        forensics = self.parse_forensics(clean_url)

        # 2. Typosquatting and brand impersonation check
        brand_score, target_brand, sim_score, brand_desc = check_brand_impersonation(
            registered_domain=forensics.domain,
            subdomain=forensics.subdomain,
            path=forensics.path,
            hostname=forensics.hostname,
            tld=forensics.tld,
        )

        typosquatting = TyposquattingDetails(
            target_brand=target_brand,
            similarity_score=sim_score,
            is_impersonation=bool(brand_score > 0.0),
            details=brand_desc,
        )

        # 3. Model inference
        inference = self.model_loader.predict(clean_url)

        # 4. Threat intelligence lookup
        threat_intel = self.threat_intel.check_reputation(clean_url)

        # Build Explainable Risk Indicators & Evidence
        indicators: List[ExplainableRiskIndicator] = []
        evidence: List[str] = [
            f"Parsed hostname '{forensics.hostname}' (Domain: '{forensics.domain}.{forensics.tld}').",
            f"URL length: {forensics.url_length} characters.",
        ]

        # Structural Heuristic Indicators
        if forensics.has_ip_address:
            evidence.append("Host is formatted as a raw IP address rather than a registered domain name.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="IP_ADDRESS_HOSTNAME",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="Host is formatted as a direct IP address rather than a registered domain name.",
                )
            )

        if typosquatting.is_impersonation:
            evidence.append(f"Brand Impersonation Warning: {typosquatting.details}")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="BRAND_IMPERSONATION_SUSPICION",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description=typosquatting.details,
                )
            )

        # Lexical feature indicators
        fdict = extract_url_feature_dict(clean_url)
        if fdict.get("count_subdomains", 0) >= 3:
            evidence.append(f"Excessive subdomain depth detected ({int(fdict['count_subdomains'])} levels).")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="EXCESSIVE_SUBDOMAINS",
                    contribution_type=IndicatorContributionType.MODEL_FEATURE,
                    description=f"URL contains {int(fdict['count_subdomains'])} subdomain levels, frequently used in domain cloaking.",
                )
            )

        if fdict.get("has_at_symbol", 0) > 0:
            evidence.append("Contains '@' symbol in URL, often used to obscure actual host destination.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="EMBEDDED_AT_SYMBOL",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="The '@' symbol can cause browsers or parsers to misidentify the actual destination host.",
                )
            )

        if fdict.get("has_double_slash_path", 0) > 0:
            evidence.append("Contains '//' separator inside URL path, indicative of open redirect abuse.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="DOUBLE_SLASH_PATH",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="Repeated slashes ('//') in path can be used for URL path redirection exploits.",
                )
            )

        if fdict.get("suspicious_token_count", 0) > 0:
            evidence.append(f"Contains sensitive authentication/security tokens ({int(fdict['suspicious_token_count'])} keywords).")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="SUSPICIOUS_SENSITIVE_TOKENS",
                    contribution_type=IndicatorContributionType.MODEL_FEATURE,
                    description="Path/subdomain contains sensitive keywords ('login', 'verify', 'account', 'banking').",
                )
            )

        if fdict.get("suspicious_tld", 0) > 0:
            evidence.append(f"Top-level domain (.{forensics.tld}) belongs to an extension often associated with high abuse rates.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="SUSPICIOUS_TLD",
                    contribution_type=IndicatorContributionType.MODEL_FEATURE,
                    description=f"Extension .{forensics.tld} is frequently observed in automated disposable phishing registrations.",
                )
            )

        # 5. Model Prediction Formatting
        model_prediction: Optional[URLModelPrediction] = None
        if inference is not None:
            model_prediction = URLModelPrediction(
                is_phishing=inference.is_phishing,
                confidence=inference.probability,
                model_name=inference.model_name,
            )
            evidence.append(
                f"Random Forest ML phishing probability: {inference.probability:.1%} (Decision threshold: {inference.decision_threshold:.2f})."
            )
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="RANDOM_FOREST_PHISHING_PROBABILITY",
                    contribution_type=IndicatorContributionType.MODEL_FEATURE,
                    description=f"Model estimated {inference.probability:.1%} probability of phishing based on 34 structural characteristics.",
                )
            )

        # 5b. Domain Intelligence Analysis
        domain_intel = self.domain_intel.analyze_domain(
            url_or_hostname=clean_url,
            is_impersonation=typosquatting.is_impersonation,
            is_excessive_subdomains=bool(fdict.get("count_subdomains", 0) >= 3),
        )

        # 6. Multi-Factor Risk Synthesis via UnifiedRiskEngine
        full_reg_domain = f"{forensics.domain}.{forensics.tld}".lower()
        is_known_authoritative = (
            (full_reg_domain in AUTHORITATIVE_LEGIT_DOMAINS or is_exempt_academic_or_gov(forensics.tld, forensics.hostname))
            and not typosquatting.is_impersonation
        )

        classification, status, synth_evidence, unified_evidence, recommendations = UnifiedRiskEngine.synthesize_url_risk(
            clean_url=clean_url,
            forensics=forensics,
            typosquatting=typosquatting,
            inference_prediction=model_prediction,
            threat_intel=threat_intel,
            domain_intel=domain_intel,
            fdict=fdict,
            is_known_authoritative=is_known_authoritative,
        )

        # Context-aware structured recommendation with verified official links
        rec_strings, structured_rec = get_recommendation_engine().generate_url_recommendation(
            classification=classification,
            clean_url=clean_url,
            forensics=forensics,
            typosquatting=typosquatting,
            inference_prediction=model_prediction,
            threat_intel=threat_intel,
            fdict=fdict,
            is_known_authoritative=is_known_authoritative,
            domain_intel=domain_intel,
        )

        return URLAnalysisResponse(
            target_url=clean_url,
            classification=classification,
            status=status,
            model_prediction=model_prediction,
            typosquatting=typosquatting,
            forensics=forensics,
            explainable_risk_indicators=indicators,
            threat_intelligence=threat_intel,
            domain_intelligence=domain_intel,
            evidence=synth_evidence,
            unified_evidence=unified_evidence,
            recommendations=rec_strings if rec_strings else recommendations,
            structured_recommendation=structured_rec,
            timestamp=now_iso,
        )


_global_url_service: Optional[URLAnalysisService] = None


def get_url_service() -> URLAnalysisService:
    """Dependency injector for singleton URLAnalysisService."""
    global _global_url_service
    if _global_url_service is None:
        _global_url_service = URLAnalysisService()
    return _global_url_service
