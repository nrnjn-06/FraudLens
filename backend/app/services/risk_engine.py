"""Unified Risk Synthesis Engine for FraudLens.

Orchestrates multi-evidence risk synthesis across Scam Messages, Phishing URLs, and QR codes.
Enforces canonical platform invariants:
1. Strict separation of MODEL_PREDICTION, HEURISTIC, CONFIRMED_THREAT_INTEL, and INFORMATIONAL evidence.
2. Direct escalation to HIGH RISK upon confirmed threat intelligence matches.
3. Defensive/educational advisory context guards against false alarms.
4. Fail-safe UNABLE TO VERIFY when required ML model artifacts are unavailable.
5. No single score as the primary verdict; no false safety claims from clean lookups or HTTPS.
6. Zero double-counting between messages and embedded URLs.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Tuple

from backend.app.schemas.common import (
    EvidenceCategory,
    EvidenceSeverity,
    EvidenceStatus,
    UnifiedEvidenceItem,
    UnifiedRiskClassification,
)
from backend.app.schemas.url import (
    DomainForensics,
    DomainIntelligenceResult,
    ThreatIntelResult,
    TyposquattingDetails,
    URLModelPrediction,
)
from backend.app.services.recommendation_engine import get_recommendation_engine

logger = logging.getLogger(__name__)

# Verified official brand directory with authoritative domains and safe alternatives
VERIFIED_BRAND_DIRECTORY: Dict[str, Dict[str, str]] = {
    "paypal": {
        "display_name": "PayPal",
        "service_type": "payment and wallet service",
        "official_domain": "paypal.com",
        "safe_alternative": "Navigate directly to https://www.paypal.com or use the official PayPal mobile app to access your account securely.",
    },
    "sbi": {
        "display_name": "State Bank of India (SBI)",
        "service_type": "banking and KYC portal",
        "official_domain": "onlinesbi.sbi",
        "safe_alternative": "Access SBI services exclusively via https://www.onlinesbi.sbi or the verified YONO SBI mobile app.",
    },
    "hdfc": {
        "display_name": "HDFC Bank",
        "service_type": "banking and netbanking portal",
        "official_domain": "hdfcbank.com",
        "safe_alternative": "Visit the official HDFC Bank portal at https://www.hdfcbank.com or use the verified HDFC Bank MobileBanking app.",
    },
    "icici": {
        "display_name": "ICICI Bank",
        "service_type": "banking and payment portal",
        "official_domain": "icicibank.com",
        "safe_alternative": "Access your account only through https://www.icicibank.com or the official iMobile Pay application.",
    },
    "chase": {
        "display_name": "Chase Bank",
        "service_type": "banking and credit card service",
        "official_domain": "chase.com",
        "safe_alternative": "Log in directly via https://www.chase.com or the verified Chase Mobile app.",
    },
    "wellsfargo": {
        "display_name": "Wells Fargo",
        "service_type": "banking service",
        "official_domain": "wellsfargo.com",
        "safe_alternative": "Log in directly at https://www.wellsfargo.com or through the official Wells Fargo Mobile app.",
    },
    "bankofamerica": {
        "display_name": "Bank of America",
        "service_type": "banking service",
        "official_domain": "bankofamerica.com",
        "safe_alternative": "Access your accounts only through https://www.bankofamerica.com or the official Bank of America mobile app.",
    },
    "citi": {
        "display_name": "Citibank",
        "service_type": "banking and card service",
        "official_domain": "citi.com",
        "safe_alternative": "Visit https://www.citi.com directly or use the official Citi Mobile application.",
    },
    "google": {
        "display_name": "Google",
        "service_type": "account and identity service",
        "official_domain": "google.com",
        "safe_alternative": "Manage your Google account directly at https://myaccount.google.com or use your trusted browser bookmarks.",
    },
    "apple": {
        "display_name": "Apple",
        "service_type": "Apple ID and cloud service",
        "official_domain": "apple.com",
        "safe_alternative": "Sign in to Apple ID services only at https://appleid.apple.com or through official Apple device settings.",
    },
    "microsoft": {
        "display_name": "Microsoft",
        "service_type": "account and cloud service",
        "official_domain": "microsoft.com",
        "safe_alternative": "Log in directly at https://login.microsoftonline.com or https://account.microsoft.com.",
    },
    "amazon": {
        "display_name": "Amazon",
        "service_type": "shopping and account service",
        "official_domain": "amazon.com",
        "safe_alternative": "Open https://www.amazon.com directly or use the official Amazon shopping app to review orders and account status.",
    },
    "netflix": {
        "display_name": "Netflix",
        "service_type": "streaming membership service",
        "official_domain": "netflix.com",
        "safe_alternative": "Update membership or payment details directly at https://www.netflix.com/youraccount or via the official Netflix app.",
    },
    "dhl": {
        "display_name": "DHL Express",
        "service_type": "shipment tracking service",
        "official_domain": "dhl.com",
        "safe_alternative": "Track shipments only on the official DHL portal at https://www.dhl.com or through official courier communications.",
    },
    "fedex": {
        "display_name": "FedEx",
        "service_type": "package tracking service",
        "official_domain": "fedex.com",
        "safe_alternative": "Track deliveries directly at https://www.fedex.com or using the official FedEx mobile application.",
    },
    "usps": {
        "display_name": "US Postal Service (USPS)",
        "service_type": "postal delivery service",
        "official_domain": "usps.com",
        "safe_alternative": "Verify shipment tracking directly at https://tools.usps.com or via the official USPS Mobile app.",
    },
    "binance": {
        "display_name": "Binance",
        "service_type": "cryptocurrency exchange",
        "official_domain": "binance.com",
        "safe_alternative": "Access trading and wallet services exclusively at https://www.binance.com or through the verified Binance app.",
    },
    "coinbase": {
        "display_name": "Coinbase",
        "service_type": "cryptocurrency platform",
        "official_domain": "coinbase.com",
        "safe_alternative": "Authenticate only on https://www.coinbase.com or via the verified Coinbase mobile application.",
    },
    "facebook": {
        "display_name": "Facebook",
        "service_type": "social network",
        "official_domain": "facebook.com",
        "safe_alternative": "Log in only at https://www.facebook.com or through official Meta applications.",
    },
    "instagram": {
        "display_name": "Instagram",
        "service_type": "social media platform",
        "official_domain": "instagram.com",
        "safe_alternative": "Access your profile directly at https://www.instagram.com or through the official Instagram mobile app.",
    },
    "whatsapp": {
        "display_name": "WhatsApp",
        "service_type": "messaging service",
        "official_domain": "whatsapp.com",
        "safe_alternative": "Connect to WhatsApp Web only via https://web.whatsapp.com by scanning the code from your official WhatsApp mobile app.",
    },
    "yahoo": {
        "display_name": "Yahoo",
        "service_type": "portal and email service",
        "official_domain": "yahoo.com",
        "safe_alternative": "Access Yahoo Mail and account settings directly at https://login.yahoo.com.",
    },
    "ebay": {
        "display_name": "eBay",
        "service_type": "marketplace platform",
        "official_domain": "ebay.com",
        "safe_alternative": "Review transactions and sign in directly at https://www.ebay.com or using the official eBay mobile app.",
    },
    "dropbox": {
        "display_name": "Dropbox",
        "service_type": "cloud storage service",
        "official_domain": "dropbox.com",
        "safe_alternative": "Sign in to your files directly at https://www.dropbox.com or through the official Dropbox desktop/mobile app.",
    },
}


class UnifiedRiskEngine:
    """Central decision engine for synthesising evidence into the 4 canonical risk levels."""

    @staticmethod
    def synthesize_url_risk(
        clean_url: str,
        forensics: DomainForensics,
        typosquatting: TyposquattingDetails,
        inference_prediction: Optional[URLModelPrediction],
        threat_intel: Optional[ThreatIntelResult],
        fdict: dict,
        is_known_authoritative: bool,
        domain_intel: Optional[DomainIntelligenceResult] = None,
    ) -> Tuple[UnifiedRiskClassification, str, List[str], List[UnifiedEvidenceItem], List[str]]:
        """Synthesize risk verdict, evidence strings, unified structured evidence, and guidance for a URL."""
        now_iso = datetime.now(timezone.utc).isoformat()
        evidence_strings: List[str] = [
            f"Parsed hostname '{forensics.hostname}' (Domain: '{forensics.domain}.{forensics.tld}').",
            f"URL length: {forensics.url_length} characters.",
        ]
        unified_items: List[UnifiedEvidenceItem] = []

        # 1. Structural Forensics Evidence (Informational)
        unified_items.append(
            UnifiedEvidenceItem(
                category=EvidenceCategory.INFORMATIONAL,
                description=f"Hostname: {forensics.hostname}, Registered Domain: {forensics.domain}.{forensics.tld}, Path: {forensics.path}",
                source="DomainForensics",
                severity=EvidenceSeverity.INFORMATIONAL,
                status=EvidenceStatus.CONFIRMED,
                timestamp=now_iso,
                indicator_id="DOMAIN_FORENSICS_STRUCTURE",
            )
        )

        # 2. Local Heuristic Checks
        has_severe_heuristic = False
        has_moderate_heuristic = False

        if forensics.has_ip_address:
            desc = "Host is formatted as a direct raw IP address rather than a registered domain name."
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="IPHostDetector",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="IP_ADDRESS_HOSTNAME",
                )
            )

        if typosquatting.is_impersonation:
            desc = f"Brand Impersonation Warning: {typosquatting.details}"
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="TyposquattingDetector",
                    severity=EvidenceSeverity.HIGH if typosquatting.similarity_score and typosquatting.similarity_score >= 0.8 else EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="BRAND_IMPERSONATION",
                )
            )

        if fdict.get("count_subdomains", 0) >= 3:
            desc = f"Excessive subdomain depth detected ({int(fdict['count_subdomains'])} levels), common in cloaking."
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="SubdomainAnalyzer",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="EXCESSIVE_SUBDOMAINS",
                )
            )

        if fdict.get("has_at_symbol", 0) > 0:
            desc = "Contains '@' symbol in URL, often used to obscure actual host destination."
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="LexicalAnalyzer",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="EMBEDDED_AT_SYMBOL",
                )
            )

        if fdict.get("suspicious_token_count", 0) > 0:
            desc = f"Contains sensitive authentication tokens ({int(fdict['suspicious_token_count'])} keywords: login/verify/account)."
            evidence_strings.append(desc)
            if forensics.has_ip_address or typosquatting.is_impersonation:
                has_severe_heuristic = True
            else:
                has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="TokenInspector",
                    severity=EvidenceSeverity.HIGH if has_severe_heuristic else EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="SENSITIVE_AUTH_TOKENS",
                )
            )

        if fdict.get("has_double_slash_path", 0) > 0:
            desc = "Contains '//' separator inside URL path, indicative of open redirect abuse."
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="LexicalAnalyzer",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="DOUBLE_SLASH_PATH",
                )
            )

        if fdict.get("suspicious_tld", 0) > 0:
            desc = f"Top-level domain (.{forensics.tld}) belongs to an extension often associated with high abuse rates."
            evidence_strings.append(desc)
            has_moderate_heuristic = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=desc,
                    source="TLDAnalyzer",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="SUSPICIOUS_TLD",
                )
            )

        # 3. Model Prediction Evidence
        ml_high_confidence = False
        ml_score: Optional[float] = None
        if inference_prediction is not None:
            prob = inference_prediction.confidence or 0.0
            ml_score = prob
            evidence_strings.append(
                f"Random Forest ML phishing probability: {prob:.1%} (Model: {inference_prediction.model_name})."
            )
            severity = EvidenceSeverity.HIGH if prob >= 0.60 else (EvidenceSeverity.MEDIUM if prob >= 0.35 else EvidenceSeverity.LOW)
            if prob >= 0.60 and not is_known_authoritative:
                ml_high_confidence = True
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.MODEL_PREDICTION,
                    description=f"Model estimated {prob:.1%} phishing probability across 34 lexical/structural features.",
                    source=inference_prediction.model_name,
                    severity=severity,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="RANDOM_FOREST_PHISHING_PROBABILITY",
                )
            )

        # 4. Threat Intelligence Evidence
        confirmed_threat_intel_match = False
        threat_score: Optional[float] = None
        if threat_intel is not None:
            provider = threat_intel.provider_name or threat_intel.source
            if threat_intel.is_flagged and threat_intel.lookup_status == "MATCH_FOUND":
                confirmed_threat_intel_match = True
                threat_score = 1.0
                desc = f"External threat intelligence match: {threat_intel.details or 'Flagged malicious by security vendors.'}"
                evidence_strings.append(f"Confirmed Threat Intel Alert: {desc}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.CONFIRMED_THREAT_INTEL,
                        description=desc,
                        source=provider,
                        severity=EvidenceSeverity.HIGH,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        provider_lookup_timestamp=threat_intel.lookup_timestamp,
                        indicator_id="EXTERNAL_THREAT_INTEL_MATCH",
                        is_cached=threat_intel.is_cached,
                    )
                )
            elif threat_intel.lookup_status == "CLEAN":
                threat_score = 0.0
                desc = threat_intel.details or f"Clean lookup across {provider} vendor checks."
                evidence_strings.append(f"Threat Intelligence: {desc}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.INFORMATIONAL,
                        description=f"{desc} (Note: Absence of external reports is not proof of safety).",
                        source=provider,
                        severity=EvidenceSeverity.LOW,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        provider_lookup_timestamp=threat_intel.lookup_timestamp,
                        indicator_id="EXTERNAL_THREAT_INTEL_CLEAN",
                        is_cached=threat_intel.is_cached,
                    )
                )
            elif threat_intel.lookup_status in ("UNCONFIGURED", "SERVICE_UNAVAILABLE", "RATE_LIMITED"):
                desc = threat_intel.details or "External threat intelligence was unconfigured or temporarily unavailable."
                evidence_strings.append(f"Threat Intelligence Telemetry: {desc}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.INFORMATIONAL,
                        description=desc,
                        source=provider,
                        severity=EvidenceSeverity.INFORMATIONAL,
                        status=EvidenceStatus.UNAVAILABLE,
                        timestamp=now_iso,
                        provider_lookup_timestamp=threat_intel.lookup_timestamp,
                        indicator_id="EXTERNAL_THREAT_INTEL_UNAVAILABLE",
                        is_cached=threat_intel.is_cached,
                    )
                )

        # 5. Domain Intelligence Evidence & Scoring
        has_new_domain_warning = False
        domain_intel_score: Optional[float] = None

        if domain_intel is not None:
            # Append diagnostic findings
            for finding in domain_intel.domain_intelligence_findings:
                evidence_strings.append(f"Domain Intelligence: {finding}")

            # Structured registration metadata item
            reg_name = domain_intel.registrar or "Unspecified/Redacted"
            age_label = f"{domain_intel.domain_age_days} day(s)" if domain_intel.domain_age_days is not None else "Unavailable"
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.INFORMATIONAL,
                    description=f"Domain: {domain_intel.domain}, Age: {age_label}, Registrar: {reg_name}, Status: {domain_intel.lookup_status}.",
                    source="DomainIntelligence",
                    severity=EvidenceSeverity.INFORMATIONAL,
                    status=EvidenceStatus.CONFIRMED if domain_intel.lookup_status in ("SUCCESS", "PARTIAL") else EvidenceStatus.UNAVAILABLE,
                    timestamp=now_iso,
                    indicator_id="DOMAIN_REGISTRATION_METADATA",
                    is_cached=domain_intel.is_cached,
                )
            )

            # Structured TLS item
            if domain_intel.tls_certificate_valid is not None:
                tls_desc = "Valid TLS certificate" if domain_intel.tls_certificate_valid else "Invalid or untrusted TLS certificate"
                if domain_intel.tls_issuer:
                    tls_desc += f" (Issued by {domain_intel.tls_issuer})"
                tls_desc += ". Note: Presence of HTTPS does not establish website legitimacy."
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.INFORMATIONAL,
                        description=tls_desc,
                        source="TLSInspector",
                        severity=EvidenceSeverity.INFORMATIONAL if domain_intel.tls_certificate_valid else EvidenceSeverity.MEDIUM,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        indicator_id="TLS_CERTIFICATE_VERIFICATION",
                    )
                )

            # Evaluate age severity
            if domain_intel.domain_age_days is not None:
                d_age = domain_intel.domain_age_days
                if d_age <= 30:
                    has_new_domain_warning = True
                    sev = EvidenceSeverity.HIGH if d_age < 7 else EvidenceSeverity.MEDIUM
                    desc = f"Newly registered domain: '{domain_intel.domain}' was created only {d_age} day(s) ago."
                    unified_items.append(
                        UnifiedEvidenceItem(
                            category=EvidenceCategory.HEURISTIC,
                            description=desc,
                            source="DomainIntelligence",
                            severity=sev,
                            status=EvidenceStatus.CONFIRMED,
                            timestamp=now_iso,
                            indicator_id="NEWLY_REGISTERED_DOMAIN",
                            is_cached=domain_intel.is_cached,
                        )
                    )

            if domain_intel.lookup_status in ("SUCCESS", "PARTIAL") and domain_intel.domain_intelligence_score is not None:
                domain_intel_score = domain_intel.domain_intelligence_score

        # 6. Composite Score Calculation with Dynamic Weight Normalization (Change 2 A)
        # Weights: Domain intelligence (40%), ML prediction (35%), Heuristics (15%), Threat intel (10%)
        active_weights: Dict[str, float] = {}
        component_scores: Dict[str, float] = {}

        if domain_intel_score is not None:
            active_weights["domain_intel"] = 0.40
            component_scores["domain_intel"] = domain_intel_score

        if ml_score is not None:
            active_weights["ml"] = 0.35
            component_scores["ml"] = ml_score

        # Heuristic score
        heuristic_score = 1.0 if has_severe_heuristic else (0.6 if typosquatting.is_impersonation else (0.4 if has_moderate_heuristic else 0.0))
        active_weights["heuristics"] = 0.15
        component_scores["heuristics"] = heuristic_score

        if threat_score is not None:
            active_weights["threat_intel"] = 0.10
            component_scores["threat_intel"] = threat_score

        total_weight = sum(active_weights.values())
        composite_score = sum(component_scores[k] * (active_weights[k] / total_weight) for k in active_weights) if total_weight > 0 else 0.0

        # 7. Synthesis Decision Matrix
        if inference_prediction is None and not confirmed_threat_intel_match:
            # Model missing and no confirmed external threat -> UNABLE TO VERIFY
            classification = UnifiedRiskClassification.UNABLE_TO_VERIFY
            status = "MODEL_UNAVAILABLE"
            evidence_strings.append("ML model artifact unavailable; returning safe fail-over verification status.")
        elif confirmed_threat_intel_match:
            # External confirmed threat -> Immediate HIGH RISK override
            classification = UnifiedRiskClassification.HIGH_RISK
            status = "CONFIRMED_THREAT_INTEL_MATCH"
        elif has_severe_heuristic:
            classification = UnifiedRiskClassification.HIGH_RISK
            status = "HIGH_CONFIDENCE_MALICIOUS_IP" if forensics.has_ip_address else "BRAND_IMPERSONATION_PHISHING"
        elif ml_high_confidence:
            classification = UnifiedRiskClassification.HIGH_RISK
            status = "HIGH_PROBABILITY_PHISHING"
        elif is_known_authoritative and not forensics.has_ip_address and not typosquatting.is_impersonation:
            classification = UnifiedRiskClassification.LOW_RISK
            status = "AUTHORITATIVE_DOMAIN_VERIFIED"
        elif has_new_domain_warning and (typosquatting.is_impersonation or (inference_prediction and (inference_prediction.confidence or 0.0) >= 0.40)):
            classification = UnifiedRiskClassification.HIGH_RISK
            status = "NEW_DOMAIN_BRAND_IMPERSONATION" if typosquatting.is_impersonation else "NEW_DOMAIN_SUSPICIOUS_SIGNALS"
        elif composite_score >= 0.55:
            classification = UnifiedRiskClassification.HIGH_RISK
            status = "HIGH_RISK_COMPOSITE_SCORE"
        elif has_moderate_heuristic or has_new_domain_warning or (inference_prediction and inference_prediction.confidence and inference_prediction.confidence >= 0.25) or composite_score >= 0.25:
            classification = UnifiedRiskClassification.MEDIUM_RISK
            status = "SUSPICIOUS_ANOMALOUS_STRUCTURE" if not has_new_domain_warning else "NEWLY_REGISTERED_DOMAIN"
        else:
            classification = UnifiedRiskClassification.LOW_RISK
            status = "NO_INDICATORS_OBSERVED"

        # 8. Actionable Safety Recommendations
        recommendations = UnifiedRiskEngine.generate_url_recommendations(
            classification=classification,
            clean_url=clean_url,
            forensics=forensics,
            typosquatting=typosquatting,
            inference_prediction=inference_prediction,
            threat_intel=threat_intel,
            fdict=fdict,
            is_known_authoritative=is_known_authoritative,
            domain_intel=domain_intel,
        )

        return classification, status, evidence_strings, unified_items, recommendations

    @staticmethod
    def generate_url_recommendations(
        classification: UnifiedRiskClassification,
        clean_url: str,
        forensics: DomainForensics,
        typosquatting: TyposquattingDetails,
        inference_prediction: Optional[URLModelPrediction],
        threat_intel: Optional[ThreatIntelResult],
        fdict: dict,
        is_known_authoritative: bool,
        domain_intel: Optional[DomainIntelligenceResult] = None,
    ) -> List[str]:
        """Produce structured, context-aware security recommendations based on real evidence."""
        rec_engine = get_recommendation_engine()
        rec_strings, _ = rec_engine.generate_url_recommendation(
            classification=classification,
            clean_url=clean_url,
            forensics=forensics,
            typosquatting=typosquatting,
            inference_prediction=inference_prediction,
            threat_intel=threat_intel,
            fdict=fdict,
            is_known_authoritative=is_known_authoritative,
            domain_intel=domain_intel,
        )
        return rec_strings

    @staticmethod
    def synthesize_message_risk(
        original_text: str,
        is_model_available: bool,
        pred_is_scam: bool,
        pred_confidence: float,
        model_name: str,
        se_findings: list,
        is_advisory: bool,
        is_benign: bool,
        scam_category: str,
        embedded_url_analyses: list,
    ) -> Tuple[UnifiedRiskClassification, str, List[str], List[UnifiedEvidenceItem], List[str]]:
        """Synthesize risk verdict, evidence strings, unified structured evidence, and guidance for a message."""
        now_iso = datetime.now(timezone.utc).isoformat()
        evidence_strings: List[str] = [f"Message text received ({len(original_text)} characters)."]
        unified_items: List[UnifiedEvidenceItem] = []
        recommendations: List[str] = []

        # 1. Model Prediction
        if not is_model_available:
            classification = UnifiedRiskClassification.UNABLE_TO_VERIFY
            status = "MODEL_UNAVAILABLE"
            evidence_strings.append("Model status: Statistical message classification model is not available.")
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.MODEL_PREDICTION,
                    description="Message ML model artifact unavailable.",
                    source=model_name,
                    severity=EvidenceSeverity.INFORMATIONAL,
                    status=EvidenceStatus.UNAVAILABLE,
                    timestamp=now_iso,
                    indicator_id="MESSAGE_MODEL_UNAVAILABLE",
                )
            )
            recommendations.append("Unable to verify message authenticity due to offline model service.")
            return classification, status, evidence_strings, unified_items, recommendations

        pred_label = "SCAM" if pred_is_scam else "LEGITIMATE"
        evidence_strings.append(
            f"Statistical model prediction: {pred_label} (confidence: {pred_confidence:.4f}, model: {model_name})."
        )
        unified_items.append(
            UnifiedEvidenceItem(
                category=EvidenceCategory.MODEL_PREDICTION,
                description=f"TF-IDF Logistic Regression predicted {pred_label} with {pred_confidence:.2%} confidence.",
                source=model_name,
                severity=EvidenceSeverity.HIGH if pred_is_scam and pred_confidence >= 0.80 else (EvidenceSeverity.MEDIUM if pred_is_scam else EvidenceSeverity.LOW),
                status=EvidenceStatus.CONFIRMED,
                timestamp=now_iso,
                indicator_id="TFIDF_SCAM_PROBABILITY",
            )
        )

        # 2. Local Heuristic Persuasion Findings
        has_critical_coercion = False
        has_moderate_coercion = False

        if se_findings:
            cat_summary = ", ".join(dict.fromkeys(f.category for f in se_findings))
            evidence_strings.append(f"Heuristic persuasion tactics detected: {len(se_findings)} indicator(s) ({cat_summary}).")
            for f in se_findings:
                sev = EvidenceSeverity.HIGH if f.severity == "HIGH" else EvidenceSeverity.MEDIUM
                if f.category in ("otp_requests", "threats_and_demands") or f.severity == "HIGH":
                    has_critical_coercion = True
                else:
                    has_moderate_coercion = True

                evidence_strings.append(f"  [{f.category.upper()}] '{f.matched_text}': {f.explanation}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.HEURISTIC,
                        description=f"[{f.category.upper()}] {f.explanation} (Matched: '{f.matched_text}')",
                        source="SocialEngineeringDetector",
                        severity=sev,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        indicator_id=f"SE_{f.category.upper()}",
                    )
                )
        else:
            evidence_strings.append("Heuristic analysis: No coercive social engineering indicators observed.")

        if scam_category != "UNKNOWN":
            evidence_strings.append(f"Scam category identified: {scam_category}.")
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=f"Message matches {scam_category} behavioral typology pattern.",
                    source="ScamTypologyClassifier",
                    severity=EvidenceSeverity.MEDIUM,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id=f"SCAM_TYPE_{scam_category}",
                )
            )

        # 3. Embedded URL Findings & Threat Intelligence
        has_url_high_risk = False
        has_new_domain_url = False
        for url_resp in embedded_url_analyses:
            if url_resp.classification == UnifiedRiskClassification.HIGH_RISK:
                has_url_high_risk = True
                desc = f"Embedded URL '{url_resp.target_url}' identified as HIGH RISK phishing."
                evidence_strings.append(f"Embedded URL Alert: {desc}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.HEURISTIC,
                        description=desc,
                        source="URLAnalysisService",
                        severity=EvidenceSeverity.HIGH,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        indicator_id="EMBEDDED_URL_HIGH_RISK",
                    )
                )
            # Inherit external threat intelligence from embedded URL if match exists
            if url_resp.threat_intelligence and url_resp.threat_intelligence.is_flagged:
                ti = url_resp.threat_intelligence
                desc = f"Embedded URL '{url_resp.target_url}' confirmed malicious via {ti.source}."
                evidence_strings.append(f"Confirmed External Threat Intel: {desc}")
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.CONFIRMED_THREAT_INTEL,
                        description=desc,
                        source=ti.provider_name or ti.source,
                        severity=EvidenceSeverity.HIGH,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        provider_lookup_timestamp=ti.lookup_timestamp,
                        indicator_id="EMBEDDED_URL_EXTERNAL_THREAT_MATCH",
                        is_cached=ti.is_cached,
                    )
                )
            # Inherit domain intelligence warnings from embedded URL
            if getattr(url_resp, "domain_intelligence", None):
                d_intel = url_resp.domain_intelligence
                if d_intel and d_intel.domain_age_days is not None and d_intel.domain_age_days <= 30:
                    has_new_domain_url = True
                    desc = f"Embedded URL '{url_resp.target_url}' directs to newly registered domain '{d_intel.domain}' ({d_intel.domain_age_days} day(s) old)."
                    evidence_strings.append(f"Domain Age Warning: {desc}")
                    unified_items.append(
                        UnifiedEvidenceItem(
                            category=EvidenceCategory.HEURISTIC,
                            description=desc,
                            source="DomainIntelligence",
                            severity=EvidenceSeverity.HIGH if d_intel.domain_age_days < 7 else EvidenceSeverity.MEDIUM,
                            status=EvidenceStatus.CONFIRMED,
                            timestamp=now_iso,
                            indicator_id="EMBEDDED_URL_NEW_DOMAIN",
                            is_cached=d_intel.is_cached,
                        )
                    )

        # 4. Contextual Guards and Synthesis Decision
        status = "ANALYSIS_ACTIVE"

        if is_advisory:
            classification = UnifiedRiskClassification.LOW_RISK
            evidence_strings.append("Contextual Security Guard: Defensive security advisory notice detected (e.g. 'never share OTP').")
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description="Defensive security education context suppresses coercive trigger false alarms.",
                    source="SecurityAdvisoryGuard",
                    severity=EvidenceSeverity.LOW,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="DEFENSIVE_SECURITY_ADVISORY",
                )
            )
        elif is_benign and not has_critical_coercion and not has_url_high_risk and not has_new_domain_url:
            classification = UnifiedRiskClassification.LOW_RISK
            evidence_strings.append("Notice: Legitimate transactional notification context observed without coercive indicators.")
        elif has_url_high_risk or (has_new_domain_url and (pred_is_scam or has_moderate_coercion)) or (has_critical_coercion and (pred_is_scam or pred_confidence >= 0.70)):
            classification = UnifiedRiskClassification.HIGH_RISK
        elif pred_is_scam and (has_critical_coercion or pred_confidence >= 0.80 or scam_category != "UNKNOWN"):
            classification = UnifiedRiskClassification.HIGH_RISK
        elif has_critical_coercion:
            classification = UnifiedRiskClassification.HIGH_RISK
        elif has_moderate_coercion or pred_is_scam:
            classification = UnifiedRiskClassification.MEDIUM_RISK
        else:
            classification = UnifiedRiskClassification.LOW_RISK

        # Context-aware recommendations via recommendation engine
        rec_engine = get_recommendation_engine()
        rec_strings, _ = rec_engine.generate_message_recommendation(
            classification=classification,
            original_text=original_text,
            scam_category=scam_category,
            pred_is_scam=pred_is_scam,
            pred_confidence=pred_confidence,
            se_findings=se_findings,
            is_advisory=is_advisory,
            is_benign=is_benign,
            embedded_url_analyses=embedded_url_analyses,
        )

        return classification, status, evidence_strings, unified_items, rec_strings

    @staticmethod
    def synthesize_qr_risk(
        qr_count: int,
        primary_item_classification: UnifiedRiskClassification,
        decoded_items: list,
    ) -> Tuple[UnifiedRiskClassification, str, List[UnifiedEvidenceItem]]:
        """Synthesize multi-QR symbol evidence into unified structured items."""
        now_iso = datetime.now(timezone.utc).isoformat()
        unified_items: List[UnifiedEvidenceItem] = []

        if qr_count == 0:
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description="No readable QR barcode matrix detected in uploaded image file.",
                    source="QRScannerService",
                    severity=EvidenceSeverity.INFORMATIONAL,
                    status=EvidenceStatus.UNAVAILABLE,
                    timestamp=now_iso,
                    indicator_id="NO_QR_SYMBOL_DETECTED",
                )
            )
            return UnifiedRiskClassification.UNABLE_TO_VERIFY, "NO_QR_DETECTED", unified_items

        if qr_count > 1:
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.INFORMATIONAL,
                    description=f"Multi-QR Detection: Image contains {qr_count} separate barcodes. Verdict reflects highest-severity symbol.",
                    source="MultiQRAggregator",
                    severity=EvidenceSeverity.INFORMATIONAL,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id="MULTI_QR_IMAGE",
                )
            )

        for item in decoded_items:
            sev = (
                EvidenceSeverity.HIGH
                if item.classification == UnifiedRiskClassification.HIGH_RISK
                else (EvidenceSeverity.MEDIUM if item.classification == UnifiedRiskClassification.MEDIUM_RISK else EvidenceSeverity.LOW)
            )
            unified_items.append(
                UnifiedEvidenceItem(
                    category=EvidenceCategory.HEURISTIC,
                    description=f"QR #{item.qr_index} ({item.payload_type}): Classified as {item.classification.value}.",
                    source="QRScannerService",
                    severity=sev,
                    status=EvidenceStatus.CONFIRMED,
                    timestamp=now_iso,
                    indicator_id=f"QR_ITEM_{item.qr_index}_{item.payload_type}",
                )
            )
            # If item has URL analysis with threat intel, inherit structured threat intel
            if item.url_analysis and item.url_analysis.threat_intelligence and item.url_analysis.threat_intelligence.is_flagged:
                ti = item.url_analysis.threat_intelligence
                unified_items.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.CONFIRMED_THREAT_INTEL,
                        description=f"QR Destination URL confirmed malicious via {ti.source}.",
                        source=ti.provider_name or ti.source,
                        severity=EvidenceSeverity.HIGH,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=now_iso,
                        provider_lookup_timestamp=ti.lookup_timestamp,
                        indicator_id="QR_DESTINATION_THREAT_INTEL_MATCH",
                        is_cached=ti.is_cached,
                    )
                )

        return primary_item_classification, "ANALYSIS_ACTIVE", unified_items


_global_risk_engine: Optional[UnifiedRiskEngine] = None


def get_unified_risk_engine() -> UnifiedRiskEngine:
    """Dependency injector for singleton UnifiedRiskEngine."""
    global _global_risk_engine
    if _global_risk_engine is None:
        _global_risk_engine = UnifiedRiskEngine()
    return _global_risk_engine
