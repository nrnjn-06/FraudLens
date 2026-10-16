"""Context-Aware Recommendation Engine for FraudLens.

Synthesizes findings from:
- Detected scam typology (Banking/KYC, Delivery, Job, Prize, Crypto, Government, etc.)
- Public-suffix-aware domain & URL forensics
- Typosquatting and brand lookalike detection
- WHOIS/RDAP domain age & registration metadata
- External threat intelligence feeds
- Unified risk classification (HIGH, MEDIUM, LOW, UNABLE TO VERIFY)
- Official Domain Registry

Generates both:
1. StructuredSecurityRecommendation (rich structured object with verified official links)
2. List[str] (clean human-readable bullet recommendations for backward compatibility)
"""

from typing import List, Optional, Tuple
from backend.app.schemas.common import (
    StructuredSecurityRecommendation,
    UnifiedRiskClassification,
)
from backend.app.schemas.url import (
    DomainForensics,
    DomainIntelligenceResult,
    ThreatIntelResult,
    TyposquattingDetails,
    URLModelPrediction,
)
from backend.app.services.official_registry import (
    OfficialDomainRegistry,
    OfficialOrganizationEntry,
    get_official_domain_registry,
)


class RecommendationEngine:
    """Context-aware recommendation generation engine with verified official domain mappings."""

    def __init__(self, registry: Optional[OfficialDomainRegistry] = None):
        self.registry = registry or get_official_domain_registry()

    # -------------------------------------------------------------
    # 1. URL Analysis Recommendations
    # -------------------------------------------------------------
    def generate_url_recommendation(
        self,
        classification: UnifiedRiskClassification,
        clean_url: str,
        forensics: DomainForensics,
        typosquatting: TyposquattingDetails,
        inference_prediction: Optional[URLModelPrediction],
        threat_intel: Optional[ThreatIntelResult],
        fdict: dict,
        is_known_authoritative: bool,
        domain_intel: Optional[DomainIntelligenceResult] = None,
    ) -> Tuple[List[str], StructuredSecurityRecommendation]:
        """Produce structured, context-aware security recommendations for a URL."""
        hostname = forensics.hostname.lower()
        reg_domain = f"{forensics.domain}.{forensics.tld}".lower()

        # Step 1: Match against verified official registry
        matched_org: Optional[OfficialOrganizationEntry] = None
        is_impersonation = False
        impersonation_reason = ""

        # Check explicit brand first
        if typosquatting.target_brand:
            matched_org = self.registry.match_organization(brand_name=typosquatting.target_brand)

        # Fallback: check hostname tokens
        if not matched_org:
            matched_org = self.registry.match_organization(url_or_hostname=clean_url)

        if matched_org:
            is_impersonation, impersonation_reason = self.registry.evaluate_impersonation(clean_url, matched_org)
        elif typosquatting.is_impersonation and typosquatting.target_brand:
            # Impersonation detected by heuristic, but brand not in official verified directory
            is_impersonation = True
            impersonation_reason = f"Domain reflects brand typosquatting targeting '{typosquatting.target_brand.title()}'."

        # Step 2: Build Section 2 - Suspicious reasons
        suspicious_reasons: List[str] = []

        if is_impersonation and matched_org:
            suspicious_reasons.append(
                f"Hostname mismatch: The target host '{hostname}' (domain: '{reg_domain}') does not match the verified official domain '{matched_org.official_domain}'."
            )
        elif is_impersonation and typosquatting.target_brand:
            suspicious_reasons.append(
                f"Brand lookalike: Host structure reflects typosquatting or brand spoofing targeting '{typosquatting.target_brand.title()}'."
            )

        if forensics.has_ip_address:
            suspicious_reasons.append(
                f"Raw IP address host ('{hostname}'): Used to bypass domain take-down notices and domain reputation filtering."
            )

        if domain_intel and domain_intel.domain_age_days is not None:
            if domain_intel.domain_age_days < 7:
                suspicious_reasons.append(
                    f"Newly registered domain: Registered only {domain_intel.domain_age_days} day(s) ago (under 7 days). Very high correlation with disposable fraud vectors."
                )
            elif domain_intel.domain_age_days <= 30:
                suspicious_reasons.append(
                    f"Recent domain registration: Created {domain_intel.domain_age_days} days ago (within 30 days)."
                )

        if domain_intel and domain_intel.tls_certificate_valid is False:
            suspicious_reasons.append(
                "Invalid or untrusted TLS certificate: Connection cannot be cryptographically verified."
            )

        if threat_intel and threat_intel.is_flagged and threat_intel.lookup_status == "MATCH_FOUND":
            provider = threat_intel.provider_name or threat_intel.source
            suspicious_reasons.append(
                f"Confirmed threat intelligence alert: Flagged malicious on active threat databases ({provider})."
            )

        if fdict.get("suspicious_token_count", 0) > 0:
            suspicious_reasons.append(
                f"Sensitive authentication keywords ({int(fdict['suspicious_token_count'])} tokens: login/verify/account) embedded in unverified path/subdomain."
            )

        if fdict.get("count_subdomains", 0) >= 3:
            suspicious_reasons.append(
                f"Excessive subdomain depth ({int(fdict['count_subdomains'])} levels) obscuring the true destination."
            )

        # Step 3: Determine detected threat summary and action checklist based on classification
        action_steps: List[str] = []
        rec_strings: List[str] = []
        scam_cat = matched_org.category if matched_org else "UNKNOWN"

        if classification == UnifiedRiskClassification.HIGH_RISK:
            title = f"High Risk: Suspected {matched_org.name if matched_org else 'Phishing'} Deception"
            detected_threat = (
                f"Critical risk detected: The URL appears to be a fraudulent phishing or lookalike portal"
                f"{f' targeting {matched_org.name}' if matched_org else ''}."
            )
            rec_action = "DO NOT visit this destination, download files, or submit login or financial credentials."
            action_steps = [
                "Do not open the link or bypass browser security warnings.",
                "Never enter passwords, PINs, OTP codes, or personal identification details.",
                "If you arrived from an SMS or email, delete the message or report it to your organization's security team.",
            ]
            if is_impersonation and matched_org:
                action_steps.append(
                    f"If you need to access {matched_org.name}, use only the verified official website: {matched_org.canonical_url}"
                )

        elif classification == UnifiedRiskClassification.MEDIUM_RISK:
            title = f"Medium Risk: Anomalous Structure {f'targeting {matched_org.name}' if matched_org else ''}"
            detected_threat = (
                f"Suspicious characteristics observed: The destination contains structural anomalies"
                f"{f' referencing {matched_org.name}' if matched_org else ''} that warrant heightened caution."
            )
            rec_action = "Exercise heightened caution. Verify the destination independently before proceeding."
            action_steps = [
                "Check your browser's address bar to ensure the registrable domain matches your expected destination.",
                "Avoid entering sensitive credentials or making payments on unverified web addresses.",
            ]
            if is_impersonation and matched_org:
                action_steps.append(
                    f"Navigate to {matched_org.name} directly via official channels: {matched_org.canonical_url}"
                )

        elif classification == UnifiedRiskClassification.LOW_RISK:
            if is_known_authoritative or (matched_org and not is_impersonation):
                org_label = matched_org.name if matched_org else forensics.domain.title()
                title = f"Low Risk: Verified Authoritative Destination ({org_label})"
                detected_threat = f"Standard authoritative web patterns observed for {org_label}. No deceptive markers found."
                rec_action = "Maintain standard security awareness. Confirm browser shows valid HTTPS."
                action_steps = [
                    "Verify the browser displays a secure connection (lock icon) before submitting data.",
                    "Remember that LOW RISK is not an absolute guarantee of safety. Remain alert for unsolicited requests.",
                ]
            else:
                title = "Low Risk: No Deceptive Patterns Detected"
                detected_threat = "Structural analysis observed ordinary, legitimate web characteristics. No suspicious signals triggered."
                rec_action = "Maintain standard security awareness."
                action_steps = [
                    "Check the address bar to ensure you are on the intended site.",
                    "LOW RISK is an assessment of structural patterns, not an endorsement or absolute guarantee of safety.",
                ]

        else:  # UNABLE_TO_VERIFY
            title = "Unable to Verify Destination Authenticity"
            detected_threat = "The web address could not be fully verified due to unavailable verification components or missing contextual data."
            rec_action = "Treat unverified links with caution. Do not disclose sensitive information."
            action_steps = [
                "Do not submit credentials or payment information until authenticity is established.",
                "Navigate to the genuine service from a trusted bookmark or official app.",
            ]

        # Step 4: Official website recommendation details
        official_url: Optional[str] = None
        official_domain: Optional[str] = None
        official_source: Optional[str] = None
        official_verified = False

        if matched_org and is_impersonation:
            # Recommend the verified official website
            official_url = matched_org.canonical_url
            official_domain = matched_org.official_domain
            official_source = matched_org.verification_source
            official_verified = True
        elif matched_org and not is_impersonation:
            # Legitimate official website
            official_url = matched_org.canonical_url
            official_domain = matched_org.official_domain
            official_source = matched_org.verification_source
            official_verified = True

        # Build backward-compatible recommendations string list
        rec_strings.append(f"Finding: {detected_threat}")
        if suspicious_reasons:
            rec_strings.append(f"Warning Signs: {'; '.join(suspicious_reasons[:2])}")
        rec_strings.append(f"Action: {rec_action}")
        if official_verified and official_url and is_impersonation:
            rec_strings.append(f"Safer Official Destination: Visit the official {matched_org.name} website directly at {official_url}")
        elif is_impersonation and not official_verified:
            rec_strings.append("Guidance: We could not confidently identify the official website. Open the organization's official app or find its website independently using a trusted source.")

        structured = StructuredSecurityRecommendation(
            title=title,
            detected_threat=detected_threat,
            suspicious_reasons=suspicious_reasons,
            organization_name=matched_org.name if matched_org else None,
            official_url=official_url if is_impersonation else None,
            official_domain=official_domain if is_impersonation else None,
            official_url_source=official_source if is_impersonation else None,
            official_url_verified=official_verified if is_impersonation else False,
            recommended_action=rec_action,
            action_steps=action_steps,
            is_impersonation_detected=is_impersonation,
            scam_category=scam_cat,
        )

        return rec_strings, structured

    # -------------------------------------------------------------
    # 2. Scam Message Recommendations
    # -------------------------------------------------------------
    def generate_message_recommendation(
        self,
        classification: UnifiedRiskClassification,
        original_text: str,
        scam_category: str,
        pred_is_scam: bool,
        pred_confidence: float,
        se_findings: list,
        is_advisory: bool,
        is_benign: bool,
        embedded_url_analyses: list,
    ) -> Tuple[List[str], StructuredSecurityRecommendation]:
        """Produce structured, context-aware security recommendations for a message."""
        # Check if an organization was matched from embedded URLs or message text
        matched_org: Optional[OfficialOrganizationEntry] = None
        is_impersonation = False
        target_url = None

        # Inspect embedded URLs first
        for u in embedded_url_analyses:
            target_url = getattr(u, "target_url", None)
            if target_url:
                typosquatting = getattr(u, "typosquatting", None)
                target_brand = getattr(typosquatting, "target_brand", None) if typosquatting else None
                matched_org = self.registry.match_organization(brand_name=target_brand, url_or_hostname=target_url)
                if matched_org:
                    is_imp, _ = self.registry.evaluate_impersonation(target_url, matched_org)
                    if is_imp:
                        is_impersonation = True
                        break

        # If not matched via URL, search message text
        if not matched_org:
            matched_org = self.registry.match_organization(text_context=original_text)
            if matched_org:
                # If message contains untrusted links and mentions a known brand, flag impersonation
                if embedded_url_analyses:
                    is_impersonation = True

        suspicious_reasons: List[str] = []
        action_steps: List[str] = []
        rec_strings: List[str] = []

        norm_cat = (scam_category or "UNKNOWN").upper()

        # Build category-specific guidance
        if is_advisory:
            title = "Defensive Security Advisory Notice"
            detected_threat = "Legitimate defensive security advisory or educational alert (e.g. 'Bank never asks for OTP')."
            rec_action = "Maintain standard security awareness. No coercive threat detected."
            action_steps = [
                "Remember this advice: Legitimate organizations never request passwords or OTPs over phone or message.",
                "No action is required for educational security notices.",
            ]
        elif is_benign and classification == UnifiedRiskClassification.LOW_RISK:
            title = "Low Risk: Legitimate Service Notification"
            detected_threat = "Standard informational or transactional update without coercive pressure signals."
            rec_action = "Maintain standard security awareness. LOW RISK is not an absolute guarantee of safety."
            action_steps = [
                "Review the message details normally.",
                "Always verify unexpected requests through official apps or customer support.",
            ]
        elif classification == UnifiedRiskClassification.HIGH_RISK:
            title = f"High Risk: Suspected {matched_org.name if matched_org else norm_cat.replace('_', ' ').title()} Scam"
            detected_threat = f"Deceptive social engineering patterns detected targeting {matched_org.name if matched_org else 'unsolicited credentials/funds'}."

            if norm_cat in ("BANK_KYC", "BANKING_KYC"):
                rec_action = "DO NOT click the link, disclose OTPs, or share banking credentials."
                suspicious_reasons.append("Coercive bank/KYC urgency claiming immediate account suspension or document expiry.")
                action_steps = [
                    "Never share OTPs, PINs, passwords, or full card numbers with anyone.",
                    "Banks never require KYC verification via third-party SMS links or unverified forms.",
                ]
                if matched_org and is_impersonation:
                    suspicious_reasons.append(f"Message impersonates {matched_org.name} but directs to an unverified destination.")
                    action_steps.append(f"Check your genuine account status only on the official {matched_org.name} portal: {matched_org.canonical_url}")
                else:
                    action_steps.append("Contact your bank only through the phone number printed on the back of your physical debit card.")

            elif norm_cat in ("DELIVERY", "DELIVERY_COURIER"):
                rec_action = "DO NOT pay redelivery fees or update address details on suspicious links."
                suspicious_reasons.append("Fake package delivery or customs fee alert creating false urgency.")
                action_steps = [
                    "Courier services do not require small redelivery fees or address updates via random links.",
                    "If you are expecting a shipment, copy your genuine tracking number and check it directly on the courier's official portal.",
                ]
                if matched_org:
                    suspicious_reasons.append(f"Message references {matched_org.name} but links to an unauthorized domain.")
                    action_steps.append(f"Track your package directly at {matched_org.canonical_url}")

            elif norm_cat in ("LOTTERY", "PRIZE", "LOTTERY_PRIZE"):
                rec_action = "DO NOT pay advance processing fees or share personal identification documents."
                suspicious_reasons.append("Unsolicited lottery or high-value prize claim requiring upfront fees or personal details.")
                action_steps = [
                    "Legitimate lotteries and sweepstakes NEVER ask winners to pay advance tax or processing fees.",
                    "Do not provide bank account details, identity documents, or UPI PINs.",
                ]

            elif norm_cat in ("JOB", "JOB_OFFER"):
                rec_action = "DO NOT pay registration deposits or disclose government ID cards to unverified recruiters."
                suspicious_reasons.append("Lucrative work-from-home or part-time job offer with disproportionate salary claims.")
                action_steps = [
                    "Reputable employers never demand upfront security deposits or training fees.",
                    "Verify open vacancies exclusively on the company's official careers portal.",
                ]
                if matched_org:
                    action_steps.append(f"Verify job listings on the official {matched_org.name} careers portal: {matched_org.canonical_url}")

            elif norm_cat in ("INVESTMENT", "INVESTMENT_CRYPTO"):
                rec_action = "DO NOT transfer funds or connect cryptocurrency wallets to unverified portals."
                suspicious_reasons.append("Guaranteed return claims or pressure to deposit into private crypto wallets.")
                action_steps = [
                    "All investments involve market risk; guaranteed high-return promises are typical Ponzi/fraud schemes.",
                    "Never transfer digital currency to personal wallet addresses provided in messaging apps.",
                ]
                if matched_org:
                    action_steps.append(f"Trade only through verified platforms: {matched_org.canonical_url}")

            elif norm_cat in ("GOVERNMENT", "GOVERNMENT_TAX"):
                rec_action = "DO NOT disclose PAN, Aadhaar, or tax login details on third-party links."
                suspicious_reasons.append("Government penalty or tax refund lure creating artificial urgency.")
                action_steps = [
                    "Government departments do not process refunds or issue legal summons via SMS links.",
                    "Verify notices directly on official government (.gov or .gov.in) portals.",
                ]
                if matched_org:
                    action_steps.append(f"Access official government services at {matched_org.canonical_url}")

            else:
                rec_action = "DO NOT click embedded links, disclose credentials, or make payments."
                suspicious_reasons.append("Social engineering tactics detected (urgency, coercive threats, or unverified credential demands).")
                action_steps = [
                    "Do not open links from unknown senders.",
                    "Never enter authentication credentials on pages reached through unsolicited messages.",
                ]
                if matched_org and is_impersonation:
                    action_steps.append(f"Navigate to {matched_org.name} directly via official channels: {matched_org.canonical_url}")

        elif classification == UnifiedRiskClassification.MEDIUM_RISK:
            title = f"Medium Risk: Caution Advised ({matched_org.name if matched_org else norm_cat.title()})"
            detected_threat = "Unconfirmed social engineering cues or anomalous message characteristics observed."
            rec_action = "Exercise heightened caution. Verify the sender independently before replying or clicking."
            action_steps = [
                "Verify the sender's identity through an independent, verified contact method.",
                "Do not click links or provide sensitive security details if the communication was unsolicited.",
            ]
            if matched_org and is_impersonation:
                action_steps.append(f"Visit the official {matched_org.name} portal directly: {matched_org.canonical_url}")

        else:
            title = "Low Risk: No Deceptive Patterns Detected"
            detected_threat = "No recognized scam patterns or psychological coercion markers found in message."
            rec_action = "Maintain standard security awareness. Remember LOW RISK is not an absolute guarantee of safety."
            action_steps = [
                "Always treat unexpected requests for sensitive data with caution.",
            ]

        # Official destination mapping
        official_url = matched_org.canonical_url if (matched_org and is_impersonation) else None
        official_domain = matched_org.official_domain if (matched_org and is_impersonation) else None
        official_source = matched_org.verification_source if (matched_org and is_impersonation) else None
        official_verified = bool(official_url)

        # Build backward-compatible recommendations string list
        rec_strings.append(f"Finding: {detected_threat}")
        rec_strings.append(f"Action: {rec_action}")
        if official_verified and official_url:
            rec_strings.append(f"Safer Official Destination: Visit the official {matched_org.name} website directly at {official_url}")
        elif is_impersonation and not official_verified:
            rec_strings.append("Guidance: We could not confidently identify the official website. Open the organization's official app or find its website independently using a trusted source.")

        structured = StructuredSecurityRecommendation(
            title=title,
            detected_threat=detected_threat,
            suspicious_reasons=suspicious_reasons,
            organization_name=matched_org.name if matched_org else None,
            official_url=official_url,
            official_domain=official_domain,
            official_url_source=official_source,
            official_url_verified=official_verified,
            recommended_action=rec_action,
            action_steps=action_steps,
            is_impersonation_detected=is_impersonation,
            scam_category=norm_cat,
        )

        return rec_strings, structured

    # -------------------------------------------------------------
    # 3. QR Code Recommendations
    # -------------------------------------------------------------
    def generate_qr_recommendation(
        self,
        classification: UnifiedRiskClassification,
        payload_type: str,
        decoded_text: str,
        upi_details: Optional[dict] = None,
        url_recommendation: Optional[StructuredSecurityRecommendation] = None,
        url_rec_strings: Optional[List[str]] = None,
    ) -> Tuple[List[str], StructuredSecurityRecommendation]:
        """Produce structured safety guidance for a scanned QR code symbol."""
        rec_strings: List[str] = []

        # If payload is a URL and we already have a structured URL recommendation, reuse it!
        if url_recommendation:
            rec_strings = list(url_rec_strings) if url_rec_strings else [
                f"Finding: {url_recommendation.detected_threat}",
                f"Action: {url_recommendation.recommended_action}",
            ]
            if url_recommendation.official_url:
                rec_strings.append(f"Safer Official Destination: Visit {url_recommendation.organization_name} directly at {url_recommendation.official_url}")
            return rec_strings, url_recommendation

        # Handle UPI payments
        if payload_type in ("UPI", "UPI_PAYMENT") and upi_details:
            payee_name = upi_details.get("payee_name") or "Unspecified Merchant"
            payee_vpa = upi_details.get("payee_vpa") or "Unknown VPA"
            amount = upi_details.get("amount")

            title = "UPI Payment QR Code Verification"
            detected_threat = f"UPI Payment Request decoded for recipient '{payee_name}' ({payee_vpa}){f' for INR {amount}' if amount else ''}."
            rec_action = "Verify the recipient name and amount on your banking app before authorizing payment."
            action_steps = [
                "Receiving money NEVER requires entering your UPI PIN. If someone asked you to scan this to receive money, it is a scam.",
                f"Confirm the exact beneficiary name ('{payee_name}') and VPA handle ('{payee_vpa}') match your intended recipient.",
                "Do not authorize payments from unverified QR code stickers in public places.",
            ]
            suspicious_reasons = [
                "Decoded UPI payload targets an untrusted digital VPA handle.",
            ]
            rec_strings = [
                f"Finding: {detected_threat}",
                f"Action: {rec_action}",
                "Critical Warning: Entering your UPI PIN always DEBITS funds from your bank account. It is never used to receive refunds or prizes.",
            ]

            structured = StructuredSecurityRecommendation(
                title=title,
                detected_threat=detected_threat,
                suspicious_reasons=suspicious_reasons,
                organization_name=payee_name,
                official_url=None,
                official_domain=None,
                official_url_source=None,
                official_url_verified=False,
                recommended_action=rec_action,
                action_steps=action_steps,
                is_impersonation_detected=False,
                scam_category="PAYMENT",
            )
            return rec_strings, structured

        # Generic QR code payload
        title = "QR Code Safety Guidance"
        if classification == UnifiedRiskClassification.HIGH_RISK:
            detected_threat = "The decoded barcode matrix exhibits dangerous, coercive, or malicious payload patterns."
            rec_action = "DO NOT open the destination or interact with this decoded payload."
            action_steps = [
                "Do not scan or execute unknown QR codes found on physical stickers or unsolicited messages.",
                "Verify the true service provider through official applications or verified websites.",
            ]
        elif classification == UnifiedRiskClassification.LOW_RISK:
            detected_threat = "Standard QR code structure detected with no recognized malicious patterns."
            rec_action = "Maintain standard security awareness. LOW RISK is not an absolute guarantee of safety."
            action_steps = [
                "Verify the destination before approving any transactions or authorizations.",
            ]
        else:
            detected_threat = "The decoded QR code payload contains unverified or anomalous components."
            rec_action = "Exercise caution with unverified QR barcode symbols."
            action_steps = [
                "Verify destination authenticity through independent channels.",
            ]

        rec_strings = [
            f"Finding: {detected_threat}",
            f"Action: {rec_action}",
        ]

        structured = StructuredSecurityRecommendation(
            title=title,
            detected_threat=detected_threat,
            suspicious_reasons=[],
            organization_name=None,
            official_url=None,
            official_domain=None,
            official_url_source=None,
            official_url_verified=False,
            recommended_action=rec_action,
            action_steps=action_steps,
            is_impersonation_detected=False,
            scam_category="QR_CODE",
        )
        return rec_strings, structured


_global_engine: Optional[RecommendationEngine] = None


def get_recommendation_engine() -> RecommendationEngine:
    """Dependency injector for singleton RecommendationEngine."""
    global _global_engine
    if _global_engine is None:
        _global_engine = RecommendationEngine()
    return _global_engine
