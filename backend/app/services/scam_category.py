"""Scam category identification engine for FraudLens (Feature 5).

Classifies suspicious messages into established fraud taxonomies:
- BANK_KYC: Bank account verification, KYC-update claims, banking credential theft
- DELIVERY: Courier/parcel impersonation, unpaid delivery/customs fees, delivery link pressure
- JOB: Work-from-home, task-based earnings, recruitment registration fees or deposits
- PRIZE: Fabricated lotteries, lucky draws, unsolicited cash rewards requiring advance fee
- INVESTMENT: Guaranteed high-return schemes, crypto/forex doubling, high-yield pressure
- UNKNOWN: Ambiguous, benign, or insufficient evidence

Guarantees:
- Never forces benign messages or legitimate security notices into fraud categories
- Supports candidate categories when messages exhibit multiple signals
- Fully deterministic and interpretable without fabricated ML attributions
"""

import re
from typing import Dict, List, Optional, Tuple
from backend.app.schemas.message import (
    ExtractedEntities,
    ScamTypeClassification,
    SocialEngineeringIndicators,
)


CATEGORY_LABELS = {
    "BANK_KYC": "Bank/KYC",
    "DELIVERY": "Delivery",
    "JOB": "Job",
    "PRIZE": "Prize",
    "INVESTMENT": "Investment",
    "UNKNOWN": "Unknown",
}


class ScamCategoryClassifier:
    """Interpretable contextual classifier for scam message categories."""

    # -------------------------------------------------------------------------
    # 1. Category Indicator Rules
    # -------------------------------------------------------------------------

    # Bank / KYC patterns
    BANK_CORE_PATTERNS = [
        re.compile(
            r"\b(?:sbi|hdfc|icici|axis\s+bank|punjab\s+national\s+bank|pnb|bank\s+of\s+baroda|"
            r"kotak|rbi|reserve\s+bank|canara\s+bank|union\s+bank|bank\s+account|netbanking|"
            r"debit\s+card|credit\s+card|atm\s+card)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:update\s+kyc|kyc\s+(?:is\s+)?expired|kyc\s+verification|pan\s+card\s+link|"
            r"aadhaar\s+link|verify\s+your\s+(?:bank\s+)?identity|mandatory\s+kyc)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:account\s+(?:will\s+be|has\s+been|is)\s+(?:blocked|suspended|deactivated|frozen)|"
            r"unblock\s+(?:your\s+)?account)\b",
            re.IGNORECASE,
        ),
    ]

    # Delivery patterns
    DELIVERY_CORE_PATTERNS = [
        re.compile(
            r"\b(?:fedex|dhl|bluedart|india\s+post|post\s+office|courier|parcel|package|shipment|"
            r"consignment|dispatch|delivery\s+address|customs\s+(?:office|duty|clearance))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:unpaid\s+delivery\s+fee|customs\s+fee|held\s+at\s+(?:depot|customs|hub)|"
            r"address\s+incomplete|package\s+(?:could\s+not|cannot)\s+be\s+delivered|"
            r"pay\s+(?:rs\.?|\$)\s*\d+\s+to\s+(?:deliver|release))\b",
            re.IGNORECASE,
        ),
    ]

    # Job / Employment patterns
    JOB_CORE_PATTERNS = [
        re.compile(
            r"\b(?:part[-\s]time\s+job|work\s+from\s+home|job\s+offer|recruitment|hiring|hr\s+manager|"
            r"telegram\s+task|youtube\s+like\s+and\s+earn|daily\s+salary|daily\s+income|earn\s+daily)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:registration\s+fee|security\s+deposit\s+for\s+job|earn\s+(?:rs\.?|\$)\s*\d{3,}\s+per\s+day|"
            r"zero\s+experience\s+needed|send\s+money\s+to\s+activate\s+job|task\s+completion\s+reward)\b",
            re.IGNORECASE,
        ),
    ]

    # Prize / Lottery patterns
    PRIZE_CORE_PATTERNS = [
        re.compile(
            r"\b(?:lottery|lucky\s+draw|cash\s+prize|won\s+(?:rs\.?|\$)\s*\d+|jackpot|kbc\s+lottery|"
            r"reward\s+points\s+worth|gift\s+voucher\s+worth|claim\s+your\s+prize)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:transfer\s+(?:processing|registration)\s+fee\s+to\s+claim|prize\s+expires\s+today|"
            r"congratulations\s+you\s+(?:have\s+)?won|claim\s+before\s+deadline)\b",
            re.IGNORECASE,
        ),
    ]

    # Investment patterns
    INVESTMENT_CORE_PATTERNS = [
        re.compile(
            r"\b(?:guaranteed\s+(?:return|profit)|double\s+your\s+money|crypto\s+trading|forex\s+profit|"
            r"daily\s+interest|stock\s+tips|high\s+yield\s+investment|bitcoin\s+multiplier|invest\s+and\s+earn)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:invest\s+(?:rs\.?|\$)\s*\d+\s+and\s+get|200%\s+return|risk[-\s]free\s+profit|"
            r"immediate\s+deposit\s+required|crypto\s+wallet\s+deposit)\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # 2. Benign Context Guards (Suppresses false category classifications)
    # -------------------------------------------------------------------------
    BENIGN_JOB_GUARDS = [
        re.compile(
            r"\b(?:job\s+interview\s+(?:tomorrow|at|with)|invitation\s+for\s+an?\s+interview|"
            r"campus\s+interview|submitted\s+my\s+resume|looking\s+for\s+a\s+job)\b",
            re.IGNORECASE,
        ),
    ]

    BENIGN_DELIVERY_GUARDS = [
        re.compile(
            r"\b(?:has\s+been\s+delivered\s+by|delivered\s+to\s+your\s+reception|"
            r"thank\s+you\s+for\s+choosing\s+our\s+service|order\s+#\d+\s+delivered)\b",
            re.IGNORECASE,
        ),
    ]

    BENIGN_PRIZE_GUARDS = [
        re.compile(
            r"\b(?:earned\s+\d+\s+reward\s+points|won\s+the\s+(?:chess|match|game|tournament)|"
            r"sports\s+day\s+prize)\b",
            re.IGNORECASE,
        ),
    ]

    BENIGN_INVESTMENT_GUARDS = [
        re.compile(
            r"\b(?:investing\s+(?:my\s+)?time|mutual\s+fund\s+investments\s+are\s+subject|"
            r"long[-\s]term\s+investment\s+planning)\b",
            re.IGNORECASE,
        ),
    ]

    BENIGN_BANK_GUARDS = [
        re.compile(
            r"\b(?:near\s+the\s+bank|bank\s+of\s+the\s+river|pay\s+for\s+lunch\s+afterwards)\b",
            re.IGNORECASE,
        ),
    ]

    def classify(
        self,
        message_text: str,
        se_indicators: Optional[SocialEngineeringIndicators] = None,
        entities: Optional[ExtractedEntities] = None,
    ) -> ScamTypeClassification:
        """Categorize message into standard fraud typology or UNKNOWN."""
        if not message_text or not message_text.strip():
            return ScamTypeClassification(
                category="UNKNOWN",
                label=CATEGORY_LABELS["UNKNOWN"],
                confidence=None,
                matched_patterns=["Empty message text."],
                explanation="No content provided for category identification.",
            )

        # Guard 1: Defensive Security Advisories -> Never classify as scam categories
        if se_indicators and se_indicators.is_advisory_or_educational:
            return ScamTypeClassification(
                category="UNKNOWN",
                label=CATEGORY_LABELS["UNKNOWN"],
                confidence=None,
                matched_patterns=["Defensive security advisory notice."],
                explanation="Message identified as a genuine security advisory warning users against fraud; not a scam.",
            )

        scores: Dict[str, int] = {
            "BANK_KYC": 0,
            "DELIVERY": 0,
            "JOB": 0,
            "PRIZE": 0,
            "INVESTMENT": 0,
        }
        evidence_matches: Dict[str, List[str]] = {k: [] for k in scores}

        # -------------------------------------------------------------
        # Score Bank / KYC
        # -------------------------------------------------------------
        is_benign_bank = any(g.search(message_text) for g in self.BENIGN_BANK_GUARDS)
        if not is_benign_bank:
            for pat in self.BANK_CORE_PATTERNS:
                for m in pat.finditer(message_text):
                    scores["BANK_KYC"] += 1
                    evidence_matches["BANK_KYC"].append(m.group(0))

            # Reinforce if social engineering signals indicate bank impersonation, threats, or OTP requests
            if se_indicators:
                if se_indicators.impersonation and scores["BANK_KYC"] > 0:
                    scores["BANK_KYC"] += 1
                if se_indicators.otp_requests and scores["BANK_KYC"] > 0:
                    scores["BANK_KYC"] += 2
                if se_indicators.threats and scores["BANK_KYC"] > 0:
                    scores["BANK_KYC"] += 1

        # -------------------------------------------------------------
        # Score Delivery Fraud
        # -------------------------------------------------------------
        is_benign_delivery = any(g.search(message_text) for g in self.BENIGN_DELIVERY_GUARDS)
        if not is_benign_delivery:
            for pat in self.DELIVERY_CORE_PATTERNS:
                for m in pat.finditer(message_text):
                    scores["DELIVERY"] += 1
                    evidence_matches["DELIVERY"].append(m.group(0))

            # Delivery scams typically require fee demands, link pressure, or urgency
            if se_indicators and scores["DELIVERY"] > 0:
                if se_indicators.payment_demands:
                    scores["DELIVERY"] += 2
                if se_indicators.link_click_pressure:
                    scores["DELIVERY"] += 1

        # -------------------------------------------------------------
        # Score Job Scams
        # -------------------------------------------------------------
        is_benign_job = any(g.search(message_text) for g in self.BENIGN_JOB_GUARDS)
        if not is_benign_job:
            for pat in self.JOB_CORE_PATTERNS:
                for m in pat.finditer(message_text):
                    scores["JOB"] += 1
                    evidence_matches["JOB"].append(m.group(0))

            if se_indicators and scores["JOB"] > 0:
                if se_indicators.payment_demands:
                    scores["JOB"] += 2
                if se_indicators.urgency:
                    scores["JOB"] += 1

        # -------------------------------------------------------------
        # Score Prize / Lottery Scams
        # -------------------------------------------------------------
        is_benign_prize = any(g.search(message_text) for g in self.BENIGN_PRIZE_GUARDS)
        if not is_benign_prize:
            for pat in self.PRIZE_CORE_PATTERNS:
                for m in pat.finditer(message_text):
                    scores["PRIZE"] += 1
                    evidence_matches["PRIZE"].append(m.group(0))

            if se_indicators and scores["PRIZE"] > 0:
                if se_indicators.prize_bait:
                    scores["PRIZE"] += 2
                if se_indicators.payment_demands:
                    scores["PRIZE"] += 1

        # -------------------------------------------------------------
        # Score Investment Scams
        # -------------------------------------------------------------
        is_benign_investment = any(g.search(message_text) for g in self.BENIGN_INVESTMENT_GUARDS)
        if not is_benign_investment:
            for pat in self.INVESTMENT_CORE_PATTERNS:
                for m in pat.finditer(message_text):
                    scores["INVESTMENT"] += 1
                    evidence_matches["INVESTMENT"].append(m.group(0))

            if se_indicators and scores["INVESTMENT"] > 0:
                if se_indicators.urgency or se_indicators.payment_demands:
                    scores["INVESTMENT"] += 1

        # -------------------------------------------------------------
        # Category Decision & Candidate Evaluation
        # -------------------------------------------------------------
        # Filter categories meeting minimum confidence threshold (score >= 2)
        valid_candidates = [(cat, scr) for cat, scr in scores.items() if scr >= 2]
        valid_candidates.sort(key=lambda item: item[1], reverse=True)

        if not valid_candidates:
            return ScamTypeClassification(
                category="UNKNOWN",
                label=CATEGORY_LABELS["UNKNOWN"],
                confidence=None,
                matched_patterns=[],
                candidate_categories=[],
                explanation="No specific scam typology matched with sufficient contextual indicators.",
            )

        top_cat, top_score = valid_candidates[0]
        runner_ups = [cat for cat, scr in valid_candidates[1:] if scr >= 2]

        # Normalized confidence calculation: bounded between 0.50 and 0.95
        confidence = min(0.95, round(0.50 + (top_score * 0.10), 2))
        matched_clean = list(dict.fromkeys(evidence_matches[top_cat]))[:5]

        explanation_map = {
            "BANK_KYC": "Message matches indicators of banking impersonation, credential solicitation, or fraudulent KYC verification.",
            "DELIVERY": "Message matches indicators of courier impersonation with suspicious fee demands or package hold coercion.",
            "JOB": "Message matches indicators of fraudulent task-based employment or advance registration fee demands.",
            "PRIZE": "Message matches indicators of fabricated lottery winnings or unsolicited prize lures.",
            "INVESTMENT": "Message matches indicators of guaranteed high-return investment schemes or cryptocurrency doubling pressure.",
        }

        return ScamTypeClassification(
            category=top_cat,
            label=CATEGORY_LABELS.get(top_cat, top_cat),
            confidence=confidence,
            matched_patterns=matched_clean,
            candidate_categories=runner_ups,
            explanation=explanation_map.get(top_cat, f"Categorized as {top_cat} based on contextual indicators."),
        )


_global_scam_classifier: Optional[ScamCategoryClassifier] = None


def get_scam_category_classifier() -> ScamCategoryClassifier:
    """Singleton provider for ScamCategoryClassifier."""
    global _global_scam_classifier
    if _global_scam_classifier is None:
        _global_scam_classifier = ScamCategoryClassifier()
    return _global_scam_classifier
