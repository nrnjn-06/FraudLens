"""Social engineering and manipulative persuasion heuristic engine for FraudLens.

Part of Message Detection Engine (Feature 2): Social Engineering Detection.

Identifies 7 categories of deceptive psychological coercion in message text:
1. Urgency and artificial deadlines
2. Threats and consequences
3. Impersonation indicators
4. OTP and credential requests
5. Prize and reward bait
6. Suspicious payment demands
7. Link-click pressure

Also implements context-aware detection for legitimate security advisories
(e.g., banks advising 'never share OTP'), preventing false-positive escalations.
"""

import re
from typing import List, Optional, Tuple

from backend.app.schemas.message import (
    HeuristicFinding,
    HighlightedPhrase,
    SocialEngineeringIndicators,
)


class SocialEngineeringDetector:
    """Heuristic rule engine for detecting social engineering manipulation."""

    # -------------------------------------------------------------------------
    # Defensive Advisory / Negation Patterns
    # (Legitimate educational messages warning users NOT to disclose information)
    # -------------------------------------------------------------------------
    ADVISORY_PATTERNS = [
        re.compile(
            r"\b(?:never|do not|don'?t|neither)\s+(?:share|disclose|tell|reveal|give|send|forward)\s+"
            r"(?:your\s+)?(?:otp|one[-\s]time\s+password|pin|mpin|cvv|password|passcode|credentials|bank\s+details)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:we|bank|staff|executive|official|customer\s+care|rbi)\s+"
            r"(?:never|will not|does not|do not)\s+ask\s+(?:for\s+)?(?:your\s+)?"
            r"(?:otp|password|pin|cvv|credentials|sensitive\s+information|details)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:protect\s+yourself\s+from\s+e-threats|beware\s+of\s+(?:fraud|fake|phishing)|"
            r"fraud\s+alert|security\s+tip|safety\s+tip|caution\s+against\s+fraud)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:never\s+asks?\s+for\s+sensitive\s+information|keep\s+your\s+otp\s+secret)\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # Category 1: Urgency and Artificial Deadlines
    # -------------------------------------------------------------------------
    URGENCY_PATTERNS = [
        re.compile(
            r"\b(?:within|in)\s+(?:\d{1,2}|twenty-four|24|48|12|one|two)\s+(?:hours?|hrs?|mins?|minutes?|days?)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:expires?\s+(?:today|in\s+\d+|within)|valid\s+only\s+(?:today|for\s+\d+|until\s+midnight))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:urgently|immediately|at\s+once|act\s+fast|hurry|asap|without\s+delay|right\s+now)\b|"
            r"\burgent(?:\s+(?:action|notice|update|attention|required|call)\b|[:!])",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:last\s+chance|final\s+notice|final\s+warning|deadline\s+approaching|before\s+it(?:'?s|\s+is)\s+too\s+late)\b",
            re.IGNORECASE,
        ),
    ]

    # Negative context guard for urgency (casual mentions like "not urgent" or "urgent meeting")
    BENIGN_URGENCY_GUARDS = [
        re.compile(r"\b(?:not\s+urgent|no\s+urgency|urgent\s+meeting\s+with)\b", re.IGNORECASE),
    ]

    # -------------------------------------------------------------------------
    # Category 2: Threats and Consequences
    # -------------------------------------------------------------------------
    THREAT_PATTERNS = [
        re.compile(
            r"\b(?:account|service|card|sim|connection|profile|kyc|electricity|power)\s+"
            r"(?:will\s+be|has\s+been|is\s+being|is)\s+"
            r"(?:blocked|suspended|deactivated|terminated|closed|locked|disconnected|cancelled|disabled|frozen)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:will\s+be\s+(?:permanently\s+)?(?:blocked|suspended|disconnected|closed|terminated))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:legal\s+action|police\s+complaint|court\s+notice|arrest\s+warrant|penal\s+action|"
            r"fine\s+will\s+be\s+imposed|penalty\s+of\s+rs\.?\s*\d+)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:electricity\s+will\s+be\s+(?:cut|disconnected)|power\s+will\s+be\s+cut\s+tonight)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:update\s+kyc\s+or\s+(?:your\s+account|else)|kyc\s+(?:is\s+)?expired)\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # Category 3: Impersonation Indicators
    # -------------------------------------------------------------------------
    IMPERSONATION_PATTERNS = [
        re.compile(
            r"\b(?:dear\s+(?:customer|user|cardholder|account\s+holder)|official\s+notice\s+from|"
            r"from\s+(?:your\s+)?bank|bank\s+manager|customer\s+support\s+desk)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:sbi|hdfc|icici|axis\s+bank|punjab\s+national\s+bank|pnb|bank\s+of\s+baroda|kotak|"
            r"paytm|rbi|reserve\s+bank)\s+(?:account|customer|alert|notice|kyc|card|update|team)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:income\s+tax\s+department|customs\s+(?:office|department)|electricity\s+board|"
            r"telecom\s+regulatory|india\s+post|fedex|dhl)\s+(?:notice|alert|officer|delivery|dept)?\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # Category 4: OTP and Credential Requests (Solicitations)
    # -------------------------------------------------------------------------
    OTP_PATTERNS = [
        re.compile(
            r"\b(?:send|share|reply\s+with|provide|enter|submit|forward|disclose|give)\s+"
            r"(?:your\s+)?(?:otp|one[-\s]time\s+password|pin|mpin|cvv|password|passcode|security\s+code|secret\s+code)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:share\s+(?:the\s+)?(?:\d[-\s]?digit\s+)?(?:otp|code|pin|mpin))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:verify\s+your\s+(?:password|pin|mpin|cvv|secret\s+code))\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # Category 5: Prize and Reward Bait
    # -------------------------------------------------------------------------
    PRIZE_PATTERNS = [
        re.compile(
            r"\b(?:you\s+have\s+won|selected\s+(?:as\s+a\s+winner|to\s+win)|won\s+a\s+(?:cash\s+)?prize|"
            r"lottery\s+winner|congratulations!\s+you\s+won|awarded\s+a\s+(?:bonus\s+)?prize)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:claim\s+your\s+(?:free\s+)?(?:reward|prize|voucher|gift|cash\s+prize|bonus|lottery))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:cashback\s+of\s+(?:rs\.?|inr|\$|£)\s*\d+|lucky\s+draw\s+winner|unclaimed\s+(?:reward|lottery|prize))\b",
            re.IGNORECASE,
        ),
    ]

    # Negative guard for legitimate reward notifications
    BENIGN_PRIZE_GUARDS = [
        re.compile(r"\b(?:earned\s+\d+\s+reward\s+points|points\s+statement)\b", re.IGNORECASE),
    ]

    # -------------------------------------------------------------------------
    # Category 6: Suspicious Payment Demands
    # -------------------------------------------------------------------------
    PAYMENT_PATTERNS = [
        re.compile(
            r"\b(?:pay\s+(?:(?:rs\.?|inr|\$|£)\s*\d+\s*)?(?:immediately|now|within\s+\d+|processing\s+fee|registration\s+fee|clearance\s+fee|customs\s+fee|charges))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:transfer\s+(?:(?:processing|registration)\s+fee|fee|funds|money|amount)(?:\s+of\s+(?:rs\.?|\$)\s*\d+)?\s*(?:immediately|to\s+upi|via\s+gift\s+card|to\s+claim))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:pay\s+(?:rs\.?|inr|\$|£)\s*\d+(?:\s+\w+){0,3}\s+(?:to\s+(?:claim|avoid|reactivate|release)|as\s+processing\s+fee))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:(?:electricity\s+bill|power\s+bill|dues|fine|bill)\s+(?:is\s+)?unpaid(?:\.|\s+)?(?:\w+\s+){0,4}pay)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:clear\s+(?:your\s+)?dues\s+(?:immediately|to\s+avoid))\b",
            re.IGNORECASE,
        ),
    ]

    # Negative guard for benign payment phrases ("pay for lunch", "pay at the counter")
    BENIGN_PAYMENT_GUARDS = [
        re.compile(r"\b(?:pay\s+for\s+(?:lunch|dinner|coffee|food|drinks|tickets)|pay\s+at\s+the\s+counter)\b", re.IGNORECASE),
    ]

    # Negative guards for benign transactional notifications (delivery & job interviews)
    BENIGN_DELIVERY_GUARDS = [
        re.compile(
            r"\b(?:has\s+been\s+delivered\s+by|delivered\s+to\s+your\s+reception|"
            r"thank\s+you\s+for\s+choosing\s+our\s+service|order\s+#\d+\s+delivered)\b",
            re.IGNORECASE,
        ),
    ]

    BENIGN_JOB_GUARDS = [
        re.compile(
            r"\b(?:job\s+interview\s+(?:tomorrow|at|with)|invitation\s+for\s+an?\s+interview|"
            r"campus\s+interview|travel\s+reimbursement)\b",
            re.IGNORECASE,
        ),
    ]

    # -------------------------------------------------------------------------
    # Category 7: Link-Click Pressure
    # -------------------------------------------------------------------------
    LINK_CLICK_PATTERNS = [
        re.compile(
            r"\b(?:click\s+(?:here|the\s+link|below|this\s+link|on\s+the\s+link)|tap\s+(?:here|the\s+link|below))\s+"
            r"(?:to\s+(?:update|verify|claim|activate|avoid|unblock|complete|proceed)|immediately|now)?\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:click\s+(?:to\s+)?(?:update|verify)\s+(?:kyc|pan|aadhaar|account|details))\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:open\s+(?:the\s+)?link\s+to\s+(?:update|verify|claim|avoid|unblock))\b",
            re.IGNORECASE,
        ),
    ]

    def _match_first(self, patterns: List[re.Pattern], text: str) -> Optional[str]:
        """Return the first matched substring among a list of patterns."""
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(0).strip()
        return None

    def analyze(self, text: str) -> SocialEngineeringIndicators:
        """Inspect input text and return structured social engineering findings."""
        clean_text = text.strip() if text else ""
        if not clean_text:
            return SocialEngineeringIndicators(
                urgency=False,
                threats=False,
                impersonation=False,
                otp_requests=False,
                prize_bait=False,
                payment_demands=False,
                link_click_pressure=False,
                is_advisory_or_educational=False,
                signals=[],
                findings=[],
            )

        findings: List[HeuristicFinding] = []
        signals: List[str] = []

        # 1. Check for Educational / Defensive Security Advisory
        is_advisory = False
        advisory_match = self._match_first(self.ADVISORY_PATTERNS, clean_text)
        if advisory_match:
            is_advisory = True
            signals.append(
                f"DEFENSIVE ADVISORY DETECTED: Contains educational warning against fraud ('{advisory_match}')."
            )

        # 2. Category 1: Urgency & Artificial Deadlines
        has_urgency = False
        is_benign_urgency = any(g.search(clean_text) for g in self.BENIGN_URGENCY_GUARDS)
        if not is_benign_urgency:
            urgency_match = self._match_first(self.URGENCY_PATTERNS, clean_text)
            if urgency_match:
                has_urgency = True
                findings.append(
                    HeuristicFinding(
                        category="urgency",
                        explanation="Language exerts psychological pressure through artificial deadlines or demands for immediate action.",
                        matched_text=urgency_match,
                        severity="MEDIUM",
                    )
                )
                signals.append(f"URGENCY: Artificial time pressure detected ('{urgency_match}').")

        # 3. Category 2: Threats & Consequences
        has_threats = False
        if not is_advisory:
            threat_match = self._match_first(self.THREAT_PATTERNS, clean_text)
            if threat_match:
                has_threats = True
                findings.append(
                    HeuristicFinding(
                        category="threats",
                        explanation="Threatens negative consequences (account closure, power disconnection, legal action) if demands are not met.",
                        matched_text=threat_match,
                        severity="HIGH",
                    )
                )
                signals.append(f"THREATS: Negative repercussion warning detected ('{threat_match}').")

        # 4. Category 3: Impersonation Indicators
        has_impersonation = False
        impersonation_match = self._match_first(self.IMPERSONATION_PATTERNS, clean_text)
        if impersonation_match:
            has_impersonation = True
            findings.append(
                HeuristicFinding(
                    category="impersonation",
                    explanation="Claims institutional authority (bank, utility provider, delivery service, government agency).",
                    matched_text=impersonation_match,
                    severity="MEDIUM",
                )
            )
            signals.append(f"IMPERSONATION: Institutional representation cues detected ('{impersonation_match}').")

        # 5. Category 4: OTP and Credential Requests (Strictly suppressed in advisories)
        has_otp = False
        if not is_advisory:
            otp_match = self._match_first(self.OTP_PATTERNS, clean_text)
            if otp_match:
                has_otp = True
                findings.append(
                    HeuristicFinding(
                        category="otp_requests",
                        explanation="Directly solicits confidential credentials (OTP, PIN, password, or CVV) that legitimate institutions never request.",
                        matched_text=otp_match,
                        severity="HIGH",
                    )
                )
                signals.append(f"OTP_REQUEST: Inbound credential solicitation detected ('{otp_match}').")

        # 6. Category 5: Prize and Reward Bait
        has_prize = False
        is_benign_prize = any(g.search(clean_text) for g in self.BENIGN_PRIZE_GUARDS)
        if not is_benign_prize:
            prize_match = self._match_first(self.PRIZE_PATTERNS, clean_text)
            if prize_match:
                has_prize = True
                findings.append(
                    HeuristicFinding(
                        category="prize_bait",
                        explanation="Lures recipient with fabricated lotteries, cash winnings, or gift bait to induce engagement.",
                        matched_text=prize_match,
                        severity="MEDIUM",
                    )
                )
                signals.append(f"PRIZE_BAIT: Winnings or lottery lure detected ('{prize_match}').")

        # 7. Category 6: Suspicious Payment Demands
        has_payment = False
        is_benign_payment = any(g.search(clean_text) for g in self.BENIGN_PAYMENT_GUARDS)
        if not is_benign_payment:
            payment_match = self._match_first(self.PAYMENT_PATTERNS, clean_text)
            if payment_match:
                has_payment = True
                findings.append(
                    HeuristicFinding(
                        category="payment_demands",
                        explanation="Demands immediate payment, fee transfer, or settlement of purported dues under coercion.",
                        matched_text=payment_match,
                        severity="HIGH",
                    )
                )
                signals.append(f"PAYMENT_DEMANDS: Coercive payment demand detected ('{payment_match}').")

        # 8. Category 7: Link-Click Pressure
        has_link_pressure = False
        link_match = self._match_first(self.LINK_CLICK_PATTERNS, clean_text)
        if link_match:
            has_link_pressure = True
            findings.append(
                HeuristicFinding(
                    category="link_click_pressure",
                    explanation="Pressures user to immediately open or tap an external link to complete verification or avoid penalty.",
                    matched_text=link_match,
                    severity="MEDIUM",
                )
            )
            signals.append(f"LINK_PRESSURE: Directive urging link navigation detected ('{link_match}').")

        # Check benign transactional notifications
        is_benign_notif = False
        all_benign_notifs = self.BENIGN_DELIVERY_GUARDS + self.BENIGN_JOB_GUARDS
        for b_pat in all_benign_notifs:
            if b_pat.search(clean_text):
                is_benign_notif = True
                break

        return SocialEngineeringIndicators(
            urgency=has_urgency,
            threats=has_threats,
            impersonation=has_impersonation,
            otp_requests=has_otp,
            prize_bait=has_prize,
            payment_demands=has_payment,
            link_click_pressure=has_link_pressure,
            is_advisory_or_educational=is_advisory,
            is_benign_notification=is_benign_notif,
            signals=signals,
            findings=findings,
        )

    def extract_highlighted_phrases(self, original_text: str) -> List[HighlightedPhrase]:
        """Extract exact character spans for all detected suspicious phrases (Feature 3).

        Offsets are guaranteed to satisfy: original_text[start:end] == phrase == text.
        Returns empty list for empty messages, legitimate security advisories, or benign contexts.
        """
        if not original_text or not original_text.strip():
            return []

        # 1. Protective Security Advisory check: Never flag legitimate security warnings
        for adv_pat in self.ADVISORY_PATTERNS:
            if adv_pat.search(original_text):
                return []

        # 2. Gather benign guard intervals
        benign_spans: List[Tuple[int, int]] = []
        all_guards = (
            self.BENIGN_URGENCY_GUARDS
            + self.BENIGN_PRIZE_GUARDS
            + self.BENIGN_PAYMENT_GUARDS
            + self.BENIGN_DELIVERY_GUARDS
            + self.BENIGN_JOB_GUARDS
        )
        for guard in all_guards:
            for g_match in guard.finditer(original_text):
                benign_spans.append((g_match.start(), g_match.end()))

        def is_within_benign_guard(s: int, e: int) -> bool:
            for b_start, b_end in benign_spans:
                if max(s, b_start) < min(e, b_end):
                    return True
            return False

        # 3. Category pattern configurations
        category_rules = [
            (
                "urgency",
                self.URGENCY_PATTERNS,
                "Language exerts artificial psychological urgency or calls for immediate compliance.",
            ),
            (
                "threats",
                self.THREAT_PATTERNS,
                "Threatens negative consequences (account closure, power disconnection, legal penalty).",
            ),
            (
                "impersonation",
                self.IMPERSONATION_PATTERNS,
                "Claims institutional authority (bank, utility provider, delivery service, government agency).",
            ),
            (
                "otp_requests",
                self.OTP_PATTERNS,
                "Directly solicits confidential credentials (OTP, PIN, password, or CVV).",
            ),
            (
                "prize_bait",
                self.PRIZE_PATTERNS,
                "Lures recipient with fabricated lotteries, cash winnings, or gift bait.",
            ),
            (
                "payment_demands",
                self.PAYMENT_PATTERNS,
                "Demands immediate payment, fee transfer, or settlement of dues under coercion.",
            ),
            (
                "link_click_pressure",
                self.LINK_CLICK_PATTERNS,
                "Directs user to immediately open or tap an external link.",
            ),
        ]

        extracted_spans: List[HighlightedPhrase] = []
        seen_exact_spans = set()

        for category, patterns, explanation in category_rules:
            for pattern in patterns:
                for match in pattern.finditer(original_text):
                    s, e = match.start(), match.end()
                    if s == e:
                        continue
                    if is_within_benign_guard(s, e):
                        continue

                    span_key = (s, e)
                    if span_key in seen_exact_spans:
                        continue
                    seen_exact_spans.add(span_key)

                    matched_substring = original_text[s:e]
                    extracted_spans.append(
                        HighlightedPhrase(
                            phrase=matched_substring,
                            reason=explanation,
                            start_idx=s,
                            end_idx=e,
                            start=s,
                            end=e,
                            text=matched_substring,
                            category=category,
                            explanation=explanation,
                        )
                    )

        # Sort spans deterministically by start offset, then by length descending
        extracted_spans.sort(key=lambda x: (x.start_idx, -(x.end_idx - x.start_idx)))
        return extracted_spans


# Singleton instance
_detector_instance: Optional[SocialEngineeringDetector] = None


def get_social_engineering_detector() -> SocialEngineeringDetector:
    """Dependency injector / singleton accessor for SocialEngineeringDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = SocialEngineeringDetector()
    return _detector_instance
