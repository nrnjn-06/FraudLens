"""Unit and integration tests for FraudLens Unified Risk Synthesis Engine.

Verifies canonical platform invariants:
1. Strict separation of MODEL_PREDICTION, HEURISTIC, CONFIRMED_THREAT_INTEL, and INFORMATIONAL evidence.
2. Immediate escalation to HIGH RISK upon confirmed external threat intelligence match.
3. Contextual defensive/educational security advisory guards against false positive alarms.
4. Fail-safe UNABLE TO VERIFY classification when required ML models are unavailable.
5. Invariant of statistical humility: no claim of absolute safety from clean external lookups.
6. Multi-QR code highest-risk severity synthesis.
"""

from datetime import datetime, timezone
import unittest

from backend.app.schemas.common import (
    EvidenceCategory,
    EvidenceSeverity,
    EvidenceStatus,
    UnifiedEvidenceItem,
    UnifiedRiskClassification,
)
from backend.app.schemas.message import HeuristicFinding
from backend.app.schemas.qr import DecodedQRItem, QRPayloadType
from backend.app.schemas.url import (
    DomainForensics,
    ThreatIntelResult,
    TyposquattingDetails,
    URLAnalysisResponse,
    URLModelPrediction,
)
from backend.app.services.risk_engine import UnifiedRiskEngine


class TestUnifiedRiskEngineURL(unittest.TestCase):
    """Test URL multi-evidence synthesis and invariants."""

    def setUp(self):
        self.default_forensics = DomainForensics(
            hostname="test-domain.com",
            subdomain="",
            domain="test-domain",
            tld="com",
            path="/index.html",
            query_params={},
            has_ip_address=False,
            url_length=28,
        )
        self.default_typo = TyposquattingDetails(
            target_brand=None,
            similarity_score=0.0,
            is_impersonation=False,
            details="No impersonation observed.",
        )
        self.default_fdict = {
            "count_subdomains": 0,
            "has_at_symbol": 0,
            "has_double_slash_path": 0,
            "suspicious_token_count": 0,
            "suspicious_tld": 0,
        }

    def test_invariant_confirmed_threat_intel_escalates_to_high_risk(self):
        """Verify that a confirmed threat intel match escalates to HIGH RISK even with low ML score."""
        low_ml_pred = URLModelPrediction(
            is_phishing=False,
            confidence=0.08,
            model_name="RandomForest_URL_v1",
        )
        threat_match = ThreatIntelResult(
            source="VirusTotal",
            provider_name="VirusTotal",
            is_flagged=True,
            lookup_timestamp=datetime.now(timezone.utc).isoformat(),
            lookup_status="MATCH_FOUND",
            details="Confirmed malicious by 12 external security vendors.",
            malicious_count=12,
        )

        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_url_risk(
            clean_url="https://test-domain.com/index.html",
            forensics=self.default_forensics,
            typosquatting=self.default_typo,
            inference_prediction=low_ml_pred,
            threat_intel=threat_match,
            fdict=self.default_fdict,
            is_known_authoritative=False,
        )

        self.assertEqual(classification, UnifiedRiskClassification.HIGH_RISK)
        self.assertEqual(status, "CONFIRMED_THREAT_INTEL_MATCH")
        self.assertTrue(any("DO NOT visit" in r for r in recs))

        # Verify evidence category separation
        categories = {item.category for item in unified_items}
        self.assertIn(EvidenceCategory.CONFIRMED_THREAT_INTEL, categories)
        self.assertIn(EvidenceCategory.MODEL_PREDICTION, categories)
        self.assertIn(EvidenceCategory.INFORMATIONAL, categories)

    def test_invariant_clean_threat_intel_does_not_claim_absolute_safety(self):
        """Verify clean threat intel lookup does not falsely declare guaranteed safety."""
        ml_pred = URLModelPrediction(
            is_phishing=False,
            confidence=0.04,
            model_name="RandomForest_URL_v1",
        )
        threat_clean = ThreatIntelResult(
            source="VirusTotal",
            provider_name="VirusTotal",
            is_flagged=False,
            lookup_timestamp=datetime.now(timezone.utc).isoformat(),
            lookup_status="CLEAN",
            details="Zero vendor reports found.",
            harmless_count=65,
        )

        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_url_risk(
            clean_url="https://test-domain.com/index.html",
            forensics=self.default_forensics,
            typosquatting=self.default_typo,
            inference_prediction=ml_pred,
            threat_intel=threat_clean,
            fdict=self.default_fdict,
            is_known_authoritative=False,
        )

        self.assertEqual(classification, UnifiedRiskClassification.LOW_RISK)
        # Verify informational disclaimer is recorded
        clean_item = next(
            (i for i in unified_items if i.indicator_id == "EXTERNAL_THREAT_INTEL_CLEAN"), None
        )
        self.assertIsNotNone(clean_item)
        self.assertEqual(clean_item.category, EvidenceCategory.INFORMATIONAL)
        self.assertIn("Absence of external reports is not proof of safety", clean_item.description)

    def test_invariant_model_missing_failsafe_unable_to_verify(self):
        """Verify missing ML model fails safely to UNABLE TO VERIFY without crashing."""
        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_url_risk(
            clean_url="https://test-domain.com/index.html",
            forensics=self.default_forensics,
            typosquatting=self.default_typo,
            inference_prediction=None,  # Model missing
            threat_intel=None,
            fdict=self.default_fdict,
            is_known_authoritative=False,
        )

        self.assertEqual(classification, UnifiedRiskClassification.UNABLE_TO_VERIFY)
        self.assertEqual(status, "MODEL_UNAVAILABLE")

    def test_severe_heuristics_malicious_ip_host(self):
        """Verify raw IP address combined with sensitive token keywords triggers HIGH RISK."""
        ip_forensics = DomainForensics(
            hostname="192.168.1.1",
            subdomain="",
            domain="192.168.1.1",
            tld="",
            path="/login.php",
            query_params={},
            has_ip_address=True,
            url_length=32,
        )
        fdict_tokens = self.default_fdict.copy()
        fdict_tokens["suspicious_token_count"] = 2

        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_url_risk(
            clean_url="http://192.168.1.1/login.php",
            forensics=ip_forensics,
            typosquatting=self.default_typo,
            inference_prediction=URLModelPrediction(is_phishing=True, confidence=0.40, model_name="RF"),
            threat_intel=None,
            fdict=fdict_tokens,
            is_known_authoritative=False,
        )

        self.assertEqual(classification, UnifiedRiskClassification.HIGH_RISK)
        self.assertEqual(status, "HIGH_CONFIDENCE_MALICIOUS_IP")


class TestUnifiedRiskEngineMessage(unittest.TestCase):
    """Test Message risk synthesis and contextual security guards."""

    def test_defensive_advisory_guard_suppresses_false_alarm(self):
        """Verify bank warning 'Never share OTP' is classified LOW RISK despite containing trigger words."""
        findings = [
            HeuristicFinding(
                category="otp_requests",
                explanation="Contains OTP security alert",
                matched_text="never share your OTP",
                severity="HIGH",
            )
        ]

        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_message_risk(
            original_text="Bank Alert: Never share your OTP or password with anyone claiming to be bank staff.",
            is_model_available=True,
            pred_is_scam=False,
            pred_confidence=0.12,
            model_name="LogisticRegression_TFIDF_v1",
            se_findings=findings,
            is_advisory=True,  # Contextual defensive guard active
            is_benign=False,
            scam_category="UNKNOWN",
            embedded_url_analyses=[],
        )

        self.assertEqual(classification, UnifiedRiskClassification.LOW_RISK)
        self.assertIn(status, ("ANALYSIS_ACTIVE", "STAGE_3_ANALYSIS_ACTIVE"))
        advisory_item = next(
            (i for i in unified_items if i.indicator_id == "DEFENSIVE_SECURITY_ADVISORY"), None
        )
        self.assertIsNotNone(advisory_item)
        self.assertEqual(advisory_item.severity, EvidenceSeverity.LOW)

    def test_embedded_url_high_risk_escalates_message(self):
        """Verify embedded phishing URL escalates an otherwise neutral message to HIGH RISK."""
        mock_url_resp = URLAnalysisResponse(
            target_url="https://secure-login-fake.net/account",
            classification=UnifiedRiskClassification.HIGH_RISK,
            status="HIGH_PROBABILITY_PHISHING",
            model_prediction=URLModelPrediction(is_phishing=True, confidence=0.92, model_name="RF"),
            forensics=DomainForensics(
                hostname="secure-login-fake.net",
                subdomain="",
                domain="secure-login-fake",
                tld="net",
                path="/account",
                query_params={},
                has_ip_address=False,
                url_length=42,
            ),
            explainable_risk_indicators=[],
            evidence=["High probability phishing URL"],
            recommendations=["Do not visit"],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        classification, status, evidence_strings, unified_items, recs = UnifiedRiskEngine.synthesize_message_risk(
            original_text="Please check your account status at: https://secure-login-fake.net/account",
            is_model_available=True,
            pred_is_scam=False,
            pred_confidence=0.20,
            model_name="LogisticRegression_TFIDF_v1",
            se_findings=[],
            is_advisory=False,
            is_benign=False,
            scam_category="UNKNOWN",
            embedded_url_analyses=[mock_url_resp],
        )

        self.assertEqual(classification, UnifiedRiskClassification.HIGH_RISK)
        url_evidence = next(
            (i for i in unified_items if i.indicator_id == "EMBEDDED_URL_HIGH_RISK"), None
        )
        self.assertIsNotNone(url_evidence)
        self.assertEqual(url_evidence.severity, EvidenceSeverity.HIGH)


class TestUnifiedRiskEngineQR(unittest.TestCase):
    """Test multi-QR barcode risk synthesis."""

    def test_multi_qr_highest_severity_invariant(self):
        """Verify image containing both a benign and phishing QR code preserves HIGH RISK verdict."""
        item_benign = DecodedQRItem(
            qr_index=1,
            payload_type=QRPayloadType.PLAIN_TEXT,
            raw_payload="Harmless meeting notes",
            classification=UnifiedRiskClassification.LOW_RISK,
            evidence=["Plain text"],
        )
        item_phishing = DecodedQRItem(
            qr_index=2,
            payload_type=QRPayloadType.URL,
            raw_payload="https://phishing-portal.com/login",
            classification=UnifiedRiskClassification.HIGH_RISK,
            evidence=["Phishing URL"],
        )

        classification, status, unified_items = UnifiedRiskEngine.synthesize_qr_risk(
            qr_count=2,
            primary_item_classification=UnifiedRiskClassification.HIGH_RISK,
            decoded_items=[item_benign, item_phishing],
        )

        self.assertEqual(classification, UnifiedRiskClassification.HIGH_RISK)
        self.assertIn(status, ("ANALYSIS_ACTIVE", "STAGE_6_ANALYSIS_ACTIVE"))

        # Multi-QR tracking item present
        multi_item = next((i for i in unified_items if i.indicator_id == "MULTI_QR_IMAGE"), None)
        self.assertIsNotNone(multi_item)
        self.assertIn("2 separate barcodes", multi_item.description)

    def test_zero_qr_returns_unable_to_verify(self):
        """Verify zero detected barcodes produces UNABLE TO VERIFY."""
        classification, status, unified_items = UnifiedRiskEngine.synthesize_qr_risk(
            qr_count=0,
            primary_item_classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
            decoded_items=[],
        )

        self.assertEqual(classification, UnifiedRiskClassification.UNABLE_TO_VERIFY)
        self.assertIn(status, ("NO_QR_DETECTED", "STAGE_6_NO_QR_DETECTED"))
        no_qr_item = next((i for i in unified_items if i.indicator_id == "NO_QR_SYMBOL_DETECTED"), None)
        self.assertIsNotNone(no_qr_item)
        self.assertEqual(no_qr_item.status, EvidenceStatus.UNAVAILABLE)
