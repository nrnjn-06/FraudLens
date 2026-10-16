"""QR code safety scanner service for FraudLens.

Integrates:
1. Optical image upload validation, dimension enforcement, and in-memory CV decoding.
2. OpenCV (QRCodeDetector) + Pyzbar multi-barcode decoding with contrast enhancement.
3. Strict payload categorization (URL, UPI_PAYMENT, WIFI, CONTACT, EMAIL, PLAIN_TEXT, OTHER, UNSUPPORTED).
4. Direct integration with the reusable URLAnalysisService (Random Forest phishing model, forensics, typosquatting).
5. UPI payment inspection (pa, pn, am, cu, tn parameters, coercive pattern heuristics, amount formatting).
6. Multi-QR aggregation and unified 4-level risk synthesis.
"""

from datetime import datetime, timezone
import html
import io
import logging
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse
import cv2
import numpy as np
import pyzbar.pyzbar as pyzbar
from PIL import Image
from fastapi import HTTPException, status

from backend.app.config import settings
from backend.app.schemas.common import (
    EvidenceCategory,
    EvidenceSeverity,
    EvidenceStatus,
    ExplainableRiskIndicator,
    IndicatorContributionType,
    UnifiedEvidenceItem,
    UnifiedRiskClassification,
)
from backend.app.schemas.qr import (
    ContactDetails,
    DecodedQRItem,
    DestinationPreview,
    QRAnalysisResponse,
    QRPayloadType,
    UPIPaymentDetails,
    WiFiDetails,
)
from backend.app.services.recommendation_engine import get_recommendation_engine
from backend.app.services.risk_engine import UnifiedRiskEngine
from backend.app.services.url_service import URLAnalysisService, get_url_service

logger = logging.getLogger(__name__)

# Dangerous URI pseudo-schemes that must never be treated as navigable web destinations
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

# Common coercive phrases observed in deceptive payment requests (UPI)
COERCIVE_PAYMENT_PATTERNS = [
    r"\bkyc\b",
    r"\bunblock\b",
    r"\bblock(?:ed)?\b",
    r"\blottery\b",
    r"\bprize\b",
    r"\bcashback\s*claim\b",
    r"\bpenalty\b",
    r"\btax\s*deposit\b",
    r"\bsecurity\s*deposit\b",
    r"\bverification\s*fee\b",
    r"\bactivation\s*fee\b",
    r"\baccount\s*frozen\b",
    r"\burgent\b",
    r"\brefund\s*claim\b",
    r"\bclaim\s*reward\b",
]

VPA_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$")
URL_SCHEME_REGEX = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)


class QRScannerService:
    """Service orchestrating QR code safety analysis and payload inspection."""

    def __init__(self, url_service: Optional[URLAnalysisService] = None):
        self.url_service = url_service or get_url_service()
        self.max_file_size = settings.MAX_IMAGE_UPLOAD_BYTES
        self.max_dimension = getattr(settings, "MAX_IMAGE_DIMENSION", 4096)
        self.enable_multi_qr = getattr(settings, "ENABLE_MULTI_QR", True)
        self.cv_detector = cv2.QRCodeDetector()

    def validate_image_upload(self, file_bytes: bytes, filename: Optional[str] = None) -> np.ndarray:
        """Validate uploaded image integrity, file constraints, format headers, and dimensions.

        Returns decoded OpenCV image (BGR numpy array).
        """
        if len(file_bytes) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )

        if len(file_bytes) > self.max_file_size:
            max_mb = self.max_file_size // (1024 * 1024)
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Uploaded file exceeds maximum limit of {max_mb}MB.",
            )

        # Magic byte inspection for supported image types
        is_png = file_bytes.startswith(b"\x89PNG\r\n\x1a\n")
        is_jpeg = file_bytes.startswith(b"\xff\xd8\xff")
        is_gif = file_bytes.startswith((b"GIF87a", b"GIF89a"))
        is_bmp = file_bytes.startswith(b"BM")
        is_webp = file_bytes.startswith(b"RIFF") and b"WEBP" in file_bytes[:16]

        if not (is_png or is_jpeg or is_gif or is_bmp or is_webp):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Unsupported file format. Please upload a valid PNG, JPEG, WEBP, or BMP image.",
            )

        # In-memory decoding using OpenCV
        img = None
        try:
            nparr = np.frombuffer(file_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        except Exception as ex:
            logger.warning(f"Failed to decode image bytes with OpenCV: {ex}")
            img = None

        # Fallback decoding via Pillow if OpenCV imdecode failed
        if img is None:
            try:
                pil_img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
                img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
            except Exception as ex:
                logger.warning(f"Failed to decode image with Pillow fallback: {ex}")
                img = None

        if img is not None and img.size > 0:
            # Enforce maximum image dimensions
            height, width = img.shape[:2]
            if height > self.max_dimension or width > self.max_dimension:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Image dimensions ({width}x{height}) exceed maximum allowable limit ({self.max_dimension}x{self.max_dimension} pixels).",
                )

        return img

    def decode_qr_payloads(self, img: np.ndarray) -> List[str]:
        """Decode all QR code symbols present in the image using dual pyzbar + OpenCV pipeline.

        Applies contrast enhancement (Otsu thresholding) defensively if initial decoding fails.
        """
        decoded_payloads: List[str] = []
        seen_payloads: Set[str] = set()

        def _add_payload(raw_text: str):
            clean = (raw_text or "").strip()
            if clean and clean not in seen_payloads:
                seen_payloads.add(clean)
                decoded_payloads.append(clean)

        # 1. Primary pass with pyzbar (high rotation and symbol resilience)
        try:
            zbar_results = pyzbar.decode(img)
            for item in zbar_results:
                if item.type == "QRCODE":
                    try:
                        text = item.data.decode("utf-8", errors="replace")
                        _add_payload(text)
                    except Exception as err:
                        logger.debug(f"Failed decoding pyzbar QR bytes: {err}")
        except Exception as err:
            logger.debug(f"Pyzbar pass failed: {err}")

        # 2. Secondary pass with OpenCV detectAndDecodeMulti
        try:
            ret, cv_texts, _, _ = self.cv_detector.detectAndDecodeMulti(img)
            if ret and cv_texts:
                for t in cv_texts:
                    _add_payload(t)
            elif not ret:
                # Single detector fallback
                single_ret, single_val, _, _ = self.cv_detector.detectAndDecode(img)
                if single_ret and single_val:
                    _add_payload(single_val)
        except Exception as err:
            logger.debug(f"OpenCV detection pass failed: {err}")

        # 3. Defensive pass: if no QR symbols detected, attempt Otsu contrast enhancement
        if len(decoded_payloads) == 0:
            try:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

                # Try pyzbar on thresholded image
                thresh_zbar = pyzbar.decode(thresh)
                for item in thresh_zbar:
                    if item.type == "QRCODE":
                        text = item.data.decode("utf-8", errors="replace")
                        _add_payload(text)

                if len(decoded_payloads) == 0:
                    ret_th, cv_th, _, _ = self.cv_detector.detectAndDecodeMulti(thresh)
                    if ret_th and cv_th:
                        for t in cv_th:
                            _add_payload(t)
            except Exception as err:
                logger.debug(f"Contrast enhancement pass failed: {err}")

        return decoded_payloads

    def classify_payload_type(self, raw_text: str) -> Tuple[QRPayloadType, str]:
        """Categorize raw QR payload string into canonical types.

        Returns (QRPayloadType, extracted_scheme).
        """
        text = raw_text.strip()
        lower = text.lower()

        # UPI Payment schemes
        if lower.startswith("upi://pay") or lower.startswith("upi://"):
            return QRPayloadType.UPI_PAYMENT, "upi"

        # Check for dangerous client-side script schemes
        for dangerous_scheme in DANGEROUS_SCHEMES:
            if lower.startswith(f"{dangerous_scheme}:"):
                return QRPayloadType.OTHER_SUPPORTED_SCHEME, dangerous_scheme

        # Web URLs
        if URL_SCHEME_REGEX.match(lower) or lower.startswith("www."):
            scheme = "https" if lower.startswith("https://") else "http"
            return QRPayloadType.URL, scheme

        # Wi-Fi Configuration
        if lower.startswith("wifi:"):
            return QRPayloadType.WIFI_CONFIGURATION, "wifi"

        # Phone and contact triggers
        if lower.startswith(("tel:", "sms:", "smsto:", "mms:", "mmsto:", "begin:vcard", "mecard:")):
            scheme = lower.split(":", 1)[0]
            return QRPayloadType.PHONE_OR_CONTACT, scheme

        # Email triggers
        if lower.startswith(("mailto:", "matmsg:")):
            scheme = lower.split(":", 1)[0]
            return QRPayloadType.EMAIL_OR_MESSAGE, scheme

        # Other standard URI schemes (e.g. geo:, market:, intent:)
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", text)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            return QRPayloadType.OTHER_SUPPORTED_SCHEME, scheme

        # Plain text
        return QRPayloadType.PLAIN_TEXT, "text"

    def inspect_upi_payload(self, raw_text: str) -> Tuple[UPIPaymentDetails, UnifiedRiskClassification, List[str], List[ExplainableRiskIndicator]]:
        """Safely parse and evaluate parameters from `upi://pay` URIs."""
        evidence: List[str] = []
        indicators: List[ExplainableRiskIndicator] = []
        validation_notes: List[str] = []
        risk = UnifiedRiskClassification.LOW_RISK

        try:
            parsed = urlparse(raw_text)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
        except Exception as err:
            logger.warning(f"Failed parsing UPI URI query: {err}")
            query_params = {}

        def _get_param(key: str) -> Optional[str]:
            vals = query_params.get(key, [])
            return unquote(vals[0].strip()) if vals and vals[0].strip() else None

        payee_vpa = _get_param("pa")
        payee_name = _get_param("pn")
        amount_str = _get_param("am")
        currency = _get_param("cu") or "INR"
        note = _get_param("tn")
        mc = _get_param("mc")
        tr = _get_param("tr")
        embedded_url = _get_param("url")

        has_amount = bool(amount_str)

        evidence.append("Decoded standard UPI payment URI payload.")
        if payee_vpa:
            evidence.append(f"Payee UPI ID (VPA): '{payee_vpa}'")
        if payee_name:
            evidence.append(f"Payee Display Name: '{payee_name}'")
        if amount_str:
            evidence.append(f"Requested Pre-set Amount: {amount_str} {currency}")

        # 1. Payee VPA Validation
        if not payee_vpa:
            validation_notes.append("Missing mandatory payee address ('pa') parameter.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="MISSING_PAYEE_VPA",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="The UPI payload does not specify a recipient VPA address.",
                )
            )
            risk = UnifiedRiskClassification.MEDIUM_RISK
        elif not VPA_REGEX.match(payee_vpa):
            validation_notes.append(f"Payee address '{payee_vpa}' is not in standard VPA handle format.")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="MALFORMED_UPI_VPA",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description=f"Payee address '{payee_vpa}' departs from standard user@bank syntax.",
                )
            )
            risk = UnifiedRiskClassification.MEDIUM_RISK

        # 2. Amount Validation
        if amount_str:
            try:
                amt_val = float(amount_str)
                if amt_val <= 0.0:
                    validation_notes.append("Requested transaction amount is zero or negative.")
                    indicators.append(
                        ExplainableRiskIndicator(
                            indicator="INVALID_TRANSACTION_AMOUNT",
                            contribution_type=IndicatorContributionType.HEURISTIC,
                            description="Amount parameter contains a non-positive value.",
                        )
                    )
                    risk = UnifiedRiskClassification.MEDIUM_RISK
                elif amt_val > 100000.0:
                    validation_notes.append(f"Unusually large payment request ({amt_val:,.2f} {currency}) via static QR.")
                    indicators.append(
                        ExplainableRiskIndicator(
                            indicator="HIGH_VALUE_STATIC_PAYMENT",
                            contribution_type=IndicatorContributionType.HEURISTIC,
                            description=f"Transaction requests a high amount of {amt_val:,.2f} {currency}.",
                        )
                    )
                    if risk != UnifiedRiskClassification.HIGH_RISK:
                        risk = UnifiedRiskClassification.MEDIUM_RISK
            except ValueError:
                validation_notes.append(f"Amount parameter '{amount_str}' is non-numeric.")
                indicators.append(
                    ExplainableRiskIndicator(
                        indicator="NON_NUMERIC_AMOUNT",
                        contribution_type=IndicatorContributionType.HEURISTIC,
                        description="Amount parameter cannot be parsed as a valid numeric currency value.",
                    )
                )
                risk = UnifiedRiskClassification.MEDIUM_RISK

        # 3. Coercive and Social Engineering Language in Payee Name or Transaction Note
        combined_text = f"{payee_name or ''} {note or ''}".lower()
        matched_coercion = []
        for pat in COERCIVE_PAYMENT_PATTERNS:
            if re.search(pat, combined_text):
                matched_coercion.append(pat.replace(r"\b", "").replace(r"\s*", " "))

        if matched_coercion:
            coercion_desc = f"Coercive scam keywords detected in payment memo/name: {', '.join(set(matched_coercion))}."
            validation_notes.append(coercion_desc)
            evidence.append(f"Social Engineering Alert: {coercion_desc}")
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="COERCIVE_UPI_PAYMENT_MEMO",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="Payment note or payee name uses coercive pressure (e.g. KYC, penalties, lottery claim fees).",
                )
            )
            risk = UnifiedRiskClassification.HIGH_RISK

        # 4. Embedded URL Analysis inside UPI payload
        if embedded_url:
            evidence.append(f"Embedded reference URL found in UPI payload: '{embedded_url}'")
            try:
                url_resp = self.url_service.analyze_url(embedded_url)
                if url_resp.classification == UnifiedRiskClassification.HIGH_RISK:
                    risk = UnifiedRiskClassification.HIGH_RISK
                    validation_notes.append(f"Embedded URL '{embedded_url}' identified as HIGH RISK phishing.")
                elif url_resp.classification == UnifiedRiskClassification.MEDIUM_RISK:
                    if risk != UnifiedRiskClassification.HIGH_RISK:
                        risk = UnifiedRiskClassification.MEDIUM_RISK
            except Exception as err:
                logger.warning(f"Failed analyzing embedded UPI URL '{embedded_url}': {err}")

        upi_details = UPIPaymentDetails(
            payee_name=payee_name,
            payee_vpa=payee_vpa,
            amount=amount_str,
            currency=currency,
            transaction_note=note,
            merchant_code=mc,
            transaction_ref=tr,
            safety_warning="Verify the payee UPI ID and amount directly on your banking app. Syntactic validity does not prove legitimacy.",
            is_verified_merchant=False,
            has_prepopulated_amount=has_amount,
            validation_notes=validation_notes,
        )

        return upi_details, risk, evidence, indicators

    def parse_wifi_payload(self, raw_text: str) -> Tuple[WiFiDetails, UnifiedRiskClassification, List[str], List[ExplainableRiskIndicator]]:
        """Parse `WIFI:S:<SSID>;T:<TYPE>;P:<PASS>;;` configurations."""
        evidence: List[str] = ["Decoded Wi-Fi configuration barcode."]
        indicators: List[ExplainableRiskIndicator] = []
        risk = UnifiedRiskClassification.LOW_RISK

        # Extract fields using regex
        def _match_field(prefix: str) -> Optional[str]:
            m = re.search(rf"{prefix}:([^;]*)", raw_text, re.IGNORECASE)
            return m.group(1) if m else None

        ssid = _match_field("S") or "Unknown"
        auth = (_match_field("T") or "WPA").upper()
        has_pass = bool(_match_field("P"))
        hidden = (_match_field("H") or "").lower() == "true"

        evidence.append(f"Wi-Fi SSID: '{ssid}' (Auth: {auth})")

        warning = None
        if auth in ("NOPASS", "NONE", ""):
            risk = UnifiedRiskClassification.MEDIUM_RISK
            warning = "Unencrypted open Wi-Fi network. Traffic may be subject to local eavesdropping."
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="OPEN_WIFI_NETWORK",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="Wi-Fi network specifies no encryption password (open access).",
                )
            )
        elif "WEP" in auth:
            risk = UnifiedRiskClassification.MEDIUM_RISK
            warning = "Obsolete WEP encryption is cryptographically broken and vulnerable to exploitation."
            indicators.append(
                ExplainableRiskIndicator(
                    indicator="OBSOLETE_WEP_ENCRYPTION",
                    contribution_type=IndicatorContributionType.HEURISTIC,
                    description="Wi-Fi network uses obsolete WEP authentication instead of modern WPA2/WPA3.",
                )
            )

        wifi_details = WiFiDetails(
            ssid=ssid,
            auth_type=auth,
            is_hidden=hidden,
            has_password=has_pass,
            security_warning=warning,
        )
        return wifi_details, risk, evidence, indicators

    def parse_contact_payload(self, raw_text: str, scheme: str) -> Tuple[ContactDetails, UnifiedRiskClassification, List[str], List[ExplainableRiskIndicator]]:
        """Extract telephone, contact card, or SMS payload details."""
        evidence: List[str] = [f"Decoded contact/communication trigger ({scheme.upper()})."]
        indicators: List[ExplainableRiskIndicator] = []
        risk = UnifiedRiskClassification.LOW_RISK

        contact_type = "PHONE"
        target = None
        name = None
        body = None

        if scheme in ("tel", "sms", "smsto", "mms", "mmsto"):
            parts = raw_text.split(":", 1)
            raw_target = parts[1] if len(parts) > 1 else ""
            if "?" in raw_target:
                target_part, query = raw_target.split("?", 1)
                target = target_part
                parsed_q = parse_qs(query)
                body = parsed_q.get("body", [""])[0] or None
            elif ":" in raw_target:
                target_part, body_part = raw_target.split(":", 1)
                target = target_part
                body = body_part
            else:
                target = raw_target
            contact_type = "SMS" if "sms" in scheme else "PHONE"
        elif "vcard" in scheme or "mecard" in scheme:
            contact_type = "VCARD" if "vcard" in scheme else "MECARD"
            fn_m = re.search(r"\b(?:FN|N):([^\r\n;]+)", raw_text, re.IGNORECASE)
            tel_m = re.search(r"\bTEL[^:]*:([^\r\n;]+)", raw_text, re.IGNORECASE)
            name = fn_m.group(1).strip() if fn_m else None
            target = tel_m.group(1).strip() if tel_m else None

        if target:
            evidence.append(f"Target number/address: '{target}'")
        if name:
            evidence.append(f"Contact Name: '{name}'")
        if body:
            evidence.append(f"Pre-filled message text: '{body}'")

        contact_details = ContactDetails(
            contact_type=contact_type,
            target=target,
            name=name,
            body=body,
        )
        return contact_details, risk, evidence, indicators

    def analyze_single_payload(self, raw_text: str, index: int = 1) -> DecodedQRItem:
        """Categorize and execute end-to-end security analysis on a single decoded payload."""
        payload_type, scheme = self.classify_payload_type(raw_text)

        evidence: List[str] = []
        destination_preview: Optional[DestinationPreview] = None
        url_analysis = None
        upi_inspection = None
        wifi_details = None
        contact_details = None
        classification = UnifiedRiskClassification.LOW_RISK

        # 1. URL Payloads
        if payload_type == QRPayloadType.URL:
            clean_url = raw_text.strip()
            if not clean_url.startswith(("http://", "https://")):
                clean_url = f"https://{clean_url}"

            parsed_url = urlparse(clean_url)
            destination_preview = DestinationPreview(
                destination=clean_url,
                scheme=parsed_url.scheme or "https",
                title=f"Web URL Destination ({parsed_url.hostname or 'unknown'})",
                note="Destination previewed safely. FraudLens will never automatically navigate to this target.",
            )

            try:
                url_analysis = self.url_service.analyze_url(clean_url)
                classification = url_analysis.classification
                evidence.append(f"Evaluated URL through FraudLens Phishing Detection Engine: {classification.value}.")
                evidence.extend(url_analysis.evidence)
            except Exception as ex:
                logger.error(f"URL analysis failed for QR payload '{clean_url}': {ex}")
                classification = UnifiedRiskClassification.UNABLE_TO_VERIFY
                evidence.append("Phishing model inference was unavailable; classified as UNABLE TO VERIFY.")

        # 2. UPI Payment Payloads
        elif payload_type in (QRPayloadType.UPI_PAYMENT, QRPayloadType.UPI):
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme="upi",
                title="UPI Mobile Payment Request",
                note="UPI payment string decoded safely. FraudLens does not execute or initiate payments.",
            )
            upi_inspection, classification, upi_evidence, upi_indicators = self.inspect_upi_payload(raw_text)
            evidence.extend(upi_evidence)

        # 3. Wi-Fi Configuration
        elif payload_type == QRPayloadType.WIFI_CONFIGURATION:
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme="wifi",
                title="Wi-Fi Network Configuration",
                note="Network settings decoded safely without joining the access point.",
            )
            wifi_details, classification, wifi_evidence, _ = self.parse_wifi_payload(raw_text)
            evidence.extend(wifi_evidence)

        # 4. Phone / Contact / SMS
        elif payload_type == QRPayloadType.PHONE_OR_CONTACT:
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme=scheme,
                title="Communication or Contact Target",
                note="Contact target displayed safely without placing calls or sending messages.",
            )
            contact_details, classification, contact_evidence, _ = self.parse_contact_payload(raw_text, scheme)
            evidence.extend(contact_evidence)

        # 5. Email triggers
        elif payload_type == QRPayloadType.EMAIL_OR_MESSAGE:
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme="mailto",
                title="Pre-composed Email Message",
                note="Email destination rendered safely without launching mail client.",
            )
            evidence.append(f"Decoded email communication trigger: '{raw_text[:60]}...'")
            classification = UnifiedRiskClassification.LOW_RISK

        # 6. Dangerous Script Schemas (javascript:, data:)
        elif scheme in DANGEROUS_SCHEMES:
            payload_type = QRPayloadType.OTHER_SUPPORTED_SCHEME
            classification = UnifiedRiskClassification.HIGH_RISK
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme=scheme,
                title=f"Dangerous Executable URI Scheme ({scheme}:)",
                note="BLOCKED: Script execution target safely isolated and denied navigation.",
            )
            evidence.append(f"Security Alert: QR contains dangerous executable scheme '{scheme}:' designed for client injection.")

        # 7. Plain Text
        elif payload_type == QRPayloadType.PLAIN_TEXT:
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme="text",
                title="Plain Text Payload",
                note="Plain text rendered safely with zero HTML/script evaluation.",
            )
            lower_text = raw_text.lower()
            if "<script" in lower_text or "javascript:" in lower_text:
                classification = UnifiedRiskClassification.HIGH_RISK
                evidence.append("Detected malicious script injection tags in raw plain text payload.")
            else:
                classification = UnifiedRiskClassification.LOW_RISK
                evidence.append(f"Plain text content ({len(raw_text)} characters) contains no recognized threat indicators.")

        # 8. Unsupported / Custom Schemes
        else:
            destination_preview = DestinationPreview(
                destination=raw_text,
                scheme=scheme,
                title="Custom or Unsupported Format",
                note="Payload format is not in recognized standard taxonomy.",
            )
            classification = UnifiedRiskClassification.UNABLE_TO_VERIFY
            evidence.append(f"Unrecognized scheme '{scheme}' or custom data structure cannot be verified safely.")

        item_unified_evidence: List[UnifiedEvidenceItem] = []
        if url_analysis and url_analysis.unified_evidence:
            item_unified_evidence.extend(url_analysis.unified_evidence)
        elif upi_inspection and upi_inspection.validation_notes:
            for note in upi_inspection.validation_notes:
                item_unified_evidence.append(
                    UnifiedEvidenceItem(
                        category=EvidenceCategory.HEURISTIC,
                        description=note,
                        source="UPIPaymentInspector",
                        severity=EvidenceSeverity.HIGH if classification == UnifiedRiskClassification.HIGH_RISK else EvidenceSeverity.MEDIUM,
                        status=EvidenceStatus.CONFIRMED,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        indicator_id="UPI_STRUCTURAL_FLAG",
                    )
                )

        return DecodedQRItem(
            qr_index=index,
            payload_type=payload_type,
            raw_payload=raw_text,
            classification=classification,
            destination_preview=destination_preview,
            url_analysis=url_analysis,
            upi_inspection=upi_inspection,
            wifi_details=wifi_details,
            contact_details=contact_details,
            evidence=evidence,
            unified_evidence=item_unified_evidence,
        )

    def analyze_qr_image(self, file_bytes: bytes, filename: Optional[str] = None) -> QRAnalysisResponse:
        """Analyze an uploaded QR image for deceptive payloads, payment manipulation, and phishing links."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Image validation and in-memory loading
        img = self.validate_image_upload(file_bytes, filename)

        if img is None:
            evidence = [
                f"Image header validated ({len(file_bytes)} bytes).",
                "Pixel data could not be parsed as a valid image bitmap (corrupted or truncated image data).",
            ]
            recommendations = [
                "Ensure the image file is valid and undamaged.",
                "Try taking another picture or screenshot of the QR code.",
            ]
            _, _, unified_items = UnifiedRiskEngine.synthesize_qr_risk(
                qr_count=0,
                primary_item_classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
                decoded_items=[],
            )
            return QRAnalysisResponse(
                classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
                status="NO_QR_DETECTED",
                qr_count_detected=0,
                payload_type=QRPayloadType.UNREADABLE,
                raw_payload=None,
                destination_preview=DestinationPreview(
                    destination="Unreadable or corrupt image data.",
                    scheme="none",
                    title="Unreadable Image",
                    note="The uploaded image could not be decoded as a valid bitmap.",
                ),
                url_analysis=None,
                upi_inspection=UPIPaymentDetails(
                    payee_name=None,
                    payee_vpa=None,
                    amount=None,
                    safety_warning="No UPI payment payload detected in image.",
                    is_verified_merchant=False,
                ),
                wifi_details=None,
                contact_details=None,
                decoded_items=[],
                explainable_risk_indicators=[
                    ExplainableRiskIndicator(
                        indicator="CORRUPT_OR_UNREADABLE_IMAGE",
                        contribution_type=IndicatorContributionType.HEURISTIC,
                        description="Computer vision decoders could not parse bitmap data from the image file.",
                    )
                ],
                evidence=evidence,
                unified_evidence=unified_items,
                recommendations=recommendations,
                timestamp=now_iso,
            )

        # 2. QR symbol decoding
        decoded_strings = self.decode_qr_payloads(img)
        qr_count = len(decoded_strings)

        # 3. Handle unreadable or empty QR detection
        if qr_count == 0:
            evidence = [
                f"Image upload validated successfully ({len(file_bytes)} bytes, {img.shape[1]}x{img.shape[0]} px).",
                "Computer vision barcode detection pipeline scanned the image.",
                "No QR code symbol or readable barcode was detected.",
            ]
            recommendations = [
                "Ensure the QR code is centered, well-lit, and not blurred or cropped.",
                "Avoid scanning unreadable or degraded barcodes from untrusted physical posters.",
            ]
            _, _, unified_items = UnifiedRiskEngine.synthesize_qr_risk(
                qr_count=0,
                primary_item_classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
                decoded_items=[],
            )
            return QRAnalysisResponse(
                classification=UnifiedRiskClassification.UNABLE_TO_VERIFY,
                status="NO_QR_DETECTED",
                qr_count_detected=0,
                payload_type=QRPayloadType.UNREADABLE,
                raw_payload=None,
                destination_preview=DestinationPreview(
                    destination="No readable QR code found in image.",
                    scheme="none",
                    title="No Symbol Found",
                    note="No barcode symbol was detected in the submitted image.",
                ),
                url_analysis=None,
                upi_inspection=UPIPaymentDetails(
                    payee_name=None,
                    payee_vpa=None,
                    amount=None,
                    safety_warning="No UPI payment payload detected in image.",
                    is_verified_merchant=False,
                ),
                wifi_details=None,
                contact_details=None,
                decoded_items=[],
                explainable_risk_indicators=[
                    ExplainableRiskIndicator(
                        indicator="UNREADABLE_IMAGE",
                        contribution_type=IndicatorContributionType.HEURISTIC,
                        description="Computer vision decoders could not detect any valid QR matrix in the submitted file.",
                    )
                ],
                evidence=evidence,
                unified_evidence=unified_items,
                recommendations=recommendations,
                timestamp=now_iso,
            )

        # 4. Analyze each decoded QR symbol
        decoded_items: List[DecodedQRItem] = []
        for i, raw_payload in enumerate(decoded_strings, start=1):
            item = self.analyze_single_payload(raw_payload, index=i)
            decoded_items.append(item)

        # 5. Multi-QR risk synthesis (highest risk invariant)
        risk_rank = {
            UnifiedRiskClassification.HIGH_RISK: 4,
            UnifiedRiskClassification.MEDIUM_RISK: 3,
            UnifiedRiskClassification.UNABLE_TO_VERIFY: 2,
            UnifiedRiskClassification.LOW_RISK: 1,
        }

        # Select primary item as the highest risk symbol
        primary_item = max(decoded_items, key=lambda it: risk_rank.get(it.classification, 0))
        final_classification = primary_item.classification

        # Aggregate evidence and recommendations
        aggregated_evidence: List[str] = [
            f"Image validated ({len(file_bytes)} bytes, {img.shape[1]}x{img.shape[0]} px).",
            f"Detected {qr_count} QR code symbol{'s' if qr_count > 1 else ''} in image.",
        ]
        if qr_count > 1:
            aggregated_evidence.append(
                f"Multi-QR Detection: Image contains {qr_count} separate QR codes. Overall verdict reflects highest severity item."
            )

        aggregated_evidence.extend(primary_item.evidence)

        # Build recommendations via RecommendationEngine
        recommendations: List[str] = []
        structured_rec = None
        rec_engine = get_recommendation_engine()

        if primary_item.url_analysis:
            recommendations.extend(primary_item.url_analysis.recommendations or [])
            structured_rec = primary_item.url_analysis.structured_recommendation
        elif primary_item.upi_inspection and primary_item.upi_inspection.payee_vpa:
            upi_data = primary_item.upi_inspection
            upi_dict = {
                "payee_name": upi_data.payee_name,
                "payee_vpa": upi_data.payee_vpa,
                "amount": upi_data.amount,
                "currency": upi_data.currency,
            }
            recs, structured_rec = rec_engine.generate_qr_recommendation(
                classification=final_classification,
                payload_type=primary_item.payload_type,
                decoded_text=primary_item.raw_payload or "",
                upi_details=upi_dict,
            )
            recommendations = recs
        elif primary_item.destination_preview and primary_item.destination_preview.scheme in ("javascript", "data", "vbscript", "file"):
            recommendations.append(
                f"Finding: Optical barcode encodes an executable script payload ({primary_item.destination_preview.scheme}:) designed for client injection."
            )
            recommendations.append(
                "Action: DO NOT execute, copy, or run this payload. FraudLens has safely blocked script execution in an offline sandbox."
            )
        else:
            recs, structured_rec = rec_engine.generate_qr_recommendation(
                classification=final_classification,
                payload_type=primary_item.payload_type,
                decoded_text=primary_item.raw_payload or "",
            )
            recommendations = recs

        # Aggregate explainable risk indicators
        explainable_indicators: List[ExplainableRiskIndicator] = []
        if primary_item.url_analysis and primary_item.url_analysis.explainable_risk_indicators:
            explainable_indicators.extend(primary_item.url_analysis.explainable_risk_indicators)
        if primary_item.upi_inspection and primary_item.upi_inspection.validation_notes:
            for note in primary_item.upi_inspection.validation_notes:
                explainable_indicators.append(
                    ExplainableRiskIndicator(
                        indicator="UPI_STRUCTURAL_FLAG",
                        contribution_type=IndicatorContributionType.HEURISTIC,
                        description=note,
                    )
                )

        synth_classification, _, unified_items = UnifiedRiskEngine.synthesize_qr_risk(
            qr_count=qr_count,
            primary_item_classification=final_classification,
            decoded_items=decoded_items,
        )

        return QRAnalysisResponse(
            classification=final_classification,
            status="ANALYSIS_ACTIVE",
            qr_count_detected=qr_count,
            payload_type=primary_item.payload_type,
            raw_payload=primary_item.raw_payload,
            destination_preview=primary_item.destination_preview,
            url_analysis=primary_item.url_analysis,
            upi_inspection=primary_item.upi_inspection,
            wifi_details=primary_item.wifi_details,
            contact_details=primary_item.contact_details,
            decoded_items=decoded_items,
            explainable_risk_indicators=explainable_indicators,
            evidence=aggregated_evidence,
            unified_evidence=unified_items,
            recommendations=recommendations,
            structured_recommendation=structured_rec,
            timestamp=now_iso,
        )


_global_qr_service: Optional[QRScannerService] = None


def get_qr_service() -> QRScannerService:
    """Dependency injector for QRScannerService singleton."""
    global _global_qr_service
    if _global_qr_service is None:
        _global_qr_service = QRScannerService()
    return _global_qr_service
