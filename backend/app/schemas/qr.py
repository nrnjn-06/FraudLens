"""Schemas for Module 3: QR Code Safety Scanner."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.common import (
    BaseRiskAssessment,
    ExplainableRiskIndicator,
    UnifiedEvidenceItem,
    UnifiedRiskClassification,
)
from backend.app.schemas.url import URLAnalysisResponse


class QRPayloadType(str, Enum):
    """Recognized payload types decoded from QR codes (Feature 1)."""

    URL = "URL"
    UPI = "UPI"  # Retained for backward compatibility
    UPI_PAYMENT = "UPI_PAYMENT"
    PHONE_OR_CONTACT = "PHONE_OR_CONTACT"
    WIFI_CONFIGURATION = "WIFI_CONFIGURATION"
    EMAIL_OR_MESSAGE = "EMAIL_OR_MESSAGE"
    PLAIN_TEXT = "PLAIN_TEXT"
    OTHER_SUPPORTED_SCHEME = "OTHER_SUPPORTED_SCHEME"
    UNSUPPORTED = "UNSUPPORTED"
    UNSUPPORTED_OR_UNRECOGNIZED = "UNSUPPORTED_OR_UNRECOGNIZED"
    UNREADABLE = "UNREADABLE"


class UPIPaymentDetails(BaseModel):
    """Extracted parameters from `upi://pay` URIs for user verification (Feature 4).

    IMPORTANT: Syntactic extraction is NOT proof of recipient identity or financial safety.
    FraudLens does not initiate payments or endorse payees.
    """

    payee_name: Optional[str] = Field(
        default=None,
        description="Payee display name (`pn`) parameter extracted from UPI URI.",
    )
    payee_vpa: Optional[str] = Field(
        default=None,
        description="Virtual Payment Address / UPI ID (`pa`) extracted from URI.",
    )
    amount: Optional[str] = Field(
        default=None,
        description="Pre-populated transaction amount (`am`), if requested by the QR.",
    )
    currency: Optional[str] = Field(
        default="INR",
        description="Currency code (`cu`), typically INR.",
    )
    transaction_note: Optional[str] = Field(
        default=None,
        description="Transaction note or remark (`tn`), if included.",
    )
    merchant_code: Optional[str] = Field(
        default=None,
        description="Merchant Category Code (`mc`), if present in URI.",
    )
    transaction_ref: Optional[str] = Field(
        default=None,
        description="Transaction reference (`tr`) or order ID parameter.",
    )
    safety_warning: str = Field(
        default="Verify the payee UPI ID and amount directly in your banking app. Syntactic validity does not prove legitimacy.",
        description="Mandatory cautionary notice regarding UPI payment deception.",
    )
    is_verified_merchant: bool = Field(
        default=False,
        description="Always false unless confirmed against an authorized bank registry.",
    )
    has_prepopulated_amount: bool = Field(
        default=False,
        description="True if the QR requests a specific pre-set debit amount.",
    )
    validation_notes: List[str] = Field(
        default_factory=list,
        description="Specific structural findings or potential coercive markers observed.",
    )


class WiFiDetails(BaseModel):
    """Structured fields from `WIFI:` configuration barcodes."""

    ssid: Optional[str] = Field(default=None, description="Network SSID.")
    auth_type: Optional[str] = Field(default="WPA", description="Authentication protocol (WPA/WEP/nopass).")
    is_hidden: bool = Field(default=False, description="Whether network broadcast is hidden.")
    has_password: bool = Field(default=True, description="Whether network requires a passphrase.")
    security_warning: Optional[str] = Field(default=None, description="Security caveat if unencrypted or weak.")


class ContactDetails(BaseModel):
    """Structured fields from contact cards, telephone URIs, or SMS triggers."""

    contact_type: str = Field(default="PHONE", description="Format type: PHONE, SMS, VCARD, MECARD, EMAIL.")
    target: Optional[str] = Field(default=None, description="Phone number or primary target identifier.")
    name: Optional[str] = Field(default=None, description="Contact name if provided in vCard/MeCard.")
    body: Optional[str] = Field(default=None, description="Pre-filled message text or email body.")


class DestinationPreview(BaseModel):
    """Preview of hidden destination before user navigation (Feature 2)."""

    destination: str = Field(..., description="The exact decoded destination or payload string.")
    scheme: str = Field(default="unknown", description="URI scheme (e.g. 'https', 'http', 'upi', 'text').")
    title: Optional[str] = Field(default=None, description="Safe descriptive title for the destination.")
    note: str = Field(
        default="Destination previewed safely. FraudLens will never automatically navigate to this target.",
        description="Safety guarantee notice.",
    )


class DecodedQRItem(BaseModel):
    """Individual QR code symbol finding when one or multiple codes exist in an image."""

    qr_index: int = Field(default=1, description="1-based index of the QR code in the image.")
    payload_type: QRPayloadType = Field(default=QRPayloadType.PLAIN_TEXT, description="Payload category.")
    raw_payload: str = Field(..., description="Raw decoded payload string.")
    classification: UnifiedRiskClassification = Field(..., description="Individual risk classification.")
    destination_preview: Optional[DestinationPreview] = Field(default=None, description="Target preview.")
    url_analysis: Optional[URLAnalysisResponse] = Field(default=None, description="Phishing URL analysis if applicable.")
    upi_inspection: Optional[UPIPaymentDetails] = Field(default=None, description="UPI payment inspection if applicable.")
    wifi_details: Optional[WiFiDetails] = Field(default=None, description="Wi-Fi configuration details if applicable.")
    contact_details: Optional[ContactDetails] = Field(default=None, description="Contact or communication details.")
    evidence: List[str] = Field(default_factory=list, description="Evidence signals for this specific QR code.")
    unified_evidence: List[UnifiedEvidenceItem] = Field(
        default_factory=list, description="Structured evidence signals for this specific QR code."
    )


class QRAnalysisResponse(BaseRiskAssessment):
    """Comprehensive response contract for QR code safety scanning."""

    qr_count_detected: int = Field(
        default=0,
        description="Number of QR codes detected in the uploaded image (Feature 5).",
    )
    payload_type: QRPayloadType = Field(
        default=QRPayloadType.UNREADABLE,
        description="Classified payload format of primary QR code (Feature 1).",
    )
    raw_payload: Optional[str] = Field(
        default=None,
        description="Raw decoded byte string or text from the primary QR symbol.",
    )
    destination_preview: Optional[DestinationPreview] = Field(
        default=None,
        description="Safe preview of the target without navigating (Feature 2).",
    )
    url_analysis: Optional[URLAnalysisResponse] = Field(
        default=None,
        description="Phishing analysis if the QR code contained a web URL (Feature 3).",
    )
    upi_inspection: Optional[UPIPaymentDetails] = Field(
        default=None,
        description="Payee and amount details if the QR code contained a UPI payment URI (Feature 4).",
    )
    wifi_details: Optional[WiFiDetails] = Field(
        default=None,
        description="Extracted Wi-Fi configuration parameters if payload is a Wi-Fi QR.",
    )
    contact_details: Optional[ContactDetails] = Field(
        default=None,
        description="Extracted contact information if payload is phone/vCard/SMS.",
    )
    decoded_items: List[DecodedQRItem] = Field(
        default_factory=list,
        description="Details of all decoded QR symbols if multiple codes are detected in the image.",
    )
    explainable_risk_indicators: List[ExplainableRiskIndicator] = Field(
        default_factory=list,
        description="Explicit breakdown of risk contributors for transparency.",
    )
