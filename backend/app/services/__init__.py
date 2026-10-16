"""Service layer for FraudLens detection modules."""

from backend.app.services.threat_intel import ThreatIntelService
from backend.app.services.url_service import URLAnalysisService, get_url_service
from backend.app.services.message_service import MessageAnalysisService, get_message_service
from backend.app.services.qr_service import QRScannerService, get_qr_service

__all__ = [
    "ThreatIntelService",
    "URLAnalysisService",
    "get_url_service",
    "MessageAnalysisService",
    "get_message_service",
    "QRScannerService",
    "get_qr_service",
]
