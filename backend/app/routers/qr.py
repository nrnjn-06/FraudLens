"""API endpoint for Module 3: QR Code Safety Scanner."""

from fastapi import APIRouter, Depends, File, UploadFile
from backend.app.schemas.qr import QRAnalysisResponse
from backend.app.services.qr_service import QRScannerService, get_qr_service

router = APIRouter(tags=["QR Code Safety Scanner"])


@router.post(
    "/analyze-qr",
    response_model=QRAnalysisResponse,
    summary="Scan and Analyze QR Image (Module 3)",
    description="Uploads a QR code image to decode payload, preview destination safely, inspect UPI URI details, and scan embedded URLs.",
)
async def analyze_qr_endpoint(
    file: UploadFile = File(..., description="Uploaded image file containing one or more QR symbols."),
    service: QRScannerService = Depends(get_qr_service),
) -> QRAnalysisResponse:
    """Analyze uploaded QR image for deceptive payloads, payment manipulation, and phishing links."""
    file_bytes = await file.read()
    return service.analyze_qr_image(file_bytes, filename=file.filename)
