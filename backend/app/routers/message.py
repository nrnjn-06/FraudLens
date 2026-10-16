"""API endpoint for Module 1: Scam Message Detection."""

from fastapi import APIRouter, Depends
from backend.app.schemas.message import MessageAnalysisRequest, MessageAnalysisResponse
from backend.app.services.message_service import MessageAnalysisService, get_message_service

router = APIRouter(tags=["Scam Message Detection"])


@router.post(
    "/analyze-message",
    response_model=MessageAnalysisResponse,
    summary="Analyze Message for Scam Patterns (Module 1)",
    description="Submits SMS, email, or chat text to detect social engineering signals, extract embedded entities, and route URLs.",
)
async def analyze_message_endpoint(
    request: MessageAnalysisRequest,
    service: MessageAnalysisService = Depends(get_message_service),
) -> MessageAnalysisResponse:
    """Analyze raw message text for scam patterns, entities, and embedded URLs."""
    return service.analyze_message(request.message_text)
