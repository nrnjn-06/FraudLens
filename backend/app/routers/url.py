"""API endpoint for Module 2: Phishing URL Detection."""

from fastapi import APIRouter, Depends
from backend.app.schemas.url import URLAnalysisRequest, URLAnalysisResponse
from backend.app.services.url_service import URLAnalysisService, get_url_service

router = APIRouter(tags=["Phishing URL Detection"])


@router.post(
    "/analyze-url",
    response_model=URLAnalysisResponse,
    summary="Analyze URL for Phishing and Deceptive Structure (Module 2)",
    description="Inspects domain structure, typosquatting risk, lexical features, and reputation feed status.",
)
async def analyze_url_endpoint(
    request: URLAnalysisRequest,
    service: URLAnalysisService = Depends(get_url_service),
) -> URLAnalysisResponse:
    """Analyze target URL for phishing patterns, brand impersonation, and structural anomalies."""
    return service.analyze_url(request.url)
