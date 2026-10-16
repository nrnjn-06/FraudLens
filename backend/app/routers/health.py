"""Health check endpoint for FraudLens system monitoring."""

from datetime import datetime, timezone
from typing import Dict
from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.services.message_model_loader import get_message_model_loader

router = APIRouter(tags=["Health"])


class HealthCheckResponse(BaseModel):
    """Health check payload detailing platform identity and subsystem state."""

    status: str = Field(default="healthy", description="General system operational status.")
    app_name: str = Field(default="FraudLens", description="Application branding identifier.")
    stage: int = Field(default=8, description="API version or pipeline release milestone.")
    environment: str = Field(default="development", description="Deployment environment.")
    version: str = Field(default="0.1.0", description="SemVer release string.")
    timestamp: str = Field(..., description="ISO 8601 heartbeat timestamp.")
    subsystems: Dict[str, str] = Field(
        ...,
        description="Readiness status of the three fraud detection modules and intelligence services.",
    )


@router.get("/health", response_model=HealthCheckResponse, summary="System Health & Subsystem Readiness")
async def get_health() -> HealthCheckResponse:
    """Check API heartbeat and operational readiness of detection modules."""
    model_loader = get_message_model_loader()
    msg_status = (
        "ACTIVE (TF-IDF + Logistic Regression Model v1.0.0)"
        if model_loader.is_available
        else "MODEL_UNAVAILABLE"
    )

    from backend.app.services.url_model_loader import get_url_model_loader
    url_loader = get_url_model_loader()
    url_status = (
        "ACTIVE (RandomForest Phishing Classifier v1.0.0)"
        if url_loader.is_available
        else "MODEL_UNAVAILABLE"
    )

    return HealthCheckResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        stage=settings.CURRENT_STAGE,
        environment=settings.APP_ENV,
        version=settings.APP_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        subsystems={
            "message_detector": msg_status,
            "url_detector": url_status,
            "qr_scanner": "ACTIVE (OpenCV + Pyzbar Dual CV Scanner & UPI Engine)",
            "threat_intel": (
                "ACTIVE (VirusTotal & URLScan Adapters with TTL Cache)"
                if settings.THREAT_INTEL_ENABLED
                else "INTEGRATED (Local-only mode, unconfigured adapters)"
            ),
        },
    )
