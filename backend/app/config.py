"""FraudLens Application Configuration.

Loads environment variables with fallback defaults. Does not expose secrets.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """FraudLens runtime configuration settings."""

    APP_NAME: str = "FraudLens"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    # System Release Milestone Flag
    CURRENT_STAGE: int = 8

    # Optional Threat Intelligence API keys & Caching (Never committed, defaulted to None)
    THREAT_INTEL_ENABLED: bool = False
    THREAT_INTEL_VIRUSTOTAL_API_KEY: Optional[str] = None
    THREAT_INTEL_URLSCAN_API_KEY: Optional[str] = None
    THREAT_INTEL_TIMEOUT_SECONDS: float = 5.0
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 3600
    THREAT_INTEL_MAX_CACHE_ENTRIES: int = 1000

    # Domain Intelligence Settings (WHOIS/RDAP, Domain Age, TLS)
    DOMAIN_INTEL_ENABLED: bool = True
    DOMAIN_INTEL_TIMEOUT_SECONDS: float = 3.0
    DOMAIN_INTEL_CACHE_TTL_SECONDS: int = 86400  # 24 hours
    DOMAIN_INTEL_MAX_CACHE_ENTRIES: int = 2000
    DOMAIN_INTEL_RDAP_BASE_URL: str = "https://rdap.org/domain"

    # Max Upload Size and Dimensions (for QR image analysis)
    MAX_IMAGE_UPLOAD_BYTES: int = 5 * 1024 * 1024
    MAX_IMAGE_DIMENSION: int = 4096
    ENABLE_MULTI_QR: bool = True

    # ML Model Artifact Paths
    MESSAGE_MODEL_PATH: str = "backend/models/message_model.joblib"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
