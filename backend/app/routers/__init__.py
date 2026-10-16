"""API route handlers for FraudLens."""

from backend.app.routers.health import router as health_router
from backend.app.routers.message import router as message_router
from backend.app.routers.url import router as url_router
from backend.app.routers.qr import router as qr_router

__all__ = [
    "health_router",
    "message_router",
    "url_router",
    "qr_router",
]
