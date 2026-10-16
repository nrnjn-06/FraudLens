"""FraudLens API Gateway and Application Bootstrap.

Unified ML-Based Fraud Detection Platform.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from backend.app.config import settings
from backend.app.routers.health import router as health_router
from backend.app.routers.message import router as message_router
from backend.app.routers.qr import router as qr_router
from backend.app.routers.url import router as url_router
from backend.app.routers.auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for resource initialization and teardown."""
    print("\n" + "=" * 68)
    print(f"  [*] {settings.APP_NAME} - Unified Digital Fraud Detection Platform")
    print("=" * 68)
    print("  Direct Access Links (Ctrl + Click to Open):")
    print(f"  -> Frontend Web Dashboard: http://localhost:5173")
    print(f"  -> Backend API Gateway:    http://{settings.API_HOST}:{settings.API_PORT}/")
    print(f"  -> Interactive API Docs:   http://{settings.API_HOST}:{settings.API_PORT}/docs")
    print(f"  -> System Health Check:    http://{settings.API_HOST}:{settings.API_PORT}/health")
    print("=" * 68)
    print("  To launch the Frontend Dashboard, run in another terminal:")
    print("  npm --prefix frontend run dev")
    print("=" * 68 + "\n")
    yield
    print(f"\n[{settings.APP_NAME}] Shutdown complete.")


app = FastAPI(
    title="FraudLens — Unified ML-Based Fraud Detection Platform",
    description=(
        "Unified digital fraud defense platform integrating Scam Message NLP, "
        "Phishing URL Random Forest classification, and QR Code Safety Inspection "
        "under a consistent four-level risk taxonomy."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for local Vite development frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Subsystem Routers
app.include_router(health_router)
app.include_router(message_router)
app.include_router(url_router)
app.include_router(qr_router)
app.include_router(auth_router)


@app.get("/", tags=["Root"])
async def root_endpoint(request: Request):
    """Root redirect, interactive HTML landing gateway, and JSON metadata."""
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header and "application/json" not in accept_header:
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FraudLens — Unified Fraud Detection Gateway</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #020617; color: #f8fafc; margin: 0; padding: 40px 20px; }}
    .card {{ max-width: 680px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    h1 {{ color: #38bdf8; margin-top: 0; font-size: 26px; }}
    p {{ color: #94a3b8; font-size: 14px; line-height: 1.6; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold; background: #064e3b; color: #34d399; margin-bottom: 16px; border: 1px solid #059669; }}
    .links {{ display: flex; flex-direction: column; gap: 12px; margin-top: 24px; }}
    .btn {{ display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 600; border: 1px solid #334155; transition: all 0.2s; }}
    .btn-primary {{ background: #0284c7; color: #ffffff; border-color: #0ea5e9; }}
    .btn-primary:hover {{ background: #0369a1; }}
    .btn-secondary {{ background: #1e293b; color: #38bdf8; }}
    .btn-secondary:hover {{ background: #334155; color: #ffffff; }}
    .hint {{ font-size: 12px; color: #64748b; margin-top: 20px; font-family: monospace; background: #020617; padding: 10px; border-radius: 6px; border: 1px solid #1e293b; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Operational &amp; Verified</span>
    <h1>FraudLens API Gateway</h1>
    <p>Unified Machine Learning Fraud Detection Platform integrating Scam Message NLP, Phishing URL Random Forest Classification, and Optical QR Safety Inspection.</p>
    <div class="links">
      <a class="btn btn-primary" href="http://localhost:5173" target="_blank">
        <span>🌐 Open Frontend Web Dashboard</span>
        <span>http://localhost:5173 &rarr;</span>
      </a>
      <a class="btn btn-secondary" href="/docs">
        <span>📖 Open Interactive Swagger API Docs</span>
        <span>/docs &rarr;</span>
      </a>
      <a class="btn btn-secondary" href="/health">
        <span>🩺 Check Subsystems Health Telemetry</span>
        <span>/health &rarr;</span>
      </a>
    </div>
    <div class="hint">
      To run the Frontend Dashboard, execute in another terminal:<br>
      <code>npm --prefix frontend run dev</code>
    </div>
  </div>
</body>
</html>"""
        return HTMLResponse(content=html_content)

    return {
        "app_name": settings.APP_NAME,
        "description": "FraudLens Unified ML-Based Fraud Detection API",
        "stage": settings.CURRENT_STAGE,
        "docs_url": "/docs",
        "health_url": "/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )
