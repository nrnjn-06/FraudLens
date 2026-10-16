"""Tests for GET /health endpoint."""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_check_status_and_identity():
    """Verify that health check reports 200, FraudLens branding, and platform metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "FraudLens"
    assert data["stage"] in (1, 8)
    assert "timestamp" in data
    assert "subsystems" in data
    subsystems = data["subsystems"]
    assert "message_detector" in subsystems
    assert "url_detector" in subsystems
    assert "qr_scanner" in subsystems
    assert "threat_intel" in subsystems
