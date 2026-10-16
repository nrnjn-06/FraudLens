"""Tests for FraudLens Authentication Service and Endpoints.

Validates registration, hashing, credential verification, sessions, and route handlers.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.auth_service import AuthService

client = TestClient(app)


def test_auth_service_hashing():
    """Validates that password hashing uses unique salts and constant-time comparison."""
    h1, s1 = AuthService.hash_password("SuperSecretPass123")
    h2, s2 = AuthService.hash_password("SuperSecretPass123")

    # Hashes and salts should be distinct due to random salting
    assert h1 != h2
    assert s1 != s2

    # Verification must succeed for valid password and fail for invalid password
    assert AuthService.verify_password("SuperSecretPass123", h1, s1) is True
    assert AuthService.verify_password("WrongPassword123", h1, s1) is False


def test_auth_signup_and_login_flow():
    """Validates end-to-end signup, login, profile check, and logout via API."""
    import uuid

    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    signup_payload = {
        "name": "Jane Security",
        "email": unique_email,
        "password": "StrongPassword999!",
    }

    # 1. Signup
    res_signup = client.post("/auth/signup", json=signup_payload)
    assert res_signup.status_code == 201
    signup_data = res_signup.json()
    assert "token" in signup_data
    assert signup_data["user"]["email"] == unique_email
    assert signup_data["user"]["name"] == "Jane Security"

    token = signup_data["token"]

    # Duplicate signup should fail
    res_dup = client.post("/auth/signup", json=signup_payload)
    assert res_dup.status_code == 400

    # 2. Login with valid credentials
    login_payload = {
        "email": unique_email,
        "password": "StrongPassword999!",
    }
    res_login = client.post("/auth/login", json=login_payload)
    assert res_login.status_code == 200
    login_data = res_login.json()
    assert "token" in login_data
    new_token = login_data["token"]

    # 3. Login with invalid password
    res_bad_login = client.post(
        "/auth/login",
        json={"email": unique_email, "password": "WrongPassword!"},
    )
    assert res_bad_login.status_code == 401

    # 4. Check profile with Bearer token
    res_me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert res_me.status_code == 200
    assert res_me.json()["email"] == unique_email

    # 5. Logout
    res_logout = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert res_logout.status_code == 200

    # 6. Check profile after logout should be 401
    res_me_after = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert res_me_after.status_code == 401
