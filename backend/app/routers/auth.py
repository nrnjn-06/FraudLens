"""FraudLens Authentication API Router.

Endpoints for user registration, credential login, profile retrieval, and logout.
"""

from fastapi import APIRouter, HTTPException, Header, status
from typing import Optional

from backend.app.schemas.auth import (
    UserSignupRequest,
    UserLoginRequest,
    UserResponse,
    AuthResponse,
)
from backend.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def signup(payload: UserSignupRequest):
    """Registers a new user and issues a session token."""
    try:
        user_data, token = AuthService.register_user(
            name=payload.name,
            email=payload.email,
            password=payload.password,
        )
        return AuthResponse(
            user=UserResponse(**user_data),
            token=token,
            token_type="bearer",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/login", response_model=AuthResponse)
async def login(payload: UserLoginRequest):
    """Authenticates user credentials and issues a session token."""
    try:
        user_data, token = AuthService.authenticate_user(
            email=payload.email,
            password=payload.password,
        )
        return AuthResponse(
            user=UserResponse(**user_data),
            token=token,
            token_type="bearer",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Retrieves current user profile from bearer session token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    token = authorization.split("Bearer ", 1)[1].strip()
    user_data = AuthService.get_user_by_token(token)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
        )

    return UserResponse(**user_data)


@router.post("/logout")
async def logout(authorization: Optional[str] = Header(None)):
    """Revokes the current session token."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()
        AuthService.revoke_session(token)

    return {"message": "Logged out successfully."}
