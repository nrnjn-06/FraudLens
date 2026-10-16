"""FraudLens Authentication Pydantic Schemas.

Defines schemas for secure user signup, login, session tokens, and user profiles.
Uses standard regex for email validation without requiring external email-validator package.
"""

from pydantic import BaseModel, Field

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"


class UserSignupRequest(BaseModel):
    """Payload for registering a new user."""

    name: str = Field(..., min_length=2, max_length=100, description="User full or preferred name")
    email: str = Field(..., pattern=EMAIL_REGEX, description="Valid unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password (at least 8 characters)")


class UserLoginRequest(BaseModel):
    """Payload for logging in an existing user."""

    email: str = Field(..., pattern=EMAIL_REGEX, description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="Account password")


class UserResponse(BaseModel):
    """Public user profile data."""

    id: str
    name: str
    email: str
    created_at: str


class AuthResponse(BaseModel):
    """Response returned upon successful authentication containing user profile and session token."""

    user: UserResponse
    token: str
    token_type: str = "bearer"
