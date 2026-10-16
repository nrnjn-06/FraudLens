"""FraudLens Secure Authentication Service.

Implements server-side credential validation, PBKDF2-HMAC password hashing with random salt,
constant-time verification, SQLite persistence, and session token lifecycle management.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, Any


_proj_root = Path(__file__).resolve().parent.parent.parent.parent
DB_PATH = os.environ.get("FRAUDLENS_AUTH_DB", str(_proj_root / "data" / "fraudlens_auth.db"))
PBKDF2_ITERATIONS = 100_000
SESSION_EXPIRY_DAYS = 7


def _get_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database and ensures tables exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    """Initializes users and sessions tables with appropriate constraints."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


# Ensure tables are initialized at module import
_init_db()


class AuthService:
    """Service providing secure authentication, hashing, and session management."""

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Hashes password with PBKDF2-HMAC-SHA256 and a random 16-byte salt."""
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        return pwd_hash.hex(), salt.hex()

    @staticmethod
    def verify_password(password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
        """Verifies candidate password against stored hash using constant-time comparison."""
        try:
            salt = bytes.fromhex(stored_salt_hex)
            expected_hash = bytes.fromhex(stored_hash_hex)
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                PBKDF2_ITERATIONS,
            )
            return hmac.compare_digest(computed_hash, expected_hash)
        except Exception:
            return False

    @classmethod
    def register_user(cls, name: str, email: str, password: str) -> Tuple[Dict[str, Any], str]:
        """Registers a new user and generates an initial session token.
        
        Raises ValueError if email is already taken or inputs are invalid.
        """
        clean_name = name.strip()
        clean_email = email.strip().lower()

        if len(clean_name) < 2:
            raise ValueError("Name must be at least 2 characters long.")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")

        pwd_hash, pwd_salt = cls.hash_password(password)
        user_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (clean_email,))
            if cursor.fetchone() is not None:
                raise ValueError("An account with this email address already exists.")

            cursor.execute(
                """
                INSERT INTO users (id, name, email, password_hash, password_salt, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, clean_name, clean_email, pwd_hash, pwd_salt, now_iso),
            )
            conn.commit()

        user_data = {
            "id": user_id,
            "name": clean_name,
            "email": clean_email,
            "created_at": now_iso,
        }
        token = cls.create_session(user_id)
        return user_data, token

    @classmethod
    def authenticate_user(cls, email: str, password: str) -> Tuple[Dict[str, Any], str]:
        """Authenticates user with email and password.
        
        Raises ValueError on invalid credentials.
        """
        clean_email = email.strip().lower()

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, email, password_hash, password_salt, created_at FROM users WHERE email = ?",
                (clean_email,),
            )
            row = cursor.fetchone()

        if row is None:
            raise ValueError("Invalid email or password.")

        if not cls.verify_password(password, row["password_hash"], row["password_salt"]):
            raise ValueError("Invalid email or password.")

        user_data = {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "created_at": row["created_at"],
        }
        token = cls.create_session(row["id"])
        return user_data, token

    @staticmethod
    def create_session(user_id: str) -> str:
        """Creates a cryptographically secure session token valid for 7 days."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=SESSION_EXPIRY_DAYS)

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions (token, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token, user_id, now.isoformat(), expires_at.isoformat()),
            )
            conn.commit()

        return token

    @staticmethod
    def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
        """Retrieves user profile for a valid, non-expired session token."""
        if not token:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.name, u.email, u.created_at, s.expires_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ? AND s.expires_at > ?
                """,
                (token, now_iso),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def revoke_session(token: str) -> bool:
        """Revokes a session token (logout)."""
        if not token:
            return False

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return cursor.rowcount > 0
