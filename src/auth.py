"""
Authentication, Cryptography & Token Management Engine for NetGuard AI.
Part of Phase 1: Authentication & Tenancy Isolation.

Features:
- Secure password hashing using bcrypt with configurable work factor (default 12 rounds)
- Constant-time password verification
- Cryptographically secure JWT issuance & validation with standard claims (sub, exp, iat, role)
- Secure API key generation (prefixed with 'ng_live_') for background agents
"""

from datetime import datetime, timedelta, timezone
import os
import secrets
from typing import Any, Dict, Optional
import bcrypt
import jwt

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Use environment variable or a strong persistent default
JWT_SECRET_KEY = os.getenv(
    "NETGUARD_JWT_SECRET",
    "netguard-ai-soc-super-secret-cryptographic-jwt-key-2026-v1"
)
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("NETGUARD_TOKEN_EXPIRE_HOURS", "24"))
BCRYPT_ROUNDS = 12


# ==============================================================================
# PASSWORD HASHING & VERIFICATION
# ==============================================================================

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with random salt.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a bcrypt hash in constant time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


# ==============================================================================
# JWT TOKEN MANAGEMENT
# ==============================================================================

def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Creates a signed JWT access token containing subject, role, and expiration claims.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(hours=JWT_ACCESS_TOKEN_EXPIRE_HOURS)

    to_encode.update({
        "exp": expire,
        "iat": now,
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token.
    Raises jwt.ExpiredSignatureError if expired or jwt.InvalidTokenError if invalid.
    """
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    return payload


# ==============================================================================
# API KEY GENERATION
# ==============================================================================

def generate_api_key() -> str:
    """
    Generates a secure, cryptographically random API key for external agents/collectors.
    Format: ng_live_<64 hex chars>
    """
    random_hex = secrets.token_hex(32)
    return f"ng_live_{random_hex}"
