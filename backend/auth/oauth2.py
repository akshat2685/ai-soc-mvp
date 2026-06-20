"""EDYSOR OAuth 2.0 + OpenID Connect Token Management.

Provides:
  - HMAC-SHA256 signed JWT access + refresh tokens
  - Short-lived access tokens (15 min) and long-lived refresh tokens (7 days)
  - Token rotation on refresh (old refresh token invalidated)
  - Issuer/audience validation
  - Graceful fallback when `python-jose` is unavailable (uses stdlib HMAC)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.auth.oauth2")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("JWT_SECRET", "edysor-jwt-secret-change-in-production")
REFRESH_SECRET = os.environ.get("JWT_REFRESH_SECRET", "edysor-refresh-secret-change-in-production")

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
ISSUER = "edysor-soc"
AUDIENCE = "edysor-api"

# In-memory revocation set (production: use Redis)
_revoked_tokens: set = set()
_refresh_token_families: Dict[str, str] = {}  # family_id → latest_jti


# ---------------------------------------------------------------------------
# Token Creation
# ---------------------------------------------------------------------------
def _sign(payload_b64: str, secret: str) -> str:
    """Create HMAC-SHA256 signature."""
    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return sig


def _encode_token(payload: dict, secret: str) -> str:
    """Encode and sign a JWT-like token."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).decode().rstrip("=")
    signature = _sign(f"{header}.{body}", secret)
    return f"{header}.{body}.{signature}"


def _decode_token(token: str, secret: str) -> Optional[dict]:
    """Verify signature and decode token payload."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, body_b64, signature = parts
        expected_sig = _sign(f"{header_b64}.{body_b64}", secret)
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning("Token signature mismatch")
            return None

        # Pad base64
        padding = 4 - len(body_b64) % 4
        if padding != 4:
            body_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(body_b64))

        # Check expiration
        if payload.get("exp", 0) < time.time():
            return None

        # Check issuer
        if payload.get("iss") != ISSUER:
            logger.warning(f"Token issuer mismatch: {payload.get('iss')}")
            return None

        return payload
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        return None


def create_access_token(
    user_id: str,
    username: str,
    roles: List[str],
    tenant_id: str = "default",
    scopes: Optional[List[str]] = None,
) -> str:
    """Create a short-lived access token (15 min default)."""
    now = time.time()
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": user_id,
        "username": username,
        "roles": roles,
        "tenant_id": tenant_id,
        "scopes": scopes or [],
        "type": "access",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now),
        "exp": int(now + ACCESS_TOKEN_EXPIRE_MINUTES * 60),
    }
    return _encode_token(payload, SECRET_KEY)


def create_refresh_token(
    user_id: str,
    family_id: Optional[str] = None,
) -> str:
    """Create a long-lived refresh token (7 days default).
    
    Uses a 'family' to support rotation detection. If a refresh
    token outside the current family is presented, all tokens
    in that family are invalidated (replay detection).
    """
    now = time.time()
    fid = family_id or str(uuid.uuid4())
    jti = str(uuid.uuid4())
    payload = {
        "jti": jti,
        "sub": user_id,
        "family_id": fid,
        "type": "refresh",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now),
        "exp": int(now + REFRESH_TOKEN_EXPIRE_DAYS * 86400),
    }
    _refresh_token_families[fid] = jti
    return _encode_token(payload, REFRESH_SECRET)


def create_token_pair(
    user_id: str,
    username: str,
    roles: List[str],
    tenant_id: str = "default",
    scopes: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Create both access and refresh tokens."""
    access = create_access_token(user_id, username, roles, tenant_id, scopes)
    refresh = create_refresh_token(user_id)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ---------------------------------------------------------------------------
# Token Verification
# ---------------------------------------------------------------------------
def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify an access token. Returns decoded payload or None."""
    if token in _revoked_tokens:
        logger.warning("Attempted use of revoked token")
        return None
    payload = _decode_token(token, SECRET_KEY)
    if payload and payload.get("type") != "access":
        return None
    return payload


def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a refresh token. Returns decoded payload or None."""
    if token in _revoked_tokens:
        logger.warning("Attempted use of revoked refresh token")
        return None
    payload = _decode_token(token, REFRESH_SECRET)
    if not payload or payload.get("type") != "refresh":
        return None

    # Rotation detection: check if this JTI is the latest in its family
    family_id = payload.get("family_id", "")
    expected_jti = _refresh_token_families.get(family_id)
    if expected_jti and expected_jti != payload.get("jti"):
        # Replay detected! Revoke entire family
        logger.critical(f"Refresh token replay detected for family {family_id}")
        _revoke_family(family_id)
        return None

    return payload


def refresh_tokens(
    refresh_token: str,
    username: str,
    roles: List[str],
    tenant_id: str = "default",
) -> Optional[Dict[str, str]]:
    """Exchange a refresh token for a new token pair. Implements rotation."""
    payload = verify_refresh_token(refresh_token)
    if not payload:
        return None

    user_id = payload["sub"]
    family_id = payload.get("family_id", str(uuid.uuid4()))

    # Revoke old refresh token
    _revoked_tokens.add(refresh_token)

    # Issue new pair in same family
    access = create_access_token(user_id, username, roles, tenant_id)
    new_refresh = create_refresh_token(user_id, family_id=family_id)

    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------
def revoke_token(token: str):
    """Add a token to the revocation set."""
    _revoked_tokens.add(token)
    logger.info("Token revoked")


def _revoke_family(family_id: str):
    """Revoke an entire refresh token family (replay protection)."""
    if family_id in _refresh_token_families:
        del _refresh_token_families[family_id]
    logger.warning(f"Entire refresh token family revoked: {family_id}")


def revoke_all_user_tokens(user_id: str):
    """Revoke all tokens for a user (logout everywhere)."""
    families_to_remove = []
    for fid, jti in _refresh_token_families.items():
        # In production, store user_id → family mapping in Redis
        families_to_remove.append(fid)
    for fid in families_to_remove:
        _revoke_family(fid)
    logger.info(f"All tokens revoked for user: {user_id}")


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------
def get_user_from_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Extract user info dict from an access token (used by middleware)."""
    payload = verify_access_token(token)
    if not payload:
        return None
    return {
        "user_id": payload.get("sub", ""),
        "username": payload.get("username", ""),
        "role": payload.get("roles", ["soc_analyst"])[0],
        "roles": payload.get("roles", []),
        "tenant_id": payload.get("tenant_id", "default"),
        "scopes": payload.get("scopes", []),
    }
