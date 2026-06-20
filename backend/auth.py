"""JWT-based Authentication & Role-Based Access Control.

Roles:
- analyst: read alerts, logs, set verdicts, use chat
- senior_analyst: analyst + approve actions, send emails
- admin: senior_analyst + manage users, configure rules
"""
import os
import hashlib
import json
import time
from datetime import datetime, timedelta
from database import get_db

# Industry standard JWT and Password Hashing (Phase 1 Hardening)
from jose import jwt, JWTError
from passlib.context import CryptContext

SECRET_KEY = os.environ.get("JWT_SECRET", "shieldai-soc-secret-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_PERMISSIONS = {
    "analyst": [
        "read_alerts", "read_logs", "read_incidents", "read_responses",
        "read_stats", "set_verdict", "use_chat", "read_audit",
        "read_approvals", "read_email_drafts",
    ],
    "senior_analyst": [
        "read_alerts", "read_logs", "read_incidents", "read_responses",
        "read_stats", "set_verdict", "use_chat", "read_audit",
        "read_approvals", "read_email_drafts",
        "approve_actions", "reject_actions", "send_emails", "manage_blocks",
    ],
    "admin": [
        "read_alerts", "read_logs", "read_incidents", "read_responses",
        "read_stats", "set_verdict", "use_chat", "read_audit",
        "read_approvals", "read_email_drafts",
        "approve_actions", "reject_actions", "send_emails", "manage_blocks",
        "manage_users", "configure_rules", "generate_reports",
    ],
}


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return pwd_context.verify(password, password_hash)


def create_token(username: str, role: str, tenant_id: str = "default") -> str:
    """Create a secure JWT token."""
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    to_encode = {
        "sub": username,
        "role": role,
        "tenant_id": tenant_id,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def authenticate(username: str, password: str) -> dict:
    """Authenticate a user and return a token."""
    with get_db() as conn:
        cur = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        )
        user = cur.fetchone()
        if not user:
            return None

        user = dict(user)
        # Note: If migrating from old SHA256 hashes, you'd need logic to re-hash.
        # Since we are going to clear the DB, we just rely on bcrypt.
        try:
            if not verify_password(password, user['password_hash']):
                return None
        except Exception:
            # Fallback if old hash exists
            if user['password_hash'] != hashlib.sha256(password.encode()).hexdigest():
                return None

        # Update last login
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?",
            (user['id'],)
        )
        conn.commit()

    token = create_token(username, user['role'], user.get('tenant_id', 'default'))
    return {
        "token": token,
        "username": username,
        "role": user['role'],
        "tenant_id": user.get('tenant_id', 'default'),
    }


def register_user(username: str, password: str, role: str = "analyst") -> dict:
    """Register a new user (admin only)."""
    if role not in ROLE_PERMISSIONS:
        return {"error": f"Invalid role. Must be one of: {list(ROLE_PERMISSIONS.keys())}"}

    pw_hash = hash_password(password)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, pw_hash, role)
            )
            conn.commit()
        return {"status": "ok", "username": username, "role": role}
    except Exception as e:
        return {"error": str(e)}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, [])
    return permission in perms


def get_user_from_token(token: str) -> dict:
    """Extract user info from token."""
    payload = verify_token(token)
    if not payload:
        return None
    return {
        "username": payload.get("sub"), 
        "role": payload.get("role"),
        "tenant_id": payload.get("tenant_id", "default")
    }
