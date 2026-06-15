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

# Simple JWT-like token using HMAC (for MVP; use PyJWT in production)
SECRET_KEY = os.environ.get("JWT_SECRET", "shieldai-soc-secret-change-me")
TOKEN_EXPIRY_HOURS = 24

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
    """Hash a password with SHA-256 (use bcrypt in production)."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return hash_password(password) == password_hash


def create_token(username: str, role: str) -> str:
    """Create a simple JWT-like token."""
    payload = {
        "username": username,
        "role": role,
        "exp": int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600),
        "iat": int(time.time()),
    }
    payload_str = json.dumps(payload)
    import base64
    token_data = base64.b64encode(payload_str.encode()).decode()
    signature = hashlib.sha256(f"{token_data}{SECRET_KEY}".encode()).hexdigest()[:16]
    return f"{token_data}.{signature}"


def verify_token(token: str) -> dict:
    """Verify and decode a token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        token_data, signature = parts
        expected_sig = hashlib.sha256(f"{token_data}{SECRET_KEY}".encode()).hexdigest()[:16]
        if signature != expected_sig:
            return None
        import base64
        payload = json.loads(base64.b64decode(token_data))
        if payload.get("exp", 0) < time.time():
            return None  # Expired
        return payload
    except Exception:
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
        if not verify_password(password, user['password_hash']):
            return None

        # Update last login
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?",
            (user['id'],)
        )
        conn.commit()

    token = create_token(username, user['role'])
    return {
        "token": token,
        "username": username,
        "role": user['role'],
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
    return {"username": payload["username"], "role": payload["role"]}
