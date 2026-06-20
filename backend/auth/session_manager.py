"""EDYSOR Session Manager — Token Lifecycle & Session Tracking.

Provides:
  - Per-user session tracking with metadata (IP, user-agent, device)
  - Concurrent session limits per role
  - Session invalidation (single / all)
  - Idle timeout enforcement
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.auth.session")


@dataclass
class Session:
    session_id: str
    user_id: str
    username: str
    role: str
    tenant_id: str
    ip_address: str
    user_agent: str
    created_at: float
    last_activity: float
    access_token: str = ""
    refresh_token: str = ""
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# Max concurrent sessions per role tier
MAX_SESSIONS: Dict[str, int] = {
    "soc_analyst": 3,
    "senior_analyst": 3,
    "soc_manager": 5,
    "incident_commander": 5,
    "detection_engineer": 3,
    "threat_hunter": 3,
    "devops": 2,
    "audit": 2,
    "ciso": 5,
    "admin": 10,
    # Legacy
    "analyst": 3,
}

IDLE_TIMEOUT_SECONDS = 30 * 60  # 30 minutes


class SessionManager:
    """In-memory session store. Production: back with Redis."""

    def __init__(self):
        self._sessions: Dict[str, Session] = {}  # session_id → Session
        self._user_sessions: Dict[str, List[str]] = {}  # user_id → [session_ids]

    def create_session(
        self,
        user_id: str,
        username: str,
        role: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        access_token: str = "",
        refresh_token: str = "",
    ) -> Session:
        """Create a new session, enforcing concurrent session limits."""
        now = time.time()

        # Enforce concurrent session limits
        user_session_ids = self._user_sessions.get(user_id, [])
        active_sessions = [
            sid for sid in user_session_ids
            if sid in self._sessions and self._sessions[sid].is_active
        ]

        max_allowed = MAX_SESSIONS.get(role, 3)
        if len(active_sessions) >= max_allowed:
            # Evict oldest session
            oldest_sid = min(active_sessions, key=lambda s: self._sessions[s].last_activity)
            self.invalidate_session(oldest_sid, reason="concurrent_limit")
            logger.info(f"Evicted oldest session {oldest_sid} for user {user_id} (limit={max_allowed})")

        session = Session(
            session_id=str(uuid.uuid4()),
            user_id=user_id,
            username=username,
            role=role,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            last_activity=now,
            access_token=access_token,
            refresh_token=refresh_token,
        )

        self._sessions[session.session_id] = session
        self._user_sessions.setdefault(user_id, []).append(session.session_id)

        logger.info(f"Session created: {session.session_id} for {username} from {ip_address}")
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve a session, checking idle timeout."""
        session = self._sessions.get(session_id)
        if not session or not session.is_active:
            return None

        # Check idle timeout
        if time.time() - session.last_activity > IDLE_TIMEOUT_SECONDS:
            self.invalidate_session(session_id, reason="idle_timeout")
            return None

        return session

    def touch_session(self, session_id: str):
        """Update last activity timestamp (heartbeat)."""
        session = self._sessions.get(session_id)
        if session and session.is_active:
            session.last_activity = time.time()

    def invalidate_session(self, session_id: str, reason: str = "manual"):
        """Mark a session as inactive."""
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            session.metadata["invalidation_reason"] = reason
            session.metadata["invalidated_at"] = time.time()
            logger.info(f"Session invalidated: {session_id} reason={reason}")

    def invalidate_all_user_sessions(self, user_id: str, reason: str = "logout_all"):
        """Invalidate all sessions for a user."""
        session_ids = self._user_sessions.get(user_id, [])
        for sid in session_ids:
            self.invalidate_session(sid, reason=reason)
        logger.info(f"All sessions invalidated for user {user_id}")

    def list_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """List all active sessions for a user."""
        session_ids = self._user_sessions.get(user_id, [])
        result = []
        for sid in session_ids:
            session = self._sessions.get(sid)
            if session and session.is_active:
                # Check idle timeout
                if time.time() - session.last_activity > IDLE_TIMEOUT_SECONDS:
                    self.invalidate_session(sid, reason="idle_timeout")
                    continue
                result.append({
                    "session_id": session.session_id,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                })
        return result

    def cleanup_expired(self):
        """Purge expired sessions from memory."""
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if not s.is_active or (now - s.last_activity > IDLE_TIMEOUT_SECONDS * 2)
        ]
        for sid in expired:
            session = self._sessions.pop(sid, None)
            if session:
                user_sids = self._user_sessions.get(session.user_id, [])
                if sid in user_sids:
                    user_sids.remove(sid)
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.is_active)


# Global session manager instance
session_manager = SessionManager()
