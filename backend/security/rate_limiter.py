"""EDYSOR Role-Aware Distributed Rate Limiter.

Provides:
  - Endpoint-specific rate limits with configurable windows
  - Role-based limit multipliers (CISO gets 3x, analyst gets 1x)
  - In-memory sliding window (production: Redis backend)
  - Response headers with remaining/reset info
  - Global burst protection
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("edysor.security.rate_limiter")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class RateLimitConfig:
    """Rate limiting tiers for different endpoints."""

    # Endpoint → "requests/window"
    ENDPOINT_LIMITS: Dict[str, str] = {
        # High-volume
        "/api/alerts": "200/minute",
        "/api/alerts/ingest": "100/minute",
        "/api/v1/alerts": "200/minute",
        # Moderate
        "/api/incidents": "60/minute",
        "/api/copilot": "30/minute",
        "/api/v1/copilot": "30/minute",
        # Dangerous operations
        "/api/playbooks/execute": "10/minute",
        "/api/v1/soar/playbooks/trigger": "10/minute",
        "/api/v1/purple-team/run": "5/minute",
        "/api/v1/training/run": "3/minute",
        # Admin
        "/api/settings": "10/minute",
        "/api/users": "20/minute",
        # Auth
        "/api/auth/login": "5/minute",
        "/api/auth/register": "3/minute",
        "/api/auth/refresh": "60/minute",
    }

    # Role multipliers
    ROLE_MULTIPLIERS: Dict[str, float] = {
        "soc_analyst": 1.0,
        "senior_analyst": 1.2,
        "soc_manager": 1.5,
        "incident_commander": 1.5,
        "detection_engineer": 1.2,
        "threat_hunter": 1.2,
        "devops": 2.0,
        "audit": 1.0,
        "ciso": 3.0,
        "admin": 3.0,
        # Legacy
        "analyst": 1.0,
    }

    # Global burst limit (across all users/endpoints)
    GLOBAL_BURST_LIMIT = 5000
    GLOBAL_BURST_WINDOW = 60  # seconds

    # Default for unlisted endpoints
    DEFAULT_LIMIT = "120/minute"


def _parse_limit(limit_str: str) -> Tuple[int, int]:
    """Parse '100/minute' → (100, 60)."""
    parts = limit_str.split("/")
    count = int(parts[0])
    window_map = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    window = window_map.get(parts[1], 60)
    return count, window


class RoleAwareRateLimiter:
    """Distributed rate limiter with role-based multipliers."""

    def __init__(self):
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._global_window: deque = deque()
        self._blocked_until: Dict[str, float] = {}

    def check(
        self,
        user_id: str,
        role: str,
        endpoint: str,
        ip_address: str = "",
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is allowed.
        
        Returns (is_allowed, headers_dict) where headers_dict contains
        X-RateLimit-* headers to include in the response.
        """
        now = time.time()

        # Check if user is temporarily blocked
        blocked_until = self._blocked_until.get(user_id, 0)
        if now < blocked_until:
            return False, {
                "X-RateLimit-Limit": "0",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(blocked_until)),
                "Retry-After": str(int(blocked_until - now)),
            }

        # Find matching endpoint limit
        limit_str = RateLimitConfig.DEFAULT_LIMIT
        for path, lim in RateLimitConfig.ENDPOINT_LIMITS.items():
            if endpoint.startswith(path):
                limit_str = lim
                break

        base_count, window_seconds = _parse_limit(limit_str)

        # Apply role multiplier
        multiplier = RateLimitConfig.ROLE_MULTIPLIERS.get(role, 1.0)
        adjusted_limit = int(base_count * multiplier)

        # --- Per-user/endpoint check ---
        key = f"{user_id}:{endpoint}"
        user_window = self._windows[key]
        cutoff = now - window_seconds

        # Clean expired entries
        while user_window and user_window[0] < cutoff:
            user_window.popleft()

        # --- Global burst check ---
        global_cutoff = now - RateLimitConfig.GLOBAL_BURST_WINDOW
        while self._global_window and self._global_window[0] < global_cutoff:
            self._global_window.popleft()

        if len(self._global_window) >= RateLimitConfig.GLOBAL_BURST_LIMIT:
            logger.warning(f"Global burst limit reached ({len(self._global_window)} requests)")
            return False, {
                "X-RateLimit-Limit": str(adjusted_limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now + window_seconds)),
                "Retry-After": str(window_seconds),
            }

        remaining = max(0, adjusted_limit - len(user_window))

        if len(user_window) >= adjusted_limit:
            logger.info(
                f"Rate limit exceeded: user={user_id} endpoint={endpoint} "
                f"limit={adjusted_limit}/{window_seconds}s"
            )
            return False, {
                "X-RateLimit-Limit": str(adjusted_limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now + window_seconds)),
                "Retry-After": str(window_seconds),
            }

        # Allow request
        user_window.append(now)
        self._global_window.append(now)

        return True, {
            "X-RateLimit-Limit": str(adjusted_limit),
            "X-RateLimit-Remaining": str(remaining - 1),
            "X-RateLimit-Reset": str(int(now + window_seconds)),
        }

    def block_user(self, user_id: str, duration_seconds: int = 300):
        """Temporarily block a user (e.g., after brute-force detection)."""
        self._blocked_until[user_id] = time.time() + duration_seconds
        logger.warning(f"User {user_id} blocked for {duration_seconds}s")

    def unblock_user(self, user_id: str):
        """Remove temporary block for a user."""
        self._blocked_until.pop(user_id, None)

    def get_usage(self, user_id: str, endpoint: str) -> Dict[str, Any]:
        """Get current usage stats for a user/endpoint."""
        key = f"{user_id}:{endpoint}"
        window = self._windows.get(key, deque())
        return {
            "current_requests": len(window),
            "is_blocked": time.time() < self._blocked_until.get(user_id, 0),
        }

    def cleanup(self):
        """Purge stale entries to prevent memory growth."""
        now = time.time()
        stale = [
            k for k, w in self._windows.items()
            if not w or w[-1] < now - 3600
        ]
        for k in stale:
            del self._windows[k]

        expired_blocks = [
            uid for uid, until in self._blocked_until.items()
            if now >= until
        ]
        for uid in expired_blocks:
            del self._blocked_until[uid]


# Global rate limiter instance
rate_limiter = RoleAwareRateLimiter()
