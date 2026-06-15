"""Rate Limiter for /ingest endpoint protection.

Implements a sliding window rate limiter to prevent abuse of the
log ingestion endpoint itself (meta-protection for the security tool).
"""
import time
from collections import defaultdict, deque


class IngestRateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 1000, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.windows: dict[str, deque] = defaultdict(deque)
        self._global_window: deque = deque()
        self.global_max = max_requests * 10  # Global limit across all IPs

    def check(self, source_ip: str) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        now = time.time()
        cutoff = now - self.window_seconds

        # Per-IP check
        window = self.windows[source_ip]
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_requests:
            return False

        # Global check
        while self._global_window and self._global_window[0] < cutoff:
            self._global_window.popleft()

        if len(self._global_window) >= self.global_max:
            return False

        window.append(now)
        self._global_window.append(now)
        return True

    def get_remaining(self, source_ip: str) -> int:
        """Get remaining requests for an IP in the current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        window = self.windows.get(source_ip, deque())
        while window and window[0] < cutoff:
            window.popleft()
        return max(0, self.max_requests - len(window))

    def cleanup(self):
        """Remove stale IP entries to prevent memory growth."""
        now = time.time()
        cutoff = now - self.window_seconds
        stale_ips = [
            ip for ip, window in self.windows.items()
            if not window or window[-1] < cutoff
        ]
        for ip in stale_ips:
            del self.windows[ip]
