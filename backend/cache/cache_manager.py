"""EDYSOR Multi-Level Cache Manager — Distributed Caching with Redis.

Provides:
  - L1 in-memory cache (fastest, per-process)
  - L2 Redis cache (shared, medium speed)
  - Configurable TTLs per cache level
  - Pattern-based invalidation
  - @cached decorator for transparent caching
  - Cache hit/miss metrics
"""
from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from functools import wraps
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("edysor.cache")


class LRUCache:
    """Simple LRU cache for L1 in-memory layer."""

    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._expiry: Dict[str, float] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value, returning None if expired or missing."""
        if key not in self._cache:
            return None
        # Check TTL
        expiry = self._expiry.get(key, float('inf'))
        if time.time() > expiry:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)
            return None
        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return self._cache[key]

    def set(self, key: str, value: Any, ttl: int = 60):
        """Set value with TTL in seconds."""
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        self._expiry[key] = time.time() + ttl
        # Evict oldest if over capacity
        while len(self._cache) > self._max_size:
            oldest_key, _ = self._cache.popitem(last=False)
            self._expiry.pop(oldest_key, None)

    def delete(self, key: str):
        self._cache.pop(key, None)
        self._expiry.pop(key, None)

    def invalidate_pattern(self, pattern: str):
        """Invalidate keys matching a simple prefix pattern."""
        keys_to_delete = [k for k in self._cache if k.startswith(pattern.rstrip("*"))]
        for k in keys_to_delete:
            self.delete(k)

    def clear(self):
        self._cache.clear()
        self._expiry.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


class CacheManager:
    """Multi-level caching system with optional Redis L2."""

    # Default TTLs per level
    L1_TTL = 60       # 1 minute — local memory
    L2_TTL = 300      # 5 minutes — Redis
    L3_TTL = 3600     # 1 hour — long-term

    def __init__(self, redis_client=None, l1_max_size: int = 2000):
        self._l1 = LRUCache(max_size=l1_max_size)
        self._redis = redis_client  # Optional redis.Redis instance

        # Metrics
        self.hits = 0
        self.misses = 0
        self.l1_hits = 0
        self.l2_hits = 0

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache, checking L1 then L2."""
        # L1 check
        value = self._l1.get(key)
        if value is not None:
            self.hits += 1
            self.l1_hits += 1
            return value

        # L2 check (Redis)
        if self._redis:
            try:
                data = self._redis.get(key) if hasattr(self._redis, 'get') else None
                if data:
                    value = json.loads(data)
                    # Promote to L1
                    self._l1.set(key, value, ttl=self.L1_TTL)
                    self.hits += 1
                    self.l2_hits += 1
                    return value
            except Exception as e:
                logger.warning(f"Redis cache read error: {e}")

        self.misses += 1
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache (both L1 and L2)."""
        l1_ttl = min(ttl or self.L1_TTL, self.L1_TTL)
        l2_ttl = ttl or self.L2_TTL

        # L1
        self._l1.set(key, value, ttl=l1_ttl)

        # L2 (Redis)
        if self._redis:
            try:
                serialized = json.dumps(value, default=str)
                self._redis.setex(key, l2_ttl, serialized)
            except Exception as e:
                logger.warning(f"Redis cache write error: {e}")

    async def invalidate(self, pattern: str):
        """Invalidate cache entries matching pattern."""
        # L1
        self._l1.invalidate_pattern(pattern)

        # L2 (Redis)
        if self._redis:
            try:
                keys = self._redis.keys(pattern)
                if keys:
                    self._redis.delete(*keys)
            except Exception as e:
                logger.warning(f"Redis cache invalidation error: {e}")

    async def delete(self, key: str):
        """Delete a specific cache key from all levels."""
        self._l1.delete(key)
        if self._redis:
            try:
                self._redis.delete(key)
            except Exception:
                pass

    def get_sync(self, key: str) -> Optional[Any]:
        """Synchronous L1-only get (for non-async contexts)."""
        value = self._l1.get(key)
        if value is not None:
            self.hits += 1
            self.l1_hits += 1
        else:
            self.misses += 1
        return value

    def set_sync(self, key: str, value: Any, ttl: int = 60):
        """Synchronous L1-only set."""
        self._l1.set(key, value, ttl=ttl)

    def get_metrics(self) -> Dict[str, Any]:
        """Return cache performance metrics."""
        total = self.hits + self.misses
        return {
            "total_requests": total,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 4) if total > 0 else 0,
            "l1_hits": self.l1_hits,
            "l2_hits": self.l2_hits,
            "l1_size": self._l1.size,
        }

    def clear_all(self):
        """Clear all cache levels."""
        self._l1.clear()
        if self._redis:
            try:
                self._redis.flushdb()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------
# Global cache instance (initialized without Redis — will use L1 only)
cache_manager = CacheManager()


def cached(ttl: int = 300, key_prefix: str = ""):
    """Decorator for transparent function-level caching.
    
    Usage:
        @cached(ttl=600)
        async def get_incident(incident_id: str):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            prefix = key_prefix or func.__name__
            cache_key = f"{prefix}:{str(args)}:{str(sorted(kwargs.items()))}"

            # Try cache
            result = await cache_manager.get(cache_key)
            if result is not None:
                return result

            # Execute function
            result = await func(*args, **kwargs)

            # Store in cache
            if result is not None:
                await cache_manager.set(cache_key, result, ttl=ttl)

            return result
        return wrapper
    return decorator
