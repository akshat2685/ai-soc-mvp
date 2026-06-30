import time
import logging
from typing import Optional
from redis import Redis
from fastapi import Response

logger = logging.getLogger(__name__)

class TokenBucketRateLimiter:
    """
    Token Bucket algorithm for rate limiting.
    Allows burst traffic while enforcing sustained rate limit.
    """
    
    def __init__(
        self,
        redis: Redis,
        capacity: int,
        refill_rate: float,
        key_prefix: str = "ratelimit"
    ):
        self.redis = redis
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.key_prefix = key_prefix
    
    async def is_allowed(self, key: str, cost: int = 1) -> bool:
        bucket_key = f"{self.key_prefix}:{key}"
        now = time.time()
        
        try:
            data = self.redis.hgetall(bucket_key)
        except Exception as e:
            logger.error(f"Redis error in rate limiter: {e}")
            return True # Fail open
            
        if not data:
            self.redis.hset(bucket_key, mapping={
                "tokens": float(self.capacity - cost),
                "last_refill": float(now)
            })
            self.redis.expire(bucket_key, 3600)
            return True
            
        try:
            # Handle both string keys (decode_responses=True) and byte keys
            last_refill_val = data.get("last_refill") or data.get(b"last_refill")
            tokens_val = data.get("tokens") or data.get(b"tokens")
            last_refill = float(last_refill_val) if last_refill_val is not None else now
            tokens = float(tokens_val) if tokens_val is not None else self.capacity
        except (ValueError, TypeError):
            self.redis.delete(bucket_key)
            return True
            
        time_passed = max(0.0, now - last_refill)
        tokens_gained = time_passed * self.refill_rate
        tokens = min(float(self.capacity), tokens + tokens_gained)
        
        if tokens >= cost:
            tokens -= cost
            self.redis.hset(bucket_key, mapping={
                "tokens": float(tokens),
                "last_refill": float(now)
            })
            return True
        else:
            return False

class RateLimitMiddleware:
    """FastAPI middleware for rate limiting"""
    def __init__(
        self,
        app,
        redis: Redis,
        capacity: int = 100,
        refill_rate: float = 10.0,
        exempt_paths: Optional[list] = None
    ):
        self.app = app
        self.limiter = TokenBucketRateLimiter(redis=redis, capacity=capacity, refill_rate=refill_rate)
        self.exempt_paths = exempt_paths or ["/health", "/readiness", "/docs", "/openapi.json"]
        
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
            
        path = scope["path"]
        if any(path.startswith(p) for p in self.exempt_paths):
            return await self.app(scope, receive, send)
            
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        
        if not await self.limiter.is_allowed(client_ip):
            response = Response(
                content="Rate limit exceeded",
                status_code=429,
                headers={
                    "Retry-After": "1",
                    "X-RateLimit-Limit": str(self.limiter.capacity),
                    "X-RateLimit-Remaining": "0"
                }
            )
            await response(scope, receive, send)
            return
            
        # Standard flow; not modifying headers here to avoid breaking ASGI protocol complexities directly in raw middleware,
        # usually it's better done in a BaseHTTPMiddleware, but keeping it raw ASGI for performance.
        await self.app(scope, receive, send)
