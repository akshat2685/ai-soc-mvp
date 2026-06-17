"""Redis active defense and caching client."""
import os
import time
import redis
import logging

logger = logging.getLogger(__name__)

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

class RedisClient:
    def __init__(self):
        try:
            self.client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0
            )
            # Ping connection to check readiness
            self.client.ping()
            self.connected = True
            logger.info("Connected to Redis successfully.")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis ({REDIS_HOST}:{REDIS_PORT}): {e}. Falling back to in-memory mocks.")
            self.client = None
            self.connected = False
            # Fallback memory stores for local-only testing when Redis is off
            self._blocks = {}
            self._rate_limits = {}

    def is_blocked(self, ip_address: str, fingerprint: str = None) -> bool:
        """Check if an IP or device fingerprint is blocked."""
        if not self.connected:
            now = time.time()
            for k in [f"block:ip:{ip_address}", f"block:fp:{fingerprint}"]:
                if k in self._blocks:
                    if self._blocks[k] > now:
                        return True
                    else:
                        del self._blocks[k]
            return False

        keys = []
        if ip_address:
            keys.append(f"block:ip:{ip_address}")
        if fingerprint and fingerprint != "unknown":
            keys.append(f"block:fp:{fingerprint}")
        
        if not keys:
            return False

        try:
            existing = self.client.exists(*keys)
            return existing > 0
        except Exception as e:
            logger.error(f"Redis block check error: {e}")
            return False

    def block_target(self, target: str, expires_in_seconds: int = None, is_ip: bool = True):
        """Block an IP address or device fingerprint for a specific duration."""
        prefix = "ip" if is_ip else "fp"
        key = f"block:{prefix}:{target}"
        
        if not self.connected:
            self._blocks[key] = time.time() + (expires_in_seconds or 315360000)
            return

        try:
            if expires_in_seconds:
                self.client.setex(key, expires_in_seconds, "BLOCKED")
            else:
                self.client.set(key, "BLOCKED")
            logger.info(f"Target {target} blocked in Redis (expires: {expires_in_seconds}s).")
        except Exception as e:
            logger.error(f"Redis block write error: {e}")

    def remove_block(self, target: str, is_ip: bool = True):
        """Unblock a target IP address or fingerprint."""
        prefix = "ip" if is_ip else "fp"
        key = f"block:{prefix}:{target}"
        
        if not self.connected:
            self._blocks.pop(key, None)
            return

        try:
            self.client.delete(key)
            logger.info(f"Target {target} unblocked in Redis.")
        except Exception as e:
            logger.error(f"Redis block delete error: {e}")

    def check_rate_limit(self, client_ip: str, max_requests: int = 500, window_seconds: int = 60) -> bool:
        """Sliding-window rate limiter using Redis sorted sets."""
        if not self.connected:
            now = time.time()
            history = self._rate_limits.setdefault(client_ip, [])
            # filter old requests
            history = [t for t in history if t > now - window_seconds]
            self._rate_limits[client_ip] = history
            if len(history) >= max_requests:
                return False
            history.append(now)
            return True

        key = f"rate:{client_ip}"
        now = time.time()
        try:
            pipe = self.client.pipeline()
            # Remove requests older than the time window
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            # Count elements in the set
            pipe.zcard(key)
            # Add the current request
            pipe.zadd(key, {str(now): now})
            # Set key expiration
            pipe.expire(key, window_seconds + 10)
            _, card, _, _ = pipe.execute()
            
            return card <= max_requests
        except Exception as e:
            logger.error(f"Redis rate limiter error: {e}")
            return True  # Fallback to allow requests in case of cache issues

    def get_cache(self, key: str) -> str:
        if not self.connected:
            return None
        try:
            return self.client.get(key)
        except Exception:
            return None

    def set_cache(self, key: str, value: str, expire_seconds: int = 3600):
        if not self.connected:
            return
        try:
            self.client.setex(key, expire_seconds, value)
        except Exception:
            pass

redis_client = RedisClient()
