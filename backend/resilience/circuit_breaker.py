"""EDYSOR Circuit Breaker — Resilient External API Calls.

Provides:
  - Three-state circuit breaker (CLOSED → OPEN → HALF_OPEN → CLOSED)
  - Per-service circuit instances (Gemini, VirusTotal, MISP, etc.)
  - Configurable failure thresholds, recovery timeouts, and success thresholds
  - Metrics tracking (total calls, failures, state transitions)
  - Fallback function support
"""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("edysor.resilience.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"        # Normal operation — requests flow through
    OPEN = "open"            # Failing — reject requests immediately
    HALF_OPEN = "half_open"  # Testing — allow limited requests to check recovery


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is OPEN."""
    def __init__(self, service: str, state: CircuitState, retry_after: float):
        self.service = service
        self.state = state
        self.retry_after = retry_after
        super().__init__(f"Circuit breaker {state.value} for '{service}' — retry in {retry_after:.0f}s")


class CircuitBreaker:
    """Circuit breaker for external API calls with configurable thresholds."""

    def __init__(
        self,
        service_name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2,
        half_open_max_calls: int = 3,
    ):
        self.service_name = service_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout  # seconds before trying again
        self.success_threshold = success_threshold  # successes needed to close
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_calls = 0
        self.last_failure_time: Optional[float] = None
        self.last_state_change: float = time.time()

        # Metrics
        self.total_calls = 0
        self.total_failures = 0
        self.total_successes = 0
        self.total_rejected = 0
        self.state_transitions: List[Dict[str, Any]] = []

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        self.total_calls += 1

        if self.state == CircuitState.OPEN:
            elapsed = time.time() - (self.last_failure_time or 0)
            if elapsed > self.recovery_timeout:
                self._transition(CircuitState.HALF_OPEN)
            else:
                self.total_rejected += 1
                raise CircuitBreakerError(
                    self.service_name,
                    self.state,
                    self.recovery_timeout - elapsed,
                )

        if self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls >= self.half_open_max_calls:
                self.total_rejected += 1
                raise CircuitBreakerError(
                    self.service_name,
                    self.state,
                    self.recovery_timeout,
                )
            self.half_open_calls += 1

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    def call_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function synchronously with circuit breaker protection."""
        self.total_calls += 1

        if self.state == CircuitState.OPEN:
            elapsed = time.time() - (self.last_failure_time or 0)
            if elapsed > self.recovery_timeout:
                self._transition(CircuitState.HALF_OPEN)
            else:
                self.total_rejected += 1
                raise CircuitBreakerError(
                    self.service_name,
                    self.state,
                    self.recovery_timeout - elapsed,
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    async def call_with_fallback(
        self,
        func: Callable,
        fallback: Callable,
        *args,
        **kwargs,
    ) -> Any:
        """Try primary function, fall back if circuit is open or call fails."""
        try:
            return await self.call(func, *args, **kwargs)
        except (CircuitBreakerError, Exception) as e:
            logger.warning(
                f"Circuit breaker fallback for {self.service_name}: {e}"
            )
            if asyncio.iscoroutinefunction(fallback):
                return await fallback(*args, **kwargs)
            return fallback(*args, **kwargs)

    def _on_success(self):
        self.total_successes += 1
        self.failure_count = 0

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self._transition(CircuitState.CLOSED)
                logger.info(f"Circuit CLOSED for {self.service_name} — service recovered")

    def _on_failure(self, error: Exception):
        self.total_failures += 1
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN)
            logger.warning(f"Circuit re-OPENED for {self.service_name} — recovery failed: {error}")
        elif self.failure_count >= self.failure_threshold:
            self._transition(CircuitState.OPEN)
            logger.error(
                f"Circuit OPENED for {self.service_name} — "
                f"{self.failure_count} consecutive failures: {error}"
            )

    def _transition(self, new_state: CircuitState):
        old_state = self.state
        self.state = new_state
        self.last_state_change = time.time()

        if new_state == CircuitState.HALF_OPEN:
            self.half_open_calls = 0
            self.success_count = 0

        if new_state == CircuitState.CLOSED:
            self.failure_count = 0
            self.success_count = 0

        self.state_transitions.append({
            "from": old_state.value,
            "to": new_state.value,
            "timestamp": time.time(),
            "failure_count": self.failure_count,
        })

    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        return {
            "service": self.service_name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "total_calls": self.total_calls,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "total_rejected": self.total_rejected,
            "last_failure_time": self.last_failure_time,
            "last_state_change": self.last_state_change,
            "transitions": len(self.state_transitions),
        }

    def reset(self):
        """Manually reset the circuit breaker to CLOSED state."""
        self._transition(CircuitState.CLOSED)
        logger.info(f"Circuit breaker manually reset for {self.service_name}")


# ---------------------------------------------------------------------------
# Circuit Breaker Registry
# ---------------------------------------------------------------------------
class CircuitBreakerRegistry:
    """Manages circuit breakers for multiple external services."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        service_name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2,
    ) -> CircuitBreaker:
        """Get existing or create new circuit breaker for a service."""
        if service_name not in self._breakers:
            self._breakers[service_name] = CircuitBreaker(
                service_name=service_name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
                success_threshold=success_threshold,
            )
        return self._breakers[service_name]

    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get metrics for all circuit breakers."""
        return [cb.get_metrics() for cb in self._breakers.values()]

    def reset_all(self):
        """Reset all circuit breakers."""
        for cb in self._breakers.values():
            cb.reset()


# Global registry
circuit_registry = CircuitBreakerRegistry()

# Pre-configured circuit breakers for known services
gemini_breaker = circuit_registry.get_or_create("gemini_api", failure_threshold=5, recovery_timeout=60)
virustotal_breaker = circuit_registry.get_or_create("virustotal", failure_threshold=3, recovery_timeout=120)
misp_breaker = circuit_registry.get_or_create("misp", failure_threshold=3, recovery_timeout=120)
abuseipdb_breaker = circuit_registry.get_or_create("abuseipdb", failure_threshold=3, recovery_timeout=120)
neo4j_breaker = circuit_registry.get_or_create("neo4j", failure_threshold=5, recovery_timeout=30)
