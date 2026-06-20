"""OpenTelemetry configuration module for distributed tracing and Prometheus metrics.

Tracks:
- Tracing spans targeting Jaeger OTLP endpoint
- Metrics (latency, token usage, cost, error rates, hallucination scores, memory usage) via prometheus_client
"""
from __future__ import annotations

import os
import logging
import time
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger(__name__)

# OTLP config
OTEL_EXPORTER_OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

# --- Tracing Setup ---
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False
    logger.warning("OpenTelemetry tracing libraries not found. Falling back to mock tracing.")

# --- Prometheus Metrics Setup ---
try:
    from prometheus_client import Counter, Histogram, Gauge, make_asgi_app
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    logger.warning("prometheus_client library not found. Falling back to mock metrics.")

try:
    import psutil
except ImportError:
    psutil = None


# Mock implementations for degraded modes
class MockSpan:
    def set_attribute(self, key: str, value: Any) -> None: pass
    def record_exception(self, exception: Exception) -> None: pass
    def set_status(self, status: Any) -> None: pass


class MockTracer:
    @contextmanager
    def start_as_current_span(self, name: str, *args: Any, **kwargs: Any) -> Generator[MockSpan, None, None]:
        yield MockSpan()


class MockMetric:
    def labels(self, *args: Any, **kwargs: Any) -> MockMetric: return self
    def inc(self, amount: float = 1.0) -> None: pass
    def observe(self, value: float) -> None: pass
    def set(self, value: float) -> None: pass


# Initialize Prometheus Metrics if available
if HAS_PROMETHEUS:
    LATENCY_HIST = Histogram("soc_latency_seconds", "Request or action latency in seconds", ["type"])
    TOKEN_COUNTER = Counter("soc_token_usage_total", "LLM token usage", ["model", "type"])  # type=prompt/completion
    COST_COUNTER = Counter("soc_cost_usd_total", "Estimated LLM cost in USD", ["model"])
    ERROR_COUNTER = Counter("soc_errors_total", "Count of errors", ["component"])
    HALLUCINATION_HIST = Histogram("soc_hallucination_score", "LLM hallucination scores [0.0 - 1.0]", ["model"])
    MEMORY_GAUGE = Gauge("soc_memory_usage_bytes", "Memory consumption of the SOC process in bytes")
else:
    LATENCY_HIST = MockMetric()
    TOKEN_COUNTER = MockMetric()
    COST_COUNTER = MockMetric()
    ERROR_COUNTER = MockMetric()
    HALLUCINATION_HIST = MockMetric()
    MEMORY_GAUGE = MockMetric()


# --- Public Tracing APIs ---
def init_telemetry(service_name: str = "soc-backend") -> None:
    if not HAS_OTEL:
        return
    try:
        resource = Resource.create(attributes={"service.name": service_name})
        provider = TracerProvider(resource=resource)
        
        processor = BatchSpanProcessor(
            OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True)
        )
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logger.info("OpenTelemetry tracing initialized targeting %s.", OTEL_EXPORTER_OTLP_ENDPOINT)
    except Exception as e:
        logger.warning("Failed to initialize OpenTelemetry: %s. Using mock tracer.", e)


def get_tracer(name: str = "default") -> trace.Tracer | MockTracer:
    if HAS_OTEL:
        try:
            return trace.get_tracer(name)
        except Exception:
            pass
    return MockTracer()


# --- Public Metrics Recording APIs ---
def record_latency(action_type: str, duration: float) -> None:
    """Record execution latency of a request, RAG step, or SOAR action."""
    try:
        LATENCY_HIST.labels(type=action_type).observe(duration)
    except Exception as e:
        logger.debug("Failed to record latency metric: %s", e)


def record_tokens(model: str, prompt_tokens: int, completion_tokens: int) -> None:
    """Record prompt and completion tokens for LLM requests."""
    try:
        TOKEN_COUNTER.labels(model=model, type="prompt").inc(prompt_tokens)
        TOKEN_COUNTER.labels(model=model, type="completion").inc(completion_tokens)
        
        # Estimate cost (rough defaults for typical LLM pricing models)
        # e.g., $0.0015 / 1K prompt, $0.002 / 1K completion
        cost = (prompt_tokens * 0.0015 + completion_tokens * 0.002) / 1000.0
        COST_COUNTER.labels(model=model).inc(cost)
    except Exception as e:
        logger.debug("Failed to record token usage: %s", e)


def record_error(component: str) -> None:
    """Record an execution error in any system component."""
    try:
        ERROR_COUNTER.labels(component=component).inc(1.0)
    except Exception as e:
        logger.debug("Failed to record error: %s", e)


def record_hallucination(model: str, score: float) -> None:
    """Record the assessed hallucination score of an LLM answer."""
    try:
        HALLUCINATION_HIST.labels(model=model).observe(score)
    except Exception as e:
        logger.debug("Failed to record hallucination score: %s", e)


def update_memory_metric() -> None:
    """Update gauge with current memory footprint of the python process."""
    if psutil:
        try:
            process = psutil.Process(os.getpid())
            mem_bytes = process.memory_info().rss
            MEMORY_GAUGE.set(mem_bytes)
        except Exception as e:
            logger.debug("Failed to read memory usage: %s", e)


@contextmanager
def trace_and_time(component: str, operation: str) -> Generator[trace.Span | MockSpan, None, None]:
    """Convenience context manager that wraps code in a trace span and records latency/errors."""
    tracer = get_tracer(component)
    start_time = time.perf_counter()
    with tracer.start_as_current_span(operation) as span:
        try:
            yield span
        except Exception as e:
            record_error(component)
            span.record_exception(e)
            span.set_status(trace.StatusCode.ERROR if HAS_OTEL else None)
            raise
        finally:
            duration = time.perf_counter() - start_time
            record_latency(f"{component}:{operation}", duration)
            update_memory_metric()
