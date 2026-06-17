"""OpenTelemetry configuration module for distributed tracing with Jaeger OTLP."""
import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

OTEL_EXPORTER_OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False
    logger.warning("OpenTelemetry library not found. Falling back to mock telemetry.")

class MockSpan:
    def set_attribute(self, key, value):
        pass
    def record_exception(self, exception):
        pass
    def set_status(self, status):
        pass

class MockTracer:
    @contextmanager
    def start_as_current_span(self, name, *args, **kwargs):
        yield MockSpan()

def init_telemetry(service_name="soc-backend"):
    if not HAS_OTEL:
        return
    try:
        resource = Resource.create(attributes={"service.name": service_name})
        provider = TracerProvider(resource=resource)
        
        # Configure OTLP gRPC span exporter (standard for Jaeger)
        processor = BatchSpanProcessor(
            OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True)
        )
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logger.info(f"OpenTelemetry tracing initialized targeting {OTEL_EXPORTER_OTLP_ENDPOINT}.")
    except Exception as e:
        logger.warning(f"Failed to initialize OpenTelemetry: {e}. Using mock tracer.")

def get_tracer(name="default"):
    if HAS_OTEL:
        try:
            return trace.get_tracer(name)
        except Exception:
            pass
    return MockTracer()
