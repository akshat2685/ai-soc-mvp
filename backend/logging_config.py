import logging
import json
import uuid
import sys
from typing import Optional
from datetime import datetime
from contextvars import ContextVar
from pythonjsonlogger import jsonlogger
try:
    from opentelemetry import trace
    has_otel = True
except ImportError:
    has_otel = False

correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to all log records"""
    def filter(self, record):
        correlation_id = correlation_id_var.get()
        record.correlation_id = correlation_id or str(uuid.uuid4())
        return True

class SecurityEventJsonFormatter(jsonlogger.JsonFormatter):
    """JSON formatter with security-relevant context"""
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        
        if 'correlation_id' not in log_record:
            log_record['correlation_id'] = correlation_id_var.get() or str(uuid.uuid4())
            
        if has_otel:
            span = trace.get_current_span()
            if span:
                log_record['trace_id'] = span.get_span_context().trace_id
                log_record['span_id'] = span.get_span_context().span_id
                
        for field in ['request_id', 'user_id', 'source_ip']:
            if hasattr(record, field):
                log_record[field] = getattr(record, field)

def setup_logging(app_name: str = "ai-soc", log_level: str = "INFO"):
    logging.getLogger().handlers.clear()
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SecurityEventJsonFormatter())
    handler.addFilter(CorrelationIdFilter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)
    
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("kafka").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

def get_logger(name: str):
    return logging.getLogger(name)

async def set_correlation_id(request):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    correlation_id_var.set(correlation_id)
    return correlation_id

