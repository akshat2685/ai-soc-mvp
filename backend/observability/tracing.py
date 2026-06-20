import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AgentTraceSpan:
    def __init__(self, agent_name: str, task: str):
        self.agent_name = agent_name
        self.task = task
        self.start_time = None
        self.end_time = None
        self.metadata = {}

    def __enter__(self):
        import time
        self.start_time = time.time()
        logger.info(f"[Trace Start] Agent '{self.agent_name}' initiated task context.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        self.end_time = time.time()
        duration = round(self.end_time - self.start_time, 4)
        status = "SUCCESS" if exc_type is None else "FAILED"
        
        logger.info(
            f"[Trace End] Agent '{self.agent_name}' finished task. "
            f"Status: {status}, Duration: {duration}s"
        )
        if exc_type is not None:
            logger.error(f"[Trace Error] Exception in '{self.agent_name}' execution: {exc_val}")

        # Record span metrics to Prometheus gauges
        try:
            from observability.metrics import record_agent_duration
            record_agent_duration(self.agent_name, duration)
        except Exception:
            pass

def start_agent_span(agent_name: str, task: str) -> AgentTraceSpan:
    """Convenience helper to initialize a trace context span."""
    return AgentTraceSpan(agent_name, task)
