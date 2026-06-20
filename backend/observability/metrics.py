import logging
from typing import Dict

logger = logging.getLogger(__name__)

# Simulated Prometheus gauges in memory
PROMETHEUS_METRICS = {
    "agent_durations": {},
    "agent_token_costs": {},
    "agent_failures": {}
}

def record_agent_duration(agent_name: str, duration_sec: float):
    global PROMETHEUS_METRICS
    PROMETHEUS_METRICS["agent_durations"][agent_name] = duration_sec
    logger.info(f"[Metrics Gauge] agent_execution_duration_seconds{{agent='{agent_name}'}} = {duration_sec}")

def record_token_cost(agent_name: str, cost_usd: float):
    global PROMETHEUS_METRICS
    current = PROMETHEUS_METRICS["agent_token_costs"].get(agent_name, 0.0)
    PROMETHEUS_METRICS["agent_token_costs"][agent_name] = round(current + cost_usd, 6)
    logger.info(f"[Metrics Gauge] agent_llm_cost_usd{{agent='{agent_name}'}} = {PROMETHEUS_METRICS['agent_token_costs'][agent_name]}")

def increment_failure_count(agent_name: str):
    global PROMETHEUS_METRICS
    current = PROMETHEUS_METRICS["agent_failures"].get(agent_name, 0)
    PROMETHEUS_METRICS["agent_failures"][agent_name] = current + 1
    logger.info(f"[Metrics Counter] agent_failures_total{{agent='{agent_name}'}} = {PROMETHEUS_METRICS['agent_failures'][agent_name]}")

def get_observability_metrics() -> Dict[str, Dict]:
    return PROMETHEUS_METRICS
