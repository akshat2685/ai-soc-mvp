import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Profiles database in-memory
_agent_profiles = {}

class AgentPerformanceProfiler:
    @staticmethod
    def get_agent_profile(agent_name: str) -> Dict[str, Any]:
        global _agent_profiles
        if agent_name not in _agent_profiles:
            _agent_profiles[agent_name] = {
                "invocations": 0,
                "retries": 0,
                "hallucination_indicators": 0
            }
        return _agent_profiles[agent_name]

    @staticmethod
    def record_invocation(agent_name: str):
        profile = AgentPerformanceProfiler.get_agent_profile(agent_name)
        profile["invocations"] += 1

    @staticmethod
    def record_retry(agent_name: str):
        profile = AgentPerformanceProfiler.get_agent_profile(agent_name)
        profile["retries"] += 1

    @staticmethod
    def flag_hallucination(agent_name: str):
        profile = AgentPerformanceProfiler.get_agent_profile(agent_name)
        profile["hallucination_indicators"] += 1
        logger.warning(f"[Profiler] Suspicious output patterns flagged for agent '{agent_name}'.")

    @staticmethod
    def get_all_profiles() -> Dict[str, Dict]:
        return _agent_profiles
