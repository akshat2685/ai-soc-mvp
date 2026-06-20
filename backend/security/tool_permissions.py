import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# Map agent roles to their designated sub-tools/API allowlists
AGENT_TOOL_ALLOWLISTS = {
    "threat_hunter": ["clickhouse_logs", "neo4j_graph", "qdrant_semantic", "logs_search"],
    "knowledge": ["threat_intel_db", "misp_enrich", "virustotal_enrich"],
    "root_cause": ["cmdb_assets", "vulnerabilities_db", "cisa_feed"],
    "soar": ["playbooks_run", "incident_remediation", "command_validation"],
    "supervisor": ["route_next_agent", "planner_decomposition"]
}

class AgentToolPermissions:
    @staticmethod
    def is_tool_authorized(agent_name: str, tool_name: str) -> bool:
        """Enforces least-privilege constraints on tool access per agent role."""
        allowed = AGENT_TOOL_ALLOWLISTS.get(agent_name, [])
        if tool_name not in allowed:
            logger.warning(f"[Tool Permission] Blocked: Agent '{agent_name}' attempted unauthorized access to tool '{tool_name}'")
            return False
        return True
