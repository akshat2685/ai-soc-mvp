import logging
from typing import Dict, Any
from ai_engine import _call_llm

logger = logging.getLogger(__name__)

class NaturalLanguageSOAR:
    """
    Translates Natural Language commands into structured SOAR playbook executions.
    """
    
    @staticmethod
    def parse_command(command: str) -> Dict[str, Any]:
        logger.info(f"[NL SOAR] Parsing natural language command: '{command}'")
        
        prompt = f"""You are the Natural Language SOAR parser.
Extract the intended action, target entity, and parameters from this command: "{command}"

Valid Actions: ISOLATE_IP, REVOKE_USER, GENERATE_SIGMA, BLOCK_DOMAIN, RUN_INVESTIGATION

Output ONLY a JSON payload with keys: 'action', 'target', 'confidence' (0-100), and 'reason'.
If the action is unrecognized, output action: "UNKNOWN"."""

        fallback = '{"action": "UNKNOWN", "target": "none", "confidence": 0, "reason": "Fallback triggered."}'
        
        try:
            import json
            import re
            result_str = _call_llm(prompt, fallback=fallback)
            data = json.loads(re.search(r'\{.*\}', result_str, re.DOTALL).group(0))
            logger.info(f"[NL SOAR] Parsed Command: {data}")
            return data
        except Exception as e:
            logger.error(f"[NL SOAR] Parsing failed: {e}")
            return json.loads(fallback)

    @staticmethod
    def execute_parsed_command(parsed_data: Dict[str, Any]) -> str:
        """Simulates executing the parsed structured command."""
        action = parsed_data.get("action")
        target = parsed_data.get("target")
        
        if action == "UNKNOWN":
            return "Command not recognized or unsupported."
            
        return f"Successfully queued playbook execution: {action} on target {target} (Confidence: {parsed_data.get('confidence')}%)"
