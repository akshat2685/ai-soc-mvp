"""Sigma Rule Generator.

Fuses LLM capability to generate standard Sigma YAML rules for newly discovered
or missed threat techniques.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Any

from ai_engine import _call_llm

from agents.prompts import PromptLoader

log = logging.getLogger(__name__)

def generate_sigma_rule(technique_id: str, technique_name: str) -> Dict[str, Any]:
    """Generates a standard Sigma detection rule YAML using the LLM."""
    
    base_prompt = f"""You are an expert SOC detection engineer and Sigma rule author.
Write a valid, standard Sigma rule in YAML format to detect the following MITRE ATT&CK technique:

Technique ID: {technique_id}
Technique Name: {technique_name}

Your Sigma rule must include standard fields:
- title
- id (auto-generated UUID)
- status (experimental)
- description
- references
- author (EDYSOR Auto-Team)
- date
- logsource (category: process_creation or webserver)
- detection (selection criteria)
- condition
- falsepositives
- level (high)

Provide your response with the YAML block inside standard ```yaml code fences.
"""
    prompt = PromptLoader.get_prompt("purple_team", base_prompt)
    try:
        response = _call_llm(prompt, fallback="")
        # Extract YAML block
        yaml_match = re.search(r'```yaml\s*(.*?)\s*```', response, re.DOTALL)
        rule_yaml = yaml_match.group(1) if yaml_match else response
        
        return {
            "technique_id": technique_id,
            "rule_yaml": rule_yaml.strip()
        }
    except Exception as e:
        log.exception("Sigma generation LLM call failed: %s", e)
        
    # Return simple fallback Sigma structure on failure
    fallback_yaml = f"""title: Detect {technique_name}
id: 550e8400-e29b-41d4-a716-446655440000
status: experimental
description: Detects behavior corresponding to {technique_id}
author: EDYSOR Fallback
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '{technique_id.lower()}'
    condition: selection
level: high"""
    return {
        "technique_id": technique_id,
        "rule_yaml": fallback_yaml
    }
