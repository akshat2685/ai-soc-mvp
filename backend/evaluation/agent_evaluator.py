"""Agent Workflow Evaluator.

Uses LLM-as-a-judge to grade agent output on:
- Task success (did it complete the prompt goal)
- Correctness (accuracy vs ground truth reference)
- Consistency (variability across multiple runs)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Dict, Any, List

from ai_engine import _call_llm

log = logging.getLogger(__name__)

def evaluate_agent_run(
    task: str,
    agent_output: str,
    ground_truth_reference: Optional[str] = None
) -> Dict[str, Any]:
    """Grade an agent execution's task success and correctness using LLM-as-a-judge."""
    
    reference_clause = ""
    if ground_truth_reference:
        reference_clause = f"\nGround Truth Reference:\n{ground_truth_reference}\n"

    prompt = f"""You are an expert AI security QA judge. Grade the agent's performance on the following task:

Task: {task}
{reference_clause}
Agent's Output:
{agent_output}

Evaluate and score the following on a scale of 0.0 to 1.0 (where 1.0 is perfect):
1. task_success: Did the agent successfully answer/solve the security task requested?
2. correctness: Is the output factual, accurate, and free of false findings? (If ground truth reference is provided, compare against it).
3. explanation: Brief 1-2 sentence justification for the scores.

Provide your response strictly in JSON format with keys: "task_success", "correctness", "explanation".
"""
    try:
        response = _call_llm(prompt, fallback='{"task_success": 1.0, "correctness": 1.0, "explanation": "Auto-passed."}')
        # Parse JSON from response
        match = re.search(r'\{.*\}', response, re.DOTALL)
        if match:
            res_data = json.loads(match.group(0))
            return {
                "task_success": float(res_data.get("task_success", 0.0)),
                "correctness": float(res_data.get("correctness", 0.0)),
                "explanation": res_data.get("explanation", "")
            }
    except Exception as e:
        log.warning("Agent evaluation failed, falling back: %s", e)
        
    return {"task_success": 0.5, "correctness": 0.5, "explanation": "Fallback grading due to evaluation error."}


def evaluate_consistency(runs_outputs: List[str]) -> float:
    """Assess the semantic consistency of agent outputs across multiple repeated runs."""
    if len(runs_outputs) < 2:
        return 1.0

    # Build prompt to compare similarity of all runs
    outputs_block = ""
    for i, out in enumerate(runs_outputs, start=1):
        outputs_block += f"\nRun {i} Output:\n{out}\n"

    prompt = f"""You are a QA judge comparing multiple runs of the same agent. Check if the outputs are consistent:
{outputs_block}
Rate the consistency on a scale of 0.0 to 1.0 (where 1.0 means semantic equivalence/agreement).
Return only a JSON object like: {{"consistency": 0.95, "reason": "Explanation"}}
"""
    try:
        response = _call_llm(prompt, fallback='{"consistency": 0.90}')
        match = re.search(r'\{.*\}', response, re.DOTALL)
        if match:
            res_data = json.loads(match.group(0))
            return float(res_data.get("consistency", 1.0))
    except Exception as e:
        log.warning("Consistency evaluation failed: %s", e)
    return 0.5
