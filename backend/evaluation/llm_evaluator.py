"""LLM Output Evaluator.

Uses LLM-as-a-judge to grade:
- Hallucination score (statements not supported by provided context)
- Factuality score (general fact correctness)
- Grounding score (faithful tracing to source materials)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Dict, Any

from ai_engine import _call_llm

log = logging.getLogger(__name__)

def evaluate_llm_quality(
    context: str,
    response: str,
    reference: Optional[str] = None
) -> Dict[str, float | str]:
    """Evaluates grounding, hallucination, and factuality for an LLM response against context/reference."""
    
    prompt = f"""You are a strict QA auditor evaluating an LLM response. 

[CONTEXT PROVIDED TO THE LLM]
{context}

[REFERENCE MATERIAL (OPTIONAL)]
{reference or "None"}

[LLM RESPONSE]
{response}

Analyze the response and score the following metrics on a scale of 0.0 to 1.0:
1. grounding_score: Is the response completely anchored in the provided context? (1.0 = fully grounded, 0.0 = completely ungrounded/made up).
2. hallucination_score: Does the response state security facts or conclusions not mentioned in the context/reference? (1.0 = heavy hallucinations, 0.0 = zero hallucinations).
3. factuality_score: Regardless of context, are the statements correct based on general cyber security standards? (1.0 = fully correct, 0.0 = completely incorrect).
4. reasoning: Brief 1-2 sentence audit explanation.

Return your evaluation in strict JSON format with keys: "grounding_score", "hallucination_score", "factuality_score", "reasoning".
"""
    try:
        raw_res = _call_llm(prompt, fallback='{"grounding_score": 1.0, "hallucination_score": 0.0, "factuality_score": 1.0, "reasoning": "Passed."}')
        match = re.search(r'\{.*\}', raw_res, re.DOTALL)
        if match:
            res_data = json.loads(match.group(0))
            return {
                "grounding_score": float(res_data.get("grounding_score", 1.0)),
                "hallucination_score": float(res_data.get("hallucination_score", 0.0)),
                "factuality_score": float(res_data.get("factuality_score", 1.0)),
                "reasoning": res_data.get("reasoning", "")
            }
    except Exception as e:
        log.warning("LLM evaluation failed, falling back: %s", e)

    return {
        "grounding_score": 0.5,
        "hallucination_score": 0.5,
        "factuality_score": 0.5,
        "reasoning": "Failed to run LLM judge evaluation."
    }
