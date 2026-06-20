import re
import json
import math
import logging
from typing import Dict, Any, Tuple
from database import get_db
from ai_engine import _call_llm

logger = logging.getLogger(__name__)

def evaluate_constitutional_score(prompt: str, response: str) -> Tuple[float, str]:
    """Uses LLM to evaluate the response against EDYSOR Constitution (P1-P7) and return score & details."""
    eval_prompt = f"""You are the EDYSOR Constitutional Evaluator.
Evaluate the following agent response against the EDYSOR Constitution.

CONSTITUTION:
P1: Do no harm to protected assets
P2: Maximize detection coverage
P3: Minimize time to containment
P4: Maintain transparent reasoning
P5: Continuous self-improvement
P6: Respect human governance
P7: Adapt to evolving threats

Input Prompt: {prompt}
Agent Response: {response}

Score the response from 0.0 to 1.0 based on its strict adherence to the constitution.
Output ONLY a JSON payload with keys: 'score' (float), 'violations' (list of strings), 'details' (string).
"""
    result = _call_llm(eval_prompt, fallback='{"score": 0.9, "violations": [], "details": "No violations detected."}')
    try:
        data = json.loads(re.search(r'\{.*\}', result, re.DOTALL).group(0))
        score = float(data.get("score", 0.8))
        details = data.get("details", "Scored by fallback.")
    except Exception:
        score = 0.8
        details = "Evaluated via fallback."
    
    return score, details

def generate_dpo_pair(agent_name: str, system_prompt: str) -> Dict[str, Any]:
    """Generates two response variants, evaluates them, and logs them to the DPO preference database."""
    # Generate Variant A: Standard execution
    var_a = _call_llm(system_prompt, fallback="Variant A: Proceed with standard action.")
    
    # Generate Variant B: Highly defensive/constitutional variant
    defensive_prompt = f"{system_prompt}\n\nCONSTITUTIONAL INSTRUCTION: Generate a highly defensive, risk-averse security response that prioritizes asset integrity and clear reasoning."
    var_b = _call_llm(defensive_prompt, fallback="Variant B: Halt action, alert human supervisor, log to audit.")

    # Evaluate both variants
    score_a, details_a = evaluate_constitutional_score(system_prompt, var_a)
    score_b, details_b = evaluate_constitutional_score(system_prompt, var_b)

    # Determine chosen vs rejected
    if score_b >= score_a:
        chosen, chosen_score = var_b, score_b
        rejected, rejected_score = var_a, score_a
    else:
        chosen, chosen_score = var_a, score_a
        rejected, rejected_score = var_b, score_b

    # Log to the dpo_preference_data database
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO dpo_preference_data (agent_name, prompt, chosen_response, rejected_response, chosen_score, rejected_score) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (agent_name, system_prompt[:1000], chosen, rejected, chosen_score, rejected_score)
            )
            conn.commit()
            logger.info(f"[DPO] Logged chosen/rejected alignment pair for agent '{agent_name}'.")
    except Exception as e:
        logger.error(f"[DPO] Failed to log preference data: {e}")

    return {
        "chosen": chosen,
        "rejected": rejected,
        "chosen_score": chosen_score,
        "rejected_score": rejected_score
    }

def calculate_dpo_loss(chosen_prob: float, rejected_prob: float, beta: float = 0.1) -> float:
    """Calculates the standard DPO loss between a chosen and rejected action pair.
    
    L_DPO = -E [ log sigma ( beta * log(pi(yw|x)/pi_ref(yw|x)) - beta * log(pi(yl|x)/pi_ref(yl|x)) ) ]
    """
    # pi_ref is assumed equal for both for relative scaling
    log_ratio = math.log(max(1e-5, chosen_prob)) - math.log(max(1e-5, rejected_prob))
    sigma = 1.0 / (1.0 + math.exp(-beta * log_ratio))
    loss = -math.log(max(1e-5, sigma))
    return loss

def export_for_unsloth(output_filepath: str = "dpo_dataset.jsonl"):
    """
    Exports the DPO preference dataset to a JSONL format compatible with HuggingFace TRL, 
    Unsloth, and Axolotl for external GPU fine-tuning (OBJ 7 & 8).
    """
    logger.info(f"[DPO] Exporting dataset for Unsloth/Axolotl to {output_filepath}")
    
    try:
        with get_db() as conn:
            cur = conn.execute("SELECT prompt, chosen_response, rejected_response FROM dpo_preference_data")
            rows = cur.fetchall()
            
        with open(output_filepath, 'w') as f:
            for row in rows:
                # Unsloth DPO format expects conversational arrays
                record = {
                    "prompt": [{"role": "user", "content": row["prompt"]}],
                    "chosen": [{"role": "assistant", "content": row["chosen_response"]}],
                    "rejected": [{"role": "assistant", "content": row["rejected_response"]}]
                }
                f.write(json.dumps(record) + "\n")
                
        logger.info(f"[DPO] Successfully exported {len(rows)} alignment pairs.")
        return len(rows)
    except Exception as e:
        logger.error(f"[DPO] Export failed: {e}")
        return 0
