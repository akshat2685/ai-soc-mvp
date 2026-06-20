import logging

logger = logging.getLogger(__name__)

# Basic pricing per 1K tokens for Qwen3 / Gemini 3.5 models (in USD)
PRICING_PER_1K = {
    "prompt": 0.0015,
    "completion": 0.0020
}

def estimate_tokens(text: str) -> int:
    # A robust token estimation: ~4 characters per token
    return len(text) // 4

def calculate_llm_cost(prompt: str, completion: str) -> float:
    """Calculates LLM cost based on prompt & completion token counts."""
    prompt_tokens = estimate_tokens(prompt)
    completion_tokens = estimate_tokens(completion)
    
    cost_prompt = (prompt_tokens / 1000.0) * PRICING_PER_1K["prompt"]
    cost_completion = (completion_tokens / 1000.0) * PRICING_PER_1K["completion"]
    
    total_cost = round(cost_prompt + cost_completion, 6)
    return total_cost
