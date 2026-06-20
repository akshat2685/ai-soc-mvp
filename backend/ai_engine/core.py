from config import settings

_gemini_model = None

def _get_gemini_model():
    global _gemini_model
    if _gemini_model is None and settings.GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.GEMINI_API_KEY)
            _gemini_model = genai.GenerativeModel(settings.GEMINI_MODEL)
        except Exception as e:
            from logging_config import get_logger
            get_logger(__name__).error(f"[AI ENGINE] Failed to initialize Gemini: {e}")
    return _gemini_model


from tenacity import retry, stop_after_attempt, wait_exponential, RetryError

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True
)
def _call_gemini_with_retry(model, prompt: str) -> str:
    """Wrapped LLM call with retry logic."""
    response = model.generate_content(prompt)
    return response.text

from pydantic import BaseModel, Field, ValidationError

class LLMInput(BaseModel):
    prompt: str = Field(..., max_length=15000)

def call_llm(prompt: str, fallback: str) -> str:
    """Core LLM call with error handling, input validation, and exponential backoff."""
    from logging_config import get_logger
    logger = get_logger(__name__)
    
    # Input Validation & Prompt Injection Prevention
    try:
        validated_input = LLMInput(prompt=prompt)
    except ValidationError as e:
        logger.warning(f"[AI ENGINE] Prompt validation failed (length limit): {e}")
        return fallback
        
    # Basic Prompt Injection Filters
    upper_prompt = validated_input.prompt.upper()
    dangerous_keywords = ["IGNORE PREVIOUS INSTRUCTIONS", "SYSTEM PROMPT", "<|IM_START|>"]
    for keyword in dangerous_keywords:
        if keyword in upper_prompt:
            logger.warning(f"[SECURITY] Possible Prompt Injection detected: {keyword}")
            return "ERROR: Malicious prompt detected."
            
    model = _get_gemini_model()
    if model:
        try:
            return _call_gemini_with_retry(model, validated_input.prompt)
        except RetryError as e:
            logger.critical(f"[AI ENGINE] Gemini API permanent failure after retries: {e}, using fallback.")
        except Exception as e:
            logger.error(f"[AI ENGINE] Gemini API unexpected error: {e}, using fallback.")
    return fallback
