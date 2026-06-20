import os
from dotenv import load_dotenv
load_dotenv()

# Try to import google.generativeai for real LLM; if unavailable, use fallback
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
_gemini_model = None


def _get_gemini_model():
    global _gemini_model
    if _gemini_model is None and GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            _gemini_model = genai.GenerativeModel("gemini-2.0-flash")
        except Exception as e:
            from logging_config import get_logger
            get_logger(__name__).error(f"[AI ENGINE] Failed to initialize Gemini: {e}")
    return _gemini_model


def call_llm(prompt: str, fallback: str) -> str:
    """Core LLM call with error handling."""
    model = _get_gemini_model()
    if model:
        try:
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            from logging_config import get_logger
            get_logger(__name__).error(f"[AI ENGINE] Gemini API call failed: {e}, using fallback.")
    return fallback
