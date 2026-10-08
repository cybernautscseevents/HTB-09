"""Small server-side adapter for text generation with the Gemini API."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


# Load backend/.env without printing or returning any secret values.
load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
logger = logging.getLogger(__name__)
DEFAULT_MODEL = "gemini-3.8-flash"
TRANSIENT_STATUS_CODES = [408, 429, 500, 502, 503, 504]
NORMAL_REQUEST_TIMEOUT_MS = 20_000


def gemini_http_options(timeout_ms: int) -> types.HttpOptions:
    """Bound provider retries to one short retry for transient HTTP failures."""
    return types.HttpOptions(
        timeout=timeout_ms,
        retry_options=types.HttpRetryOptions(
            attempts=2,
            initial_delay=0.25,
            max_delay=0.5,
            exp_base=2,
            jitter=0.1,
            http_status_codes=TRANSIENT_STATUS_CODES,
        ),
    )


class GeminiServiceError(Exception):
    """Safe-to-return error details for a failed model request."""

    def __init__(self, public_message: str, request_attempted: bool = False):
        super().__init__(public_message)
        self.public_message = public_message
        self.request_attempted = request_attempted


def get_model_name() -> str:
    return os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def generate_response(prompt: str) -> str:
    """Send only the caller-provided (already security-processed) prompt to Gemini."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GeminiServiceError(
            "Security scan completed, but the LLM service is not configured. "
            "Set GEMINI_API_KEY in backend/.env."
        )

    request_attempted = False
    try:
        client = genai.Client(
            api_key=api_key,
            http_options=gemini_http_options(NORMAL_REQUEST_TIMEOUT_MS),
        )
        request_attempted = True
        result = client.models.generate_content(
            model=get_model_name(),
            contents=prompt,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.LOW),
            ),
        )
        answer = (result.text or "").strip()
        if not answer:
            raise RuntimeError("Gemini returned no text")
        return answer
    except Exception as exc:
        # Avoid logging exception messages, prompt contents, or credentials.
        code = getattr(exc, "code", None)
        api_status = getattr(exc, "status", None)
        logger.warning(
            "Gemini request failed (type=%s code=%s status=%s)",
            type(exc).__name__,
            code,
            api_status,
        )
        if "API_KEY_INVALID" in str(exc):
            public_message = (
                "Security scan completed, but Google rejected the configured Gemini API key. "
                "Check the key in backend/.env; do not paste it into the frontend."
            )
        elif code in (400, 404):
            public_message = (
                "Security scan completed, but Gemini rejected the selected model or request. "
                "Check GEMINI_MODEL in backend/.env."
            )
        else:
            public_message = (
                "Security scan completed, but the LLM service is currently unavailable. "
                "Please try again later."
            )
        raise GeminiServiceError(
            public_message,
            request_attempted=request_attempted,
        ) from None
