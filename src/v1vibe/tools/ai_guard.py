"""AI content safety validation using TrendAI AI Guard.

Evaluates AI prompts, chatbot content, and LLM templates for:
- Harmful content (hate, harassment, sexual, violence, self-harm)
- PII leakage (personal information in prompts)
- Prompt injection attacks

Returns Allow/Block verdict with confidence scores per category.
"""

from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error


async def evaluate(
    ctx: AppContext,
    prompt: str,
    application_name: str = "v1vibe",
) -> dict[str, Any]:
    """Evaluate text for harmful content, PII leakage, and prompt injection.

    Args:
        ctx: Application context with HTTP client
        prompt: Text content to evaluate (max 1024 characters)
        application_name: Application identifier for tracking (default: "v1vibe")

    Returns:
        dict: Evaluation result with action (Allow/Block), harmfulContent list
              (categories with hasPolicyViolation and confidenceScore),
              promptAttacks list, or error dict
    """
    try:
        resp = await ctx.http.post(
            "/v3.0/aiSecurity/applyGuardrails",
            headers={
                "Content-Type": "application/json",
                "TMV1-Application-Name": application_name,
                "Prefer": "return=representation",
            },
            json={"prompt": prompt},
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
