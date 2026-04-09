from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error


async def evaluate(
    ctx: AppContext,
    prompt: str,
    application_name: str = "v1vibe",
) -> dict[str, Any]:
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
