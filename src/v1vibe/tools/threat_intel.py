from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

VALID_TYPES = {"url", "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress"}


async def check_suspicious_objects(
    ctx: AppContext,
    object_type: str,
    value: str,
    risk_level: str | None = None,
) -> dict[str, Any]:
    try:
        if object_type not in VALID_TYPES:
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid type '{object_type}'. Must be one of: {', '.join(sorted(VALID_TYPES))}",
                }
            }

        filter_parts = [f"type eq '{object_type}'"]
        # Build value filter based on type
        if object_type in ("url", "domain", "ip", "senderMailAddress"):
            filter_parts.append(f"{object_type} eq '{value}'")
        else:
            filter_parts.append(f"{object_type} eq '{value}'")

        if risk_level:
            filter_parts.append(f"riskLevel eq '{risk_level}'")

        filter_expr = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/threatintel/suspiciousObjects",
            headers={"TMV1-Filter": filter_expr},
            params={"top": 50},
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
