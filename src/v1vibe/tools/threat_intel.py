from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error, sanitize_filter_value

VALID_TYPES = {"url", "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress"}
VALID_RISK_LEVELS = {"high", "medium", "low"}
VALID_INDICATOR_TOPS = {1000, 5000, 10000}


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

        safe_value = sanitize_filter_value(value)
        filter_parts = [f"type eq '{object_type}'", f"{object_type} eq '{safe_value}'"]

        if risk_level:
            if risk_level not in VALID_RISK_LEVELS:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid risk_level '{risk_level}'. Must be one of: high, medium, low",
                    }
                }
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


async def get_threat_indicators(
    ctx: AppContext,
    top: int = 1000,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict[str, Any]:
    try:
        clamped_top = min((v for v in sorted(VALID_INDICATOR_TOPS) if v >= top), default=10000)
        params: dict[str, Any] = {"top": clamped_top}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if end_date_time:
            params["endDateTime"] = end_date_time

        resp = await ctx.http.get(
            "/v3.0/threatintel/feedIndicators",
            params=params,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


