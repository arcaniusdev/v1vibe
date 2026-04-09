from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error

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


async def add_suspicious_objects(
    ctx: AppContext,
    objects: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        if not objects:
            return {"error": {"code": "InvalidInput", "message": "At least one object is required"}}

        resp = await ctx.http.post(
            "/v3.0/threatintel/suspiciousObjects",
            json=objects,
        )
        results = check_multi_status(resp)
        return {"items": results}
    except Exception as exc:
        return format_error(exc)


async def remove_suspicious_objects(
    ctx: AppContext,
    objects: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        if not objects:
            return {"error": {"code": "InvalidInput", "message": "At least one object is required"}}

        resp = await ctx.http.post(
            "/v3.0/threatintel/suspiciousObjects/delete",
            json=objects,
        )
        results = check_multi_status(resp)
        return {"items": results}
    except Exception as exc:
        return format_error(exc)


async def get_threat_indicators(
    ctx: AppContext,
    top: int = 1000,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": top}
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


async def get_threat_reports(
    ctx: AppContext,
    top_report: int = 10,
    location: str | None = None,
    industry: str | None = None,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"topReport": top_report}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if end_date_time:
            params["endDateTime"] = end_date_time

        headers: dict[str, str] = {}
        if location or industry:
            filter_parts = []
            if location:
                filter_parts.append(f"location eq '{location}'")
            if industry:
                filter_parts.append(f"industry eq '{industry}'")
            headers["TMV1-Contextual-Filter"] = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/threatintel/feeds",
            params=params,
            headers=headers,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
