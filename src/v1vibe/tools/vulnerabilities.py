from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error, sanitize_filter_value

VALID_RISK_LEVELS = {"high", "medium", "low"}
VALID_CLUSTER_TYPES = {"kubernetes", "amazonEcs"}


async def get_cve_details(
    ctx: AppContext,
    cve_id: str,
) -> dict[str, Any]:
    try:
        safe_id = sanitize_filter_value(cve_id)
        resp = await ctx.http.get(f"/v3.0/asrm/vulnerabilities/{safe_id}")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def list_container_vulnerabilities(
    ctx: AppContext,
    cluster_type: str | None = None,
    risk_level: str | None = None,
    top: int = 50,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": top}
        headers: dict[str, str] = {}

        filter_parts = []
        if cluster_type:
            if cluster_type not in VALID_CLUSTER_TYPES:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid cluster_type '{cluster_type}'. Must be one of: {', '.join(sorted(VALID_CLUSTER_TYPES))}",
                    }
                }
            filter_parts.append(f"clusterType eq '{cluster_type}'")
        if risk_level:
            if risk_level not in VALID_RISK_LEVELS:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid risk_level '{risk_level}'. Must be one of: {', '.join(sorted(VALID_RISK_LEVELS))}",
                    }
                }
            filter_parts.append(f"riskLevel eq '{risk_level}'")
        if filter_parts:
            headers["TMV1-Filter"] = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/containerSecurity/vulnerabilities",
            params=params,
            headers=headers,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
