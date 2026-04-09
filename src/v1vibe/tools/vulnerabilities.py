from __future__ import annotations

import re
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

VALID_RISK_LEVELS = {"high", "medium", "low"}
VALID_CLUSTER_TYPES = {"kubernetes", "amazonEcs"}
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


async def get_cve_details(
    ctx: AppContext,
    cve_id: str,
) -> dict[str, Any]:
    try:
        if not _CVE_ID_PATTERN.match(cve_id):
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid CVE ID format '{cve_id}'. Expected format: CVE-YYYY-NNNNN",
                }
            }
        resp = await ctx.http.get(f"/v3.0/asrm/vulnerabilities/{cve_id}")
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
