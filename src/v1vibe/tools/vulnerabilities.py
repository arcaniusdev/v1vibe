from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

VULN_ASSET_TYPE_TO_PATH = {
    "devices": "vulnerableDevices",
    "internal_assets": "internalAssetVulnerabilities",
    "internet_facing": "internetFacingAssetVulnerabilities",
    "containers": "containerVulnerabilities",
    "cloud_vms": "cloudVmVulnerabilities",
    "serverless": "serverlessFunctionVulnerabilities",
}


async def get_cve_details(
    ctx: AppContext,
    cve_id: str,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get(f"/v3.0/asrm/vulnerabilities/{cve_id}")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def list_vulnerabilities(
    ctx: AppContext,
    asset_type: str,
    risk_level: str | None = None,
    top: int = 50,
) -> dict[str, Any]:
    try:
        path_segment = VULN_ASSET_TYPE_TO_PATH.get(asset_type)
        if not path_segment:
            valid = ", ".join(sorted(VULN_ASSET_TYPE_TO_PATH))
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid asset_type '{asset_type}'. Must be one of: {valid}",
                }
            }

        params: dict[str, Any] = {"top": top}
        headers: dict[str, str] = {}
        if risk_level:
            headers["TMV1-Filter"] = f"cveRiskLevel eq '{risk_level}'"

        resp = await ctx.http.get(
            f"/v3.0/asrm/{path_segment}",
            params=params,
            headers=headers,
        )
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
            filter_parts.append(f"clusterType eq '{cluster_type}'")
        if risk_level:
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
