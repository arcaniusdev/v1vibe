from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

VALID_TOP_VALUES = [10, 50, 100, 200, 500, 1000]

ASSET_TYPE_TO_PATH = {
    "devices": "attackSurfaceDevices",
    "cloud_assets": "attackSurfaceCloudAssets",
    "public_ips": "attackSurfacePublicIpAddresses",
    "fqdns": "attackSurfaceGlobalFqdns",
    "local_apps": "attackSurfaceLocalApps",
    "domain_accounts": "attackSurfaceDomainAccounts",
}


async def discover_assets(
    ctx: AppContext,
    asset_type: str,
    filter_expr: str | None = None,
    top: int = 50,
    order_by: str | None = None,
) -> dict[str, Any]:
    try:
        path_segment = ASSET_TYPE_TO_PATH.get(asset_type)
        if not path_segment:
            valid = ", ".join(sorted(ASSET_TYPE_TO_PATH))
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid asset_type '{asset_type}'. Must be one of: {valid}",
                }
            }

        clamped_top = min((v for v in VALID_TOP_VALUES if v >= top), default=1000)
        params: dict[str, Any] = {"top": clamped_top}
        if order_by:
            params["orderBy"] = order_by

        headers: dict[str, str] = {}
        if filter_expr:
            headers["TMV1-Filter"] = filter_expr

        resp = await ctx.http.get(
            f"/v3.0/asrm/{path_segment}",
            params=params,
            headers=headers,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
