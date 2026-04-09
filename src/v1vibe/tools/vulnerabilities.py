from __future__ import annotations

import re
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

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
