"""CVE (Common Vulnerabilities and Exposures) lookup and details.

Retrieves detailed information about specific CVEs from TrendAI Vision One,
including CVSS scores, descriptions, affected assets, and mitigation options.
"""

from __future__ import annotations

import re
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

# CVE ID format: CVE-YYYY-NNNNN (year, then 4+ digits)
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


async def get_cve_details(
    ctx: AppContext,
    cve_id: str,
) -> dict[str, Any]:
    """Get detailed information about a specific CVE.

    Validates CVE ID format and retrieves comprehensive vulnerability data
    including CVSS scores, mitigation options, and affected asset counts.

    Args:
        ctx: Application context with HTTP client
        cve_id: CVE identifier in format "CVE-YYYY-NNNNN" (e.g., "CVE-2023-44487")

    Returns:
        dict: CVE details with cvssV2Score, cvssV3Score, description, mitigations
              (patches, packages), affectedAssetCounts (devices, containers, VMs,
              serverless), or error dict if CVE ID is invalid or not found
    """
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
