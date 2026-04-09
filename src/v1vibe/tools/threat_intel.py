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
    top: int = 200,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict[str, Any]:
    try:
        clamped_top = min((v for v in sorted(VALID_INDICATOR_TOPS) if v >= top), default=1000)
        params: dict[str, Any] = {"top": clamped_top}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if end_date_time:
            params["endDateTime"] = end_date_time

        resp = await ctx.http.get(
            "/v3.0/threatintel/feedIndicators",
            params=params,
        )
        raw = check_response(resp)

        # Extract just the usable IoCs from STIX objects to keep response size manageable.
        # Raw STIX bundles are too large for MCP tool responses.
        indicators = []
        for obj in raw.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            indicator: dict[str, Any] = {
                "pattern": pattern,
                "created": obj.get("created", ""),
                "valid_from": obj.get("valid_from", ""),
                "labels": obj.get("labels", []),
            }
            # Extract the value from STIX pattern for easy matching
            # e.g., "[file:hashes.'SHA-256' = 'abc123']" -> type=sha256, value=abc123
            if "file:hashes" in pattern:
                indicator["ioc_type"] = "file_hash"
            elif "ipv4-addr:value" in pattern:
                indicator["ioc_type"] = "ipv4"
            elif "ipv6-addr:value" in pattern:
                indicator["ioc_type"] = "ipv6"
            elif "domain-name:value" in pattern:
                indicator["ioc_type"] = "domain"
            elif "url:value" in pattern:
                indicator["ioc_type"] = "url"
            elif "email-addr:value" in pattern:
                indicator["ioc_type"] = "email"
            else:
                indicator["ioc_type"] = "other"
            indicators.append(indicator)

        return {
            "totalReturned": len(indicators),
            "indicators": indicators,
        }
    except Exception as exc:
        return format_error(exc)


