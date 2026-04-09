from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import format_error


async def start_malware_scan(
    ctx: AppContext,
    endpoints: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        if not endpoints:
            return {"error": {"code": "InvalidInput", "message": "At least one endpoint is required"}}

        payload = []
        for ep in endpoints:
            item: dict[str, str] = {}
            if "agent_guid" in ep:
                item["agentGuid"] = ep["agent_guid"]
            elif "endpoint_name" in ep:
                item["endpointName"] = ep["endpoint_name"]
            else:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": "Each endpoint must have 'agent_guid' or 'endpoint_name'",
                    }
                }
            if "description" in ep:
                item["description"] = ep["description"]
            payload.append(item)

        resp = await ctx.http.post(
            "/v3.0/response/endpoints/startMalwareScan",
            json=payload,
        )
        resp.raise_for_status()

        task_url = resp.headers.get("Operation-Location", "")
        return {"status": resp.status_code, "taskUrl": task_url}
    except Exception as exc:
        return format_error(exc)
