from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error


async def search_detections(
    ctx: AppContext,
    query: str,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
    top: int = 50,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": min(top, 10000)}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if end_date_time:
            params["endDateTime"] = end_date_time
        if fields:
            params["select"] = ",".join(fields)

        resp = await ctx.http.get(
            "/v3.0/search/detections",
            headers={"TMV1-Query": query},
            params=params,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def list_alerts(
    ctx: AppContext,
    status: str | None = None,
    severity: str | None = None,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
    top: int = 50,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": top}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if end_date_time:
            params["endDateTime"] = end_date_time

        headers: dict[str, str] = {}
        filter_parts = []
        if status:
            filter_parts.append(f"status eq '{status}'")
        if severity:
            filter_parts.append(f"severity eq '{severity}'")
        if filter_parts:
            headers["TMV1-Filter"] = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/workbench/alerts",
            params=params,
            headers=headers,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
