from __future__ import annotations

from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error


async def list_yara_rules(
    ctx: AppContext,
    name_filter: str | None = None,
    top: int = 50,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": top}
        if name_filter:
            params["filter"] = f"name eq '{name_filter}'"

        resp = await ctx.http.get(
            "/v3.0/response/yaraRuleFiles",
            params=params,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def run_yara_rules(
    ctx: AppContext,
    endpoint_name: str | None = None,
    agent_guid: str | None = None,
    rule_content: str | None = None,
    rule_file_id: str | None = None,
    rule_file_name: str | None = None,
    target_file_path: str | None = None,
    target_process_name: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    try:
        if not endpoint_name and not agent_guid:
            return {"error": {"code": "InvalidInput", "message": "Either endpoint_name or agent_guid is required"}}

        if not any([rule_content, rule_file_id, rule_file_name]):
            return {"error": {"code": "InvalidInput", "message": "One of rule_content, rule_file_id, or rule_file_name is required"}}

        if not target_file_path and not target_process_name:
            return {"error": {"code": "InvalidInput", "message": "Either target_file_path or target_process_name is required"}}

        item: dict[str, Any] = {}
        if description:
            item["description"] = description
        if agent_guid:
            item["agentGuid"] = agent_guid
        else:
            item["endpointName"] = endpoint_name

        if rule_content:
            item["yaraRuleFileContent"] = rule_content
        elif rule_file_id:
            item["yaraRuleFileId"] = rule_file_id
        else:
            item["yaraRuleFileName"] = rule_file_name

        if target_file_path:
            item["target"] = "File"
            item["targetFileLocation"] = target_file_path
        else:
            item["target"] = "Process"
            item["targetProcessName"] = target_process_name

        resp = await ctx.http.post(
            "/v3.0/response/endpoints/runYaraRules",
            json=[item],
        )
        results = check_multi_status(resp)
        return {"items": results}
    except Exception as exc:
        return format_error(exc)
