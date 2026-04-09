from __future__ import annotations

import base64
import os
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error, sanitize_filter_value

VALID_SUBMISSION_STATUSES = {"succeeded", "running", "failed"}
VALID_SUBMISSION_ACTIONS = {"analyzeFile", "analyzeUrl"}


async def submit_file(
    ctx: AppContext,
    file_path: str,
    document_password: str | None = None,
    archive_password: str | None = None,
    arguments: str | None = None,
) -> dict[str, Any]:
    try:
        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
            data: dict[str, str] = {}
            if document_password:
                data["documentPassword"] = base64.b64encode(document_password.encode()).decode()
            if archive_password:
                data["archivePassword"] = base64.b64encode(archive_password.encode()).decode()
            if arguments:
                data["arguments"] = base64.b64encode(arguments.encode()).decode()

            resp = await ctx.http.post(
                "/v3.0/sandbox/files/analyze",
                files=files,
                data=data,
            )

        resp.raise_for_status()
        body = resp.json()
        body["quotaRemaining"] = resp.headers.get("TMV1-Submission-Remaining-Count")
        return body
    except Exception as exc:
        return format_error(exc)


async def submit_url(
    ctx: AppContext,
    urls: list[str],
) -> dict[str, Any]:
    try:
        if not urls:
            return {"error": {"code": "InvalidInput", "message": "At least one URL is required"}}
        if len(urls) > 10:
            return {"error": {"code": "InvalidInput", "message": "Maximum 10 URLs per request"}}

        payload = [{"url": u} for u in urls]
        resp = await ctx.http.post(
            "/v3.0/sandbox/urls/analyze",
            json=payload,
        )
        results = check_multi_status(resp)

        quota_remaining = resp.headers.get("TMV1-Submission-Remaining-Count")
        return {"items": results, "quotaRemaining": quota_remaining}
    except Exception as exc:
        return format_error(exc)


async def get_status(
    ctx: AppContext,
    task_id: str,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get(f"/v3.0/sandbox/tasks/{task_id}")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def get_report(
    ctx: AppContext,
    result_id: str,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get(f"/v3.0/sandbox/analysisResults/{result_id}")
        result = check_response(resp)

        # Also fetch suspicious objects if analysis found risks
        try:
            so_resp = await ctx.http.get(
                f"/v3.0/sandbox/analysisResults/{result_id}/suspiciousObjects"
            )
            if so_resp.status_code == 200:
                result["suspiciousObjects"] = so_resp.json().get("items", [])
        except Exception:
            result["suspiciousObjects"] = []

        return result
    except Exception as exc:
        return format_error(exc)


async def get_investigation_package(
    ctx: AppContext,
    result_id: str,
    save_path: str,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get(
            f"/v3.0/sandbox/analysisResults/{result_id}/investigationPackage",
        )
        resp.raise_for_status()

        with open(save_path, "wb") as f:
            f.write(resp.content)

        return {
            "savedTo": save_path,
            "sizeBytes": len(resp.content),
        }
    except Exception as exc:
        return format_error(exc)


async def list_submissions(
    ctx: AppContext,
    status: str | None = None,
    action: str | None = None,
    top: int = 50,
) -> dict[str, Any]:
    try:
        params: dict[str, Any] = {"top": top, "orderBy": "createdDateTime desc"}

        headers: dict[str, str] = {}
        filter_parts = []
        if status:
            if status not in VALID_SUBMISSION_STATUSES:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_SUBMISSION_STATUSES))}",
                    }
                }
            filter_parts.append(f"status eq '{status}'")
        if action:
            if action not in VALID_SUBMISSION_ACTIONS:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid action '{action}'. Must be one of: {', '.join(sorted(VALID_SUBMISSION_ACTIONS))}",
                    }
                }
            filter_parts.append(f"action eq '{action}'")
        if filter_parts:
            headers["TMV1-Filter"] = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/sandbox/tasks",
            params=params,
            headers=headers,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def get_submission_quota(
    ctx: AppContext,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get("/v3.0/sandbox/submissionUsage")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
