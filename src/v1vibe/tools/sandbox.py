from __future__ import annotations

import base64
import os
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error

# File extensions supported by Vision One sandbox for detonation.
# Source: Trend Micro docs + confirmed Python support (2026).
SANDBOX_SUPPORTED_EXTENSIONS: set[str] = {
    # Executables & libraries
    ".exe", ".dll", ".com", ".cpl", ".crt", ".scr", ".sys", ".ocx", ".drv",
    ".msi", ".o",
    # Scripts
    ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".hta",
    ".sh", ".py",
    # Documents
    ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm",
    ".xls", ".xla", ".xlt", ".xlm", ".xlsx", ".xlsb", ".xltx", ".xlsm", ".xlam", ".xltm",
    ".ppt", ".pps", ".pptx", ".ppsx", ".potm", ".ppam", ".ppsm", ".pptm",
    ".pdf", ".rtf", ".pub", ".csv", ".slk", ".iqy", ".xml",
    ".odt", ".ods", ".odp",
    # Web content
    ".htm", ".html", ".xht", ".xhtml", ".mht", ".mhtml", ".svg", ".swf",
    # Java
    ".class", ".cla", ".jar",
    # Shortcuts & links
    ".lnk", ".url",
    # Other
    ".chm", ".cell", ".mov",
    # macOS
    ".dmg", ".pkg",
    # Email
    ".eml", ".email", ".msg",
    # Archives (sandbox extracts and analyzes contents)
    ".7z", ".ace", ".alz", ".arj", ".hqx", ".bz2", ".bzip2", ".egg",
    ".gzip", ".gz", ".lha", ".lharc", ".rar", ".tar", ".tgz",
    ".tnef", ".uue", ".xz", ".zip",
}


def is_sandbox_supported(file_path: str) -> bool:
    """Check if a file's extension is supported by the Vision One sandbox."""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in SANDBOX_SUPPORTED_EXTENSIONS


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

        if not is_sandbox_supported(file_path):
            _, ext = os.path.splitext(file_path)
            return {
                "error": {
                    "code": "UnsupportedFileType",
                    "message": f"File extension '{ext}' is not supported by the Vision One sandbox. "
                    f"Use scan_file for a quick malware scan instead.",
                }
            }

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


async def get_submission_quota(
    ctx: AppContext,
) -> dict[str, Any]:
    try:
        resp = await ctx.http.get("/v3.0/sandbox/submissionUsage")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
