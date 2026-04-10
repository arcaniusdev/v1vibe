"""File and URL sandbox analysis for behavioral threat detection.

Submits files and URLs to TrendAI Vision One sandbox for deep behavioral
analysis (detonation). Monitors execution, network activity, file system
changes, and registry modifications to detect malicious behavior.

Supported file types are loaded from sandbox_filetypes.txt (user-editable).
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from v1vibe import api_endpoints
from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error

# Load sandbox-supported file extensions from external file.
# Users can edit sandbox_filetypes.txt to add/remove supported types.
_FILETYPES_PATH = Path(__file__).resolve().parent.parent / "sandbox_filetypes.txt"


def _load_sandbox_extensions() -> set[str]:
    """Load supported file extensions from sandbox_filetypes.txt.

    Returns:
        set[str]: Set of supported extensions (lowercase, including dot)
    """
    try:
        lines = _FILETYPES_PATH.read_text().splitlines()
        return {
            line.strip().lower()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        }
    except OSError:
        return set()


SANDBOX_SUPPORTED_EXTENSIONS: set[str] = _load_sandbox_extensions()


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
    """Submit a file to sandbox for deep behavioral analysis.

    Validates file extension against supported types before submission.
    Passwords are base64-encoded for secure transmission.

    Args:
        ctx: Application context with HTTP client
        file_path: Absolute path to file to submit
        document_password: Password for encrypted documents (plaintext, will be encoded)
        archive_password: Password for encrypted archives (plaintext, will be encoded)
        arguments: Command-line arguments for PE/script execution in sandbox

    Returns:
        dict: Task submission result with taskId and quotaRemaining, or error dict
    """
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

        # Read file contents first, then close before HTTP upload
        with open(file_path, "rb") as f:
            file_content = f.read()

        files = {"file": (os.path.basename(file_path), file_content, "application/octet-stream")}
        data: dict[str, str] = {}
        if document_password:
            data["documentPassword"] = base64.b64encode(document_password.encode()).decode()
        if archive_password:
            data["archivePassword"] = base64.b64encode(archive_password.encode()).decode()
        if arguments:
            data["arguments"] = base64.b64encode(arguments.encode()).decode()

        resp = await ctx.http.post(
            api_endpoints.SANDBOX_SUBMIT_FILE,
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
    """Submit up to 10 URLs for sandbox analysis.

    Args:
        ctx: Application context with HTTP client
        urls: List of URLs to analyze (1-10 URLs)

    Returns:
        dict: Batch submission result with items (per-URL task IDs) and quotaRemaining,
              or error dict if validation fails
    """
    try:
        if not urls:
            return {"error": {"code": "InvalidInput", "message": "At least one URL is required"}}
        if len(urls) > 10:
            return {"error": {"code": "InvalidInput", "message": "Maximum 10 URLs per request"}}

        payload = [{"url": u} for u in urls]
        resp = await ctx.http.post(
            api_endpoints.SANDBOX_SUBMIT_URL,
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
    """Check status of a sandbox submission.

    Args:
        ctx: Application context with HTTP client
        task_id: Task ID from submit_file or submit_url

    Returns:
        dict: Task status with action (running/succeeded/failed) and resourceLocation
              (when succeeded), or error dict
    """
    try:
        resp = await ctx.http.get(api_endpoints.SANDBOX_GET_TASK.format(task_id=task_id))
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def get_report(
    ctx: AppContext,
    result_id: str,
    save_pdf_to: str | None = None,
) -> dict[str, Any]:
    """Retrieve full sandbox analysis report.

    Fetches JSON report, suspicious objects list, and optionally downloads
    PDF report for human review.

    Args:
        ctx: Application context with HTTP client
        result_id: Result ID from resourceLocation in get_status response
        save_pdf_to: Optional absolute path to save PDF report

    Returns:
        dict: Analysis report with riskLevel, detectionNames, threatTypes,
              suspiciousObjects list, and PDF save confirmation (if requested),
              or error dict
    """
    try:
        resp = await ctx.http.get(api_endpoints.SANDBOX_GET_RESULT.format(result_id=result_id))
        result = check_response(resp)

        # Only fetch suspicious objects if analysis found risks (optimization)
        # Skip for "no_risk"/"noRisk" results to reduce unnecessary API calls (~50% savings)
        risk_level = result.get("riskLevel", "").lower()
        if risk_level and risk_level not in ("no_risk", "norisk"):
            try:
                so_resp = await ctx.http.get(
                    api_endpoints.SANDBOX_GET_SUSPICIOUS_OBJECTS.format(result_id=result_id)
                )
                if so_resp.status_code == 200:
                    result["suspiciousObjects"] = so_resp.json().get("items", [])
                else:
                    result["suspiciousObjects"] = []
            except Exception:
                result["suspiciousObjects"] = []
        else:
            # No risk detected, skip suspicious objects fetch
            result["suspiciousObjects"] = []

        # Download and save the PDF report for human review
        if save_pdf_to:
            try:
                pdf_resp = await ctx.http.get(
                    api_endpoints.SANDBOX_GET_REPORT.format(result_id=result_id)
                )
                if pdf_resp.status_code == 200:
                    pdf_dir = os.path.dirname(save_pdf_to)
                    if pdf_dir:
                        os.makedirs(pdf_dir, exist_ok=True)
                    with open(save_pdf_to, "wb") as f:
                        f.write(pdf_resp.content)
                    result["pdfReportSavedTo"] = save_pdf_to
                    result["pdfReportSizeBytes"] = len(pdf_resp.content)
            except Exception:
                result["pdfReportError"] = "Failed to download PDF report"

        return result
    except Exception as exc:
        return format_error(exc)


async def get_submission_quota(
    ctx: AppContext,
) -> dict[str, Any]:
    """Check remaining daily sandbox submission quota.

    Args:
        ctx: Application context with HTTP client

    Returns:
        dict: Quota information with daily reserve count, remaining submissions,
              and breakdown of file vs URL submission counts, or error dict
    """
    try:
        resp = await ctx.http.get(api_endpoints.SANDBOX_GET_QUOTA)
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
