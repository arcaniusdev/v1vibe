from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_multi_status, check_response, format_error

# Load sandbox-supported file extensions from external file.
# Users can edit sandbox_filetypes.txt to add/remove supported types.
_FILETYPES_PATH = Path(__file__).resolve().parent.parent / "sandbox_filetypes.txt"


def _load_sandbox_extensions() -> set[str]:
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
    save_pdf_to: str | None = None,
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

        # Download and save the PDF report for human review
        if save_pdf_to:
            try:
                pdf_resp = await ctx.http.get(
                    f"/v3.0/sandbox/analysisResults/{result_id}/report"
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
    try:
        resp = await ctx.http.get("/v3.0/sandbox/submissionUsage")
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
