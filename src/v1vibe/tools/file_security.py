"""File malware scanning using TrendAI File Security SDK.

Fast malware scanning via gRPC API. Accepts any file type and returns
scan results with malware names, file hashes (SHA1/SHA256), and optional
Predictive Machine Learning (PML) detection for novel threats.
"""

from __future__ import annotations

import json
import os
from typing import Any

import amaas.grpc.aio as amaas_aio

from v1vibe.clients import AppContext
from v1vibe.utils import format_error


async def scan_file(
    ctx: AppContext,
    file_path: str,
    tags: list[str] | None = None,
    pml: bool = False,
) -> dict[str, Any]:
    """Scan a file for malware using TrendAI File Security SDK.

    Fast malware scan (seconds) using gRPC API. Supports any file type.

    Args:
        ctx: Application context with gRPC handle
        file_path: Absolute path to file to scan
        tags: Optional list of tags for organizing scan results (max 8, 63 chars each)
        pml: Enable Predictive Machine Learning for detecting novel malware variants

    Returns:
        dict: Scan result with scanResult (0=clean, 1=malicious), foundMalwares list,
              fileSHA1, fileSHA256, or error dict on failure
    """
    try:
        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        result_json = await amaas_aio.scan_file(
            ctx.grpc_handle,
            file_name=file_path,
            tags=tags or [],
            pml=pml,
        )
        return json.loads(result_json)
    except Exception as exc:
        return format_error(exc)
