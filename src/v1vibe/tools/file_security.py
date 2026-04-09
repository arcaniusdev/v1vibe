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
