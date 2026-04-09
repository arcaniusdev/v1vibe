from __future__ import annotations

import os
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

VALID_TEMPLATE_TYPES = {"cloudformation-template", "terraform-template"}


async def scan_template(
    ctx: AppContext,
    file_path: str,
    template_type: str,
) -> dict[str, Any]:
    try:
        if template_type not in VALID_TEMPLATE_TYPES:
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid template_type '{template_type}'. Must be one of: {', '.join(sorted(VALID_TEMPLATE_TYPES))}",
                }
            }

        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        with open(file_path, "r") as f:
            content = f.read()

        resp = await ctx.http.post(
            "/beta/cloudPosture/scanTemplate",
            json={
                "type": template_type,
                "content": content,
            },
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def scan_terraform_archive(
    ctx: AppContext,
    file_path: str,
) -> dict[str, Any]:
    try:
        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        with open(file_path, "rb") as f:
            resp = await ctx.http.post(
                "/beta/cloudPosture/scanTemplateArchive",
                files={"file": (os.path.basename(file_path), f, "application/zip")},
                data={"type": "terraform-archive"},
            )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
