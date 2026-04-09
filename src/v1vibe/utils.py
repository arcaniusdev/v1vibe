from __future__ import annotations

from typing import Any

import httpx


def format_error(exc: Exception) -> dict[str, Any]:
    code = type(exc).__name__
    if isinstance(exc, httpx.HTTPStatusError):
        code = f"HTTP{exc.response.status_code}"
        try:
            body = exc.response.json()
            message = body.get("error", {}).get("message", str(exc))
        except Exception:
            message = exc.response.text or str(exc)
    else:
        message = str(exc)
    return {"error": {"code": code, "message": message}}


def check_response(response: httpx.Response) -> dict[str, Any] | list[Any]:
    response.raise_for_status()
    if response.status_code == 204:
        return {}
    return response.json()


def check_multi_status(response: httpx.Response) -> list[Any]:
    if response.status_code not in (200, 207):
        response.raise_for_status()
    return response.json()
