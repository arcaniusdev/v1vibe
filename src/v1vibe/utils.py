from __future__ import annotations

import re
from typing import Any

import httpx

# Strip characters that could break filter/query header expressions
_UNSAFE_FILTER_CHARS = re.compile(r"['\";()\\]")


def sanitize_filter_value(value: str) -> str:
    return _UNSAFE_FILTER_CHARS.sub("", value)


def format_error(exc: Exception) -> dict[str, Any]:
    """Format an exception into a safe error dict, never exposing secrets."""
    code = type(exc).__name__
    if isinstance(exc, httpx.HTTPStatusError):
        code = f"HTTP{exc.response.status_code}"
        try:
            body = exc.response.json()
            message = body.get("error", {}).get("message", "")
        except Exception:
            message = ""
        if not message:
            message = f"HTTP {exc.response.status_code} error from Vision One API"
    elif isinstance(exc, httpx.HTTPError):
        # Network errors — never call str() on httpx exceptions (may contain auth headers)
        message = f"Network error: {type(exc).__name__}"
    elif isinstance(exc, (FileNotFoundError, OSError)):
        message = str(exc)
    else:
        # Generic fallback — safe because non-httpx exceptions won't contain auth headers
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
