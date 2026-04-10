"""Utility functions for error handling and input validation.

Provides safe error formatting that never exposes secrets, and input
sanitization to prevent injection attacks in API filter expressions.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

# Strip characters that could break filter/query header expressions
_UNSAFE_FILTER_CHARS = re.compile(r"['\";()\\]")


def sanitize_filter_value(value: str) -> str:
    """Remove characters that could break Vision One API filter expressions.

    Strips characters like quotes, semicolons, parentheses, and backslashes
    that could be used for injection attacks in filter/query headers.

    Args:
        value: User-provided string to sanitize

    Returns:
        str: Sanitized string safe for use in API filters
    """
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
    """Check HTTP response status and parse JSON body.

    Raises HTTPStatusError for non-2xx responses. Handles 204 No Content
    by returning empty dict instead of attempting to parse missing JSON.

    Args:
        response: HTTP response to check

    Returns:
        dict | list: Parsed JSON response body, or {} for 204 responses

    Raises:
        httpx.HTTPStatusError: If response status is not 2xx
    """
    response.raise_for_status()
    if response.status_code == 204:
        return {}
    return response.json()


def check_multi_status(response: httpx.Response) -> list[Any]:
    """Check multi-status HTTP response (200 or 207) and parse JSON.

    Used for batch operations where some items may succeed and others fail.
    Status 207 (Multi-Status) indicates partial success.

    Args:
        response: HTTP response to check

    Returns:
        list: Parsed JSON response body (list of results)

    Raises:
        httpx.HTTPStatusError: If response status is not 200 or 207
    """
    if response.status_code not in (200, 207):
        response.raise_for_status()
    return response.json()
