"""Client lifecycle management for v1vibe.

Manages the lifespan of gRPC (File Security SDK) and HTTP (REST API) clients
with proper initialization and cleanup. Both clients share the same API token
and region configuration.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx

import amaas.grpc.aio as amaas_aio

from v1vibe.config import HTTP_TIMEOUT, Settings, load_settings


@dataclass
class AppContext:
    """Application context holding configuration and initialized clients.

    Attributes:
        settings: Configuration settings (API token, region, base URL, TMAS path)
        grpc_handle: File Security SDK gRPC handle for file scanning
        http: Async HTTP client for Vision One REST API calls
    """

    settings: Settings
    grpc_handle: Any
    http: httpx.AsyncClient


@asynccontextmanager
async def app_lifespan(server: Any) -> AsyncIterator[AppContext]:
    """Async context manager for initializing and cleaning up clients.

    Loads configuration, initializes both gRPC and HTTP clients, and ensures
    proper cleanup even if initialization partially fails.

    Args:
        server: MCP server instance (unused, required by FastMCP signature)

    Yields:
        AppContext: Initialized application context with settings and clients

    Example:
        async with app_lifespan(None) as ctx:
            result = await scan_file(ctx, "/path/to/file")
    """
    settings = load_settings()

    grpc_handle = None
    http = None
    try:
        grpc_handle = amaas_aio.init_by_region(
            region=settings.region,
            api_key=settings.api_token,
        )
        http = httpx.AsyncClient(
            base_url=settings.base_url,
            headers={"Authorization": f"Bearer {settings.api_token}"},
            timeout=httpx.Timeout(HTTP_TIMEOUT),
        )
        yield AppContext(settings=settings, grpc_handle=grpc_handle, http=http)
    finally:
        # Clean up clients even if initialization partially failed or usage errored
        # Try to close each client independently - one failure shouldn't prevent the other
        if http:
            try:
                await http.aclose()
            except Exception:
                # Don't propagate cleanup errors - just warn
                print("v1vibe: warning: failed to close HTTP client", file=sys.stderr)
        if grpc_handle:
            try:
                await amaas_aio.quit(grpc_handle)
            except Exception:
                # Don't propagate cleanup errors - just warn
                print("v1vibe: warning: failed to close gRPC channel", file=sys.stderr)
