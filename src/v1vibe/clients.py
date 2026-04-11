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

from v1vibe.config import HTTP_TIMEOUT, Settings, load_settings

# Try to import File Security SDK - make it optional for compatibility
try:
    import amaas.grpc.aio as amaas_aio
    FILE_SECURITY_AVAILABLE = True
except ImportError as e:
    amaas_aio = None
    FILE_SECURITY_AVAILABLE = False
    import warnings
    warnings.warn(
        f"File Security SDK not available: {e}. "
        "File scanning will be disabled. Install with: pip install visionone-filesecurity",
        ImportWarning
    )


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
        # Initialize File Security SDK if available
        if FILE_SECURITY_AVAILABLE and amaas_aio:
            try:
                grpc_handle = amaas_aio.init_by_region(
                    region=settings.region,
                    api_key=settings.api_token,
                )
            except Exception as e:
                print(f"v1vibe: warning: File Security initialization failed: {e}", file=sys.stderr)
                print("v1vibe: File scanning will be disabled. Run 'v1vibe status' for details.", file=sys.stderr)

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
        if grpc_handle and amaas_aio:
            try:
                await amaas_aio.quit(grpc_handle)
            except Exception:
                # Don't propagate cleanup errors - just warn
                print("v1vibe: warning: failed to close gRPC channel", file=sys.stderr)
