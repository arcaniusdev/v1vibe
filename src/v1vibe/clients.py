from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx

import amaas.grpc.aio as amaas_aio

from v1vibe.config import Settings, load_settings


@dataclass
class AppContext:
    settings: Settings
    grpc_handle: Any
    http: httpx.AsyncClient


@asynccontextmanager
async def app_lifespan(server: Any) -> AsyncIterator[AppContext]:
    settings = load_settings()

    grpc_handle = amaas_aio.init_by_region(
        region=settings.region,
        api_key=settings.api_token,
    )
    http = httpx.AsyncClient(
        base_url=settings.base_url,
        headers={"Authorization": f"Bearer {settings.api_token}"},
        timeout=httpx.Timeout(60.0),
    )
    try:
        yield AppContext(settings=settings, grpc_handle=grpc_handle, http=http)
    finally:
        await amaas_aio.quit(grpc_handle)
        await http.aclose()
