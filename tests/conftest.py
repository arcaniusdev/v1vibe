"""Pytest configuration and shared fixtures."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from v1vibe.config import Settings
from v1vibe.clients import AppContext


@pytest.fixture
def mock_settings():
    """Mock Settings object for testing."""
    return Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path="/usr/local/bin/tmas",
    )


@pytest.fixture
def mock_grpc_handle():
    """Mock gRPC handle for file security SDK."""
    return MagicMock()


@pytest.fixture
def mock_http_client():
    """Mock httpx.AsyncClient for REST API calls."""
    client = AsyncMock()
    # Set up common response patterns
    client.get = AsyncMock()
    client.post = AsyncMock()
    return client


@pytest.fixture
def mock_app_context(mock_settings, mock_grpc_handle, mock_http_client):
    """Mock AppContext with all dependencies."""
    return AppContext(
        settings=mock_settings,
        grpc_handle=mock_grpc_handle,
        http=mock_http_client,
    )
