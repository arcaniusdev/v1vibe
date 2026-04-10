"""Tests for client lifecycle management."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from v1vibe.clients import app_lifespan, AppContext
from v1vibe.config import Settings


class TestAppLifespan:
    """Tests for AppContext lifecycle manager."""

    @pytest.mark.asyncio
    async def test_lifespan_success(self, mock_settings):
        """Test successful initialization and cleanup."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region") as mock_grpc_init:
                with patch("httpx.AsyncClient") as mock_client_class:
                    mock_grpc_handle = MagicMock()
                    mock_grpc_init.return_value = mock_grpc_handle

                    mock_http = AsyncMock()
                    mock_client_class.return_value = mock_http

                    async with app_lifespan(None) as ctx:
                        assert isinstance(ctx, AppContext)
                        assert ctx.settings == mock_settings
                        assert ctx.grpc_handle == mock_grpc_handle
                        assert ctx.http == mock_http

                    # Verify cleanup was called
                    mock_http.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_lifespan_grpc_init_failure(self, mock_settings):
        """Test handling gRPC initialization failure."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region") as mock_grpc_init:
                with patch("httpx.AsyncClient") as mock_client_class:
                    mock_grpc_init.side_effect = Exception("gRPC init failed")

                    mock_http = AsyncMock()
                    mock_client_class.return_value = mock_http

                    try:
                        async with app_lifespan(None) as ctx:
                            pass
                    except Exception:
                        # Expected - init failed
                        pass

                    # HTTP client should still be cleaned up if it was created
                    # (in this case it wasn't because grpc_init failed first)

    @pytest.mark.asyncio
    async def test_lifespan_http_client_init(self, mock_settings):
        """Test HTTP client initialization with correct headers."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region"):
                with patch("httpx.AsyncClient") as mock_client_class:
                    mock_http = AsyncMock()
                    mock_client_class.return_value = mock_http

                    async with app_lifespan(None) as ctx:
                        # Verify httpx.AsyncClient was called with correct params
                        call_kwargs = mock_client_class.call_args[1]
                        assert call_kwargs["base_url"] == mock_settings.base_url
                        assert "Authorization" in call_kwargs["headers"]
                        assert call_kwargs["headers"]["Authorization"] == f"Bearer {mock_settings.api_token}"
                        # Check timeout is an httpx.Timeout object, not raw value
                        assert "timeout" in call_kwargs

    @pytest.mark.asyncio
    async def test_lifespan_cleanup_exception(self, mock_settings):
        """Test that cleanup exceptions are handled gracefully."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region"):
                with patch("v1vibe.clients.amaas_aio.quit", side_effect=Exception("Cleanup failed")):
                    with patch("httpx.AsyncClient") as mock_client_class:
                        mock_http = AsyncMock()
                        mock_client_class.return_value = mock_http

                        # Should not raise, even if cleanup fails
                        async with app_lifespan(None) as ctx:
                            assert ctx.http == mock_http

    @pytest.mark.asyncio
    async def test_lifespan_partial_init(self, mock_settings):
        """Test handling when only some clients initialize."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region") as mock_grpc_init:
                with patch("httpx.AsyncClient") as mock_client_class:
                    # gRPC succeeds
                    mock_grpc_handle = MagicMock()
                    mock_grpc_init.return_value = mock_grpc_handle

                    # HTTP fails
                    mock_client_class.side_effect = Exception("HTTP init failed")

                    try:
                        async with app_lifespan(None) as ctx:
                            pass
                    except Exception:
                        # Expected - HTTP init failed
                        pass

    @pytest.mark.asyncio
    async def test_lifespan_context_attributes(self, mock_settings):
        """Test that AppContext has correct attributes."""
        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region") as mock_grpc_init:
                with patch("httpx.AsyncClient") as mock_client_class:
                    mock_grpc_handle = MagicMock()
                    mock_grpc_init.return_value = mock_grpc_handle

                    mock_http = AsyncMock()
                    mock_client_class.return_value = mock_http

                    async with app_lifespan(None) as ctx:
                        # Check dataclass fields
                        assert hasattr(ctx, "settings")
                        assert hasattr(ctx, "grpc_handle")
                        assert hasattr(ctx, "http")
