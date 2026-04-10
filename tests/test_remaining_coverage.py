"""Additional tests to reach 60% coverage target."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import httpx


class TestSandboxOSErrorHandling:
    """Tests for sandbox error handling edge cases."""

    @pytest.mark.asyncio
    async def test_submit_file_os_error_paths(self, mock_app_context, tmp_path):
        """Test sandbox file submission OS error handling."""
        from v1vibe.tools.sandbox import submit_file

        # Test with file that becomes inaccessible during read
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"content")

        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = await submit_file(mock_app_context, str(test_file))

        assert "error" in result

    @pytest.mark.asyncio
    async def test_submit_url_empty_list(self, mock_app_context):
        """Test submitting empty URL list."""
        from v1vibe.tools.sandbox import submit_url

        result = await submit_url(mock_app_context, urls=[])

        assert "error" in result
        assert result["error"]["code"] == "InvalidInput"


class TestThreatIntelErrorPaths:
    """Tests for threat intelligence error paths."""

    @pytest.mark.asyncio
    async def test_check_suspicious_network_error(self, mock_app_context):
        """Test check_suspicious_objects network error."""
        from v1vibe.tools.threat_intel import check_suspicious_objects

        mock_app_context.http.get = AsyncMock(side_effect=httpx.ConnectError("Network down"))

        result = await check_suspicious_objects(
            mock_app_context,
            object_type="domain",
            value="test.com",
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_search_threat_indicators_exception(self, mock_app_context):
        """Test search_threat_indicators with exception."""
        from v1vibe.tools.threat_intel import search_threat_indicators, ThreatFeedCache
        from datetime import datetime, timezone

        # Mock cache that will cause error
        bad_cache = ThreatFeedCache(
            indicators=[{"id": "ind-1"}],  # Missing required fields
            last_updated_at=datetime.now(timezone.utc),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=bad_cache):
            result = await search_threat_indicators(mock_app_context, "test")

        # Should handle gracefully with error or empty result
        assert "cache_info" in result or "error" in result


class TestVulnerabilitiesEdgeCases:
    """Tests for vulnerabilities module edge cases."""

    @pytest.mark.asyncio
    async def test_get_cve_details_network_error(self, mock_app_context):
        """Test CVE details with network error."""
        from v1vibe.tools.vulnerabilities import get_cve_details

        mock_app_context.http.get = AsyncMock(side_effect=httpx.ReadTimeout("Timeout"))

        result = await get_cve_details(mock_app_context, cve_id="CVE-2023-12345")

        assert "error" in result


class TestConfigEdgeCases:
    """Tests for config module edge cases."""

    def test_load_settings_env_priority(self, monkeypatch):
        """Test that environment variables override config file."""
        from v1vibe.config import load_settings
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json
            json.dump({
                "api_token": "file-token-12345678901234567890",
                "region": "us-east-1",
            }, f)
            config_path = f.name

        try:
            # Set env vars
            monkeypatch.setenv("V1_API_TOKEN", "env-token-123456789012345678901234567890")
            monkeypatch.setenv("V1_REGION", "eu-central-1")

            with patch("v1vibe.config.CONFIG_FILE", Path(config_path)):
                settings = load_settings()

            # Env vars should take precedence
            assert settings.api_token == "env-token-123456789012345678901234567890"
            assert settings.region == "eu-central-1"
        finally:
            Path(config_path).unlink()

    def test_save_config_file_creates_directory(self, tmp_path, monkeypatch):
        """Test that save_config_file creates directory if missing."""
        from v1vibe.config import save_config_file

        new_dir = tmp_path / "newdir"
        config_file = new_dir / "config.json"

        with patch("v1vibe.config.CONFIG_DIR", new_dir):
            with patch("v1vibe.config.CONFIG_FILE", config_file):
                save_config_file(
                    api_token="test-token-12345678901234567890",
                    region="us-east-1",
                )

        assert new_dir.exists()
        assert config_file.exists()


class TestCliUtilityFunctions:
    """Tests for CLI utility functions."""

    def test_print_function(self):
        """Test _print outputs to stderr."""
        from v1vibe.cli import _print
        import sys
        from io import StringIO

        captured = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured

        try:
            _print("test message")
            output = captured.getvalue()
            assert "test message" in output
        finally:
            sys.stderr = old_stderr

    def test_input_function(self):
        """Test _input prompts on stderr and reads from stdin."""
        from v1vibe.cli import _input
        import sys
        from io import StringIO

        captured_err = StringIO()
        captured_in = StringIO("user input\n")
        old_stderr = sys.stderr
        old_stdin = sys.stdin

        sys.stderr = captured_err
        sys.stdin = captured_in

        try:
            result = _input("Enter value: ")
            assert result == "user input"
            assert "Enter value:" in captured_err.getvalue()
        finally:
            sys.stderr = old_stderr
            sys.stdin = old_stdin


class TestArtifactScannerNonDocker:
    """Tests for artifact scanner non-Docker paths."""

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path_rejected(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test artifact scanner rejects non-existent paths."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext
        from v1vibe.tools.artifact_scanner import scan_artifact

        # Binary mode (non-Docker)
        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=str(tmp_path / "tmas"),
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(
            ctx,
            artifact=str(tmp_path / "nonexistent"),
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidPath"


class TestClientCleanupPaths:
    """Tests for client cleanup edge cases."""

    @pytest.mark.asyncio
    async def test_lifespan_http_cleanup_error_suppressed(self, mock_settings):
        """Test that HTTP cleanup errors are suppressed."""
        from v1vibe.clients import app_lifespan

        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region"):
                with patch("v1vibe.clients.amaas_aio.quit"):
                    with patch("httpx.AsyncClient") as mock_client_class:
                        mock_http = AsyncMock()
                        # aclose raises error
                        mock_http.aclose.side_effect = Exception("HTTP cleanup failed")
                        mock_client_class.return_value = mock_http

                        # Should not propagate exception
                        async with app_lifespan(None) as ctx:
                            pass  # Context manager should handle cleanup error

    @pytest.mark.asyncio
    async def test_lifespan_grpc_cleanup_error_suppressed(self, mock_settings):
        """Test that gRPC cleanup errors are suppressed."""
        from v1vibe.clients import app_lifespan

        with patch("v1vibe.clients.load_settings", return_value=mock_settings):
            with patch("v1vibe.clients.amaas_aio.init_by_region") as mock_init:
                mock_handle = MagicMock()
                mock_init.return_value = mock_handle

                with patch("v1vibe.clients.amaas_aio.quit", side_effect=Exception("gRPC cleanup failed")):
                    with patch("httpx.AsyncClient") as mock_client_class:
                        mock_http = AsyncMock()
                        mock_client_class.return_value = mock_http

                        # Should not propagate exception
                        async with app_lifespan(None) as ctx:
                            pass  # Context manager should handle cleanup error
