"""Final tests to reach exactly 60% coverage."""

import pytest
from unittest.mock import patch, AsyncMock
import httpx
import json


class TestConfigWriteError:
    """Tests for config file write errors."""

    def test_save_config_oserror(self, tmp_path):
        """Test save_config_file raises RuntimeError on OSError."""
        from v1vibe.config import save_config_file
        from pathlib import Path

        config_file = tmp_path / "config.json"

        with patch("v1vibe.config.CONFIG_FILE", config_file):
            with patch("v1vibe.config.CONFIG_DIR", tmp_path):
                # Make write_text raise OSError
                with patch.object(Path, "write_text", side_effect=OSError("Disk full")):
                    with pytest.raises(RuntimeError, match="Failed to save config"):
                        save_config_file(
                            api_token="test-token-12345678901234567890",
                            region="us-east-1",
                        )


class TestThreatIntelAPIError:
    """Tests for threat intelligence API error paths."""

    @pytest.mark.asyncio
    async def test_fetch_threat_feed_api_error(self, mock_app_context):
        """Test _fetch_threat_feed with API returning error."""
        from v1vibe.tools.threat_intel import _fetch_threat_feed

        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        # API returns 200 but with error in response body (some APIs do this)
        response = httpx.Response(
            200,
            json={"error": {"code": "BadRequest", "message": "Invalid parameters"}},
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        # Should raise exception on line 154
        with pytest.raises(Exception, match="API error"):
            await _fetch_threat_feed(mock_app_context)


class TestThreatIntelOptionalFields:
    """Tests for threat intelligence indicators with optional fields."""

    @pytest.mark.asyncio
    async def test_search_with_threat_types_and_kill_chain(self, mock_app_context):
        """Test search_threat_indicators with indicators containing optional fields."""
        from v1vibe.tools.threat_intel import search_threat_indicators, ThreatFeedCache
        from datetime import datetime, timezone

        # Create cache with indicator that has threat_types and kill_chain_phases
        cache = ThreatFeedCache(
            indicators=[
                {
                    "id": "indicator--123",
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "threat_types": ["malware", "phishing"],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ],
                }
            ],
            last_updated_at=datetime.now(timezone.utc),
            first_fetched_at=datetime.now(timezone.utc),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=cache):
            with patch("v1vibe.tools.threat_intel._ensure_feed_cache", return_value=cache):
                result = await search_threat_indicators(mock_app_context, "evil.com")

        assert result["found"] is True
        assert len(result["matches"]) == 1
        # Check that optional fields are included (lines 428, 430)
        match = result["matches"][0]
        assert "threat_types" in match
        assert match["threat_types"] == ["malware", "phishing"]
        assert "kill_chain_phases" in match
        assert len(match["kill_chain_phases"]) == 1


class TestThreatIntelExceptionHandling:
    """Tests for threat intelligence exception handling."""

    @pytest.mark.asyncio
    async def test_search_unhandled_exception(self, mock_app_context):
        """Test search_threat_indicators outer exception handler."""
        from v1vibe.tools.threat_intel import search_threat_indicators

        # Make _ensure_feed_cache raise an unexpected exception
        with patch("v1vibe.tools.threat_intel._ensure_feed_cache", side_effect=Exception("Unexpected error")):
            result = await search_threat_indicators(mock_app_context, "test.com")

        # Should catch exception on lines 452-453 and return error
        assert "error" in result
        assert "Unexpected error" in result["error"]["message"]


class TestSandboxExceptionHandling:
    """Tests for sandbox exception handling."""

    @pytest.mark.asyncio
    async def test_get_report_outer_exception(self, mock_app_context):
        """Test get_report outer exception handler."""
        from v1vibe.tools.sandbox import get_report

        # Make HTTP get raise unexpected exception
        mock_app_context.http.get = AsyncMock(side_effect=Exception("Catastrophic failure"))

        result = await get_report(mock_app_context, result_id="result-123")

        # Should catch exception on lines 217-218
        assert "error" in result
        assert "Catastrophic failure" in result["error"]["message"]


class TestArtifactScannerPathEdgeCases:
    """Tests for artifact scanner path validation edge cases."""

    def test_validate_path_resolution_error(self):
        """Test path resolution error handling."""
        from v1vibe.tools.artifact_scanner import _validate_artifact_path
        from pathlib import Path

        # Make resolve() raise RuntimeError (covers lines 63-64)
        with patch.object(Path, "resolve", side_effect=RuntimeError("Symlink loop")):
            with pytest.raises(ValueError, match="Invalid path"):
                _validate_artifact_path("/some/path")
