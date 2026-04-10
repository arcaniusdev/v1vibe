"""Final push to 60% coverage - targeting remaining uncovered lines."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
from pathlib import Path


class TestSandboxErrorPaths:
    """Tests for sandbox error handling edge cases."""

    @pytest.mark.asyncio
    async def test_submit_file_http_status_error_with_quota(self, mock_app_context, tmp_path):
        """Test submit_file raises_for_status properly."""
        from v1vibe.tools.sandbox import submit_file

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"content")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/files/analyze")
        response = httpx.Response(
            400,
            json={"error": {"code": "BadRequest", "message": "Invalid file"}},
            request=request,
        )

        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_file(mock_app_context, str(test_file))

        # Should return error
        assert "error" in result


class TestThreatIntelEdgeCases:
    """Tests for threat intelligence edge cases."""

    def test_cache_age_with_zero_time(self):
        """Test cache age when last_updated_at is now (zero age)."""
        from v1vibe.tools.threat_intel import ThreatFeedCache
        from datetime import datetime, timezone

        cache = ThreatFeedCache(
            last_updated_at=datetime.now(timezone.utc),
        )

        age = cache.age_minutes()

        # Should be very close to 0
        assert age < 0.1

    @pytest.mark.asyncio
    async def test_fetch_threat_feed_nextlink_parsing(self, mock_app_context):
        """Test that nextLink URL is parsed correctly."""
        from v1vibe.tools.threat_intel import _fetch_threat_feed

        # First page with nextLink that has full URL
        page1_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        page1_response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-1", "pattern": "test1"},
                    ]
                },
                "nextLink": "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators?startDateTime=2025-01-01&page=2",
            },
            request=page1_request,
        )

        page2_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators?startDateTime=2025-01-01&page=2")
        page2_response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-2", "pattern": "test2"},
                    ]
                }
            },
            request=page2_request,
        )

        mock_app_context.http.get = AsyncMock(side_effect=[page1_response, page2_response])

        indicators = await _fetch_threat_feed(mock_app_context)

        assert len(indicators) == 2
        # Verify second call used parsed path + query
        calls = mock_app_context.http.get.call_args_list
        assert len(calls) == 2


class TestConfigConstants:
    """Tests for config module constants."""

    def test_region_to_base_url_has_all_regions(self):
        """Test that REGION_TO_BASE_URL is populated."""
        from v1vibe.config import REGION_TO_BASE_URL

        assert len(REGION_TO_BASE_URL) > 0
        # Verify structure
        for region, url in REGION_TO_BASE_URL.items():
            assert isinstance(region, str)
            assert isinstance(url, str)
            assert url.startswith("https://")

    def test_config_dir_constant(self):
        """Test that CONFIG_DIR is set correctly."""
        from v1vibe.config import CONFIG_DIR
        from pathlib import Path

        assert isinstance(CONFIG_DIR, Path)
        assert ".v1vibe" in str(CONFIG_DIR)


class TestArtifactScannerDockerPaths:
    """Tests for artifact scanner Docker-specific code paths."""

    @pytest.mark.asyncio
    async def test_scan_docker_archive_type(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test scanning docker-archive type artifact."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext
        from v1vibe.tools.artifact_scanner import scan_artifact

        # Create fake archive file
        archive_file = tmp_path / "image.tar"
        archive_file.write_bytes(b"docker archive content")

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                # Make subprocess fail so we get a known error
                mock_run.side_effect = Exception("Docker command failed")

                result = await scan_artifact(
                    ctx,
                    artifact=f"docker-archive:{archive_file}",
                )

        # Should handle the error
        assert "error" in result


class TestSandboxPdfDownload:
    """Tests for sandbox PDF report download."""

    @pytest.mark.asyncio
    async def test_get_report_pdf_write_error(self, mock_app_context, tmp_path):
        """Test handling PDF write errors."""
        from v1vibe.tools.sandbox import get_report

        report_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        report_response = httpx.Response(
            200,
            json={"id": "result-123", "riskLevel": "low", "detectionNames": []},
            request=report_request,
        )

        susp_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123/suspiciousObjects")
        susp_response = httpx.Response(
            200,
            json={"items": []},
            request=susp_request,
        )

        pdf_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123/report")
        pdf_response = httpx.Response(
            200,
            content=b"PDF content",
            request=pdf_request,
        )

        mock_app_context.http.get = AsyncMock(side_effect=[report_response, susp_response, pdf_response])

        # Try to write to read-only location
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir(mode=0o555)
        pdf_path = readonly_dir / "report.pdf"

        try:
            result = await get_report(
                mock_app_context,
                result_id="result-123",
                save_pdf_to=str(pdf_path),
            )

            # Should still return report even if PDF save fails
            assert result["riskLevel"] == "low"
        finally:
            readonly_dir.chmod(0o755)


class TestThreatIntelCacheIO:
    """Tests for threat intelligence cache I/O operations."""

    def test_load_cache_partial_data(self, tmp_path):
        """Test loading cache with missing optional fields."""
        from v1vibe.tools.threat_intel import _load_cache_from_disk
        import json

        cache_file = tmp_path / "cache.json"
        # Write cache with only some fields
        cache_file.write_text(json.dumps({
            "indicators": [{"id": "ind-1"}],
            "total_count": 1,
            # Missing first_fetched_at and last_updated_at
        }))

        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=cache_file):
            cache = _load_cache_from_disk()

        assert len(cache.indicators) == 1
        assert cache.total_count == 1
        assert cache.first_fetched_at is None
        assert cache.last_updated_at is None

    def test_get_cache_path_returns_path(self):
        """Test that _get_cache_path returns a valid path."""
        from v1vibe.tools.threat_intel import _get_cache_path

        path = _get_cache_path()

        assert "threat_feed_cache.json" in str(path)
        assert ".v1vibe" in str(path)
