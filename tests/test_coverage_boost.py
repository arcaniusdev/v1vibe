"""Additional targeted tests to boost coverage to 60%."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx


class TestSandboxReportSuspiciousObjects:
    """Tests for sandbox report suspicious objects handling."""

    @pytest.mark.asyncio
    async def test_get_report_with_suspicious_objects(self, mock_app_context):
        """Test getting report that includes suspicious objects."""
        from v1vibe.tools.sandbox import get_report

        # Report response
        report_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        report_response = httpx.Response(
            200,
            json={
                "id": "result-123",
                "riskLevel": "high",
                "detectionNames": ["Trojan"],
            },
            request=report_request,
        )

        # Suspicious objects response
        susp_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123/suspiciousObjects")
        susp_response = httpx.Response(
            200,
            json={
                "items": [
                    {"type": "domain", "value": "evil.com", "riskLevel": "high"},
                    {"type": "ip", "value": "1.2.3.4", "riskLevel": "medium"},
                ]
            },
            request=susp_request,
        )

        mock_app_context.http.get = AsyncMock(side_effect=[report_response, susp_response])

        result = await get_report(mock_app_context, result_id="result-123")

        assert result["riskLevel"] == "high"
        assert "suspiciousObjects" in result
        assert len(result["suspiciousObjects"]) == 2

    @pytest.mark.asyncio
    async def test_get_report_suspicious_objects_error_ignored(self, mock_app_context):
        """Test that suspicious objects fetch error doesn't break report."""
        from v1vibe.tools.sandbox import get_report

        # Report succeeds
        report_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        report_response = httpx.Response(
            200,
            json={
                "id": "result-123",
                "riskLevel": "low",
                "detectionNames": [],
            },
            request=report_request,
        )

        # Suspicious objects request fails
        susp_error = httpx.ConnectError("Network error")

        mock_app_context.http.get = AsyncMock(side_effect=[report_response, susp_error])

        result = await get_report(mock_app_context, result_id="result-123")

        # Report should still succeed even if suspicious objects fetch fails
        assert result["riskLevel"] == "low"


class TestThreatIntelCacheExpiry:
    """Tests for threat intelligence cache expiry logic."""

    @pytest.mark.asyncio
    async def test_ensure_cache_no_delta_when_empty(self, mock_app_context):
        """Test that empty expired cache does full fetch, not delta."""
        from v1vibe.tools.threat_intel import _ensure_feed_cache, ThreatFeedCache
        from datetime import datetime, timezone, timedelta

        # Empty expired cache (no indicators, but has last_updated_at)
        old_cache = ThreatFeedCache(
            indicators=[],
            last_updated_at=datetime.now(timezone.utc) - timedelta(hours=2),
            first_fetched_at=None,
            total_count=0,
        )

        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-1", "pattern": "test"},
                    ]
                }
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=old_cache):
            with patch("v1vibe.tools.threat_intel._save_cache_to_disk"):
                cache = await _ensure_feed_cache(mock_app_context)

        # Should do full fetch and set first_fetched_at
        assert cache.total_count == 1
        assert cache.first_fetched_at is not None


class TestSandboxSubmitFileWithArgs:
    """Tests for sandbox file submission with optional arguments."""

    @pytest.mark.asyncio
    async def test_submit_file_with_arguments(self, mock_app_context, tmp_path):
        """Test submitting file with command-line arguments."""
        from v1vibe.tools.sandbox import submit_file

        test_file = tmp_path / "script.ps1"
        test_file.write_bytes(b"script content")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/files/analyze")
        response = httpx.Response(
            202,
            json={"id": "task-123", "action": "Analyzing"},
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_file(
            mock_app_context,
            file_path=str(test_file),
            arguments="--ExecutionPolicy Bypass",
        )

        assert "id" in result
        # Verify arguments were base64 encoded and sent
        call_kwargs = mock_app_context.http.post.call_args[1]
        assert "data" in call_kwargs
        assert "arguments" in call_kwargs["data"]


class TestConfigLoadSettingsFailures:
    """Tests for config loading failure modes."""

    def test_load_settings_invalid_region_raises(self, tmp_path):
        """Test that invalid region in config raises RuntimeError."""
        from v1vibe.config import load_settings
        import json

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "api_token": "test-token-12345678901234567890",
            "region": "invalid-region-999",
        }))

        with patch("v1vibe.config.CONFIG_FILE", config_file):
            with pytest.raises(RuntimeError, match="Unknown region"):
                load_settings()


class TestSandboxQuotaHeader:
    """Tests for sandbox quota remaining header."""

    @pytest.mark.asyncio
    async def test_submit_file_includes_quota(self, mock_app_context, tmp_path):
        """Test that submit_file includes quota in response."""
        from v1vibe.tools.sandbox import submit_file

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"content")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/files/analyze")
        response = httpx.Response(
            202,
            json={"id": "task-123", "action": "Analyzing"},
            request=request,
            headers={"TMV1-Submission-Remaining-Count": "42"},
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_file(mock_app_context, str(test_file))

        assert "quotaRemaining" in result
        assert result["quotaRemaining"] == "42"


class TestThreatIntelPatternExtraction:
    """Tests for additional STIX pattern types."""

    def test_extract_directory_pattern(self):
        """Test extracting directory/file path pattern."""
        from v1vibe.tools.threat_intel import _extract_indicator_value

        ind_type, value = _extract_indicator_value("[directory:path = '/tmp/malware']")

        assert ind_type == "file_path"
        assert value == "/tmp/malware"

    def test_extract_email_message_pattern(self):
        """Test extracting email-message pattern."""
        from v1vibe.tools.threat_intel import _extract_indicator_value

        ind_type, value = _extract_indicator_value("[email-message:sender_ref.value = 'bad@evil.com']")

        assert ind_type == "email"
        assert value == "bad@evil.com"

    def test_extract_unknown_pattern_format(self):
        """Test handling unknown pattern format."""
        from v1vibe.tools.threat_intel import _extract_indicator_value

        # Pattern without brackets
        ind_type, value = _extract_indicator_value("not a valid STIX pattern")

        assert ind_type is None
        assert value is None

    def test_extract_pattern_no_value(self):
        """Test pattern with no value match."""
        from v1vibe.tools.threat_intel import _extract_indicator_value

        # Valid STIX type but no value
        ind_type, value = _extract_indicator_value("[domain-name:value]")

        assert ind_type is None
        assert value is None
