"""Tests for threat intelligence cache persistence and API fetching."""

import pytest
import httpx
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch, mock_open
from v1vibe.tools.threat_intel import (
    _get_cache_path,
    _load_cache_from_disk,
    _save_cache_to_disk,
    _fetch_threat_feed,
    _ensure_feed_cache,
    ThreatFeedCache,
)


class TestCachePath:
    """Tests for cache path resolution."""

    def test_get_cache_path(self):
        """Test cache path is in ~/.v1vibe."""
        cache_path = _get_cache_path()
        assert str(cache_path).endswith(".v1vibe/threat_feed_cache.json")
        assert cache_path.parent.name == ".v1vibe"


class TestCacheDiskIO:
    """Tests for cache loading and saving."""

    def test_load_cache_no_file(self, tmp_path):
        """Test loading when cache file doesn't exist."""
        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=tmp_path / "nonexistent.json"):
            cache = _load_cache_from_disk()

        assert cache.indicators == []
        assert cache.total_count == 0
        assert cache.last_updated_at is None

    def test_load_cache_valid_file(self, tmp_path):
        """Test loading valid cache file."""
        cache_file = tmp_path / "cache.json"
        now = datetime.now(timezone.utc)
        cache_data = {
            "indicators": [{"id": "ind-1", "pattern": "[domain-name:value = 'evil.com']"}],
            "first_fetched_at": now.isoformat(),
            "last_updated_at": now.isoformat(),
            "total_count": 1,
        }
        cache_file.write_text(json.dumps(cache_data))

        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=cache_file):
            cache = _load_cache_from_disk()

        assert len(cache.indicators) == 1
        assert cache.total_count == 1
        assert cache.last_updated_at is not None

    def test_load_cache_corrupted_file(self, tmp_path):
        """Test loading corrupted cache file."""
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("{invalid json")

        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=cache_file):
            cache = _load_cache_from_disk()

        # Should return empty cache on corruption
        assert cache.indicators == []
        assert cache.total_count == 0

    def test_save_cache_to_disk(self, tmp_path):
        """Test saving cache to disk."""
        cache_file = tmp_path / "cache.json"
        now = datetime.now(timezone.utc)

        cache = ThreatFeedCache(
            indicators=[{"id": "ind-1", "pattern": "test"}],
            first_fetched_at=now,
            last_updated_at=now,
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=cache_file):
            _save_cache_to_disk(cache)

        assert cache_file.exists()
        loaded_data = json.loads(cache_file.read_text())
        assert loaded_data["total_count"] == 1
        assert len(loaded_data["indicators"]) == 1

    def test_save_cache_atomic_write(self, tmp_path):
        """Test that cache is written atomically."""
        cache_file = tmp_path / "cache.json"
        temp_file = cache_file.with_suffix(".tmp")

        cache = ThreatFeedCache(
            indicators=[],
            total_count=0,
        )

        with patch("v1vibe.tools.threat_intel._get_cache_path", return_value=cache_file):
            _save_cache_to_disk(cache)

        # Temp file should not exist (renamed to final)
        assert not temp_file.exists()
        assert cache_file.exists()


class TestFetchThreatFeed:
    """Tests for API fetching of threat feed."""

    @pytest.mark.asyncio
    async def test_fetch_full_feed(self, mock_app_context):
        """Test fetching full 365-day feed."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-1", "pattern": "[domain-name:value = 'evil.com']"},
                        {"type": "other", "id": "obj-1"},  # Should be filtered out
                    ]
                }
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        indicators = await _fetch_threat_feed(mock_app_context)

        assert len(indicators) == 1  # Only indicator type
        assert indicators[0]["id"] == "ind-1"

    @pytest.mark.asyncio
    async def test_fetch_delta_update(self, mock_app_context):
        """Test fetching delta update since last refresh."""
        start_date = datetime.now(timezone.utc) - timedelta(hours=2)

        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-new", "pattern": "[url:value = 'http://new.com']"},
                    ]
                }
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        indicators = await _fetch_threat_feed(mock_app_context, start_date=start_date)

        assert len(indicators) == 1
        assert indicators[0]["id"] == "ind-new"
        # Verify API was called with correct date range
        call_url = mock_app_context.http.get.call_args[0][0]
        assert "startDateTime" in call_url

    @pytest.mark.asyncio
    async def test_fetch_with_pagination(self, mock_app_context):
        """Test fetching with multiple pages."""
        page1_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        page1_response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-1", "pattern": "test1"},
                    ]
                },
                "nextLink": "https://api.example.com/v3.0/threatintel/feedIndicators?page=2",
            },
            request=page1_request,
        )

        page2_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators?page=2")
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
        assert indicators[0]["id"] == "ind-1"
        assert indicators[1]["id"] == "ind-2"
        # Verify both pages were fetched
        assert mock_app_context.http.get.call_count == 2

    @pytest.mark.asyncio
    async def test_fetch_api_error(self, mock_app_context):
        """Test handling API error during fetch."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            500,
            json={"error": {"code": "InternalError", "message": "Server error"}},
            request=request,
        )
        error = httpx.HTTPStatusError("Server Error", request=request, response=response)
        mock_app_context.http.get = AsyncMock(side_effect=error)

        # check_response will raise HTTPStatusError which the function catches
        with pytest.raises(Exception, match="Server Error"):
            await _fetch_threat_feed(mock_app_context)


class TestEnsureFeedCache:
    """Tests for cache management and refresh logic."""

    @pytest.mark.asyncio
    async def test_ensure_cache_fresh(self, mock_app_context):
        """Test that fresh cache is not refreshed."""
        fresh_cache = ThreatFeedCache(
            indicators=[{"id": "ind-1"}],
            last_updated_at=datetime.now(timezone.utc) - timedelta(minutes=30),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=fresh_cache):
            cache = await _ensure_feed_cache(mock_app_context)

        assert cache.total_count == 1
        # API should not be called for fresh cache
        mock_app_context.http.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_ensure_cache_expired_delta_update(self, mock_app_context):
        """Test delta update for expired cache."""
        old_cache = ThreatFeedCache(
            indicators=[{"id": "ind-old"}],
            last_updated_at=datetime.now(timezone.utc) - timedelta(hours=2),
            first_fetched_at=datetime.now(timezone.utc) - timedelta(days=1),
            total_count=1,
        )

        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-new", "pattern": "new"},
                    ]
                }
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=old_cache):
            with patch("v1vibe.tools.threat_intel._save_cache_to_disk") as mock_save:
                cache = await _ensure_feed_cache(mock_app_context)

        # Should have both old and new indicators
        assert cache.total_count == 2
        # Cache should be saved
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_cache_first_time(self, mock_app_context):
        """Test full fetch on first cache creation."""
        empty_cache = ThreatFeedCache()

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

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=empty_cache):
            with patch("v1vibe.tools.threat_intel._save_cache_to_disk") as mock_save:
                cache = await _ensure_feed_cache(mock_app_context)

        assert cache.total_count == 1
        assert cache.first_fetched_at is not None
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_cache_deduplication(self, mock_app_context):
        """Test that duplicate indicators are not added."""
        old_cache = ThreatFeedCache(
            indicators=[{"id": "ind-1", "pattern": "test"}],
            last_updated_at=datetime.now(timezone.utc) - timedelta(hours=2),
            first_fetched_at=datetime.now(timezone.utc) - timedelta(days=1),
            total_count=1,
        )

        # API returns same indicator again
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/feedIndicators")
        response = httpx.Response(
            200,
            json={
                "bundle": {
                    "objects": [
                        {"type": "indicator", "id": "ind-1", "pattern": "test"},  # Duplicate
                    ]
                }
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=old_cache):
            with patch("v1vibe.tools.threat_intel._save_cache_to_disk"):
                cache = await _ensure_feed_cache(mock_app_context)

        # Should still have only 1 indicator (deduplicated)
        assert cache.total_count == 1

    @pytest.mark.asyncio
    async def test_ensure_cache_session_persistence(self, mock_app_context):
        """Test that cache is stored in AppContext for session."""
        fresh_cache = ThreatFeedCache(
            indicators=[],
            last_updated_at=datetime.now(timezone.utc),
            total_count=0,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=fresh_cache):
            cache1 = await _ensure_feed_cache(mock_app_context)
            cache2 = await _ensure_feed_cache(mock_app_context)

        # Should be same object from session cache
        assert cache1 is cache2
