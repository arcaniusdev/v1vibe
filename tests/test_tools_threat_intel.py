"""Tests for threat intelligence tools."""

import pytest
import httpx
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch
from v1vibe.tools.threat_intel import (
    check_suspicious_objects,
    search_threat_indicators,
    _extract_indicator_value,
    ThreatFeedCache,
    VALID_TYPES,
    VALID_RISK_LEVELS,
    FEED_CACHE_TTL_SECONDS,
)


class TestSuspiciousObjects:
    """Tests for suspicious objects lookup (tenant blocklist)."""

    @pytest.mark.asyncio
    async def test_check_domain(self, mock_app_context):
        """Test checking a domain in tenant blocklist."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/suspiciousObjects")
        response = httpx.Response(
            200,
            json={
                "items": [
                    {
                        "type": "domain",
                        "domain": "evil.com",
                        "riskLevel": "high",
                        "scanAction": "block",
                    }
                ]
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await check_suspicious_objects(
            mock_app_context,
            object_type="domain",
            value="evil.com",
        )

        assert "items" in result
        assert len(result["items"]) == 1
        assert result["items"][0]["domain"] == "evil.com"

    @pytest.mark.asyncio
    async def test_check_url(self, mock_app_context):
        """Test checking a URL."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/suspiciousObjects")
        response = httpx.Response(
            200,
            json={"items": []},
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await check_suspicious_objects(
            mock_app_context,
            object_type="url",
            value="https://example.com/path",
        )

        assert result["items"] == []

    @pytest.mark.asyncio
    async def test_check_invalid_type(self, mock_app_context):
        """Test checking with invalid object type."""
        result = await check_suspicious_objects(
            mock_app_context,
            object_type="invalid",
            value="test",
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidInput"
        assert "invalid" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_check_with_risk_level(self, mock_app_context):
        """Test checking with risk level filter."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/suspiciousObjects")
        response = httpx.Response(
            200,
            json={"items": []},
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await check_suspicious_objects(
            mock_app_context,
            object_type="ip",
            value="1.2.3.4",
            risk_level="high",
        )

        # Should succeed with risk_level filter
        assert "items" in result

    @pytest.mark.asyncio
    async def test_check_invalid_risk_level(self, mock_app_context):
        """Test checking with invalid risk level."""
        result = await check_suspicious_objects(
            mock_app_context,
            object_type="ip",
            value="1.2.3.4",
            risk_level="critical",  # Not valid
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidInput"
        assert "critical" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_check_file_hash_sha256(self, mock_app_context):
        """Test checking a SHA256 file hash."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/threatintel/suspiciousObjects")
        response = httpx.Response(
            200,
            json={"items": []},
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await check_suspicious_objects(
            mock_app_context,
            object_type="fileSha256",
            value="abc123" * 10,
        )

        assert "items" in result

    def test_valid_types_constant(self):
        """Test that VALID_TYPES contains expected values."""
        assert "url" in VALID_TYPES
        assert "domain" in VALID_TYPES
        assert "ip" in VALID_TYPES
        assert "fileSha1" in VALID_TYPES
        assert "fileSha256" in VALID_TYPES
        assert "senderMailAddress" in VALID_TYPES

    def test_valid_risk_levels_constant(self):
        """Test that VALID_RISK_LEVELS contains expected values."""
        assert "high" in VALID_RISK_LEVELS
        assert "medium" in VALID_RISK_LEVELS
        assert "low" in VALID_RISK_LEVELS


class TestThreatFeedCache:
    """Tests for threat feed cache data structure."""

    def test_cache_is_expired_no_update(self):
        """Test that cache with no update time is expired."""
        cache = ThreatFeedCache()
        assert cache.is_expired() is True

    def test_cache_is_expired_old(self):
        """Test that old cache is expired."""
        old_time = datetime.now(timezone.utc) - timedelta(seconds=FEED_CACHE_TTL_SECONDS + 100)
        cache = ThreatFeedCache(last_updated_at=old_time)
        assert cache.is_expired() is True

    def test_cache_is_not_expired_fresh(self):
        """Test that fresh cache is not expired."""
        fresh_time = datetime.now(timezone.utc) - timedelta(seconds=100)
        cache = ThreatFeedCache(last_updated_at=fresh_time)
        assert cache.is_expired() is False

    def test_cache_age_minutes(self):
        """Test cache age calculation."""
        time_5min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        cache = ThreatFeedCache(last_updated_at=time_5min_ago)
        age = cache.age_minutes()
        assert 4.9 < age < 5.1  # Allow small tolerance

    def test_cache_age_no_update(self):
        """Test age when never updated."""
        cache = ThreatFeedCache()
        assert cache.age_minutes() == 0.0

    def test_cache_total_count(self):
        """Test cache total count tracking."""
        cache = ThreatFeedCache(
            indicators=[{"id": "1"}, {"id": "2"}],
            total_count=2,
        )
        assert cache.total_count == 2


class TestIndicatorExtraction:
    """Tests for STIX pattern extraction."""

    def test_extract_domain(self):
        """Test extracting domain from STIX pattern."""
        ind_type, value = _extract_indicator_value("[domain-name:value = 'evil.com']")
        assert ind_type == "domain"
        assert value == "evil.com"

    def test_extract_url(self):
        """Test extracting URL from STIX pattern."""
        ind_type, value = _extract_indicator_value("[url:value = 'http://evil.com/malware']")
        assert ind_type == "url"
        assert value == "http://evil.com/malware"

    def test_extract_ipv4(self):
        """Test extracting IPv4 from STIX pattern."""
        ind_type, value = _extract_indicator_value("[ipv4-addr:value = '1.2.3.4']")
        assert ind_type == "ip"
        assert value == "1.2.3.4"

    def test_extract_ipv6(self):
        """Test extracting IPv6 from STIX pattern."""
        ind_type, value = _extract_indicator_value("[ipv6-addr:value = '2001:db8::1']")
        assert ind_type == "ip"
        assert value == "2001:db8::1"

    def test_extract_file_hash_sha256(self):
        """Test extracting SHA256 file hash."""
        pattern = "[file:hashes.SHA256 = 'abc123def456']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "file_hash_sha256"
        assert value == "abc123def456"

    def test_extract_file_hash_sha1(self):
        """Test extracting SHA1 file hash."""
        pattern = "[file:hashes.SHA1 = 'abc123']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "file_hash_sha1"
        assert value == "abc123"

    def test_extract_file_hash_md5(self):
        """Test extracting MD5 file hash."""
        pattern = "[file:hashes.MD5 = 'abc123']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "file_hash_md5"
        assert value == "abc123"

    def test_extract_email(self):
        """Test extracting email address."""
        ind_type, value = _extract_indicator_value("[email-addr:value = 'bad@evil.com']")
        assert ind_type == "email"
        assert value == "bad@evil.com"

    def test_extract_registry_key(self):
        """Test extracting Windows registry key."""
        pattern = "[windows-registry-key:key = 'HKLM\\\\Software\\\\Malware']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "registry_key"
        assert value == "HKLM\\\\Software\\\\Malware"

    def test_extract_mutex(self):
        """Test extracting mutex."""
        pattern = "[mutex:name = 'Global\\\\MalwareMutex']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "mutex"
        assert value == "Global\\\\MalwareMutex"

    def test_extract_network_traffic(self):
        """Test extracting network traffic destination."""
        pattern = "[network-traffic:dst_ref.value = 'evil.com']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "network_traffic_dest"
        assert value == "evil.com"

    def test_extract_file_name(self):
        """Test extracting file name."""
        pattern = "[file:name = 'malware.exe']"
        ind_type, value = _extract_indicator_value(pattern)
        assert ind_type == "file_name"
        assert value == "malware.exe"

    def test_extract_invalid_pattern(self):
        """Test extracting from invalid pattern."""
        ind_type, value = _extract_indicator_value("not a valid pattern")
        assert ind_type is None
        assert value is None

    def test_extract_hostname(self):
        """Test extracting hostname."""
        ind_type, value = _extract_indicator_value("[hostname:value = 'malicious-host']")
        assert ind_type == "hostname"
        assert value == "malicious-host"

    def test_extract_process(self):
        """Test extracting process name."""
        ind_type, value = _extract_indicator_value("[process:name = 'malware.exe']")
        assert ind_type == "process"
        assert value == "malware.exe"


class TestSearchThreatIndicators:
    """Tests for threat intelligence feed search."""

    @pytest.mark.asyncio
    async def test_search_domain_found(self, mock_app_context):
        """Test searching for a domain that exists in cache."""
        # Mock the cache loading
        mock_cache = ThreatFeedCache(
            indicators=[
                {
                    "id": "indicator--123",
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "valid_from": "2025-01-01T00:00:00.000Z",
                    "valid_until": "2026-01-01T00:00:00.000Z",
                    "name": "Malicious domain",
                    "labels": ["malicious-activity"],
                }
            ],
            last_updated_at=datetime.now(timezone.utc),
            first_fetched_at=datetime.now(timezone.utc),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=mock_cache):
            result = await search_threat_indicators(
                mock_app_context,
                indicator_value="evil.com",
            )

        assert result["found"] is True
        assert result["match_count"] == 1
        assert len(result["matches"]) == 1
        assert result["matches"][0]["pattern"] == "[domain-name:value = 'evil.com']"
        assert result["cache_info"]["total_indicators"] == 1

    @pytest.mark.asyncio
    async def test_search_domain_not_found(self, mock_app_context):
        """Test searching for a domain that doesn't exist."""
        mock_cache = ThreatFeedCache(
            indicators=[],
            last_updated_at=datetime.now(timezone.utc),
            total_count=0,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=mock_cache):
            result = await search_threat_indicators(
                mock_app_context,
                indicator_value="safe.com",
            )

        assert result["found"] is False
        assert result["match_count"] == 0
        assert result["matches"] == []

    @pytest.mark.asyncio
    async def test_search_case_insensitive(self, mock_app_context):
        """Test that search is case-insensitive."""
        mock_cache = ThreatFeedCache(
            indicators=[
                {
                    "id": "indicator--123",
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "valid_from": "2025-01-01T00:00:00.000Z",
                    "name": "Test",
                    "labels": [],
                }
            ],
            last_updated_at=datetime.now(timezone.utc),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=mock_cache):
            result = await search_threat_indicators(
                mock_app_context,
                indicator_value="EVIL.COM",  # Uppercase
            )

        assert result["found"] is True
        assert result["match_count"] == 1

    @pytest.mark.asyncio
    async def test_search_file_hash(self, mock_app_context):
        """Test searching for a file hash."""
        mock_cache = ThreatFeedCache(
            indicators=[
                {
                    "id": "indicator--456",
                    "type": "indicator",
                    "pattern": "[file:hashes.SHA256 = 'abc123']",
                    "valid_from": "2025-01-01T00:00:00.000Z",
                    "name": "Malware hash",
                    "labels": ["malware"],
                }
            ],
            last_updated_at=datetime.now(timezone.utc),
            total_count=1,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=mock_cache):
            result = await search_threat_indicators(
                mock_app_context,
                indicator_value="abc123",
            )

        assert result["found"] is True
        assert result["matches"][0]["indicator_subtype"] == "file_hash_sha256"

    @pytest.mark.asyncio
    async def test_search_includes_cache_info(self, mock_app_context):
        """Test that results include cache metadata."""
        now = datetime.now(timezone.utc)
        mock_cache = ThreatFeedCache(
            indicators=[],
            last_updated_at=now,
            first_fetched_at=now,
            total_count=0,
        )

        with patch("v1vibe.tools.threat_intel._load_cache_from_disk", return_value=mock_cache):
            result = await search_threat_indicators(
                mock_app_context,
                indicator_value="test",
            )

        assert "cache_info" in result
        assert "total_indicators" in result["cache_info"]
        assert "age_minutes" in result["cache_info"]
        assert "last_updated" in result["cache_info"]
        assert "indicator_breakdown" in result["cache_info"]
