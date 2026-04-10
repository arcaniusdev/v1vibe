from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error, sanitize_filter_value

VALID_TYPES = {"url", "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress"}
VALID_RISK_LEVELS = {"high", "medium", "low"}

# Threat feed cache TTL (1 hour)
FEED_CACHE_TTL_SECONDS = 3600


@dataclass
class ThreatFeedCache:
    """Cache for threat intelligence feed indicators."""

    indicators: list[dict[str, Any]] = field(default_factory=list)
    first_fetched_at: datetime | None = None  # When cache was first created
    last_updated_at: datetime | None = None  # When last refreshed
    total_count: int = 0

    def is_expired(self) -> bool:
        """Check if cache needs refresh (older than TTL)."""
        if self.last_updated_at is None:
            return True
        age = datetime.now(timezone.utc) - self.last_updated_at
        return age.total_seconds() > FEED_CACHE_TTL_SECONDS

    def age_minutes(self) -> float:
        """Get cache age in minutes since last update."""
        if self.last_updated_at is None:
            return 0.0
        age = datetime.now(timezone.utc) - self.last_updated_at
        return age.total_seconds() / 60


def _get_cache_path() -> Any:
    """Get path to threat feed cache file."""
    from pathlib import Path

    cache_dir = Path.home() / ".v1vibe"
    cache_dir.mkdir(mode=0o700, exist_ok=True)
    return cache_dir / "threat_feed_cache.json"


def _load_cache_from_disk() -> ThreatFeedCache:
    """Load threat feed cache from disk."""
    import json

    cache_path = _get_cache_path()
    if not cache_path.exists():
        return ThreatFeedCache()

    try:
        with open(cache_path) as f:
            data = json.load(f)

        cache = ThreatFeedCache(
            indicators=data.get("indicators", []),
            first_fetched_at=(
                datetime.fromisoformat(data["first_fetched_at"])
                if data.get("first_fetched_at")
                else None
            ),
            last_updated_at=(
                datetime.fromisoformat(data["last_updated_at"])
                if data.get("last_updated_at")
                else None
            ),
            total_count=data.get("total_count", 0),
        )
        return cache
    except Exception:
        # If cache is corrupted, start fresh
        return ThreatFeedCache()


def _save_cache_to_disk(cache: ThreatFeedCache) -> None:
    """Save threat feed cache to disk."""
    import json

    cache_path = _get_cache_path()

    data = {
        "indicators": cache.indicators,
        "first_fetched_at": cache.first_fetched_at.isoformat() if cache.first_fetched_at else None,
        "last_updated_at": cache.last_updated_at.isoformat() if cache.last_updated_at else None,
        "total_count": cache.total_count,
    }

    # Write atomically using temp file + rename
    temp_path = cache_path.with_suffix(".tmp")
    with open(temp_path, "w") as f:
        json.dump(data, f)
    temp_path.replace(cache_path)


async def _fetch_threat_feed(
    ctx: AppContext, start_date: datetime | None = None
) -> list[dict[str, Any]]:
    """
    Fetch threat intelligence feed indicators.

    Args:
        ctx: Application context
        start_date: If provided, only fetch indicators newer than this date (delta update)
                   If None, fetch all indicators from last 365 days (full refresh)

    Returns:
        List of indicator objects from STIX bundle
    """
    end_time = datetime.now(timezone.utc)

    if start_date is None:
        # Full fetch: get everything from last year
        start_time = end_time - timedelta(days=365)
    else:
        # Delta fetch: get only new indicators
        start_time = start_date

    start_dt = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_dt = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    all_indicators = []
    url = (
        f"/v3.0/threatintel/feedIndicators"
        f"?startDateTime={start_dt}&endDateTime={end_dt}&top=10000"
    )

    # Fetch all pages
    while url:
        resp = await ctx.http.get(url)
        result = check_response(resp)

        if "error" in result:
            raise Exception(f"API error: {result['error'].get('message', 'Unknown')}")

        bundle = result.get("bundle", {})
        objects = bundle.get("objects", [])

        # Filter for indicator objects only
        indicators = [obj for obj in objects if obj.get("type") == "indicator"]
        all_indicators.extend(indicators)

        # Check for next page
        next_link = result.get("nextLink")
        if next_link:
            # Extract just the path + query from nextLink
            import urllib.parse

            parsed = urllib.parse.urlparse(next_link)
            url = f"{parsed.path}?{parsed.query}"
        else:
            url = None

    return all_indicators


async def _ensure_feed_cache(ctx: AppContext) -> ThreatFeedCache:
    """
    Ensure threat feed cache is loaded and up-to-date.

    This function:
    1. Loads cache from disk if available
    2. Checks if cache needs refresh (expired)
    3. Fetches new indicators (full or delta update)
    4. Merges and deduplicates
    5. Saves updated cache to disk
    6. Returns the cache

    The cache is stored in AppContext for the session and persisted to disk.
    """
    # Check if we already have cache in memory for this session
    if not hasattr(ctx, "_threat_feed_cache"):
        ctx._threat_feed_cache = _load_cache_from_disk()

    cache = ctx._threat_feed_cache

    # Check if refresh needed
    if not cache.is_expired():
        return cache

    # Fetch new indicators
    if cache.last_updated_at and cache.indicators:
        # Delta update: fetch only new indicators since last update
        new_indicators = await _fetch_threat_feed(ctx, cache.last_updated_at)

        if new_indicators:
            # Merge with existing, deduplicate by ID
            existing_ids = {ind["id"] for ind in cache.indicators}
            unique_new = [ind for ind in new_indicators if ind["id"] not in existing_ids]
            cache.indicators.extend(unique_new)
    else:
        # Full refresh: fetch everything
        cache.indicators = await _fetch_threat_feed(ctx)
        cache.first_fetched_at = datetime.now(timezone.utc)

    # Update metadata
    cache.last_updated_at = datetime.now(timezone.utc)
    cache.total_count = len(cache.indicators)

    # Save to disk
    _save_cache_to_disk(cache)

    return cache


def _extract_indicator_value(pattern: str) -> tuple[str | None, str | None]:
    """
    Extract indicator type and value from STIX pattern.

    Supports all STIX indicator types found in threat feed:
    - File hashes (SHA1, SHA256, MD5)
    - Domains, URLs, IPs (IPv4/IPv6)
    - Email addresses, sender addresses
    - Windows registry keys
    - Mutexes
    - File paths/directories
    - Hostnames
    - Process names
    - Network traffic (domain/IP references)

    Examples:
        "[domain-name:value = 'example.com']" -> ("domain", "example.com")
        "[url:value = 'http://evil.com/path']" -> ("url", "http://evil.com/path")
        "[ipv4-addr:value = '1.2.3.4']" -> ("ip", "1.2.3.4")
        "[file:hashes.SHA256 = 'abc123...']" -> ("file_hash_sha256", "abc123...")
        "[email-addr:value = 'bad@evil.com']" -> ("email", "bad@evil.com")
        "[mutex:name = '{guid}']" -> ("mutex", "{guid}")
        "[network-traffic:dst_ref.value = 'evil.com']" -> ("domain", "evil.com")

    Returns:
        Tuple of (indicator_type, value) or (None, None) if pattern can't be parsed
    """
    # Handle network-traffic patterns (they reference domains/IPs)
    if "[network-traffic:dst_ref.value = " in pattern:
        match = re.search(r"dst_ref\.value\s*=\s*'([^']+)'", pattern)
        if match:
            value = match.group(1)
            # Could be domain or IP, let caller determine
            return "network_traffic_dest", value

    # Standard STIX pattern format: [type:property = 'value']
    match = re.search(r"\[([^:]+):([^\]]+)\]", pattern)
    if not match:
        return None, None

    stix_type = match.group(1).strip()
    rest = match.group(2).strip()

    # Extract value from "property = 'value'" format
    value_match = re.search(r"=\s*'([^']+)'", rest)
    if not value_match:
        return None, None

    value = value_match.group(1)

    # Map STIX types to our indicator types
    # For file hashes, preserve the hash type
    if stix_type == "file":
        if "hashes.SHA256" in rest:
            return "file_hash_sha256", value
        elif "hashes.SHA1" in rest:
            return "file_hash_sha1", value
        elif "hashes.MD5" in rest:
            return "file_hash_md5", value
        elif "name" in rest:
            return "file_name", value
        else:
            return "file_hash", value

    type_map = {
        "domain-name": "domain",
        "url": "url",
        "ipv4-addr": "ip",
        "ipv6-addr": "ip",
        "email-addr": "email",
        "email-message": "email",  # sender_ref.value
        "windows-registry-key": "registry_key",
        "mutex": "mutex",
        "directory": "file_path",
        "hostname": "hostname",
        "process": "process",
    }

    indicator_type = type_map.get(stix_type)
    return indicator_type, value


async def search_threat_indicators(
    ctx: AppContext,
    indicator_value: str,
) -> dict[str, Any]:
    """
    Search TrendAI threat intelligence feed for a specific indicator of compromise (IOC).

    Searches the complete threat intelligence feed (71K+ indicators from last 365 days)
    for matches. The feed is cached locally (~29MB) and refreshed hourly with delta updates.

    This provides instant lookups against global threat intelligence from TrendAI,
    complementing check_suspicious_objects (tenant blocklist) and sandbox_submit_url.

    **Indicator types automatically detected** (71K+ total indicators):
    - **File hashes** (27K): SHA256, SHA1, MD5 hashes of malware/trojans
    - **Domains** (12K): Malicious domain names (C2, phishing, malware distribution)
    - **IPs** (10K): IPv4/IPv6 addresses associated with threats
    - **URLs** (7K): Full URLs with paths (phishing, malware downloads, C2)
    - **Network traffic** (15K): Domain/IP references in network patterns
    - **Email addresses** (150+): Malicious sender addresses, phishing emails
    - **Windows registry keys** (50+): Malware persistence indicators
    - **Mutexes** (9): Malware synchronization objects
    - **File paths** (8): Known malware installation paths
    - **Hostnames** (5): Specific malicious hostnames
    - **Process names** (3): Malicious service/process names

    **Use this to scan projects for:**
    - Hardcoded IPs, domains, URLs in code/configs
    - File hashes in build artifacts, dependencies, downloads
    - Email addresses in configs (sender/recipient validation)
    - Registry keys in Windows scripts/installers
    - Mutex names in malware analysis code
    - File paths in scripts (detect known malware paths)

    Args:
        ctx: Application context
        indicator_value: The IOC to search for (supports all types above)

    Returns:
        {
            "value": "example.com",
            "found": true,
            "match_count": 1,
            "matches": [
                {
                    "id": "indicator--abc123...",
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'example.com']",
                    "valid_from": "2025-01-15T10:00:00.000Z",
                    "valid_until": "2026-01-15T10:00:00.000Z",
                    "name": "Malicious domain",
                    "description": "...",
                    "labels": ["malicious-activity"]
                }
            ],
            "cache_info": {
                "total_indicators": 71445,
                "age_minutes": 15.2,
                "last_updated": "2026-04-10T02:15:00Z",
                "breakdown": {
                    "file_hashes": 27352,
                    "network_traffic": 15034,
                    "domains": 11922,
                    "ips": 10074,
                    "urls": 6833,
                    "email": 153,
                    "registry_keys": 52,
                    "mutexes": 9,
                    "paths": 8,
                    "hostnames": 5,
                    "processes": 3
                }
            }
        }
    """
    try:
        # Ensure cache is loaded and up-to-date
        cache = await _ensure_feed_cache(ctx)

        # Search for matches (case-insensitive)
        value_lower = indicator_value.lower()
        matches = []

        # Calculate indicator type breakdown for cache_info
        type_breakdown = {}

        for indicator in cache.indicators:
            pattern = indicator.get("pattern", "")

            # Extract value and type from pattern
            ind_type, extracted_value = _extract_indicator_value(pattern)

            # Track type for breakdown stats
            if ind_type:
                type_breakdown[ind_type] = type_breakdown.get(ind_type, 0) + 1

            # Check if it matches our search value
            if extracted_value and extracted_value.lower() == value_lower:
                # Include relevant fields only
                match = {
                    "id": indicator.get("id"),
                    "type": indicator.get("type"),
                    "indicator_subtype": ind_type,  # e.g., "file_hash_sha256", "domain", etc.
                    "pattern": pattern,
                    "valid_from": indicator.get("valid_from"),
                    "valid_until": indicator.get("valid_until"),
                    "name": indicator.get("name"),
                    "description": indicator.get("description"),
                    "labels": indicator.get("labels", []),
                }

                # Add optional fields if present
                if "threat_types" in indicator:
                    match["threat_types"] = indicator["threat_types"]
                if "kill_chain_phases" in indicator:
                    match["kill_chain_phases"] = indicator["kill_chain_phases"]

                matches.append(match)

        return {
            "value": indicator_value,
            "found": len(matches) > 0,
            "match_count": len(matches),
            "matches": matches,
            "cache_info": {
                "total_indicators": cache.total_count,
                "age_minutes": round(cache.age_minutes(), 1),
                "last_updated": (
                    cache.last_updated_at.isoformat() if cache.last_updated_at else None
                ),
                "first_fetched": (
                    cache.first_fetched_at.isoformat() if cache.first_fetched_at else None
                ),
                "indicator_breakdown": type_breakdown,
            },
        }

    except Exception as exc:
        return format_error(exc)


async def check_suspicious_objects(
    ctx: AppContext,
    object_type: str,
    value: str,
    risk_level: str | None = None,
) -> dict[str, Any]:
    try:
        if object_type not in VALID_TYPES:
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid type '{object_type}'. Must be one of: {', '.join(sorted(VALID_TYPES))}",
                }
            }

        safe_value = sanitize_filter_value(value)
        filter_parts = [f"type eq '{object_type}'", f"{object_type} eq '{safe_value}'"]

        if risk_level:
            if risk_level not in VALID_RISK_LEVELS:
                return {
                    "error": {
                        "code": "InvalidInput",
                        "message": f"Invalid risk_level '{risk_level}'. Must be one of: high, medium, low",
                    }
                }
            filter_parts.append(f"riskLevel eq '{risk_level}'")

        filter_expr = " and ".join(filter_parts)

        resp = await ctx.http.get(
            "/v3.0/threatintel/suspiciousObjects",
            headers={"TMV1-Filter": filter_expr},
            params={"top": 50},
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
