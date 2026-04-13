# Threat Intelligence Feed

Implementation details for `search_threat_indicators` tool.

## Architecture

- **API endpoint:** `/v3.0/threatintel/feedIndicators` (REST v3.0)
- **Cache location:** `~/.v1vibe/threat_feed_cache.json` (~95MB)
- **Cache TTL:** 1 hour (3600 seconds)
- **Persistence:** Survives restarts, atomic writes (temp file + rename for crash safety)

## Behavior

- **First run:** Downloads full historical feed from 2018-present (~266K indicators, ~60 seconds, 27 pages)
- **Subsequent runs:** Instant lookups from disk cache (0.1s)
- **Hourly refresh:** Delta update (only fetches indicators newer than last update)
- **Deduplication:** Merges by indicator ID to avoid duplicates

## Data Structure

- `ThreatFeedCache` dataclass with `indicators`, `first_fetched_at`, `last_updated_at`, `total_count`
- Each indicator is a STIX object with `id`, `type`, `pattern`, `valid_from`, `valid_until`, `labels`
- Pattern extraction via `_extract_indicator_value()` supports all STIX types

## IOC Coverage

~266K total indicators from 2018-present (~8.1 years):

- File hashes (SHA256/SHA1/MD5): 123K indicators (46.2%)
- IP addresses (IPv4/IPv6): 91K indicators (34.3%)
- Domains: 39K indicators (14.8%)
- URLs: 11K indicators (4.3%)
- Email addresses: 350+ indicators (0.1%)
- Windows registry keys: 50+ indicators
- Mutexes: 9 indicators
- File paths: 8 indicators
- Hostnames, process names, other: 731 indicators (0.3%)

## Pagination

- API returns max 10,000 indicators per page
- Follows `nextLink` until exhausted
- Full historical fetch: 27 pages

## Pattern Extraction

- STIX patterns like `[domain-name:value = 'evil.com']` parsed to extract IOC type and value
- Supports all indicator types: file, domain-name, url, ipv4-addr, ipv6-addr, email-addr, email-message, windows-registry-key, mutex, directory, hostname, process, network-traffic
- Network traffic patterns extract domain/IP from `dst_ref.value`

## Testing Locally

```python
# Test search_threat_indicators
import asyncio
from v1vibe.tools.threat_intel import search_threat_indicators
from v1vibe.clients import app_lifespan
from v1vibe.config import load_settings

async def test():
    settings = load_settings()
    async with app_lifespan(settings) as ctx:
        # First run: downloads full historical feed (~60s, 266K indicators)
        # Subsequent runs: instant from cache
        result = await search_threat_indicators(ctx, "example.com")
        print(f"Found: {result['found']}")
        print(f"Total indicators: {result['cache_info']['total_indicators']:,}")
        print(f"Date range: 2018-present (~8.1 years)")

asyncio.run(test())
```

Cache location: `~/.v1vibe/threat_feed_cache.json`
Cache inspection: `ls -lh ~/.v1vibe/threat_feed_cache.json` (should be ~95MB)
