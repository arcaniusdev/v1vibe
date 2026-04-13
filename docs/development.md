# Development Guide

## Quick Start

```bash
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe
uv sync
```

## Running Locally

```bash
uv run v1vibe setup    # interactive config wizard
uv run v1vibe test     # smoke test connectivity
uv run v1vibe status   # show config + health
```

## Development Workflow

1. **Make changes** to source code
2. **Run tests** before committing:
   ```bash
   uv run pytest --cov=v1vibe
   ```
3. **Check coverage** stays ≥53%
4. **Test manually** with:
   ```bash
   uv run v1vibe test
   uv run v1vibe status
   ```
5. **Commit** your changes

## Testing Specific Features

### Testing Threat Intelligence Feed

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

## Project Structure

See [architecture.md](./architecture.md) for detailed file structure and component descriptions.

## Adding New Tools

1. Create implementation in `src/v1vibe/tools/`
2. Add tool function to `src/v1vibe/server.py`
3. Create tests in `tests/test_tools_<name>.py`
4. Update [tools.md](./tools.md) documentation
5. Consider creating an MCP prompt for the tool
6. Run full test suite

## Testing Guidelines

See [testing.md](./testing.md) for comprehensive testing patterns and requirements.

## Documentation

When adding features:
- Update relevant docs in `docs/` directory
- Keep main CLAUDE.md brief with links
- Document design decisions in [design-decisions.md](./design-decisions.md)

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
