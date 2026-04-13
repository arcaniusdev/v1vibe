# v1vibe Development Guide

Quick reference for developing v1vibe. See [docs/](./docs/) for detailed documentation.

## Quick Start

```bash
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe
uv sync
uv run v1vibe test
```

## Architecture

v1vibe is an MCP server that provides 18 security tools and 11 workflow prompts to AI assistants.

**Key components:**
- `cli.py` - Setup wizard, commands (setup, test, status, uninstall)
- `server.py` - FastMCP server with 18 tools + 11 prompts
- `config.py` - Settings, configuration, environment variables
- `clients.py` - gRPC and HTTP client lifecycle
- `tools/` - Tool implementations (file security, sandbox, threat intel, IaC, AI security, etc.)

→ **See [docs/architecture.md](./docs/architecture.md) for complete file structure and patterns**

## Documentation

### Core Reference
- 📐 [Architecture](./docs/architecture.md) - File structure, components, key patterns, API reference
- 🔧 [Tools](./docs/tools.md) - All 18 security tools organized by category
- 📋 [Prompts](./docs/prompts.md) - All 11 MCP workflow prompts and design principles
- 🔑 [API Permissions](./docs/api-permissions.md) - Required permissions, credits, common errors

### Implementation Details
- 🧪 [Testing](./docs/testing.md) - Test suite, patterns, mocking, CI/CD (275 tests, 53% coverage)
- 🔍 [Threat Intelligence](./docs/threat-intelligence.md) - Feed implementation, cache strategy, IOC coverage
- ☁️ [Compliance Mapping](./docs/compliance-mapping.md) - IaC scanning, 45 frameworks, AI guidance
- 💡 [Design Decisions](./docs/design-decisions.md) - Architectural choices and rationale

### Development
- 🚀 [Development Guide](./docs/development.md) - Local setup, workflow, adding features

## Common Tasks

### Running Tests
```bash
uv run pytest                    # all tests
uv run pytest --cov=v1vibe       # with coverage
uv run pytest -k "test_scan"     # filter by keyword
```

### Manual Testing
```bash
uv run v1vibe setup    # configure
uv run v1vibe test     # smoke test
uv run v1vibe status   # show config
```

### Adding a New Tool
1. Implement in `src/v1vibe/tools/<name>.py`
2. Register in `src/v1vibe/server.py`
3. Add tests in `tests/test_tools_<name>.py`
4. Update `docs/tools.md`
5. Consider creating MCP prompt
6. Run full test suite

### Before Committing
- ✅ Run `uv run pytest --cov=v1vibe` (coverage must stay ≥53%)
- ✅ New features require tests (aim for 90%+ coverage)
- ✅ Bug fixes require regression tests
- ✅ Update relevant documentation in `docs/`

## Platform Support

- **Python:** 3.10+ (including 3.14+)
- **Platforms:** macOS, Linux, Windows
- **File Security:** gRPC SDK (Python <3.14) or CLI fallback (Python 3.14+)
- **Artifact Scanner:** TMAS CLI (Docker mode on macOS, binary on Linux/Windows)

## API Endpoints

- **v3.0 REST API:** Sandbox, threat intel, AI Guard, vulnerabilities
- **Beta REST API:** IaC scanning (CloudFormation/Terraform)
- **File Security gRPC SDK:** File malware scanning

For detailed API docs: [Trend Micro Developer Portal](https://automation.trendmicro.com/)

## Need Help?

- 📚 Check the [docs/](./docs/) directory for detailed guides
- 🐛 Report issues: [GitHub Issues](https://github.com/arcaniusdev/v1vibe/issues)
- 🤝 Contributing: See [CONTRIBUTING.md](./CONTRIBUTING.md)
