# Contributing to v1vibe

Thank you for your interest in contributing to v1vibe! This guide will help you understand the codebase structure and development workflow.

## Architecture Overview

v1vibe is an MCP (Model Context Protocol) server that provides AI coding assistants with enterprise security capabilities from TrendAI Vision One.

### Project Structure

```
v1vibe/
├── src/v1vibe/
│   ├── __init__.py
│   ├── server.py          # FastMCP server with 13 tools + 4 prompts
│   ├── cli.py             # CLI commands (setup, test, status, uninstall)
│   ├── config.py          # Configuration management (env vars + ~/.v1vibe/config.json)
│   ├── clients.py         # gRPC + HTTP client lifecycle
│   ├── utils.py           # Error handling and input validation
│   ├── sandbox_filetypes.txt  # User-editable list of sandbox-supported extensions
│   └── tools/             # Tool implementations (one file per API)
│       ├── file_security.py      # File malware scanning (gRPC SDK)
│       ├── sandbox.py            # File/URL behavioral analysis (REST v3.0)
│       ├── artifact_scanner.py   # Dependency/secret/container scanning (TMAS CLI)
│       ├── ai_guard.py           # AI content safety (REST v3.0)
│       ├── threat_intel.py       # Threat intelligence lookups (REST v3.0)
│       ├── iac_scanner.py        # IaC template scanning (REST beta)
│       └── vulnerabilities.py    # CVE details (REST v3.0)
├── README.md
├── CLAUDE.md              # Project-specific AI assistant instructions
└── pyproject.toml
```

### Key Design Patterns

#### 1. Error Handling

All tool functions return `dict[str, Any]` and never raise exceptions to MCP clients:

```python
async def scan_file(...) -> dict[str, Any]:
    try:
        # ... implementation
        return result_dict
    except Exception as exc:
        return format_error(exc)  # Safe error formatting (never leaks secrets)
```

#### 2. Client Lifecycle

Both gRPC (File Security SDK) and HTTP (REST API) clients are managed by `app_lifespan`:

```python
async with app_lifespan(server) as ctx:
    # ctx.grpc_handle for file scanning
    # ctx.http for REST API calls
    # ctx.settings for configuration
```

#### 3. Input Validation

**Always validate user input** before passing to APIs:

```python
# Path validation to prevent path traversal
resolved = Path(artifact).resolve()
if str(resolved).startswith("/etc"):
    raise ValueError("Access to /etc is not allowed")

# Filter value sanitization to prevent injection
sanitized = sanitize_filter_value(user_input)

# Enum validation
if template_type not in VALID_TEMPLATE_TYPES:
    return {"error": {...}}
```

#### 4. Security Principles

- **Never log or expose API tokens** — use `format_error()` which handles this
- **Validate all user input** — paths, filter values, enums
- **Use 0600 permissions** for config files containing secrets
- **Never call `str()` on httpx exceptions** — may contain auth headers

## Development Setup

### Prerequisites

- Python 3.10+
- uv (recommended) or pip
- Docker (for testing artifact scanning on macOS)

### Install for Development

```bash
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe
uv sync
```

### Run Locally

```bash
# Set up configuration
uv run v1vibe setup

# Test connectivity
uv run v1vibe test

# Check status
uv run v1vibe status

# Run MCP server (stdio transport)
uv run v1vibe
```

## Adding a New Tool

1. **Create a new file in `src/v1vibe/tools/`**

```python
"""Brief module description.

Explain what this tool does and what API it uses.
"""

from __future__ import annotations
from typing import Any
from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

async def my_new_tool(
    ctx: AppContext,
    param1: str,
    param2: int | None = None,
) -> dict[str, Any]:
    """Tool description.

    Args:
        ctx: Application context with HTTP client
        param1: Description of param1
        param2: Optional description of param2

    Returns:
        dict: Result structure or error dict
    """
    try:
        # Validate inputs
        if not param1:
            return {"error": {"code": "InvalidInput", "message": "param1 is required"}}

        # Make API call
        resp = await ctx.http.post("/v3.0/my/endpoint", json={"param1": param1})
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
```

2. **Add the tool to `server.py`**

```python
from v1vibe.tools import my_new_module

@mcp.tool()
async def my_new_tool(
    ctx: Context,
    param1: str,
    param2: int | None = None,
) -> dict:
    """User-facing docstring (shown in MCP client).

    This appears in Claude's tool list.

    Args:
        param1: Description for AI assistant
        param2: Optional parameter description
    """
    return await my_new_module.my_new_tool(_ctx(ctx), param1, param2)
```

3. **Update README.md** — Add to features table
4. **Test the tool** — Use `v1vibe test` or call directly

## Code Style

### Docstrings

- **Module docstrings**: Explain purpose and key concepts
- **Function docstrings**: Use Google style with Args, Returns, Raises
- **Inline comments**: Only for non-obvious logic

```python
"""Module docstring explaining the file's purpose."""

async def function_name(arg1: str, arg2: int) -> dict:
    """Brief one-line summary.

    Longer description if needed, explaining behavior, edge cases,
    or important implementation details.

    Args:
        arg1: Description of arg1
        arg2: Description of arg2

    Returns:
        dict: Description of return structure

    Raises:
        ValueError: When and why this is raised
    """
```

### Type Hints

- Use type hints for all function parameters and return values
- Use `dict[str, Any]` for API responses (JSON structure)
- Use `str | None` instead of `Optional[str]`

### Error Messages

- **User-facing errors** should be clear and actionable
- Include next steps when possible

```python
return {
    "error": {
        "code": "TmasNotInstalled",
        "message": "TMAS CLI not installed. Run: v1vibe setup",
    }
}
```

## Testing

Currently v1vibe has minimal automated tests (see [Production Readiness](https://github.com/arcaniusdev/v1vibe/issues) for roadmap).

**Manual testing:**

```bash
# Test all connectivity
uv run v1vibe test

# Test specific tool via MCP
# (requires Claude Code or other MCP client)
```

## Git Workflow

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make changes with clear, atomic commits
3. Test locally: `uv run v1vibe test`
4. Push and create a pull request
5. Ensure CI passes (when available)

### Commit Messages

Follow the existing style (imperative mood, 50-char subject):

```
Add CVE scanning tool for dependency vulnerabilities

Implement get_cve_details tool that queries Vision One v3.0
vulnerabilities API. Validates CVE ID format and returns CVSS
scores, descriptions, and mitigation options.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
```

## Resources

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [TrendAI Vision One API Docs](https://automation.trendmicro.com/xdr/api-v3)
- [MCP Protocol Specification](https://modelcontextprotocol.io)

## Questions?

Open an issue at https://github.com/arcaniusdev/v1vibe/issues
