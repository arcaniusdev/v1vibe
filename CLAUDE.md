# v1vibe Development Guide

## Architecture

- `src/v1vibe/cli.py` — CLI entry point: `main()` dispatches to `setup`, `test`, `status`, or MCP server. The `v1vibe` console script points here.
- `src/v1vibe/server.py` — FastMCP server, tool registrations. All 8 tools are defined here as thin async wrappers that delegate to tool modules.
- `src/v1vibe/config.py` — `Settings` dataclass, `load_settings()` reads env vars then falls back to `~/.v1vibe/config.json`. `save_config_file()` writes config with 0600 permissions.
- `src/v1vibe/clients.py` — `AppContext` dataclass and `app_lifespan` async context manager. Manages a gRPC handle (File Security SDK) and httpx.AsyncClient (REST API) that are shared across all tool invocations.
- `src/v1vibe/utils.py` — `format_error()`, `check_response()`, `check_multi_status()` helpers.
- `src/v1vibe/tools/` — Implementation modules: `file_security.py`, `sandbox.py`, `ai_guard.py`, `threat_intel.py`.

## Key patterns

- Tools return dicts — FastMCP serializes them as JSON. Errors are returned as `{"error": {"code": "...", "message": "..."}}`, never raised.
- gRPC handle and httpx client are initialized once in the lifespan and accessed via `ctx.request_context.lifespan_context`.
- The File Security SDK (`amaas.grpc.aio`) uses gRPC. REST API calls use httpx against v3.0 endpoints.
- Passwords/arguments for sandbox submissions are base64-encoded before sending.

## Running locally

```bash
uv sync
uv run v1vibe setup    # interactive config wizard
uv run v1vibe test     # smoke test connectivity
uv run v1vibe status   # show config + health
```

## API reference

The `sp-api-open-*.json` files are Trend Micro Vision One OpenAPI specs (v2.0, v3.0, beta). The server targets v3.0 REST endpoints + the File Security gRPC SDK (`visionone-filesecurity` package).
