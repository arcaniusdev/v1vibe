# Architecture

## File Structure

- `src/v1vibe/cli.py` — CLI entry point: `main()` dispatches to `setup`, `test`, `status`, `uninstall`, or MCP server (default). Setup wizard includes TMAS CLI installation and automatic tmfs CLI installation (Step 4.5) when SDK incompatible. The `v1vibe` console script points here.
- `src/v1vibe/server.py` — FastMCP server with 18 tools and 11 MCP prompts. Tools are thin async wrappers that delegate to tool modules. Contains SERVER_INSTRUCTIONS (mandatory checklist for AI clients) and prompt templates for comprehensive workflow guidance.
- `src/v1vibe/config.py` — `Settings` dataclass, `load_settings()` reads env vars then falls back to `~/.v1vibe/config.json`. `save_config_file()` writes config with 0600 permissions, wrapped in error handling. Contains configurable timeout constants (HTTP_TIMEOUT, SCAN_TIMEOUT, AI_SCAN_TIMEOUT) that can be overridden via environment variables.
- `src/v1vibe/constants.py` — Application-wide constants: TMAS_VERSION, TMAS_BASE_URL, TMAS_DOCKER_IMAGE, TMFS_BASE_URL, TMFS_METADATA_URL. Single source of truth to avoid duplication.
- `src/v1vibe/api_endpoints.py` — Centralized API endpoint paths for all 18 REST API endpoints. Organized by version (v3.0, beta) and functional area for easier API version migration.
- `src/v1vibe/clients.py` — `AppContext` dataclass and `app_lifespan` async context manager. Manages a gRPC handle (File Security SDK) and httpx.AsyncClient (REST API). Handles partial init failure and cleanup exceptions safely. Graceful SDK import failure on Python 3.14+ with warning. HTTP timeout configurable via HTTP_TIMEOUT constant.
- `src/v1vibe/utils.py` — `format_error()` (never leaks auth headers), `check_response()`, `check_multi_status()`, `sanitize_filter_value()`.
- `src/v1vibe/version_check.py` — SDK compatibility detection for Python 3.14+ (grpcio/protobuf version checks), used in status command and setup wizard.
- `src/v1vibe/sandbox_filetypes.txt` — External list of sandbox-supported file extensions. Users can add/remove types without editing code.

## Tool Implementation Modules

Located in `src/v1vibe/tools/`:

- `file_security.py` — scan_file (gRPC SDK with CLI fallback for Python 3.14+)
- `sandbox.py` — submit_file (with file type validation), submit_url, get_status, get_report (with PDF download), get_submission_quota
- `artifact_scanner.py` — scan_artifact (TMAS CLI wrapper for dependency/secret/container scanning)
- `ai_guard.py` — evaluate (AI content guardrails)
- `ai_scanner.py` — scan_llm_interactive, scan_llm_endpoint (TMAS CLI wrapper for LLM vulnerability testing)
- `threat_intel.py` — check_suspicious_objects (tenant blocklist lookup), search_threat_indicators (global threat feed with ~266K IOCs from 2018-present, cached locally with hourly delta updates)
- `iac_scanner.py` — scan_template (CloudFormation/Terraform with compliance mapping), scan_terraform_archive (ZIP of HCL), list_compliance_standards, list_compliance_profiles
- `vulnerabilities.py` — get_cve_details (specific CVE lookup with ID format validation)

## Key Patterns

- Tools return dicts. Errors returned as `{"error": {"code": "...", "message": "..."}}`, never raised.
- `format_error()` never calls `str()` on httpx exceptions to prevent auth header leakage.
- gRPC handle and httpx client initialized once in the lifespan, shared across all tools. Partial init failure handled safely.
- **File Security fallback** — scan_file() automatically uses CLI (tmfs binary) when SDK unavailable (Python 3.14+). Environment variable (TMFS_API_KEY) set per-subprocess via `subprocess.run(env=...)`.
- Sandbox file type validation loaded from `sandbox_filetypes.txt` at import time.
- Threat feed cache loaded from disk on first use, stored in `AppContext._threat_feed_cache` for session
- All filter/query header values sanitized via `sanitize_filter_value()`. Enum parameters validated against allowlists.
- CVE IDs validated with regex before reaching the API.
- URL and file sandboxing are both user-initiated or recommended when suspicious (e.g., unknown domains, flagged files).
- AI Guard is conditional — only used when project contains AI prompts, chatbot instructions, or LLM templates.
- **Artifact scanner** (Docker mode) creates filtered directory copies excluding .venv, node_modules, .git, etc. to avoid symlink issues. Skips all symlinks during copying.
- **Enhanced error messages** include actionable `suggestions` array when scans fail, providing specific workarounds (e.g., scan subdirectories, split scan types, use alternative tools).

## API Reference

v1vibe uses the TrendAI Vision One API with the following endpoints:
- **v3.0 REST API** — Most tools (sandbox, threat intel, AI Guard, vulnerabilities)
- **Beta REST API** — IaC scanning (CloudFormation/Terraform)
- **File Security gRPC SDK** — File malware scanning (`visionone-filesecurity` package)

For detailed API documentation, refer to the Vision One API documentation at the [Trend Micro Developer Portal](https://automation.trendmicro.com/).
