# Testing

## Test Suite Overview

**Test suite:** 275 passing tests, 53% coverage (PyPI Phase 1 target met - minimum 10%)

**Coverage breakdown:**
- ✅ **100%**: clients.py (89%), config.py (98%), utils.py, ai_guard.py, iac_scanner.py, sandbox.py (98%), threat_intel.py (98%), vulnerabilities.py
- ⚠️ **96%**: file_security.py  
- ✅ **81%**: artifact_scanner.py
- ✅ **85%**: ai_scanner.py
- ⚠️  **18%**: cli.py (complex interactive commands, lower priority)
- ⚠️  **0%**: server.py (MCP server, requires FastMCP test harness)

## Test Files

- `tests/conftest.py` — Fixtures: mock_settings, mock_app_context, mock_grpc_handle, mock_http_client
- `tests/test_config.py` — 10 tests (100% coverage): Settings, env vars, file loading, validation, save errors
- `tests/test_utils.py` — 15 tests (100% coverage): error handling, input sanitization, auth header leak prevention
- `tests/test_clients.py` — 6 tests (100% coverage): AppContext lifecycle, initialization, cleanup, error suppression
- `tests/test_tools_ai_guard.py` — 6 tests (100% coverage): clean content, harmful content, prompt injection, API errors
- `tests/test_tools_ai_scanner.py` — 17 tests (85% coverage): LLM detection (OpenAI/Anthropic/Google), scan success/failure, timeouts
- `tests/test_tools_file_security.py` — 6 tests (96% coverage): gRPC malware scanning, tags, PML detection
- `tests/test_tools_iac_scanner.py` — 15 tests (100% coverage): CloudFormation and Terraform template scanning, compliance standards/profiles
- `tests/test_tools_sandbox.py` — 8 tests: file type validation, extension loading
- `tests/test_tools_sandbox_api.py` — 16 tests (100% coverage): file/URL submission, status polling, report retrieval, PDF download
- `tests/test_tools_vulnerabilities.py` — 7 tests (100% coverage): CVE ID format validation, details retrieval
- `tests/test_tools_threat_intel.py` — 36 tests (100% coverage): pattern extraction (all STIX types), cache operations, search
- `tests/test_tools_threat_intel_cache.py` — 15 tests (100% coverage): disk persistence, pagination, delta updates, atomic writes
- `tests/test_tools_artifact_scanner.py` — 23 tests (81% coverage): path validation, forbidden paths, scan types, Docker mode, subprocess execution
- `tests/test_cli_utils.py` — 9 tests: platform detection (macOS→Linux binary), token masking, Docker checks
- `tests/test_cli_install.py` — 4 tests: Docker installation on macOS
- `tests/test_cli_commands.py` — 11 tests: status command output, region validation
- Additional test files covering edge cases, error paths, and coverage targets

## Running Tests

```bash
uv run pytest                    # run all tests (275 tests)
uv run pytest --cov=v1vibe       # with coverage report (53%)
uv run pytest tests/test_config.py  # specific file
uv run pytest -k "test_scan"     # filter by keyword
```

## Critical Test Patterns

### httpx.Response Mocking

Always include request parameter:

```python
request = httpx.Request("GET", "https://api.example.com/test")
response = httpx.Response(200, json={"data": "value"}, request=request)
mock_app_context.http.get = AsyncMock(return_value=response)
```

### gRPC Mocking

Patch amaas.grpc.aio.scan_file:

```python
import amaas.grpc.aio as amaas_aio
amaas_aio.scan_file = AsyncMock(return_value=json.dumps({
    "scanResult": 0, "foundMalwares": [], "fileSHA1": "abc", "fileSHA256": "def"
}))
```

### Settings Creation

Frozen dataclass, cannot modify after creation:

```python
# WRONG: mock_app_context.settings.tmas_binary_path = None  # raises FrozenInstanceError
# CORRECT:
settings = Settings(
    api_token="test-token-12345678901234567890",
    region="us-east-1",
    base_url="https://api.xdr.trendmicro.com",
    tmas_binary_path=None,  # or "docker" for macOS mode
)
ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)
```

### macOS Docker Mode

CRITICAL for artifact scanner tests:

```python
# On macOS: tmas_binary_path="docker", TMAS runs in Ubuntu container
# Platform detection returns os_name="Linux" (not "Darwin") because macOS uses Linux binary
settings = Settings(..., tmas_binary_path="docker")  # macOS Docker mode
settings = Settings(..., tmas_binary_path="/usr/local/bin/tmas")  # Linux/Windows binary mode
```

### Subprocess Mocking

For artifact scanner:

```python
with patch("subprocess.run") as mock_run:
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = json.dumps({"vulnerabilities": [], "malware": [], "secrets": []})
    mock_run.return_value.stderr = ""
```

### Temp File Mocking

For artifact scanner output:

```python
from unittest.mock import MagicMock
output_file = tmp_path / "tmas-output.json"
output_file.write_text(json.dumps({...}))

with patch("tempfile.NamedTemporaryFile") as mock_temp:
    mock_file = MagicMock()
    mock_file.name = str(output_file)
    mock_file.__enter__ = MagicMock(return_value=mock_file)
    mock_file.__exit__ = MagicMock(return_value=False)
    mock_temp.return_value = mock_file
```

## Development Workflow

1. **Before every commit:**
   - Run `uv run pytest --cov=v1vibe`
   - Coverage must stay ≥53% (enforced in CI)
   - New features require tests (aim for 90%+ coverage of new code)
   - Bug fixes require regression tests

2. **CI/CD integration:**
   - GitHub Actions runs full test suite on every push/PR
   - Matrix testing across Python 3.10-3.13 × [Ubuntu, macOS]
   - Coverage report uploaded to Codecov
   - Fails if coverage drops below 10% (pyproject.toml threshold)

3. **Adding new tools:**
   - Create `tests/test_tools_<name>.py` with 100% coverage target
   - Include tests for: success path, error handling, edge cases, API errors
   - Mock all external calls (HTTP, gRPC, subprocess)
   - Use existing fixtures from conftest.py

4. **Platform-specific testing:**
   - macOS tests must handle Docker mode (`tmas_binary_path="docker"`)
   - Linux/Windows tests use direct binary paths
   - Platform detection tests verify correct binary selection

5. **Regression prevention:**
   - When fixing bugs, add test that reproduces the bug first
   - Test should fail before fix, pass after fix
   - Prevents same bug from reappearing

## GitHub Actions CI/CD

- `.github/workflows/test.yml` runs on push/PR to main
- Matrix: Python 3.10-3.13 × [ubuntu-latest, macos-latest] = 8 configurations
- Uses uv for fast dependency installation
- Uploads coverage to Codecov (ubuntu-latest + Python 3.13)
- Enforces minimum 10% coverage threshold
