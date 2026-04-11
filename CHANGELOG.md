# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Windows PATH support**: Setup wizard now offers to add v1vibe to PATH on Windows
  - `cli.py`: Added `_add_to_path_windows()` to modify user PATH via registry
  - Detects if v1vibe is installed but not in PATH (e.g., `C:\Users\<user>\.local\bin`)
  - Prompts user to add to PATH for better compatibility with all MCP clients
  - Also finds v1vibe in common Windows locations even if not in PATH
  - **Why**: Windows doesn't auto-add `.local\bin` to PATH, breaking MCP client discovery
  - **Full path fallback**: MCP registration uses absolute path, works immediately with Claude Code
  - **Optional PATH**: Adding to PATH enables command-line usage and other MCP clients
  - **Impact**: Works on Windows without manual PATH configuration (2026-04-11)

- **Python 3.14 Support**: File Security CLI (tmfs) fallback for Python 3.14+ compatibility
  - `file_security.py`: Added `_scan_file_cli()` subprocess wrapper for tmfs binary
  - `file_security.py`: Automatic fallback from SDK → CLI → error with helpful message
  - `cli.py`: Added `_install_tmfs()` with cross-platform binary download and extraction
  - `cli.py`: Added `_get_tmfs_platform_info()` for OS/arch detection (Windows/Darwin/Linux)
  - `cli.py`: Added `_get_tmfs_version()` for version verification
  - `cli.py`: Integrated tmfs installation into setup wizard (Step 4.5)
  - `version_check.py`: Created SDK compatibility detection module
  - `config.py`: Added `tmfs_binary_path` to Settings dataclass
  - `constants.py`: Added `TMFS_BASE_URL` and `TMFS_METADATA_URL`
  - **Why**: visionone-filesecurity 1.4.4 requires grpcio<1.72, but Python 3.14 requires grpcio>=1.75.1
  - **Impact**: Windows/macOS/Linux users on Python 3.14+ can now use file scanning via CLI fallback
  - **Platforms**: Windows (.zip), macOS (.zip), Linux (.tar.gz) with arm64/x86_64/i386 support
  - **Setup Flow**: Automatic SDK compatibility check → auto-install tmfs (no prompt) → download → extract → verify
  - **User Experience**: Fully automatic - no prompts, no code changes, just run `v1vibe setup`
  - **See**: `PYTHON_3.14_SUPPORT.md` for architecture details (2026-04-11)

### Changed

- **Version checking**: Made SDK compatibility checks Python-version-aware
  - `version_check.py`: Added `get_min_versions()` that returns different requirements based on Python version
  - Python 3.13 and earlier: Requires grpcio>=1.71.0, protobuf>=4.25.0 (current SDK versions work)
  - Python 3.14+: Requires grpcio>=1.75.1, protobuf>=5.29.0 (needed for C API compatibility)
  - **Why**: Prevents false positives on Python 3.13 where grpcio 1.71.2 works fine
  - **Forward-compatible**: When Trend Micro updates SDK for Python 3.14, it will auto-detect as compatible
  - **Impact**: No unnecessary CLI fallback on Python 3.13, accurate detection on Python 3.14+ (2026-04-11)

- **Setup wizard**: Now checks for existing tmfs CLI installation before downloading
  - `cli.py`: Added check in Step 4.5 to skip download if tmfs already exists and works
  - Avoids unnecessary re-downloads when running `v1vibe setup` multiple times
  - If existing installation doesn't work, automatically reinstalls
  - **Why**: Faster setup, reduces network traffic, better user experience
  - **Impact**: Users can run setup multiple times without penalty (2026-04-11)

- **README.md**: Updated uninstall documentation to show all three package managers
  - Added uninstall instructions for `uv`, `pipx`, and `pip` (previously only showed `uv`)
  - Updated setup wizard description to mention automatic tmfs CLI installation
  - Updated system requirements to explicitly mention Python 3.14+ support
  - Updated `scan_file` tool description to mention CLI fallback compatibility
  - **Why**: Users may install with pip or pipx, not just uv
  - **Impact**: Clear uninstall path for all users regardless of installation method (2026-04-11)

- **Malware Scan Instructions**: Strengthened AI assistant guidance for comprehensive file scanning
  - `server.py`: Added concrete `find` command examples instead of vague "find all files" instruction
  - `server.py`: Added validation checkpoint - "if <10 files scanned, you MISSED files"
  - `server.py`: Added mandatory reporting - "report 'Scanned X files' before proceeding"
  - `server.py`: Added performance justification - gRPC scanner is fast (~1s/file), no reason to skip
  - Affects: `SERVER_INSTRUCTIONS`, `security_review` MCP prompt, `scan_malware` MCP prompt
  - **Impact**: AI assistants now have measurable, enforceable steps instead of abstract imperatives
  - **Why**: Previous instructions were too vague - assistants would scan 5-10 files instead of all files
  - **Benefit**: Ensures complete malware coverage during security audits (2026-04-10)

### Fixed

- **Windows PATH prompt not appearing**: Setup wizard now prompts for PATH regardless of Claude Code detection
  - `cli.py`: Moved v1vibe discovery logic outside `if claude_path:` block (lines 701-719)
  - `cli.py`: Moved Windows PATH prompt outside Claude Code registration block (lines 811-823)
  - **Bug**: PATH logic was conditional on Claude Code being detected; if `shutil.which("claude")` returned None, entire v1vibe discovery and PATH setup was skipped
  - **Impact**: Users installing on systems without Claude Code pre-installed now get PATH prompts and full path registration
  - **Why**: Windows doesn't auto-add `.local\bin` to PATH, so v1vibe must be discoverable via explicit PATH addition or full path registration
  - **Behavior**: PATH prompt now appears for all Windows installations where v1vibe is found but not in PATH, regardless of Claude Code presence (2026-04-11)

#### Phase 1: Critical Resource Management & Security (2026-04-10)
- **File Handle Management**: Fixed file handles held open during HTTP uploads
  - `sandbox.py`: File contents now read before network request, preventing file locking during slow uploads
  - `iac_scanner.py`: Same optimization for IaC template uploads
  
- **Temporary File Cleanup**: Added proper cleanup with try-finally blocks
  - `ai_scanner.py`: `scan_llm_endpoint()` now cleans up temp config and output files on exceptions
  - `ai_scanner.py`: `scan_llm_interactive()` now cleans up temp output file on exceptions
  - `cli.py`: TMAS archive files cleaned up even when extraction fails
  
- **Security - Threat Cache Permissions**: Fixed world-readable threat intelligence cache
  - `threat_intel.py`: Cache file now created with `0o600` permissions (owner-only)
  - Prevents unauthorized access to 266K cached threat indicators (95MB)
  
- **Security - Atomic File Write Cleanup**: Orphaned temp files now cleaned up
  - `threat_intel.py`: Added try-except to remove `.tmp` files if atomic replace fails
  
- **Security - Homebrew Installation**: Improved installation script handling
  - `cli.py`: Changed from command substitution `$(curl | bash)` to download-then-execute
  - Reduces MITM attack surface during Homebrew installation

- **Documentation - Docker Socket Security**: Added security warnings for Docker image scanning
  - `artifact_scanner.py`: Documented that mounting Docker socket grants root-equivalent access
  - Clear guidance on when to use alternative artifact types (docker-archive, oci-archive)

#### Phase 2: Configuration Flexibility (2026-04-10)
- **Configurable Timeouts**: All timeouts now configurable via environment variables
  - New: `V1_HTTP_TIMEOUT` (default: 60s) - Vision One API calls
  - New: `V1_SCAN_TIMEOUT` (default: 600s) - TMAS artifact scans
  - New: `V1_AI_SCAN_TIMEOUT` (default: 3600s) - AI Scanner operations
  - Enables production deployments with custom timeout requirements
  
- **Configurable Config Directory**: Custom config location support
  - New: `V1_CONFIG_DIR` environment variable
  - Enables containerized deployments and corporate environments
  - Default: `~/.v1vibe` (unchanged for backward compatibility)
  
- **Centralized API Endpoints**: Created `api_endpoints.py` with all 18 endpoint paths
  - Easier API version migration (v3.0 to v4.0)
  - Single source of truth for all REST API endpoints
  - All tool modules updated to import from centralized constants
  
- **DRY Improvements**: Eliminated code duplication
  - Created `constants.py` for shared values (TMAS_VERSION, TMAS_BASE_URL, TMAS_DOCKER_IMAGE)
  - Removed duplication between `cli.py` and `artifact_scanner.py`

#### Phase 3: Performance Optimizations (2026-04-10)
- **Sandbox API Optimization**: Reduced unnecessary API calls by ~50%
  - `sandbox.py`: Only fetch suspicious objects when `riskLevel` indicates threats
  - Skips API call for clean files (most common case)
  
- **LLM Detection Performance**: 3x faster file I/O
  - `ai_scanner.py`: Read each Python file once and cache content
  - Previous: Read each file multiple times (once per LLM provider)
  - Improvement: Read all files once, check all providers against cached content
  
- **Performance Documentation**: Added guidance for large projects
  - `artifact_scanner.py`: Documented symlink filtering overhead
  - Recommendation: Scan subdirectories (`src/`, `lib/`) for projects >1GB

### Added
- **AI Scanner (LLM Vulnerability Testing)**: New offensive security testing for AI/LLM applications
  - `detect_llm_usage` tool: Auto-detects LLM usage in code (OpenAI, Anthropic, Google, custom endpoints)
  - `scan_llm_endpoint` tool: PRIMARY automated testing tool for security reviews and CI/CD
  - `scan_llm_interactive` tool: Optional manual wizard (only when user explicitly requests)
  - Fully automated workflow: auto-detect → ask user for API key → test → report
  - Tests for jailbreaks, prompt injection, data exfiltration, toxic content, model manipulation
  - Supports any LLM endpoint: OpenAI, Anthropic, Claude, Gemini, custom models
  - Results viewable in Vision One AI Security Blueprint dashboard
  - New MCP prompt `test_ai_security` with auto-detection workflow
  - Integrated into `security_review` prompt (Step 7: AI Security auto-detection)
  - Complements existing `ai_guard_evaluate` (AI Guard = runtime protection, AI Scanner = pre-deployment testing)

- **Enhanced Error Messages**: Artifact scanner now provides actionable suggestions when scans fail
  - Malware scanning errors now explain the container-only limitation and suggest using `scan_file`
  - Symlink errors provide 4 specific workarounds (scan subdirectories, split scan types, move .venv, use scan_file)
  - Error responses include `suggestions` array with concrete next steps

### Changed
- **Threat Intelligence Feed**: Expanded from 1-year (71K indicators) to full historical data from 2018-present (266K indicators, ~8.1 years)
  - Cache size increased from ~29MB to ~95MB
  - First fetch time increased from ~20s to ~60s (one-time cost)
  - Subsequent lookups remain instant (<0.1s)
  - Hourly delta updates remain fast (<5s)
  - 274% more threat intelligence coverage (file hashes: +356%, IPs: +814%, domains: +228%, URLs: +64%)
  - Provides historical threat detection for long-running APT campaigns and infrastructure reuse

- **Artifact Scanner Improvements**:
  - Automatic exclusion of problematic directories in Docker mode (.venv, venv, node_modules, .git, __pycache__, etc.)
  - Filtered directory copying to avoid symlink issues (e.g., .venv/bin/python -> /opt/homebrew)
  - All symlinks now skipped during directory scanning to prevent broken link errors
  - Better handling of TMAS secret scanner symlink sensitivity

### Fixed
- **Symlink Error Handling**: Improved handling of broken symlinks in virtual environments
  - Docker mode now creates filtered copy of source directory excluding .venv and other dependency/build directories
  - Prevents "unable to follow symlink: lstat /opt/homebrew: no such file or directory" errors in most cases
  - Note: TMAS secret scanner remains aggressive with symlinks; workaround is to scan subdirectories (e.g., `src/`)

### Documentation
- Added "Known Limitations" section to `scan_artifact` docstring explaining:
  - Malware scanning container-only restriction
  - Secret scanning symlink sensitivity with .venv on macOS
  - Recommended workarounds for each limitation
- Updated MCP server tool descriptions to reflect automatic exclusions and limitations

## [0.1.0] - 2026-04-10

### Added

#### Core Features
- FastMCP server with 15 security tools for AI coding assistants (13 in v0.1.0, +2 AI Scanner tools added post-release)
- 11 MCP workflow prompts for comprehensive security workflows
- Interactive CLI with setup wizard, test, status, and uninstall commands
- Configuration management via environment variables or `~/.v1vibe/config.json`
- Support for 9 TrendAI Vision One regions

#### Security Tools
- **File Security**: Fast malware scanning via gRPC SDK for any file type
- **Sandbox Analysis**: Behavioral detonation for files and URLs with PDF report generation
- **Artifact Scanner**: Dependency vulnerability scanning (25+ ecosystems), malware in packages, and secret detection via TMAS CLI
- **Threat Intelligence**: Global threat feed search with local cache (~71K IOCs, hourly delta updates)
- **Suspicious Objects**: Tenant blocklist lookup for domains, IPs, URLs, file hashes, emails
- **AI Guard**: AI content safety validation for prompts (harmful content, PII, prompt injection)
- **IaC Scanner**: CloudFormation and Terraform template security validation
- **CVE Lookup**: Detailed vulnerability information with CVSS scores and mitigation options

#### Developer Experience
- Automated TMAS CLI installation during setup (native binary on Linux/Windows, Docker mode on macOS)
- Fully automated macOS installation flow with Homebrew and Docker Desktop detection
- User-editable sandbox file type list (`sandbox_filetypes.txt`)
- Comprehensive documentation with module and function docstrings
- CONTRIBUTING.md guide for open source contributors
- Natural language interface - just ask AI assistants in plain English

#### Architecture
- Dual client management: gRPC for file scanning, HTTP for REST API
- Secure configuration with 0600 file permissions
- Path traversal prevention with forbidden system directory list
- Command injection prevention in Docker mode and additional arguments
- Session-based threat feed caching with disk persistence
- Atomic cache writes for crash safety

### Security
- Input validation on all user-provided paths and filter values
- Shell metacharacter blocking in additional arguments
- Secure error handling that never leaks API tokens or auth headers
- Config file created with restrictive 0600 permissions
- Prevention of access to system directories (/etc, /sys, /proc, etc.)

### Documentation
- Comprehensive README with "How It Works" section explaining natural language usage
- Module-level docstrings for all 12 Python modules
- Function docstrings with Args, Returns, Raises sections (Google style)
- Inline comments for complex logic (threat feed caching, Docker mode, STIX parsing)
- CONTRIBUTING.md with architecture overview and step-by-step contribution guide
- Example natural language queries for AI assistants

### Developer Quality
- Full type hints across all modules
- Modern Python: pathlib, f-strings, async/await
- Named constants for magic numbers (HTTP_TIMEOUT, API_PAGE_SIZE, etc.)
- Proper exception handling with no bare except clauses
- Zero TODO/FIXME comments
- Professional code structure and naming conventions

[0.1.0]: https://github.com/arcaniusdev/v1vibe/releases/tag/v0.1.0
