# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-10

### Added

#### Core Features
- FastMCP server with 13 security tools for AI coding assistants
- 4 MCP workflow prompts (security_review, scan_project, check_urls, check_dependencies)
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
