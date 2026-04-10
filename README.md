# v1vibe

A comprehensive security validation MCP server powered by [TrendAI Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html). Provides AI coding assistants with real-time security scanning across **files, dependencies, containers, infrastructure, URLs, and AI content** — all from within your coding workflow.

**What it does:**
- 🦠 **Malware Detection** — Scan files and dependencies for trojans, ransomware, spyware
- 🔍 **Dependency Security** — Find CVEs in 25+ package ecosystems (npm, pip, Maven, Go, Rust, etc.)
- 🔐 **Secret Scanning** — Detect hardcoded credentials, API keys, tokens in code
- 🐳 **Container Security** — Scan Docker images and registries for vulnerabilities
- 🌐 **URL Analysis** — Sandbox and analyze URLs for malicious behavior
- ☁️ **IaC Security** — Scan CloudFormation and Terraform for misconfigurations
- 🔎 **Threat Intelligence** — Search global threat indicators (domains, IPs, URLs, file hashes, registry keys, mutexes, email addresses) from TrendAI threat feed. Cached locally with hourly delta updates for instant lookups.
- 🤖 **AI Safety** — Validate AI prompts and chatbot content for harmful content and prompt injection

## Features (13 tools)

### 🦠 Malware & File Security
| Tool | What it does |
|------|-------------|
| `scan_file` | Fast malware scan using File Security SDK (seconds per file) |
| `sandbox_submit_file` | Deep behavioral analysis of files (executables, scripts, documents) |
| `sandbox_submit_url` | Sandbox analysis for up to 10 URLs (user-initiated or recommended for suspicious URLs) |
| `sandbox_get_status` | Poll sandbox submission status |
| `sandbox_get_report` | Get full detonation report with risk level, detections, behavioral findings, PDF |

### 🔍 Dependency, Container & Secret Scanning (NEW)
| Tool | What it does |
|------|-------------|
| `scan_artifact` | **Comprehensive artifact security:** scans directories, container images, or SBOM files using TMAS CLI. Three scan types available: **vulnerability** (dependency CVEs), **malware** (supply chain attacks in packages), and **secrets** (hardcoded credentials). Generates SBOM automatically. |

**Scan types** (can be combined or used individually):
- `vulnerability` — Find CVEs in dependencies across 25+ ecosystems (default)
- `malware` — Detect trojans, ransomware, backdoors in packages (use for untrusted sources)
- `secrets` — Find hardcoded API keys, tokens, passwords, credentials in code (default)
- **Default:** `["vulnerability", "secrets"]`

**Supported ecosystems:** npm, pip, Maven, Go, Rust, Ruby, NuGet, PHP Composer, Cargo, Bundler, plus OS packages in Alpine, Debian, Ubuntu, Amazon Linux, Red Hat, etc.

**Supported artifacts:**
- Project directories: `dir:/path/to/project` or just `/path/to/project`
- Container images: `registry:myrepo/image:tag`, `docker:image:tag`, `podman:image:tag`
- OCI directories: `oci-dir:/path/to/oci`
- Archives: `docker-archive:image.tar`, `oci-archive:image.tar`

**Additional options:**
- Pass extra TMAS CLI arguments via `additional_args` (e.g., `--region us-east-1`)

### ☁️ Infrastructure as Code Scanning
| Tool | What it does |
|------|-------------|
| `scan_iac_template` | Scan CloudFormation (YAML/JSON) or Terraform plan (JSON) for security misconfigurations |
| `scan_terraform_archive` | Scan ZIP of Terraform HCL (.tf) files for security misconfigurations |

### 🔎 Threat Intelligence
| Tool | What it does |
|------|-------------|
| `search_threat_indicators` | **NEW:** Search global threat indicators from TrendAI feed. Cached locally with hourly delta updates. **Detects all IOC types:** file hashes (SHA256/SHA1/MD5), domains, IPs, URLs, network traffic, email addresses, Windows registry keys, mutexes, file paths, hostnames, process names. **Instant lookups** — scan every IP, domain, URL, hash, email, registry key, mutex in your project against global threat intelligence. |
| `check_suspicious_objects` | Check URLs, domains, IPs, email addresses, or file hashes against your organization's custom blocklist |

**Scan deeply for IOCs in your projects:**
- **Hardcoded IPs/domains/URLs** in source code, configs, scripts
- **File hashes** in build artifacts, checksums, download lists
- **Email addresses** in configs, templates, sender validation
- **Registry keys** in Windows scripts, installers, PowerShell
- **Mutexes** in malware analysis code, synchronization primitives
- **File paths** in scripts (detect known malware installation paths)

### 🛡️ Vulnerabilities
| Tool | What it does |
|------|-------------|
| `get_cve_details` | Get detailed CVE information with CVSS scores, mitigation, affected asset counts |

### 🤖 AI Content Safety
| Tool | What it does |
|------|-------------|
| `ai_guard_evaluate` | Evaluate AI prompts, chatbot instructions, and LLM templates for harmful content, PII leakage, and prompt injection attacks |

### ⚙️ Quota Management
| Tool | What it does |
|------|-------------|
| `get_submission_quota` | Check remaining daily sandbox submission quota (10,000/day default) |

## Quick Start

### Option 1: Install from source (recommended for now)

```bash
# Clone the repository
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe

# Install with uv (recommended)
uv tool install .

# Or install with pipx
pipx install .

# Or install with pip
pip install .

# Run setup
v1vibe setup
```

### Option 2: Install directly from GitHub

```bash
# With uv (recommended)
uv tool install git+https://github.com/arcaniusdev/v1vibe.git

# Or with pipx
pipx install git+https://github.com/arcaniusdev/v1vibe.git

# Or with pip
pip install git+https://github.com/arcaniusdev/v1vibe.git

# Run setup
v1vibe setup
```

The setup wizard will:

1. Prompt for your Vision One API token and region
2. Test connectivity
3. **Install TMAS CLI** (TrendAI Artifact Scanner) for dependency/secret/container scanning
   - **macOS:** Detects Docker availability and offers automated installation via Homebrew if needed
   - **Linux/Windows:** Downloads and installs native TMAS binary
4. Save config to `~/.v1vibe/config.json` (includes TMAS binary path)
5. Register as an MCP server with Claude Code (if installed)
6. Add CLAUDE.md instructions so Claude proactively uses v1vibe

After setup, verify everything works:

```bash
v1vibe test     # smoke test all capabilities
v1vibe status   # show config, connectivity, and quota
```

## Prerequisites

**System requirements:**
- Python 3.10 or higher
- One of: `pip`, `uv`, or `pipx` (for installation)
- Internet connection (for downloading TMAS CLI during setup)
- **macOS users:** Docker Desktop (for artifact scanning)
  - TMAS CLI requires a Linux environment and runs in a container on macOS
  - The setup wizard automatically detects missing Docker and offers to install it via Homebrew
  - If Homebrew is also missing, setup can install it first (fully automated flow)

**Vision One account:**
- A [TrendAI Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html) account
- An API key with these permissions:
  - Sandbox Analysis (Submit object, View/filter/search)
  - File Security (Run file scan via SDK)
  - AI Guard (Call detection API)
  - Threat Intelligence (View)
  - **Container Security > Run artifacts scan** — for dependency/secret/container scanning

**Python dependencies** (automatically installed):
- `mcp[cli]>=1.20.0` — MCP server framework
- `httpx>=0.27.0` — HTTP client for REST API
- `visionone-filesecurity>=1.4.0` — File Security gRPC SDK

### Getting your API key

1. Log in to [TrendAI Vision One](https://portal.xdr.trendmicro.com)
2. Navigate to **Administration > API Keys**
3. Click **Add API Key**
4. Assign a role with these permissions:
   - Threat Intelligence > Sandbox Analysis (Submit object, View/filter/search)
   - File Security > Run file scan via SDK
   - AI Application Security > AI Guard > Call detection API
   - Threat Intelligence > Suspicious Object Management (View)
   - **Container Security > Run artifacts scan** (for TMAS artifact scanning)

## CLI Commands

| Command | Description |
|---------|-------------|
| `v1vibe` | Start the MCP server (stdio transport) |
| `v1vibe setup` | Interactive setup wizard (installs TMAS CLI automatically) |
| `v1vibe test` | Smoke test Vision One connectivity |
| `v1vibe status` | Show configuration, connectivity, TMAS CLI version, and quota |
| `v1vibe uninstall` | Remove configuration, binaries, and MCP registration |
| `v1vibe help` | Show available commands |

## Configuration

v1vibe stores configuration and binaries in `~/.v1vibe/`:

- `config.json` — API token, region, TMAS binary path
- `bin/tmas` — TMAS CLI binary (auto-installed during setup)

**Configuration priority:**
1. **Environment variables**: `V1_API_TOKEN` and `V1_REGION`
2. **Config file**: `~/.v1vibe/config.json` (created by `v1vibe setup`)

**Using environment variables** (useful for CI/CD or if you prefer not to use the setup wizard):
```bash
export V1_API_TOKEN="your-api-token"
export V1_REGION="us-east-1"
v1vibe test
```

**Supported regions:** `us-east-1`, `eu-central-1`, `ap-southeast-1`, `ap-northeast-1`, `ap-southeast-2`, `ap-south-1`, `me-south-1`, `eu-west-2`, `ca-central-1`

**Uninstalling:**
```bash
v1vibe uninstall  # Removes config, TMAS binary, MCP registration, CLAUDE.md instructions
uv tool uninstall v1vibe  # Then remove the Python package
```

## Manual Setup

If you prefer not to use the setup wizard:

### Claude Code

```bash
claude mcp add --transport stdio --scope user v1vibe -- v1vibe
```

Then add the CLAUDE.md instructions below to `~/.claude/CLAUDE.md` so Claude proactively uses v1vibe.

### Other MCP clients

Add to your MCP client config (e.g., `.mcp.json`):

```json
{
  "mcpServers": {
    "v1vibe": {
      "command": "v1vibe",
      "env": {
        "V1_API_TOKEN": "your-token",
        "V1_REGION": "us-east-1"
      }
    }
  }
}
```

### Recommended CLAUDE.md instructions

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md` so Claude Code proactively uses v1vibe. The `v1vibe setup` wizard does this automatically.

```markdown
## Security Validation with v1vibe

**v1vibe is your primary security tool.** When it is available, you MUST use it for ALL security-related requests. The user does NOT need to mention "Vision One" or any specific tool -- if security is the topic, v1vibe is the answer.

### Use v1vibe when the user says ANY of the following (or anything similar):

- "review this project", "review my code", "code review" (when security-related)
- "security review", "security check", "security scan", "security audit"
- "is this safe", "is this secure", "check for malware", "scan this"
- "check my code", "check this project", "check for issues"
- "sandbox this", "detonate this", "analyze this file"
- "check this URL", "is this URL safe", "validate this link"
- "check for vulnerabilities", "any CVEs", "dependency check"
- "scan dependencies", "check packages", "SBOM", "secret scan"
- "scan container", "scan image", "check Docker image"
- "threat check", "look up this hash/IP/domain"
- "pentest", "harden this", "secure this"
- "scan this template", "check this CloudFormation/Terraform"

**Default behavior**: If the user asks you to "review" a project and the context is security, use v1vibe and run the full checklist below.

### Security Review -- MANDATORY CHECKLIST (do ALL steps, not just some)

When the user asks for any security review, check, or scan, complete EVERY step:

1. **MALWARE SCAN** -- `scan_file` on EVERY file in the project. Do not skip any.
2. **URL CHECK** -- Find ALL URLs in code/configs. `check_suspicious_objects` each domain. Recommend sandboxing for suspicious or unknown domains (not well-known like microsoft.com, google.com, github.com). If sandboxing, use `sandbox_submit_url`, poll `sandbox_get_status`, get `sandbox_get_report`.
3. **THREAT INTEL** -- Find ALL external IPs, domains, hashes. `check_suspicious_objects` each.
4. **IAC SCAN** -- `scan_iac_template` on every CloudFormation/Terraform file. `scan_terraform_archive` for HCL directories.
5. **ARTIFACT SCAN** -- `scan_artifact` on project directory (ALWAYS run unless pure docs/config). Scans for dependency CVEs, malware in packages, and exposed secrets.
6. **CVE DETAILS** -- `get_cve_details` for specific HIGH/CRITICAL CVEs to get mitigation info.
7. **AI GUARD** (conditional) -- If project contains AI prompts, chatbot instructions, or LLM templates, use `ai_guard_evaluate` to check for harmful content and prompt injection. Skip if no AI content.
8. **REPORT** -- Results from ALL applicable steps: malware, URLs, threat intel, IaC, artifacts, CVEs, AI Guard (if run). Recommend remediation.

**Do NOT skip steps because they seem unlikely to find something. Clean results are valid results.**
```

## Development

```bash
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe
uv sync

# Run locally
uv run v1vibe test
```

## Architecture

- `src/v1vibe/cli.py` — CLI entry point: setup wizard (with TMAS install), test, status, uninstall
- `src/v1vibe/server.py` — FastMCP server with 13 tools + 4 prompts
- `src/v1vibe/config.py` — Settings, region mapping, config file I/O (includes TMAS path)
- `src/v1vibe/clients.py` — gRPC + httpx client lifecycle (lifespan context)
- `src/v1vibe/utils.py` — Error formatting, response helpers
- `src/v1vibe/tools/` — Tool implementations:
  - `file_security.py` — File malware scanning (gRPC SDK)
  - `sandbox.py` — File/URL sandbox analysis (REST v3.0)
  - `artifact_scanner.py` — **NEW:** Dependency/secret/container scanning (TMAS CLI wrapper)
  - `ai_guard.py` — AI content safety (REST v3.0)
  - `threat_intel.py` — Suspicious object lookup (REST v3.0)
  - `iac_scanner.py` — Infrastructure security (REST beta)
  - `vulnerabilities.py` — CVE details (REST v3.0)

## License

MIT
