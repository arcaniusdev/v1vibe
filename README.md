# v1vibe

**Your AI coding assistant's security advisor.**

v1vibe is an MCP server that gives AI assistants (Claude, GitHub Copilot, Cursor, etc.) enterprise-grade security capabilities. Instead of writing code first and running security scans later, your AI can discover, report, and help you fix security issues **during development** — right in your natural conversation.

## Why v1vibe?

AI coding assistants are powerful, but they can't see security threats in:
- Dependencies with known CVEs
- Malicious files or URLs in your project  
- Hardcoded secrets and API keys
- Infrastructure misconfigurations
- AI model vulnerabilities (jailbreaks, prompt injection)

**v1vibe solves this.** Powered by [TrendAI Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html), it gives your AI assistant the ability to scan, analyze, and report security findings during development. Catch issues before they reach production, all within your natural coding conversation.

## Quick Start

### Installation

```bash
# With uv (recommended)
uv tool install git+https://github.com/arcaniusdev/v1vibe.git

# Or with pipx
pipx install git+https://github.com/arcaniusdev/v1vibe.git

# Or with pip
pip install git+https://github.com/arcaniusdev/v1vibe.git
```

### Setup

```bash
v1vibe setup    # Interactive wizard - sets up everything
v1vibe test     # Verify connectivity
v1vibe status   # Show configuration
```

The setup wizard will:
1. Prompt for your Vision One API token and region
2. Test connectivity
3. Install TMAS CLI (TrendAI Artifact Scanner) for dependency/secret/container scanning
4. Register as an MCP server with Claude Code (if installed)
5. Configure your AI assistant to use v1vibe automatically

<details>
<summary><b>📋 Installation from source</b></summary>

```bash
git clone https://github.com/arcaniusdev/v1vibe.git
cd v1vibe

# Install with uv (recommended)
uv tool install .

# Or with pipx
pipx install .

# Or with pip
pip install .

# Run setup
v1vibe setup
```
</details>

## Prerequisites

**System requirements:**
- Python 3.10 or higher
- One of: `pip`, `uv`, or `pipx` (for installation)
- Internet connection (for downloading TMAS CLI during setup)
- **macOS users:** Docker Desktop (for artifact scanning) — setup wizard can install automatically

**Vision One account:**
- A [TrendAI Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html) account
- An API key with appropriate permissions ([see required permissions](#getting-your-api-key))

<details>
<summary><b>🔑 Getting your API key</b></summary>

1. Log in to [TrendAI Vision One](https://portal.xdr.trendmicro.com)
2. Navigate to **Administration > API Keys**
3. Click **Add API Key**
4. Assign a role with these permissions:
   - **File Security** — Run file scan via SDK
   - **Sandbox Analysis** — Submit object, View/filter/search
   - **Threat Intelligence** — View, Suspicious Object Management (View)
   - **AI Application Security** — AI Guard (Call detection API), AI Scanner
   - **Container Security** — Run artifacts scan
   - **Cloud Posture** — Scan templates (for IaC scanning)
   - **Vulnerability Management** — Read CVEs
</details>

## How to Use

**Just talk to your AI coding assistant. That's it.**

No APIs to learn, no commands to memorize. Simply ask your AI assistant to check your code's security:

- _"Check the security of this project"_
- _"Is this file safe?"_
- _"Scan my dependencies for vulnerabilities"_
- _"Find any secrets in my code"_
- _"Review this CloudFormation template for security issues"_
- _"Test my chatbot for security vulnerabilities"_

Your AI assistant uses v1vibe to scan files, check dependencies, analyze URLs, search threat intelligence, and generate comprehensive security reports — all in seconds, right in your conversation.

**You don't run v1vibe directly.** It's an MCP server that runs in the background, giving your AI assistant enterprise-grade security scanning capabilities through simple conversation.

## Key Features

v1vibe provides **18 security tools** across these categories:

- 🤖 **AI Safety** — Validate AI prompts and chatbot content for harmful content and prompt injection
- 🧪 **AI Security Testing** — Auto-detect and test LLMs for jailbreaks, prompt injection, data exfiltration
- 🦠 **Malware Detection** — Scan files and deep behavioral analysis (sandbox) of suspicious files/URLs
- 🔍 **Dependency Security** — Find CVEs in 25+ package ecosystems (npm, pip, Maven, Go, Rust, etc.)
- 🔐 **Secret Scanning** — Detect hardcoded credentials, API keys, tokens in code
- 🐳 **Container Security** — Scan Docker images and registries for vulnerabilities
- ☁️ **IaC Security** — Scan CloudFormation and Terraform with automatic compliance mapping (45 standards)
- 🔎 **Threat Intelligence** — Search 266K+ global threat indicators (domains, IPs, file hashes, etc.)
- 🛡️ **CVE Intelligence** — Detailed vulnerability information with mitigation guidance

<details>
<summary><b>📚 View all 18 tools</b></summary>

### 🤖 AI Content Safety (Runtime Guardrails)
| Tool | What it does |
|------|-------------|
| `ai_guard_evaluate` | Evaluate AI prompts, chatbot instructions, and LLM templates for harmful content, PII leakage, and prompt injection attacks |

### 🧪 AI Security Testing (Pre-Deployment Vulnerability Testing)
| Tool | What it does |
|------|-------------|
| `detect_llm_usage` | Auto-detect LLM usage in projects (OpenAI, Anthropic, Google, custom endpoints). Scans code for LLM imports, extracts endpoints, models, API keys. |
| `scan_llm_endpoint` | **PRIMARY automated LLM testing tool.** Tests endpoints for jailbreaks, prompt injection, data exfiltration, toxic content, model manipulation. Fully automated - no user interaction required. |
| `scan_llm_interactive` | Manual wizard for LLM testing (ONLY when user explicitly requests interactive mode). Requires terminal interaction. |

### 🦠 Malware & File Security
| Tool | What it does |
|------|-------------|
| `scan_file` | Fast malware scan using File Security SDK (seconds per file, any file type) |
| `sandbox_submit_file` | Deep behavioral analysis of files (executables, scripts, documents) |
| `sandbox_submit_url` | Sandbox analysis for up to 10 URLs |
| `sandbox_get_status` | Poll sandbox submission status |
| `sandbox_get_report` | Get full detonation report with risk level, detections, behavioral findings, PDF |

### 🔍 Dependency, Container & Secret Scanning
| Tool | What it does |
|------|-------------|
| `scan_artifact` | **Comprehensive artifact security:** scans directories, container images, or SBOM files. Three scan types: **vulnerability** (dependency CVEs), **malware** (supply chain attacks), **secrets** (hardcoded credentials). Supports 25+ ecosystems. |

<details>
<summary>Artifact scanner details</summary>

**Scan types** (can be combined):
- `vulnerability` — Find CVEs in dependencies (default)
- `malware` — Detect trojans, ransomware, backdoors in packages
- `secrets` — Find hardcoded API keys, tokens, passwords (default)

**Supported ecosystems:** npm, pip, Maven, Go, Rust, Ruby, NuGet, PHP Composer, Cargo, Bundler, plus OS packages in Alpine, Debian, Ubuntu, Amazon Linux, Red Hat, etc.

**Supported artifacts:**
- Project directories: `dir:/path/to/project` or just `/path/to/project`
- Container images: `registry:myrepo/image:tag`, `docker:image:tag`, `podman:image:tag`
- OCI directories: `oci-dir:/path/to/oci`
- Archives: `docker-archive:image.tar`, `oci-archive:image.tar`
</details>

### ☁️ Infrastructure as Code Scanning
| Tool | What it does |
|------|-------------|
| `list_compliance_standards` | List available compliance frameworks (45 total: CIS, NIST, PCI-DSS, HIPAA, AWS Well-Architected, etc.) |
| `list_compliance_profiles` | List compliance profiles for targeted scanning |
| `scan_iac_template` | Scan CloudFormation (YAML/JSON) or Terraform plan (JSON) for misconfigurations. **Automatically maps findings to ALL applicable compliance standards.** |
| `scan_terraform_archive` | Scan ZIP of Terraform HCL (.tf) files with automatic compliance mapping |

<details>
<summary>Compliance mapping details</summary>

**Automatic compliance mapping:** Every IaC finding includes a `complianceStandards` array showing which regulatory requirements it violates across ALL frameworks (CIS, NIST, AWS Well-Architected, PCI-DSS, HIPAA, ISO 27001, etc.). No configuration needed.

**Targeted scanning (optional):** Scan against a specific compliance profile (e.g., CIS AWS Foundations) by passing a `profile_id` parameter.

**45 supported standards** including:
- Multi-cloud: CIS Controls v8, NIST 800-53, PCI-DSS, HIPAA, ISO 27001, SOC 2, FEDRAMP
- AWS: AWS Well-Architected, CIS AWS Foundations (v3-v7)
- Azure: Azure Well-Architected, CIS Azure Foundations
- GCP: Google Cloud Well-Architected, CIS GCP Foundations
- And many more (GDPR, LGPD, MAS, NIS-2, etc.)
</details>

### 🔎 Threat Intelligence
| Tool | What it does |
|------|-------------|
| `search_threat_indicators` | Search 266K+ global threat indicators from TrendAI feed. Cached locally with hourly updates. Detects: file hashes, domains, IPs, URLs, email addresses, Windows registry keys, mutexes, file paths. **Instant lookups.** |
| `check_suspicious_objects` | Check URLs, domains, IPs, email addresses, or file hashes against your organization's custom blocklist |

### 🛡️ Vulnerabilities
| Tool | What it does |
|------|-------------|
| `get_cve_details` | Get detailed CVE information with CVSS scores, mitigation, affected asset counts |

### ⚙️ Quota Management
| Tool | What it does |
|------|-------------|
| `get_submission_quota` | Check remaining daily sandbox submission quota (10,000/day default) |

</details>

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
1. Environment variables: `V1_API_TOKEN` and `V1_REGION`
2. Config file: `~/.v1vibe/config.json` (created by `v1vibe setup`)

<details>
<summary><b>⚙️ Using environment variables</b></summary>

Useful for CI/CD or if you prefer not to use the setup wizard:

```bash
export V1_API_TOKEN="your-api-token"
export V1_REGION="us-east-1"
v1vibe test
```

**Supported regions:** `us-east-1`, `eu-central-1`, `ap-southeast-1`, `ap-northeast-1`, `ap-southeast-2`, `ap-south-1`, `me-south-1`, `eu-west-2`, `ca-central-1`
</details>

## Upgrading

```bash
# If installed with uv (recommended)
uv tool upgrade v1vibe

# If installed with pipx
pipx upgrade v1vibe

# If installed with pip
pip install --upgrade v1vibe
```

<details>
<summary><b>🔄 Upgrading GitHub installs</b></summary>

```bash
# uv
uv tool upgrade --reinstall v1vibe

# pipx
pipx upgrade --force v1vibe

# pip
pip install --upgrade --force-reinstall git+https://github.com/arcaniusdev/v1vibe.git
```

**After upgrading:**
1. Your configuration (`~/.v1vibe/config.json`) and threat feed cache are preserved
2. TMAS CLI binary is automatically updated if needed
3. MCP server registration remains intact
4. Run `v1vibe status` to verify the new version
</details>

## Uninstalling

```bash
v1vibe uninstall         # Removes config, TMAS binary, MCP registration, CLAUDE.md instructions
uv tool uninstall v1vibe # Then remove the Python package
```

---

<details>
<summary><b>🔧 Advanced Configuration</b></summary>

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
- `src/v1vibe/server.py` — FastMCP server with 18 tools + 11 prompts
- `src/v1vibe/config.py` — Settings, region mapping, config file I/O (includes TMAS path)
- `src/v1vibe/clients.py` — gRPC + httpx client lifecycle (lifespan context)
- `src/v1vibe/utils.py` — Error formatting, response helpers
- `src/v1vibe/tools/` — Tool implementations:
  - `file_security.py` — File malware scanning (gRPC SDK)
  - `sandbox.py` — File/URL sandbox analysis (REST v3.0)
  - `artifact_scanner.py` — Dependency/secret/container scanning (TMAS CLI wrapper)
  - `ai_guard.py` — AI content safety (REST v3.0)
  - `ai_scanner.py` — LLM vulnerability testing (TMAS CLI wrapper)
  - `threat_intel.py` — Threat intelligence lookups (REST v3.0)
  - `iac_scanner.py` — Infrastructure security (REST beta)
  - `vulnerabilities.py` — CVE details (REST v3.0)

## License

MIT

</details>
