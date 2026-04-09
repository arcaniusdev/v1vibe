# v1vibe

An MCP server that gives AI coding assistants real-time security validation powered by [Trend Micro Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html). Scan files for malware, detonate suspicious files and URLs in a cloud sandbox, look up threat intelligence, and validate AI-generated content — all from within your AI coding workflow.

## Features (13 tools)

### File & Code Security
| Tool | What it does |
|------|-------------|
| `scan_file` | Fast malware scan via Vision One File Security SDK (seconds) |
| `sandbox_submit_file` | Submit a file for deep behavioral analysis (sandbox detonation) |
| `sandbox_submit_url` | Submit up to 10 URLs for sandbox analysis |
| `sandbox_get_status` | Poll sandbox submission status |
| `sandbox_get_report` | Get full analysis report with risk level, detections, and suspicious objects |
| `ai_guard_evaluate` | Check text for harmful content, PII leakage, and prompt injection |
| `get_submission_quota` | Check remaining daily sandbox submission quota |

### Threat Intelligence
| Tool | What it does |
|------|-------------|
| `check_suspicious_objects` | Look up URLs, domains, IPs, or file hashes in threat intelligence |
| `get_threat_indicators` | Pull IoC feed (STIX 2.1) to cross-reference against project files |

### Infrastructure as Code Scanning
| Tool | What it does |
|------|-------------|
| `scan_iac_template` | Scan CloudFormation (YAML/JSON) or Terraform plan (JSON) for security misconfigurations |
| `scan_terraform_archive` | Scan a ZIP of Terraform HCL (.tf) files for security issues |

### Vulnerabilities
| Tool | What it does |
|------|-------------|
| `get_cve_details` | Get detailed CVE info with CVSS scores, mitigation options, affected counts |
| `list_container_vulnerabilities` | List CVEs in container images with package and fix details |

## Quick Start

```bash
pip install v1vibe
v1vibe setup
```

That's it. The setup wizard will:

1. Prompt for your Vision One API token and region
2. Test connectivity
3. Save config to `~/.v1vibe/config.json`
4. Register as an MCP server with Claude Code (if installed)
5. Add CLAUDE.md instructions so Claude proactively uses v1vibe

After setup, verify everything works:

```bash
v1vibe test     # smoke test all capabilities
v1vibe status   # show config, connectivity, and quota
```

## Prerequisites

- Python 3.10+
- A [Trend Micro Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html) account
- An API key with permissions for: Sandbox Analysis, File Security (Run file scan via SDK), AI Guard, and Threat Intelligence

### Getting your API key

1. Log in to [Trend Vision One](https://portal.xdr.trendmicro.com)
2. Navigate to **Administration > API Keys**
3. Click **Add API Key**
4. Assign a role with these permissions:
   - Threat Intelligence > Sandbox Analysis (Submit object, View/filter/search)
   - File Security > Run file scan via SDK
   - AI Application Security > AI Guard > Call detection API
   - Threat Intelligence > Suspicious Object Management (View)

## CLI Commands

| Command | Description |
|---------|-------------|
| `v1vibe` | Start the MCP server (stdio transport) |
| `v1vibe setup` | Interactive setup wizard |
| `v1vibe test` | Smoke test Vision One connectivity |
| `v1vibe status` | Show configuration and health |
| `v1vibe help` | Show available commands |

## Configuration

v1vibe reads configuration from (in order of priority):

1. **Environment variables**: `V1_API_TOKEN` and `V1_REGION`
2. **Config file**: `~/.v1vibe/config.json` (created by `v1vibe setup`)

**Supported regions:** `us-east-1`, `eu-central-1`, `ap-southeast-1`, `ap-northeast-1`, `ap-southeast-2`, `ap-south-1`, `me-south-1`, `eu-west-2`, `ca-central-1`

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
- "threat check", "look up this hash/IP/domain"
- "pentest", "harden this", "secure this"
- "scan this template", "check this CloudFormation/Terraform"

**Default behavior**: If the user asks you to "review" a project and the context is security, use v1vibe and run the full checklist below.

### Security Review -- MANDATORY CHECKLIST (do ALL steps, not just some)

When the user asks for any security review, check, or scan, complete EVERY step:

1. **MALWARE SCAN** -- `scan_file` on EVERY file in the project. Do not skip any.
2. **URL CHECK** -- Find ALL URLs in code/configs. `check_suspicious_objects` each domain. `sandbox_submit_url` all URLs. Poll and get report.
3. **THREAT INTEL** -- Find ALL external IPs, domains, hashes. `check_suspicious_objects` each. `get_threat_indicators` to cross-reference IoC feed.
4. **IAC SCAN** -- `scan_iac_template` on every CloudFormation/Terraform file. `scan_terraform_archive` for HCL directories.
5. **CVE CHECK** -- Find dependency files. `get_cve_details` for known CVEs. `list_container_vulnerabilities` if Dockerized.
6. **SANDBOX** -- `sandbox_submit_file` for executables, scripts, JARs, macro docs. Poll and get report.
7. **AI GUARD** -- ALWAYS run `ai_guard_evaluate` with project summary. NOT optional.
8. **REPORT** -- Structured findings from ALL steps with remediation recommendations.

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

### Architecture

- `src/v1vibe/cli.py` — CLI entry point: setup wizard, test, status commands
- `src/v1vibe/server.py` — FastMCP server with tool registrations
- `src/v1vibe/config.py` — Settings, region mapping, config file I/O
- `src/v1vibe/clients.py` — gRPC + httpx client lifecycle (lifespan context)
- `src/v1vibe/utils.py` — Error formatting, response helpers
- `src/v1vibe/tools/` — One module per tool group (file_security, sandbox, ai_guard, threat_intel)

## License

MIT
