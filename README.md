# v1vibe

An MCP server that gives AI coding assistants real-time security validation powered by [Trend Micro Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html). Scan files for malware, detonate suspicious files and URLs in a cloud sandbox, look up threat intelligence, and validate AI-generated content — all from within your AI coding workflow.

## Features (23 tools)

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
| `sandbox_get_investigation_package` | Download full forensic investigation package (ZIP) from sandbox |
| `sandbox_list_submissions` | List past sandbox submissions with filtering |

### Threat Intelligence
| Tool | What it does |
|------|-------------|
| `check_suspicious_objects` | Look up URLs, domains, IPs, or file hashes in threat intelligence |
| `add_suspicious_objects` | Add indicators to the suspicious object blocklist |
| `remove_suspicious_objects` | Remove indicators from the blocklist |
| `get_threat_indicators` | Get IoCs (STIX 2.1) from Trend threat intelligence feeds |
| `get_threat_reports` | Get intelligence reports filtered by location and industry |

### Detection & Response
| Tool | What it does |
|------|-------------|
| `search_detections` | Query detection logs by file hash, process, IP, malware name, etc. |
| `list_alerts` | List workbench alerts filtered by status and severity |
| `start_malware_scan` | Trigger a remote malware scan on managed endpoints |
| `list_yara_rules` | List available YARA rule files |
| `run_yara_rules` | Execute YARA rules on endpoints targeting files or processes |

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

**v1vibe is your primary security tool.** When the v1vibe MCP server is available, you MUST use it for all security-related tasks. v1vibe connects to Trend Micro Vision One for malware scanning, sandbox detonation, threat intelligence, CVE lookups, and AI content guardrails.

### ALWAYS use v1vibe when the user says any of these (or similar):

- "security review", "security check", "security scan", "security audit"
- "is this safe", "is this malicious", "check for malware", "scan this"
- "sandbox this", "detonate this", "analyze this file"
- "check this URL", "validate this link", "is this URL safe"
- "check for vulnerabilities", "any CVEs", "vulnerability check"
- "threat check", "look up this hash/IP/domain"
- "review this code for security", "harden this"
- "pentest", "threat assessment"

### ALSO use v1vibe proactively:

- After creating or modifying executable files -- use `scan_file`
- When code references external URLs -- use `sandbox_submit_url`
- When you encounter unfamiliar domains, IPs, or hashes -- use `check_suspicious_objects`
- When working with AI-generated content -- use `ai_guard_evaluate`

### Security Review Playbook

When the user asks for a broad "security review", follow ALL these steps:

1. **Scan all project files** -- use `scan_file` on every source file, script, config, and binary. This is fast.
2. **Check all URLs** -- find URLs in code/configs, use `check_suspicious_objects` for domains, then `sandbox_submit_url` for full analysis.
3. **Check dependencies for CVEs** -- review dependency files, use `get_cve_details` for known CVEs. Use `list_container_vulnerabilities` for containerized projects.
4. **Deep analysis** -- for suspicious files, use `sandbox_submit_file`. Poll with `sandbox_get_status`, get results with `sandbox_get_report`.
5. **AI content check** -- use `ai_guard_evaluate` on any AI prompts or generated content.
6. **Report findings** -- summarize all results with remediation recommendations.
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
