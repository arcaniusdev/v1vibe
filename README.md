# v1vibe

An MCP server that gives AI coding assistants real-time security validation powered by [Trend Micro Vision One](https://www.trendmicro.com/en_us/business/products/one-platform.html). Scan files for malware, detonate suspicious files and URLs in a cloud sandbox, look up threat intelligence, and validate AI-generated content — all from within your AI coding workflow.

## Features

| Tool | What it does |
|------|-------------|
| `scan_file` | Fast malware scan via Vision One File Security SDK (seconds) |
| `sandbox_submit_file` | Submit a file for deep behavioral analysis (sandbox detonation) |
| `sandbox_submit_url` | Submit up to 10 URLs for sandbox analysis |
| `sandbox_get_status` | Poll sandbox submission status |
| `sandbox_get_report` | Get full analysis report with risk level, detections, and suspicious objects |
| `ai_guard_evaluate` | Check text for harmful content, PII leakage, and prompt injection |
| `check_suspicious_objects` | Look up URLs, domains, IPs, or file hashes in threat intelligence |
| `get_submission_quota` | Check remaining daily sandbox submission quota |

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

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md` to ensure Claude Code proactively uses v1vibe for security validation:

```markdown
## Security Validation with v1vibe

When the **v1vibe** MCP server is available, use it to validate the security of code and files you produce. v1vibe connects to Trend Micro Vision One for malware scanning, sandbox detonation, threat intelligence, and AI content guardrails.

### When to use v1vibe tools

- **After creating or modifying executable files** (scripts, binaries, JARs, compiled code): use `scan_file` for a quick malware check.
- **When code references external URLs** (dependencies, API endpoints, download links, webhooks): use `sandbox_submit_url` to verify they are safe.
- **When the user asks you to scan, sandbox, or security-check a file**: use the appropriate v1vibe tool (`scan_file` for quick scan, `sandbox_submit_file` for deep analysis).
- **When you encounter unfamiliar external resources** (IPs, domains, file hashes) in code or configs: use `check_suspicious_objects` to look them up in threat intelligence.
- **When evaluating AI-generated content for safety**: use `ai_guard_evaluate` to check for harmful content, PII leakage, or prompt injection.

### Workflow

1. Quick check: `scan_file` (fast, seconds)
2. Deep analysis: `sandbox_submit_file` -> poll `sandbox_get_status` -> `sandbox_get_report`
3. URL validation: `sandbox_submit_url` -> poll `sandbox_get_status` -> `sandbox_get_report`
4. Check `get_submission_quota` before batch sandbox submissions
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
