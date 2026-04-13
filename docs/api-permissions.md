# API Permissions and Credits

## Required Vision One API Permissions

Different tools require different API permissions. Users configure a single API key via `v1vibe setup` or environment variables.

| Feature | Required Permission | What It Does |
|---------|-------------------|--------------|
| **AI Guard** | `AI Application Security → AI Guard → Call detection API` | Runtime content safety (harmful content, PII, prompt injection) |
| **AI Scanner** | `AI Application Security → AI Scanner` | Pre-deployment LLM vulnerability testing (jailbreaks, attacks) |
| **File Security** | `File Security → Scan files` | Malware scanning via gRPC SDK |
| **Sandbox** | `Sandbox → Submit files/URLs` | Behavioral detonation analysis |
| **Artifact Scanner** | `Container Security → Run artifacts scan` | Dependency CVEs, malware in packages, hardcoded secrets (TMAS CLI) |
| **Threat Intel** | `Threat Intelligence → Read indicators` | IOC lookups in global threat feed |
| **IaC Scanning** | `Cloud Posture → Scan templates` | CloudFormation/Terraform security scanning with compliance mapping |
| **Vulnerabilities** | `Vulnerability Management → Read CVEs` | CVE details with CVSS scores and mitigations |

## Creating API Keys

1. Vision One Console → **Administration → API Keys**
2. Click **Add API key**
3. Assign a role with required permissions (or create custom role)
4. Save the API key → Configure via `v1vibe setup` or set `V1_API_TOKEN` environment variable

## AI Scanner Credit Usage

AI Scanner consumes Vision One credits based on deployment mode:

- **Trend-hosted (SaaS):** 800 credits per 5,000 daily API calls
- **Self-hosted (AWS):** 600 credits per instance per month

Credits are drawn on the 1st of the following month based on prior month usage.

**Check Usage:** Vision One Console → **AI Application Security → Manage usage**

## Common Permission Errors

**Error:** `403 Forbidden` or `Insufficient permissions`
- **Cause:** API key lacks required permission for the tool being used
- **Fix:** Add appropriate permission to API key role (see table above)

**Error:** `TMAS CLI not installed` (AI Scanner, Artifact Scanner)
- **Cause:** TMAS binary not configured
- **Fix:** Run `v1vibe setup` and install TMAS CLI (or use Docker mode on macOS)
