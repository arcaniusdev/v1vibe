# 18 Tools

Complete reference for all v1vibe security tools.

| Tool | API | Purpose |
|------|-----|---------|
| scan_file | gRPC SDK or CLI fallback | Fast malware scan, any file type (automatic CLI fallback on Python 3.14+) |
| sandbox_submit_file | REST v3.0 | Behavioral detonation, supported extensions only (user-initiated) |
| sandbox_submit_url | REST v3.0 | URL sandbox analysis (user-initiated or recommended for suspicious URLs) |
| sandbox_get_status | REST v3.0 | Poll sandbox submission |
| sandbox_get_report | REST v3.0 | Get results + download PDF report |
| scan_artifact | TMAS CLI | Dependency CVEs, malware in packages, hardcoded secrets (25+ ecosystems) |
| ai_guard_evaluate | REST v3.0 | AI content safety for prompts/chatbot code (runtime guardrails) |
| detect_llm_usage | Code analysis | Auto-detect LLM usage in projects (OpenAI, Anthropic, Google, custom) |
| scan_llm_endpoint | TMAS CLI | PRIMARY automated LLM vulnerability testing (jailbreaks, prompt injection, data exfiltration) |
| scan_llm_interactive | TMAS CLI | Manual wizard for LLM testing (only when explicitly requested) |
| search_threat_indicators | REST v3.0 | Search global threat feed for IOCs (file hashes, domains, IPs, URLs, emails, registry keys, mutexes). Cached locally (~95MB) with hourly delta updates. Covers 2018-present |
| check_suspicious_objects | REST v3.0 | Lookup indicator in tenant's blocklist |
| get_submission_quota | REST v3.0 | Daily sandbox quota check |
| list_compliance_standards | REST beta | List available compliance frameworks (CIS, NIST, PCI-DSS, HIPAA, AWS Well-Architected, etc.) |
| list_compliance_profiles | REST beta | List compliance profiles for targeted IaC scanning (returns profile IDs for use with scan tools) |
| scan_iac_template | REST beta | CloudFormation/Terraform template security scan with automatic compliance mapping (shows which CIS/NIST/PCI controls each finding violates) |
| scan_terraform_archive | REST beta | ZIP of Terraform HCL files with compliance mapping |
| get_cve_details | REST v3.0 | Specific CVE lookup with CVSS, mitigation |

## Tool Categories

### 🦠 Malware & File Security
- `scan_file` - Fast signature-based scanning
- `sandbox_submit_file` - Deep behavioral analysis
- `sandbox_submit_url` - URL detonation
- `sandbox_get_status` - Check sandbox progress
- `sandbox_get_report` - Get detailed results

### 🔍 Dependency & Container Security
- `scan_artifact` - Comprehensive artifact scanning (vulnerabilities, malware, secrets)

### 🤖 AI Security
- `ai_guard_evaluate` - Runtime content safety
- `detect_llm_usage` - Auto-detect LLM usage
- `scan_llm_endpoint` - Automated vulnerability testing
- `scan_llm_interactive` - Manual testing wizard

### 🔎 Threat Intelligence
- `search_threat_indicators` - Global threat feed search
- `check_suspicious_objects` - Tenant blocklist lookup

### ☁️ Infrastructure Security
- `list_compliance_standards` - List frameworks
- `list_compliance_profiles` - List profiles
- `scan_iac_template` - Scan CloudFormation/Terraform
- `scan_terraform_archive` - Scan HCL archives

### 🛡️ Vulnerability Management
- `get_cve_details` - CVE deep-dive

### ⚙️ Quota Management
- `get_submission_quota` - Check sandbox quota

## Implementation Details

See [architecture.md](./architecture.md) for file locations and implementation patterns.
