# 11 MCP Prompts

MCP prompts are workflow templates that guide AI assistants through multi-tool operations. Each prompt is self-contained with trigger scenarios, tool references, and step-by-step instructions. These work across all MCP clients (Claude Code, Cursor, GitHub Copilot, etc.) without requiring SERVER_INSTRUCTIONS or CLAUDE.md.

## Available Prompts

| Prompt | Tools Used | Purpose |
|--------|-----------|---------|
| security_review | All 16 tools | Comprehensive security audit with AI Scanner auto-detection: malware, URLs, threat intel, IaC, dependencies, secrets, LLM vulnerabilities |
| scan_dependencies | scan_artifact, get_cve_details | Dependency/container/secret scanning with CVE deep-dive for HIGH/CRITICAL vulnerabilities |
| scan_malware | scan_file | Fast signature-based malware scanning of files (seconds per file, any file type) |
| sandbox_file | sandbox_submit_file, sandbox_get_status, sandbox_get_report | Deep behavioral analysis (detonation) of suspicious files with full threat report |
| check_urls | search_threat_indicators, check_suspicious_objects, sandbox_submit_url, sandbox_get_status, sandbox_get_report | URL validation against threat intel and sandbox analysis for suspicious domains |
| check_ai_content | ai_guard_evaluate | AI prompt/chatbot content safety validation (harmful content, PII, prompt injection) |
| test_ai_security | detect_llm_usage, scan_llm_endpoint | AUTO-DETECT then test LLMs for jailbreaks, prompt injection, data exfiltration (fully automated) |
| search_threats | search_threat_indicators, check_suspicious_objects | IOC lookup in global threat feed (266K+ indicators from 2018-present) and tenant blocklist |
| scan_infrastructure | scan_iac_template, scan_terraform_archive, list_compliance_standards, list_compliance_profiles | CloudFormation/Terraform security scanning with automatic compliance mapping (CIS, NIST, PCI-DSS, AWS Well-Architected) |
| investigate_cve | get_cve_details | CVE deep-dive with CVSS scores, mitigation options, affected assets |
| check_quota | get_submission_quota | Sandbox quota management (daily limit tracking) |

## Design Principles

- **Self-contained**: Each prompt includes "USE THIS WHEN" triggers and "TOOLS USED" references
- **Step-by-step**: Complete workflow instructions with expected outputs
- **Client-agnostic**: No dependency on SERVER_INSTRUCTIONS (Claude-specific) or CLAUDE.md files
- **Comprehensive coverage**: Every tool is accessible through at least one prompt

## Prompt Structure Example

```python
@mcp.prompt()
def scan_malware(file_paths: list[str] | None = None, project_path: str = ".") -> str:
    """Fast malware scanning of files using File Security SDK.

    **USE THIS WHEN:** User asks to "scan for malware", "check this file",
    "is this safe", "scan these files", "malware check", "virus scan".

    **TOOLS USED:** scan_file
    
    # ... step-by-step workflow instructions ...
    """
```

## Usage

Prompts are invoked automatically by AI assistants when users make relevant requests. Users don't need to know prompt names - they just ask naturally (e.g., "scan this project for security issues") and the AI selects the appropriate prompt.
