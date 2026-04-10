"""FastMCP server implementing v1vibe security tools.

Provides 13 security tools and 10 workflow prompts for AI coding assistants:
- File/URL malware detection and behavioral analysis
- Dependency vulnerability and secret scanning
- Infrastructure as Code validation
- Threat intelligence lookups
- AI content safety checks

All tools are thin async wrappers that delegate to tool modules in tools/.
The server includes comprehensive instructions for AI clients via SERVER_INSTRUCTIONS.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from v1vibe.clients import AppContext, app_lifespan
from v1vibe.tools import (
    ai_guard,
    artifact_scanner,
    file_security,
    iac_scanner,
    sandbox,
    threat_intel,
    vulnerabilities,
)

SERVER_INSTRUCTIONS = """\
v1vibe is the security validation tool for this environment. ANY time the user wants \
to validate, review, check, or assess the security of code, files, a project, or \
infrastructure, you MUST use v1vibe. The user does NOT need to mention "Vision One" \
or any specific tool — if security is the topic, v1vibe is the answer.

## WHEN TO USE v1vibe

Use v1vibe when the user says ANY of the following (or anything similar):
- "review", "review this project", "review my code", "code review" (when security-related)
- "security review", "security check", "security scan", "security audit", "security assessment"
- "is this safe", "is this secure", "is this malicious", "is this suspicious"
- "check for malware", "scan for threats", "scan this", "scan this project"
- "check my code", "check this project", "check for issues", "check for problems"
- "sandbox this", "detonate this", "analyze this file"
- "check this URL", "is this URL safe", "validate this link"
- "check for vulnerabilities", "any CVEs", "vulnerability scan", "dependency check"
- "scan dependencies", "check my packages", "SBOM", "software bill of materials"
- "secret scan", "find secrets", "check for credentials", "hardcoded passwords"
- "scan container", "scan image", "check Docker image", "registry scan"
- "threat check", "threat assessment", "look up this hash/IP/domain"
- "pentest", "harden this", "secure this"
- "scan this template", "check this CloudFormation", "check this Terraform", "IaC scan"
- "Vision One", "v1vibe", "TMAS", "artifact scanner"

**Default behavior**: When the user asks you to "review" a project and the context is \
security (not just code style or functionality), use v1vibe and run the full checklist. \
When in doubt, USE v1vibe. Scanning and finding nothing is always better than skipping.

## MANDATORY CHECKLIST — Do ALL of these, not just some

When the user asks for any kind of security review, check, or scan, you MUST complete \
EVERY applicable step below. Do NOT skip steps. Do NOT stop after the first few. \
Each step targets a different attack surface — skipping any one leaves a gap.

### 1. MALWARE SCAN — scan every file
Find ALL files in the project: source code (.py, .js, .ts, .java, .go, .rs, .c, .rb, .php, etc.), \
scripts (.sh, .ps1, .bat), configs (.json, .yaml, .toml, .xml), documents (.pdf, .doc, .xls), \
archives (.zip, .jar, .war), and binaries.
→ Run `scan_file` on EACH file. This is fast (seconds). Do not skip any.
→ Report: total files scanned, any with scanResult != 0.

### 2. URL CHECK — find and check every URL
Search ALL project files for URLs: API endpoints, download links, webhook URLs, \
dependency sources, CDN links, redirect targets, OAuth endpoints, etc. Look in source \
code, configs, .env.example, README, package files, Dockerfiles, IaC templates.
→ Use `search_threat_indicators` for each unique domain/URL (searches global threat feed).
→ Also use `check_suspicious_objects` (type "domain") to check tenant blocklist.
→ Report: each URL, where found, any threat intelligence matches.
→ **Recommend sandboxing** for suspicious or unknown domains (not well-known like \
microsoft.com, google.com, github.com, etc.). If sandboxing, use `sandbox_submit_url`, \
poll with `sandbox_get_status`, and get results with `sandbox_get_report`.

### 3. THREAT INTELLIGENCE — deeply scan for ALL indicators of compromise (IOCs) [MANDATORY]
**CRITICAL:** Check EVERY potential IOC found in the project against global threat intelligence.
This is a fast, cached lookup (instant) — there is NO reason to skip any IOC.

**SCAN INSIDE FILES** — Use grep/Read to search file contents for IOCs. Do NOT just look at filenames.
Extract and check ALL of these IOC types from source code, configs, scripts, build files:

1. **Domains, URLs, IPs** (most common)
   - Search pattern: `https?://[^\\s]+`, `[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}`, domain patterns
   - Where: API endpoints, CDN URLs, external services, hardcoded addresses in code
   - Files to scan: ALL source code, configs, .env.example, README, package files, Dockerfiles, IaC templates
   - How: Use Grep with URL/IP regex patterns, then extract unique values
   - Check: Every unique domain, URL, and IP address (don't skip well-known domains - check them too)

2. **File hashes** (SHA256, SHA1, MD5)
   - Search pattern: SHA256 (64 hex chars), SHA1 (40 hex chars), MD5 (32 hex chars)
   - Where: Checksums in lock files, integrity manifests, download verification code, CI/CD scripts
   - Files to scan: package-lock.json, poetry.lock, Cargo.lock, checksums.txt, SHA256SUMS, *.sum files, scripts
   - How: Use Grep for `[a-f0-9]{64}`, `[a-f0-9]{40}`, `[a-f0-9]{32}` patterns
   - Check: Every hash found (even if it looks like a dependency checksum - could be trojaned)

3. **Email addresses**
   - Search pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}`
   - Where: Sender/recipient configs, contact lists, SMTP settings, notification configs
   - Files to scan: configs, templates, .env files, CI/CD configs, alerting rules, source code
   - How: Use Grep for email regex pattern
   - Check: Every email address (sender and recipient)

4. **Windows registry keys**
   - Search pattern: `HKEY_[A-Z_]+\\\\`, registry key paths
   - Where: PowerShell scripts, batch files, installers, uninstallers, Windows configs
   - Files to scan: .ps1, .bat, .cmd, .reg files, install/uninstall scripts
   - How: Use Grep for `HKEY_` or Read PowerShell scripts
   - Check: Every registry key path (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.)

5. **Mutexes** (synchronization primitives)
   - Search pattern: Mutex names, GUIDs in braces, CreateMutex calls
   - Where: Threading code, CreateMutex calls, named locks, semaphore names
   - Files to scan: Source code with threading, concurrent programming, system-level code
   - How: Grep for "CreateMutex", "mutex", GUID patterns `{[a-f0-9-]{36}}`
   - Check: Every mutex name (including GUIDs in braces)

6. **File paths** (system/installation paths)
   - Search pattern: Windows paths `C:\\\\`, `%[A-Z]+%`, Unix paths `/tmp/`, `/var/`, `~/`
   - Where: Installation directories, temp paths, hardcoded system paths in scripts
   - Files to scan: Install scripts, deployment configs, path constants in code
   - How: Grep for path patterns (C:\\\\, /tmp/, /var/, AppData, ProgramData)
   - Check: System paths like C:\\Users\\..., /tmp/, /var/, AppData paths, /etc/ paths

**For EACH unique IOC found:**
→ Run `search_threat_indicators` with the IOC value (instant lookup against cached global threat feed)
→ Also run `check_suspicious_objects` to check against your tenant's custom blocklist
→ Report ALL matches: IOC type, value, where found, threat indicator details, valid dates, recommended action

**Do NOT skip IOCs because they "look safe"** — many legitimate-looking values are malicious.

### 4. IAC TEMPLATE SCAN — scan every infrastructure template
Find ALL CloudFormation files (.yaml, .json, .template) and Terraform files (.tf, .tf.json).
→ For CloudFormation: run `scan_iac_template` with type "cloudformation-template" on each.
→ For Terraform plan JSON: run `scan_iac_template` with type "terraform-template".
→ For Terraform HCL directories: ZIP the .tf files and run `scan_terraform_archive`.
→ Report: all findings with status FAILURE, grouped by risk level.

### 5. ARTIFACT SCAN — scan for vulnerabilities, malware, and secrets (ALWAYS RUN)
**ALWAYS run this on every project with code dependencies or container images.** Use TMAS to scan for:
- **Vulnerabilities**: Open-source package CVEs in 25+ ecosystems (npm, pip, Maven, Go, Rust, Ruby, PHP, etc.)
- **Malware**: Trojans, ransomware, spyware in dependencies and artifacts
- **Secrets**: Hardcoded credentials, API keys, tokens, passwords in code

**When to run:**
- ANY project with package files (package.json, requirements.txt, go.mod, pom.xml, Cargo.toml, etc.)
- Container images or Dockerfiles
- ANY codebase where secrets could be hardcoded
- In other words: **ALWAYS run this unless it's a pure config/documentation repo**

→ Run `scan_artifact` with artifact path = project root directory
→ Default scan types: ["vulnerability", "secrets"] — add "malware" for untrusted sources
→ Report: CVEs with CVSS scores, malware detections, exposed secrets with file locations
→ This generates an SBOM and provides comprehensive supply chain security analysis

### 6. DEPENDENCY CVE CHECK — look up specific known vulnerabilities
Find dependency files (package.json, requirements.txt, pyproject.toml, go.mod, pom.xml, \
Cargo.toml, Gemfile, composer.json, etc.) and identify dependencies with known CVEs.
→ Run `get_cve_details` for each known CVE ID to get detailed mitigation info.
→ Report: CVE ID, CVSS score, severity, fix version availability.
→ NOTE: `scan_artifact` provides broader CVE coverage; use this for deep-dive on specific CVEs.

### 7. AI CONTENT VALIDATION — conditional (only if AI prompts/templates found)
**Only run this if the project contains AI-related content:**
- AI prompt templates or chatbot instructions
- LLM system prompts or conversation templates
- AI application code with user-facing prompts
→ Use `ai_guard_evaluate` to check each prompt/template for harmful content, PII leakage, \
and prompt injection vulnerabilities.
→ Report: Allow/Block action, harmful content categories, PII detected, prompt injection risk.
→ **Skip this step** if the project has no AI prompts or chatbot code.

### 8. REPORT — summarize ALL findings
After completing ALL applicable steps above, produce a structured report:
- Total files scanned and malware detections
- URLs checked: suspicious object matches and sandbox risk levels
- Threat intelligence matches for IPs, domains, hashes
- IaC template misconfigurations
- Artifact scan results: dependency CVEs, malware in packages, exposed secrets
- Specific CVE details from get_cve_details
- AI Guard results (only if AI prompts/templates were found and checked)
- Prioritized remediation recommendations

## IMPORTANT: Do not skip steps because they seem unlikely to find anything. \
The whole point is comprehensive coverage. A clean result is a valid result.

## SANDBOX BEHAVIOR

**Both file and URL sandboxing are user-initiated or recommended when suspicious.**

**URL sandboxing:** Use `sandbox_submit_url` when:
- The user explicitly asks to sandbox or analyze a URL
- A domain appears suspicious (flagged by `check_suspicious_objects` or unknown/untrusted)
- Skip well-known domains: microsoft.com, google.com, github.com, npmjs.com, pypi.org, \
trendmicro.com, adobe.com, amazon.com, cloudflare.com, etc.
- When recommending, explain why (e.g., "unknown domain" or "flagged in threat intel")

**File sandboxing:** Use `sandbox_submit_file` when:
- The user explicitly asks to sandbox, detonate, or deeply analyze a file
- A scan_file result or threat intelligence match looks suspicious or uncertain — \
in this case, SUGGEST sandboxing to the user and explain why

Supported file types for sandboxing: executables, scripts (.py, .js, .sh, .ps1, .bat, \
.vbs, etc.), documents (.doc, .pdf, .xls, etc.), Java (.class, .jar), web content, \
archives, and email. The tool validates extensions and rejects unsupported types.

### When sandbox results come back, you MUST:
1. Call `sandbox_get_report` with `save_pdf_to` set to a path in the project \
(e.g., `./reports/sandbox-<filename>.pdf`) so the user has the native PDF report.
2. Fully analyze ALL fields in the JSON response: risk level, detection names, \
threat types, true file type, and every suspicious object found.
3. Discuss the behavioral findings in detail with the user — what the file did \
during detonation, what network connections it made, what it dropped or modified.
4. Provide clear recommendations based on the findings.
"""

mcp = FastMCP("v1vibe", instructions=SERVER_INSTRUCTIONS, lifespan=app_lifespan)


def _ctx(ctx: Context) -> AppContext:
    return ctx.request_context.lifespan_context


@mcp.tool()
async def scan_file(
    ctx: Context,
    file_path: str,
    tags: list[str] | None = None,
    pml: bool = False,
) -> dict:
    """Scan a local file for malware using TrendAI File Security.

    Returns scan verdict with malware names and SHA1/SHA256 hashes.
    Fast (seconds). Use for any file your code produces or downloads.

    Args:
        file_path: Absolute path to the file to scan.
        tags: Optional tags for organizing scan results (max 8, 63 chars each).
        pml: Enable Predictive Machine Learning detection for novel malware variants.
    """
    return await file_security.scan_file(_ctx(ctx), file_path, tags, pml)


@mcp.tool()
async def sandbox_submit_file(
    ctx: Context,
    file_path: str,
    document_password: str | None = None,
    archive_password: str | None = None,
    arguments: str | None = None,
) -> dict:
    """Submit a file to TrendAI sandbox for deep behavioral analysis (detonation).

    Returns a task ID to check status later with sandbox_get_status.
    Only files with supported extensions can be sandboxed — unsupported types will be
    rejected with a suggestion to use scan_file instead.

    Supported: executables (.exe, .dll, .msi, .dmg, .pkg), scripts (.bat, .cmd, .js,
    .vbs, .ps1, .sh, .py, .hta, .wsf), documents (.doc, .docx, .xls, .xlsx, .ppt,
    .pptx, .pdf, .rtf, .csv, .xml), Java (.class, .jar), web (.html, .svg),
    archives (.zip, .7z, .rar, .tar, .gz), email (.eml, .msg), and more.

    Note: scan_file (File Security SDK) accepts ANY file type for malware scanning.
    This sandbox tool is for deep behavioral detonation of supported types only.

    Args:
        file_path: Absolute path to the file to submit.
        document_password: Password to decrypt an encrypted document (plaintext, will be base64-encoded).
        archive_password: Password to decrypt an encrypted archive (plaintext, will be base64-encoded).
        arguments: Command-line arguments for PE/script file execution in sandbox.
    """
    return await sandbox.submit_file(
        _ctx(ctx), file_path, document_password, archive_password, arguments
    )


@mcp.tool()
async def sandbox_submit_url(
    ctx: Context,
    urls: list[str],
) -> dict:
    """Submit up to 10 URLs to TrendAI sandbox for analysis.

    Returns per-URL task IDs. Use to check if URLs referenced in code,
    configs, or dependencies are malicious.

    Args:
        urls: List of URLs to analyze (maximum 10 per request).
    """
    return await sandbox.submit_url(_ctx(ctx), urls)


@mcp.tool()
async def sandbox_get_status(
    ctx: Context,
    task_id: str,
) -> dict:
    """Check the status of a sandbox submission by task ID.

    Returns whether analysis is running, succeeded, or failed.
    When succeeded, includes a resourceLocation URL to get the full report.

    Args:
        task_id: The task ID returned from sandbox_submit_file or sandbox_submit_url.
    """
    return await sandbox.get_status(_ctx(ctx), task_id)


@mcp.tool()
async def sandbox_get_report(
    ctx: Context,
    result_id: str,
    save_pdf_to: str | None = None,
) -> dict:
    """Get the full analysis report for a completed sandbox submission.

    Returns risk level, detection names, threat types, true file type,
    and any suspicious objects (IPs, URLs, domains, file hashes) found.
    You MUST fully analyze and discuss all findings in the report with the user.

    Also downloads the native PDF report for human review when save_pdf_to is provided.
    You SHOULD always provide save_pdf_to so the user has a copy of the full report.

    Args:
        result_id: The result ID from the resourceLocation in sandbox_get_status.
        save_pdf_to: Absolute path to save the PDF report (e.g., ./reports/sandbox-report.pdf). Recommended.
    """
    return await sandbox.get_report(_ctx(ctx), result_id, save_pdf_to)


@mcp.tool()
async def ai_guard_evaluate(
    ctx: Context,
    prompt: str,
    application_name: str = "v1vibe",
) -> dict:
    """Evaluate text against TrendAI AI Guard security policies.

    Detects harmful content, sensitive information leakage (PII, credentials),
    and prompt injection attacks. Returns Allow/Block action with detailed
    violation reasons and confidence scores.

    Args:
        prompt: The text content to evaluate (max 1024 characters).
        application_name: Name of the AI application for tracking (default: v1vibe).
    """
    return await ai_guard.evaluate(_ctx(ctx), prompt, application_name)


@mcp.tool()
async def check_suspicious_objects(
    ctx: Context,
    object_type: str,
    value: str,
    risk_level: str | None = None,
) -> dict:
    """Check if a URL, domain, IP address, email, or file hash is in your organization's custom blocklist.

    Returns matching suspicious objects with risk levels and scan actions from your
    tenant's blocklist (not global threat intelligence).

    Args:
        object_type: Type of object — one of: url, domain, ip, fileSha1, fileSha256, senderMailAddress.
        value: The value to look up (e.g., the URL, IP address, or file hash).
        risk_level: Optional filter — one of: high, medium, low.
    """
    return await threat_intel.check_suspicious_objects(
        _ctx(ctx), object_type, value, risk_level
    )


@mcp.tool()
async def search_threat_indicators(
    ctx: Context,
    indicator_value: str,
) -> dict:
    """Search TrendAI threat intelligence feed for a specific indicator.

    Searches the complete threat intelligence feed for matches. The feed is cached
    locally and refreshed hourly with delta updates.

    This provides instant lookups against global threat intelligence, complementing
    check_suspicious_objects (tenant blocklist) and sandbox_submit_url (deep analysis).

    Supported indicator types (auto-detected):
    - Domains, URLs, IPs (IPv4/IPv6)
    - File hashes (SHA256, SHA1, MD5)
    - Email addresses
    - Windows registry keys
    - Mutexes, file paths, hostnames, process names

    Args:
        indicator_value: The indicator to search for (any type listed above).

    Returns:
        Match results with indicator details, threat types, and cache info.
    """
    return await threat_intel.search_threat_indicators(_ctx(ctx), indicator_value)


@mcp.tool()
async def get_submission_quota(ctx: Context) -> dict:
    """Check remaining sandbox submission quota for today.

    Returns daily reserve count, remaining submissions, and a breakdown
    of file vs URL submission counts. Use before batch submissions.
    """
    return await sandbox.get_submission_quota(_ctx(ctx))


# --- Infrastructure as Code Scanning ---


@mcp.tool()
async def scan_iac_template(
    ctx: Context,
    file_path: str,
    template_type: str,
) -> dict:
    """Scan a CloudFormation or Terraform template for security misconfigurations.

    Checks IaC templates against hundreds of security rules covering compliance
    standards, best practices, and common misconfigurations. Returns findings with
    risk levels (LOW to EXTREME), affected resources, and remediation links.

    Use this whenever you create or modify CloudFormation or Terraform templates.

    Args:
        file_path: Absolute path to the template file.
        template_type: One of: cloudformation-template (YAML/JSON), terraform-template (Terraform plan JSON).
    """
    return await iac_scanner.scan_template(_ctx(ctx), file_path, template_type)


@mcp.tool()
async def scan_terraform_archive(
    ctx: Context,
    file_path: str,
) -> dict:
    """Scan a ZIP archive containing Terraform HCL (.tf) files for security issues.

    Scans Terraform configurations with a single root module inside the ZIP.
    Returns findings with risk levels, affected resources, and remediation links.

    Args:
        file_path: Absolute path to the ZIP file containing .tf files.
    """
    return await iac_scanner.scan_terraform_archive(_ctx(ctx), file_path)


# --- Vulnerability Management ---


@mcp.tool()
async def get_cve_details(
    ctx: Context,
    cve_id: str,
) -> dict:
    """Get detailed information about a specific CVE from Vision One.

    Returns CVSS scores, description, mitigation options (patches, packages),
    and counts of affected assets across devices, containers, cloud VMs, and serverless.
    Use when code depends on a library with a known CVE.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-44487").
    """
    return await vulnerabilities.get_cve_details(_ctx(ctx), cve_id)


@mcp.tool()
async def scan_artifact(
    ctx: Context,
    artifact: str,
    scan_types: list[str] | None = None,
    additional_args: str | None = None,
) -> dict:
    """Scans artifact using TMAS CLI for vulnerabilities, malware, and secrets.

    Generates SBOM for vulnerability scanning, detects malware in dependencies,
    and finds exposed credentials. Supports 25+ package ecosystems including
    npm, pip, Maven, Go, Rust, NuGet, Ruby, and container images.

    Use when:
    - Scanning project directories for dependency vulnerabilities and secrets
    - Analyzing container images for CVEs before deployment
    - Checking for hardcoded credentials, API keys, tokens in code
    - Detecting supply chain attacks (trojans, backdoors in dependencies)
    - Generating SBOM for compliance and supply chain security

    Scan types (can be combined):
    - "vulnerability" — Find CVEs in dependencies (included by default)
    - "malware" — Detect trojans, ransomware, backdoors in packages (use for untrusted sources)
    - "secrets" — Find hardcoded API keys, tokens, passwords in code (included by default)
    Default: ["vulnerability", "secrets"]

    Supported artifacts:
    - Directories: "dir:/path/to/project" or just "/path/to/project"
    - Container images: "registry:myrepo/image:tag", "docker:image:tag", "podman:image:tag"
    - OCI directories: "oci-dir:/path/to/oci"
    - Archives: "docker-archive:image.tar", "oci-archive:image.tar"

    Args:
        artifact: Path to artifact (directory, image reference, or archive).
        scan_types: Scan types to run. Options: "vulnerability", "malware", "secrets".
                   Default: ["vulnerability", "secrets"]
        additional_args: Extra CLI arguments (e.g., "--region us-east-1", "--output-format json").

    Returns:
        Scan results including CVEs with CVSS scores, malware detections,
        and exposed secrets with file locations.
    """
    return await artifact_scanner.scan_artifact(_ctx(ctx), artifact, scan_types, additional_args)


# ═══════════════════════════════════════════════
# MCP Prompts — workflow templates for AI clients
# ═══════════════════════════════════════════════


@mcp.prompt()
def security_review(project_path: str = ".") -> str:
    """Comprehensive security review of a project using Vision One.

    **USE THIS WHEN:** User asks for "security review", "security check", "review this project",
    "check for issues", or any general security assessment.

    **TOOLS USED:** scan_file, check_suspicious_objects, search_threat_indicators,
    sandbox_submit_url, sandbox_get_status, sandbox_get_report, scan_iac_template,
    scan_terraform_archive, scan_artifact, get_cve_details, ai_guard_evaluate

    Guides through a full security review covering ALL attack surfaces: malware,
    URLs, threat intelligence, IaC, dependencies, secrets, and AI content safety.
    """
    return f"""Perform a COMPREHENSIVE security review of the project at: {project_path}

CRITICAL: You MUST complete ALL applicable steps below. Do NOT skip any step. Do NOT stop early.
Each step covers a different attack surface. A step returning clean results is valid and expected.

## Step 1: MALWARE SCAN
Find ALL files in the project (source code, scripts, configs, documents, archives, binaries).
→ Use `scan_file` on EACH file. Fast (seconds per file).
→ Report: total files scanned, any with scanResult != 0, malware names, file hashes.

## Step 2: URL VALIDATION
Search ALL files for URLs (API endpoints, downloads, webhooks, CDN, OAuth, dependencies).
→ Use `search_threat_indicators` for each unique domain/URL (instant, cached global threat feed).
→ Use `check_suspicious_objects` (type "domain") for each unique domain (tenant blocklist).
→ **Recommend sandboxing** for suspicious/unknown domains (not well-known like github.com, microsoft.com).
→ If sandboxing: `sandbox_submit_url` → poll `sandbox_get_status` → `sandbox_get_report` (save PDF).
→ Report: each URL, where found, threat matches, sandbox risk level (if run).

## Step 3: THREAT INTELLIGENCE DEEP SCAN
Extract ALL IOCs from code/configs (use Grep to search file contents):
- Domains, URLs, IPs: grep for URL patterns, IP addresses
- File hashes (SHA256/SHA1/MD5): grep for 64/40/32 hex chars
- Email addresses: grep for email patterns
- Windows registry keys: grep for HKEY_ patterns (if Windows scripts present)
- Mutexes: grep for CreateMutex, GUID patterns (if threading code present)
- File paths: grep for C:\\, /tmp/, /var/ patterns (if scripts present)
→ For EACH unique IOC: `search_threat_indicators` + `check_suspicious_objects`.
→ Report: IOC type, value, where found, threat details, validity dates.

## Step 4: INFRASTRUCTURE SCANNING
Find ALL CloudFormation (.yaml, .json, .template) and Terraform (.tf, .tf.json) files.
→ CloudFormation: `scan_iac_template` with type "cloudformation-template".
→ Terraform plan JSON: `scan_iac_template` with type "terraform-template".
→ Terraform HCL: ZIP .tf files and use `scan_terraform_archive`.
→ Report: all FAILURE findings grouped by risk level (EXTREME > HIGH > MEDIUM > LOW).

## Step 5: ARTIFACT SCAN (dependency vulnerabilities, secrets, malware)
**ALWAYS run unless pure docs/config with no code.**
→ Use `scan_artifact` with artifact="{project_path}", scan_types=["vulnerability", "secrets"].
→ Add "malware" to scan_types if untrusted dependencies or unknown source.
→ Generates SBOM, scans 25+ ecosystems (npm, pip, Maven, Go, Rust, Ruby, PHP, NuGet, etc.).
→ Report: CVEs with CVSS scores, malware in packages, secrets with file paths and severity.

## Step 6: CVE DEEP-DIVE
For any HIGH or CRITICAL CVEs from step 5:
→ Use `get_cve_details` for each CVE ID.
→ Report: CVSS score, description, mitigation options, patch availability, affected assets.

## Step 7: AI CONTENT SAFETY (conditional)
**Only if project contains AI prompts/chatbot code/LLM templates.**
→ Use `ai_guard_evaluate` on each prompt/template.
→ Report: Allow/Block action, harmful categories, PII detected, prompt injection risk.
→ Skip if no AI content present.

## Step 8: FINAL REPORT
Structured summary with:
- Files scanned and malware detections
- URLs checked, threat matches, sandbox results
- IOCs found and threat intelligence matches
- IaC misconfigurations by risk level
- Dependency CVEs, malware in packages, exposed secrets
- CVE details for critical vulnerabilities
- AI Guard results (if applicable)
- Prioritized remediation recommendations
- Suggestions for deeper analysis (sandbox suspicious files/URLs)"""


@mcp.prompt()
def scan_dependencies(project_path: str = ".") -> str:
    """Scan project dependencies and containers for vulnerabilities, malware, and secrets.

    **USE THIS WHEN:** User asks to "check dependencies", "scan for vulnerabilities",
    "check for CVEs", "scan packages", "check my containers", "find secrets",
    "SBOM", "supply chain security".

    **TOOLS USED:** scan_artifact, get_cve_details

    Comprehensive dependency scanning using TMAS CLI across 25+ ecosystems.
    Detects CVEs, malware in packages, and hardcoded credentials.
    """
    return f"""Scan dependencies, containers, and secrets in project at: {project_path}

## What this does
Scans the project using TMAS CLI for:
- **Vulnerabilities**: CVEs in dependencies (npm, pip, Maven, Go, Rust, Ruby, PHP, NuGet, etc.)
- **Malware**: Trojans, ransomware, backdoors in packages (supply chain attacks)
- **Secrets**: Hardcoded credentials, API keys, tokens, passwords in code

## Step 1: Scan the artifact
→ Use `scan_artifact` with:
  - artifact = "{project_path}" (or specific subdirectory if root fails)
  - scan_types = ["vulnerability", "secrets"] (default)
  - Add "malware" if untrusted source or you want supply chain attack detection
→ The tool auto-detects package managers (package.json, requirements.txt, go.mod, pom.xml, etc.)
→ Generates SBOM automatically

## Step 2: Analyze results
Parse the scan results:
- **Vulnerabilities**: List CVEs with CVSS scores, severity, affected packages
- **Malware**: List detections with threat type and package name
- **Secrets**: List exposed credentials with file paths, line numbers, and secret types

## Step 3: Deep-dive on critical CVEs
For any HIGH or CRITICAL CVEs found:
→ Use `get_cve_details` with the CVE ID to get:
  - Detailed description
  - Mitigation options (patches, packages)
  - Fix version availability
  - Affected asset counts

## Step 4: Report
Provide structured output:
- Total packages scanned
- Vulnerabilities by severity (CRITICAL > HIGH > MEDIUM > LOW)
- CVE details for top risks
- Malware detections in dependencies (if malware scan was run)
- Secrets exposed with file locations
- Recommended actions: upgrade packages, rotate credentials, remove malicious dependencies

## Supported artifacts
- Directories: /path/to/project (auto-detects package files)
- Container images: registry:myrepo/image:tag, docker:image:tag
- Archives: docker-archive:image.tar, oci-archive:image.tar"""


@mcp.prompt()
def scan_malware(file_paths: list[str] | None = None, project_path: str = ".") -> str:
    """Fast malware scanning of files using File Security SDK.

    **USE THIS WHEN:** User asks to "scan for malware", "check this file",
    "is this safe", "scan these files", "malware check", "virus scan".

    **TOOLS USED:** scan_file

    Signature-based malware detection (seconds per file). Scans ANY file type.
    For behavioral analysis, use the sandbox_file prompt instead.
    """
    files_hint = f"specified files: {file_paths}" if file_paths else f"all files in {project_path}"
    return f"""Fast malware scan of {files_hint}

## What this does
Uses File Security SDK (signature-based detection) to scan files for:
- Known malware signatures
- Trojans, ransomware, spyware, adware
- Potentially unwanted programs (PUPs)
- Malicious scripts and documents

## Step 1: Find files to scan
{"Use the provided file paths." if file_paths else f"""Find ALL files in {project_path}:
- Source code (.py, .js, .ts, .java, .go, .rs, .c, .cpp, .rb, .php, etc.)
- Scripts (.sh, .bash, .ps1, .bat, .cmd)
- Config files (.json, .yaml, .yml, .toml, .xml)
- Documents (.pdf, .doc, .docx, .xls, .xlsx, .ppt)
- Archives (.zip, .tar, .gz, .7z, .rar, .jar, .war)
- Binaries and executables
- Any other files"""}

## Step 2: Scan each file
For EACH file:
→ Use `scan_file` with:
  - file_path = absolute path
  - tags = ["project_scan"] (optional, for tracking)
  - pml = true (enables ML detection for novel malware variants)

Fast (seconds per file). Accepts ANY file type.

## Step 3: Analyze results
For each scanned file, check:
- **scanResult**: 0 = clean, 1+ = malware detected
- **foundMalwares**: List of malware names detected
- **fileSHA1**, **fileSHA256**: File hashes (use for threat intel lookup)

## Step 4: Report
Provide summary:
- Total files scanned
- Clean files count
- Detections: filename, malware names, file hash, risk level
- Recommendation: quarantine/delete infected files, investigate further

## When to use behavioral analysis instead
If scan results are suspicious or uncertain, recommend using `sandbox_submit_file`
for deep behavioral detonation (shows what the file DOES when executed).
File Security SDK (this tool) is signature-based and fast.
Sandbox (sandbox_file prompt) is behavioral and thorough."""


@mcp.prompt()
def sandbox_file(file_path: str) -> str:
    """Deep behavioral analysis (sandboxing) of a suspicious file.

    **USE THIS WHEN:** User asks to "sandbox this file", "detonate this",
    "analyze this file", "what does this file do", or when scan_file results
    are suspicious/uncertain and you need behavioral analysis.

    **TOOLS USED:** sandbox_submit_file, sandbox_get_status, sandbox_get_report

    Executes the file in an isolated sandbox and monitors behavior: network
    connections, file modifications, registry changes, process creation, etc.
    """
    return f"""Deep behavioral analysis (sandboxing) of: {file_path}

## What this does
Executes the file in a secure, isolated sandbox environment and monitors:
- Network connections (IPs, domains, URLs contacted)
- File system modifications (files created, modified, deleted)
- Registry changes (Windows)
- Process creation and behavior
- Mutex creation and synchronization
- Behavioral patterns (persistence mechanisms, anti-analysis tricks)

Results in a comprehensive threat report with risk level and detection names.

## Supported file types
Executables (.exe, .dll, .msi, .dmg, .pkg), scripts (.py, .js, .sh, .ps1, .bat,
.vbs), documents (.doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf), Java (.class, .jar),
web content (.html, .svg), archives (.zip, .7z, .rar, .tar, .gz), email (.eml, .msg).

Unsupported types will be rejected with a suggestion to use scan_file instead.

## Step 1: Submit the file
→ Use `sandbox_submit_file` with:
  - file_path = "{file_path}"
  - document_password = (if encrypted document)
  - archive_password = (if encrypted archive)
  - arguments = command-line args (if PE/script needs specific execution args)
→ Returns a task_id to track the submission.

## Step 2: Poll for completion
→ Use `sandbox_get_status` with the task_id.
→ Poll every 15-30 seconds until status is "succeeded" or "failed".
→ When succeeded, you'll get a resourceLocation URL containing the result_id.

## Step 3: Get the full report
→ Extract result_id from resourceLocation (the UUID in the URL path).
→ Use `sandbox_get_report` with:
  - result_id = extracted UUID
  - save_pdf_to = "./reports/sandbox-{file_path.split('/')[-1]}.pdf" (ALWAYS save PDF)
→ You MUST fully analyze ALL fields in the JSON response.

## Step 4: Analyze and report
Parse the full report:
- **riskLevel**: no_risk, low, medium, high (overall verdict)
- **detectionNames**: List of threat names detected
- **trueFileType**: Actual file type vs claimed type (detects masquerading)
- **threatTypes**: Categories (malware, phishing, etc.)
- **suspiciousObjects**: ALL IPs, domains, URLs, file hashes found during execution
  - For EACH suspicious object: run `search_threat_indicators` and `check_suspicious_objects`
- **Behavioral findings**: What the file DID (from the full JSON response)

## Step 5: Detailed report to user
Provide comprehensive analysis:
- Risk level and detection names
- True file type vs claimed type
- Network activity: domains/IPs contacted, threat intel matches
- File system changes
- Registry modifications (Windows)
- Process behavior
- Suspicious indicators found
- Threat intelligence matches for ALL suspicious objects
- Recommendation: safe / quarantine / delete / investigate further
- PDF report location for detailed human review

## When scan quota is low
Before submitting, use `get_submission_quota` to check remaining daily quota.
If low, warn the user before proceeding."""


@mcp.prompt()
def check_urls(project_path: str = ".", urls: list[str] | None = None) -> str:
    """Validate URLs for security threats using threat intelligence and sandbox analysis.

    **USE THIS WHEN:** User asks to "check this URL", "is this URL safe",
    "validate this link", "scan these URLs", or you find URLs in code that need validation.

    **TOOLS USED:** search_threat_indicators, check_suspicious_objects,
    sandbox_submit_url, sandbox_get_status, sandbox_get_report

    Checks URLs against global threat intelligence and tenant blocklist.
    Optionally sandboxes suspicious URLs for behavioral analysis.
    """
    urls_hint = f"Validate these specific URLs: {urls}" if urls else f"Find and validate all URLs in {project_path}"
    return f"""{urls_hint}

## What this does
Validates URLs against:
- **Global threat intelligence** (71K+ cached IOCs with hourly updates)
- **Tenant blocklist** (your organization's custom suspicious objects)
- **Behavioral sandbox** (for suspicious/unknown domains - optional, recommended)

## Step 1: Extract URLs
{"Use the provided URLs." if urls else f"""Search all files in {project_path} for URLs:
- Source code (API endpoints, download URLs, webhook targets, OAuth callbacks)
- Config files (service endpoints, database URLs, Redis URLs, message queues)
- Package files (registry URLs, repository URLs, dependency sources)
- Documentation, README files
- Environment example files (.env.example)
- CI/CD configs, deployment scripts

Extract all unique URLs and domains."""}

## Step 2: Threat intelligence lookup
For EACH unique domain/URL:
→ Use `search_threat_indicators` with the domain or full URL.
  - Instant lookup (cached, no API call)
  - Checks global threat feed (domains, URLs, IPs)
  - Returns match details: threat type, validity dates, labels
→ Use `check_suspicious_objects` with type="domain" and value=domain.
  - Checks your tenant's custom blocklist
  - Returns risk level (high/medium/low) and scan action

## Step 3: Identify suspicious URLs
Mark as suspicious if:
- Matched in threat intelligence (search_threat_indicators found it)
- Matched in tenant blocklist (check_suspicious_objects found it)
- Unknown/untrusted domain (not well-known like github.com, microsoft.com, google.com,
  npmjs.com, pypi.org, aws.amazon.com, cloudflare.com, etc.)

## Step 4: Sandbox suspicious URLs (recommended)
For suspicious/unknown domains:
→ Use `sandbox_submit_url` with list of suspicious URLs (max 10 per call).
→ Poll each with `sandbox_get_status` every 15-30 seconds until succeeded.
→ Use `sandbox_get_report` with result_id and save_pdf_to="./reports/sandbox-url-<domain>.pdf".
→ Analyze: riskLevel, detectionNames, threatTypes, suspiciousObjects found.

## Step 5: Report
For EACH URL, provide:
- URL and where found in code/config
- Threat intelligence matches (if any): threat type, validity dates
- Tenant blocklist matches (if any): risk level, scan action
- Sandbox results (if run): risk level, detections, behavioral findings
- Verdict: SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN
- Recommendation: allow / block / investigate further / remove from code

Group by verdict for easy prioritization."""


@mcp.prompt()
def check_ai_content(content: str | None = None, project_path: str = ".") -> str:
    """Validate AI prompts and chatbot content for safety and prompt injection.

    **USE THIS WHEN:** User asks to "check this prompt", "validate AI content",
    "is this prompt safe", "check for prompt injection", or you find AI prompts/
    chatbot code that needs validation.

    **TOOLS USED:** ai_guard_evaluate

    Detects harmful content, PII leakage, and prompt injection attacks in AI
    prompts, chatbot instructions, and LLM templates.
    """
    content_hint = "the provided content" if content else f"all AI prompts/templates in {project_path}"
    return f"""Validate {content_hint} for AI content safety

## What this does
Checks AI prompts, chatbot instructions, and LLM templates for:
- **Harmful content**: Violence, hate speech, self-harm, illegal activities
- **PII leakage**: Personally identifiable information exposure
- **Prompt injection**: Attempts to manipulate LLM behavior or bypass guardrails

Uses TrendAI AI Guard detection policies with confidence scoring.

## Step 1: Find AI content
{"Use the provided content directly." if content else f"""Search {project_path} for AI-related content:
- AI prompt template files (.txt, .md, .prompt files)
- Chatbot instruction files (system prompts, conversation templates)
- LLM application code with hardcoded prompts
- Prompt engineering files
- AI agent configuration files
- RAG system templates

Extract each unique prompt/template."""}

## Step 2: Evaluate each prompt
For EACH prompt/template (max 1024 characters per call):
→ Use `ai_guard_evaluate` with:
  - prompt = the AI content to check
  - application_name = "v1vibe" or project-specific name for tracking

## Step 3: Analyze results
Parse the evaluation response:
- **action**: "Allow" or "Block" (overall verdict)
- **actionSource**: Which policy triggered the action
- **categories**: Specific harmful content categories detected
  - violence, hate, self_harm, sexual_content, dangerous_content, etc.
- **piiTypes**: Types of PII detected (email, phone, SSN, credit card, etc.)
- **promptInjection**: Whether prompt injection patterns were detected
- **confidenceScore**: Detection confidence (0.0-1.0)

## Step 4: Report
For EACH prompt evaluated:
- Prompt snippet (first 100 chars)
- Where found (file path, line number)
- Action: Allow or Block
- Issues detected:
  - Harmful content categories with confidence scores
  - PII types exposed
  - Prompt injection indicators
- Recommendation: safe to use / needs modification / remove / investigate

Prioritize by:
1. Blocked prompts with high confidence
2. PII leakage
3. Prompt injection risks
4. Harmful content by severity

## Best practices
- Keep prompts under 1024 characters (AI Guard limit)
- If longer, split into logical chunks and evaluate each
- Focus on user-facing prompts and system instructions
- Check both static templates and dynamically generated prompts
- Validate before deployment to production"""


@mcp.prompt()
def search_threats(
    indicators: list[str] | None = None, project_path: str = "."
) -> str:
    """Search for indicators of compromise (IOCs) in threat intelligence.

    **USE THIS WHEN:** User asks to "check this IP", "is this domain malicious",
    "look up this hash", "threat intelligence check", "search for IOCs",
    or you find suspicious indicators in code/configs.

    **TOOLS USED:** search_threat_indicators, check_suspicious_objects

    Searches global threat feed (71K+ IOCs, cached) and tenant blocklist for:
    domains, URLs, IPs, file hashes, email addresses, registry keys, mutexes.
    """
    indicators_hint = (
        f"these specific indicators: {indicators}"
        if indicators
        else f"all IOCs found in {project_path}"
    )
    return f"""Search threat intelligence for {indicators_hint}

## What this does
Searches TWO sources:
1. **Global threat intelligence feed** - 71K+ IOCs cached locally, hourly updates
2. **Tenant blocklist** - Your organization's custom suspicious objects

Supported IOC types (auto-detected):
- Domains, URLs, IPs (IPv4/IPv6)
- File hashes (SHA256, SHA1, MD5)
- Email addresses
- Windows registry keys (HKEY_*)
- Mutexes (synchronization primitives)
- File paths (C:\\, /tmp/, /var/, etc.)
- Hostnames, process names

## Step 1: Extract IOCs from project
{"Use the provided indicators directly." if indicators else f"""Search ALL files in {project_path} using Grep to find IOCs in file contents:

1. **Domains, URLs, IPs** (most common)
   - Grep patterns: https?://[^\\s]+, [0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}
   - Where: source code, configs, .env.example, README, package files, Dockerfiles
   - Extract unique values

2. **File hashes** (SHA256/SHA1/MD5)
   - Grep patterns: [a-f0-9]{{64}} (SHA256), [a-f0-9]{{40}} (SHA1), [a-f0-9]{{32}} (MD5)
   - Where: lock files, checksums.txt, SHA256SUMS, integrity manifests, CI scripts
   - Even "legitimate" checksums could be trojaned packages

3. **Email addresses**
   - Grep pattern: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}
   - Where: configs, templates, SMTP settings, notification configs

4. **Windows registry keys** (if Windows scripts present)
   - Grep pattern: HKEY_
   - Where: .ps1, .bat, .cmd, .reg files, install scripts

5. **Mutexes** (if threading code present)
   - Grep pattern: CreateMutex, mutex, {{[a-f0-9-]{{36}}}} (GUIDs)
   - Where: threading code, system-level code

6. **File paths** (system paths)
   - Grep patterns: C:\\\\, /tmp/, /var/, %[A-Z]+%, ~/
   - Where: install scripts, deployment configs, path constants

Collect all unique IOCs."""}

## Step 2: Search global threat feed
For EACH unique IOC:
→ Use `search_threat_indicators` with the IOC value.
  - Instant lookup (cached, ~71K indicators from 365 days)
  - Auto-detects IOC type (no need to specify)
  - Returns match details: indicator type, threat type, valid dates, labels
  - Cache info: total indicators, last updated

## Step 3: Check tenant blocklist
For EACH unique IOC:
→ Use `check_suspicious_objects` with appropriate type:
  - Domains: type="domain"
  - URLs: type="url"
  - IPs: type="ip"
  - File SHA256: type="fileSha256"
  - File SHA1: type="fileSha1"
  - Email: type="senderMailAddress"
→ Returns matches from your organization's custom blocklist with risk level.

## Step 4: Report
For EACH IOC checked, provide:
- IOC type and value
- Where found (file path, line number, context)
- **Global threat intel match** (if found):
  - Threat type (malware, phishing, C2, etc.)
  - Valid from/until dates
  - Labels (threat family, campaign, etc.)
  - Confidence: High (if in global feed)
- **Tenant blocklist match** (if found):
  - Risk level (high/medium/low)
  - Scan action (block/log/monitor)
  - Confidence: Organizational policy
- Verdict: MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN
- Recommendation: remove from code / investigate / allow / monitor

Group by verdict and risk level for prioritization.

## Performance note
Threat feed search is INSTANT (cached lookup, no API delay).
Always check ALL IOCs found - there's no performance penalty."""


@mcp.prompt()
def scan_infrastructure(project_path: str = ".") -> str:
    """Scan Infrastructure as Code (IaC) templates for security misconfigurations.

    **USE THIS WHEN:** User asks to "check this template", "scan CloudFormation",
    "scan Terraform", "IaC security", "check infrastructure code",
    "validate this template".

    **TOOLS USED:** scan_iac_template, scan_terraform_archive

    Scans CloudFormation and Terraform templates against hundreds of security
    rules covering compliance standards, best practices, and misconfigurations.
    """
    return f"""Scan Infrastructure as Code templates in {project_path} for security issues

## What this does
Validates IaC templates against:
- **Compliance standards**: CIS, PCI-DSS, HIPAA, GDPR, SOC 2, NIST
- **Best practices**: Least privilege, encryption, logging, monitoring
- **Common misconfigurations**: Public S3 buckets, open security groups, weak IAM policies

Checks hundreds of security rules and returns findings with risk levels.

## Supported template types
- **CloudFormation**: YAML/JSON templates (.yaml, .yml, .json, .template)
- **Terraform plan JSON**: JSON output from `terraform plan -out=plan.json`
- **Terraform HCL**: .tf files (requires ZIP archive)

## Step 1: Find IaC templates
Search {project_path} for:
- CloudFormation: *.yaml, *.yml, *.json, *.template files
  - Look in: cloudformation/, templates/, infrastructure/, infra/, .aws/
  - Check filenames: stack.yaml, template.json, main.cf.yaml, etc.
- Terraform plan JSON: plan.json, tfplan.json files
  - Generated from: terraform plan -out=plan.json && terraform show -json plan.json > tfplan.json
- Terraform HCL: *.tf, *.tf.json files
  - Look in: terraform/, tf/, infrastructure/, modules/

## Step 2: Scan CloudFormation templates
For EACH CloudFormation template file:
→ Use `scan_iac_template` with:
  - file_path = absolute path to template
  - template_type = "cloudformation-template"
→ Returns findings with status PASS or FAILURE.

## Step 3: Scan Terraform plan JSON
For EACH Terraform plan JSON file:
→ Use `scan_iac_template` with:
  - file_path = absolute path to plan JSON
  - template_type = "terraform-template"

## Step 4: Scan Terraform HCL files
If .tf files are found:
→ Create a ZIP archive containing all .tf files from the same root module.
→ Use `scan_terraform_archive` with:
  - file_path = absolute path to ZIP file
→ Only supports single root module per ZIP.

## Step 5: Analyze findings
Parse scan results for EACH template:
- **status**: PASS (no issues) or FAILURE (issues found)
- **findings**: List of security issues detected
  - **ruleName**: Specific rule violated
  - **severity**: EXTREME, HIGH, MEDIUM, LOW
  - **description**: What's misconfigured and why it's a risk
  - **resource**: Which template resource is affected
  - **remediationLink**: How to fix it (documentation URL)

## Step 6: Report
For EACH template scanned:
- Template file path and type
- Scan status (PASS/FAILURE)
- If FAILURE, list findings grouped by severity:
  - EXTREME risk issues (immediate action required)
  - HIGH risk issues (fix before deployment)
  - MEDIUM risk issues (should fix)
  - LOW risk issues (nice to fix)
- For each finding:
  - Rule name and severity
  - Description of the issue
  - Affected resource
  - Remediation link
- Summary: total findings by severity

Prioritize remediation:
1. EXTREME severity (security critical)
2. HIGH severity (significant risk)
3. MEDIUM severity (should fix)
4. LOW severity (best practice)

## Common issues detected
- Public S3 buckets without encryption
- Security groups with 0.0.0.0/0 access
- IAM policies with wildcards (*)
- Missing encryption at rest/in transit
- Disabled logging and monitoring
- Weak password policies
- Missing MFA requirements
- Unrestricted egress rules
- Plaintext secrets in templates"""


@mcp.prompt()
def investigate_cve(cve_id: str) -> str:
    """Get detailed information about a specific CVE vulnerability.

    **USE THIS WHEN:** User asks to "look up this CVE", "what is CVE-2023-12345",
    "get CVE details", "how to fix CVE-X", or you found a CVE in dependency scans
    that needs detailed investigation.

    **TOOLS USED:** get_cve_details

    Retrieves comprehensive CVE information: CVSS scores, description, mitigation
    options, affected assets, and remediation guidance.
    """
    return f"""Investigate CVE vulnerability: {cve_id}

## What this does
Retrieves detailed information about a specific CVE from Vision One:
- CVSS scores (base, temporal, environmental)
- Vulnerability description
- Mitigation options (patches, packages, workarounds)
- Affected asset counts (devices, containers, VMs, serverless)
- Remediation guidance

## Step 1: Validate CVE ID
Ensure CVE ID format is correct: CVE-YYYY-NNNNN
- Example: CVE-2023-44487, CVE-2024-12345
- Year: 1999 or later
- Number: 4-7 digits

If invalid format, correct it before proceeding.

## Step 2: Look up CVE details
→ Use `get_cve_details` with cve_id="{cve_id}"
→ Returns comprehensive vulnerability information.

## Step 3: Parse CVE details
Extract and analyze:
- **cvssV3**: CVSS v3 score breakdown
  - **baseScore**: Overall severity (0.0-10.0)
    - 0.0: None
    - 0.1-3.9: Low
    - 4.0-6.9: Medium
    - 7.0-8.9: High
    - 9.0-10.0: Critical
  - **vectorString**: Attack vector details (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
  - **attackVector**: Network, Adjacent, Local, Physical
  - **attackComplexity**: Low or High
  - **privilegesRequired**: None, Low, High
  - **userInteraction**: None or Required
  - **scope**: Unchanged or Changed
  - **confidentialityImpact**: None, Low, High
  - **integrityImpact**: None, Low, High
  - **availabilityImpact**: None, Low, High

- **description**: Detailed vulnerability explanation
- **publishedDateTime**: When CVE was disclosed
- **lastModifiedDateTime**: Most recent update

- **mitigation**: Remediation guidance
  - **patches**: Available patches with URLs
  - **packages**: Fixed package versions
  - **workarounds**: Temporary mitigations if no patch exists

- **affectedAssets**: How many assets in your environment are affected
  - **deviceCount**: Endpoints/workstations
  - **containerCount**: Container images
  - **vmCount**: Cloud VMs
  - **serverlessCount**: Serverless functions

## Step 4: Determine urgency
Prioritize based on:
1. **CVSS score**: Critical (9.0+) > High (7.0-8.9) > Medium (4.0-6.9) > Low (0.1-3.9)
2. **Attack vector**: Network (remotely exploitable) is highest risk
3. **Privileges required**: None (unauthenticated) is highest risk
4. **Affected assets**: More assets = higher priority
5. **Exploit availability**: Check if exploits exist in the wild

## Step 5: Detailed report
Provide comprehensive analysis:
- **CVE ID and severity**: {cve_id} - CVSS score and severity level
- **Description**: What the vulnerability is and how it can be exploited
- **Attack vector details**: How an attacker would exploit it
  - Attack vector, complexity, privileges, user interaction
- **Impact**: Confidentiality, integrity, availability effects
- **Affected assets in your environment**: Counts by asset type
- **Mitigation options**:
  - Patches available: versions, download URLs
  - Package upgrades: which versions fix it
  - Workarounds: temporary mitigations if no patch
- **Urgency assessment**: Why this should be prioritized (or not)
- **Recommended action**: Specific next steps
  - Upgrade to version X.Y.Z
  - Apply patch from URL
  - Implement workaround (if no fix available)
  - Schedule maintenance window for patching

## Use in combination
Often used after:
- `scan_artifact` finds CVEs in dependencies
- Dependency scanning reveals vulnerable packages
- Security alerts mention specific CVE IDs

Provides the DETAILS needed to remediate what scans DISCOVER."""


@mcp.prompt()
def check_quota() -> str:
    """Check remaining sandbox submission quota for today.

    **USE THIS WHEN:** User asks about "sandbox quota", "how many sandboxes left",
    "submission quota", or before submitting many files/URLs to sandbox.

    **TOOLS USED:** get_submission_quota

    Displays daily sandbox submission quota: reserve count, remaining submissions,
    and breakdown by file vs URL submissions.
    """
    return """Check remaining sandbox submission quota

## What this does
Retrieves current sandbox quota status from Vision One:
- Daily reserve count (total allowed per day, typically 10,000)
- Remaining submissions (how many left today)
- File submission count (files submitted today)
- URL submission count (URLs submitted today)

Quota resets at midnight UTC.

## Step 1: Get quota status
→ Use `get_submission_quota` (no parameters required)

## Step 2: Parse response
Extract quota information:
- **reserveCount**: Total daily quota (e.g., 10000)
- **submissionCount**: How many used today (file + URL)
- **fileCount**: Files submitted today
- **urlCount**: URLs submitted today
- **remainingQuota**: How many submissions left (reserveCount - submissionCount)

## Step 3: Calculate percentage used
- Percentage used = (submissionCount / reserveCount) * 100
- Percentage remaining = 100 - percentage used

## Step 4: Report
Provide clear quota status:
- **Daily quota**: reserveCount submissions per day
- **Used today**: submissionCount (X% of quota)
  - Files: fileCount
  - URLs: urlCount
- **Remaining**: remainingQuota submissions (Y% of quota)
- **Resets**: At midnight UTC

## Recommendations based on quota
- **>75% remaining**: Plenty of quota, proceed with batch submissions
- **25-75% remaining**: Moderate usage, plan large batches carefully
- **<25% remaining**: Low quota, prioritize suspicious files/URLs only
- **<10% remaining**: Very low, sandbox only confirmed threats
- **0 remaining**: Quota exhausted, wait for midnight UTC reset

## When to check quota
BEFORE:
- Batch file submissions (sandboxing multiple files)
- Batch URL submissions (sandboxing many URLs)
- Automated scanning workflows
- Large project security reviews

This helps avoid hitting quota limits mid-scan."""


if __name__ == "__main__":
    mcp.run(transport="stdio")
