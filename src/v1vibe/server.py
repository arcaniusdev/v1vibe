from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from v1vibe.clients import AppContext, app_lifespan
from v1vibe.tools import (
    ai_guard,
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
- "threat check", "threat assessment", "look up this hash/IP/domain"
- "pentest", "harden this", "secure this"
- "scan this template", "check this CloudFormation", "check this Terraform", "IaC scan"
- "Vision One", "v1vibe"

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

### 2. URL EXTRACTION & SANDBOX — find and detonate every URL
Search ALL project files for URLs: API endpoints, download links, webhook URLs, \
dependency sources, CDN links, redirect targets, OAuth endpoints, etc. Look in source \
code, configs, .env.example, README, package files, Dockerfiles, IaC templates.
→ Use `check_suspicious_objects` (type "domain") for each unique domain first (instant).
→ Then submit all unique URLs with `sandbox_submit_url` (up to 10 per call).
→ Poll each with `sandbox_get_status` until done.
→ Get results with `sandbox_get_report`.
→ Report: each URL, where found, risk level.

### 3. THREAT INTELLIGENCE — check every external reference
Find ALL external IPs, domains, email addresses, and file hashes in the code and configs.
→ Run `check_suspicious_objects` for each one.
→ Run `get_threat_indicators` to pull the IoC feed and cross-reference against project artifacts.
→ Report: any matches with risk level and recommended action.

### 4. IAC TEMPLATE SCAN — scan every infrastructure template
Find ALL CloudFormation files (.yaml, .json, .template) and Terraform files (.tf, .tf.json).
→ For CloudFormation: run `scan_iac_template` with type "cloudformation-template" on each.
→ For Terraform plan JSON: run `scan_iac_template` with type "terraform-template".
→ For Terraform HCL directories: ZIP the .tf files and run `scan_terraform_archive`.
→ Report: all findings with status FAILURE, grouped by risk level.

### 5. DEPENDENCY CVE CHECK — look up every known vulnerability
Find dependency files (package.json, requirements.txt, pyproject.toml, go.mod, pom.xml, \
Cargo.toml, Gemfile, composer.json, etc.) and identify dependencies with known CVEs.
→ Run `get_cve_details` for each known CVE ID.
→ If the project has a Dockerfile or docker-compose.yml, run `list_container_vulnerabilities`.
→ Report: CVE ID, CVSS score, severity, fix version availability.

### 6. SANDBOX DETONATION — detonate files with supported extensions
The sandbox supports these file types: executables (.exe, .dll, .com, .msi, .dmg, .pkg), \
scripts (.bat, .cmd, .js, .vbs, .ps1, .sh, .py, .hta, .wsf), documents (.doc, .docx, .xls, \
.xlsx, .ppt, .pptx, .pdf, .rtf, .odt, .ods, .odp, .csv, .xml), Java (.class, .jar), \
web content (.html, .svg, .mht), archives (.zip, .7z, .rar, .tar, .gz), email (.eml, .msg), \
and more. Only submit files with supported extensions — the tool will reject unsupported types.
→ Run `sandbox_submit_file` on each supported file.
→ Poll with `sandbox_get_status` until done.
→ Get results with `sandbox_get_report`.
→ Report: risk level, detections, suspicious objects extracted.
→ For files with unsupported extensions, rely on `scan_file` results from step 1.

### 7. AI CONTENT VALIDATION — always run this
Run `ai_guard_evaluate` on EVERY security review. Submit a summary of the project's purpose \
and key code patterns as the prompt. This checks for harmful content, sensitive information \
leakage (hardcoded credentials, PII, API keys), and prompt injection patterns in the codebase.
Also check any AI prompts, prompt templates, or system instructions found in the project.
→ Run `ai_guard_evaluate` at least once per review — this is not optional.
→ Report: Allow/Block action, harmful content categories, PII detected, prompt injection risk.

### 8. REPORT — summarize ALL findings
After completing ALL steps above, produce a structured report:
- Total files scanned and malware detections
- URLs checked and risk levels
- Threat intelligence matches
- IaC template misconfigurations
- CVEs found with severity
- Sandbox detonation results
- AI content validation results
- Prioritized remediation recommendations

## IMPORTANT: Do not skip steps because they seem unlikely to find anything. \
The whole point is comprehensive coverage. A clean result is a valid result.
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
    """Scan a local file for malware using Trend Micro File Security.

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
    """Submit a file to Trend Micro sandbox for deep behavioral analysis (detonation).

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
    """Submit up to 10 URLs to Trend Micro sandbox for analysis.

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
) -> dict:
    """Get the full analysis report for a completed sandbox submission.

    Returns risk level, detection names, threat types, true file type,
    and any suspicious objects (IPs, URLs, domains, file hashes) found.

    Args:
        result_id: The result ID from the resourceLocation in sandbox_get_status.
    """
    return await sandbox.get_report(_ctx(ctx), result_id)


@mcp.tool()
async def ai_guard_evaluate(
    ctx: Context,
    prompt: str,
    application_name: str = "v1vibe",
) -> dict:
    """Evaluate text against Trend Micro AI Guard security policies.

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
    """Look up a URL, domain, IP address, email, or file hash in Trend Micro threat intelligence.

    Returns matching suspicious objects with risk levels and scan actions.
    Use to validate external resources referenced in code.

    Args:
        object_type: Type of object — one of: url, domain, ip, fileSha1, fileSha256, senderMailAddress.
        value: The value to look up (e.g., the URL, IP address, or file hash).
        risk_level: Optional filter — one of: high, medium, low.
    """
    return await threat_intel.check_suspicious_objects(
        _ctx(ctx), object_type, value, risk_level
    )


@mcp.tool()
async def get_submission_quota(ctx: Context) -> dict:
    """Check remaining sandbox submission quota for today.

    Returns daily reserve count, remaining submissions, and a breakdown
    of file vs URL submission counts. Use before batch submissions.
    """
    return await sandbox.get_submission_quota(_ctx(ctx))


# --- Threat Intelligence ---


@mcp.tool()
async def get_threat_indicators(
    ctx: Context,
    top: int = 200,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict:
    """Get indicators of compromise (IoCs) from the Trend Micro threat intelligence feed.

    Returns extracted IoCs (file hashes, IPs, domains, URLs, emails) with their STIX
    patterns and labels. Use to cross-reference against project files and dependencies.

    Args:
        top: Maximum indicators to return (default 200, max 10000).
        start_date_time: ISO 8601 start of time range.
        end_date_time: ISO 8601 end of time range.
    """
    return await threat_intel.get_threat_indicators(_ctx(ctx), top, start_date_time, end_date_time)


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
async def list_container_vulnerabilities(
    ctx: Context,
    cluster_type: str | None = None,
    risk_level: str | None = None,
    top: int = 50,
) -> dict:
    """List CVEs found in container images across Kubernetes and ECS clusters.

    Returns vulnerability details including affected packages, CVSS scores,
    fix versions, and image/registry information.

    Args:
        cluster_type: Filter by cluster type — one of: kubernetes, amazonEcs.
        risk_level: Filter by risk level — one of: high, medium, low.
        top: Maximum results to return.
    """
    return await vulnerabilities.list_container_vulnerabilities(_ctx(ctx), cluster_type, risk_level, top)


# ═══════════════════════════════════════════════
# MCP Prompts — workflow templates for AI clients
# ═══════════════════════════════════════════════


@mcp.prompt()
def security_review(project_path: str = ".") -> str:
    """Comprehensive security review of a project using Vision One.

    Guides the AI through a full security review: scan all files for malware,
    check URLs found in code, look up dependencies in threat intelligence,
    check for known CVEs, and validate AI-generated content.
    """
    return f"""Perform a COMPREHENSIVE security review of the project at: {project_path}

IMPORTANT: You MUST complete ALL 8 steps below. Do NOT skip any step. Do NOT stop early. \
Each step covers a different attack surface. A step returning clean results is expected — \
report it and move to the next step.

## Step 1: MALWARE SCAN — scan every file
Find ALL files in the project. Use `scan_file` on EACH one. Do not skip any.
→ Report: total files scanned, any with scanResult != 0.

## Step 2: URL EXTRACTION & SANDBOX — find and check every URL
Search ALL project files for URLs (API endpoints, download links, webhooks, CDN, OAuth, etc.).
→ Use `check_suspicious_objects` (type "domain") for each unique domain.
→ Submit all unique URLs with `sandbox_submit_url` (up to 10 per call).
→ Poll with `sandbox_get_status`, get results with `sandbox_get_report`.
→ Report: each URL, where found, risk level.

## Step 3: THREAT INTELLIGENCE — check every external reference
Find ALL external IPs, domains, email addresses, and file hashes in code and configs.
→ Run `check_suspicious_objects` for each.
→ Run `get_threat_indicators` and cross-reference IoCs against project artifacts.
→ Report: any matches with risk level.

## Step 4: IAC TEMPLATE SCAN — scan every infrastructure template
Find ALL CloudFormation (.yaml, .json, .template) and Terraform (.tf, .tf.json) files.
→ Run `scan_iac_template` or `scan_terraform_archive` as appropriate.
→ Report: all FAILURE findings grouped by risk level.

## Step 5: DEPENDENCY CVE CHECK — look up every known vulnerability
Find dependency files and identify packages with known CVEs.
→ Run `get_cve_details` for each CVE.
→ If Dockerfile exists, run `list_container_vulnerabilities`.
→ Report: CVE ID, CVSS score, severity, fix version.

## Step 6: SANDBOX DETONATION — detonate suspicious or executable files
Identify executables, scripts with complex logic, documents with macros, JARs, binaries.
→ Run `sandbox_submit_file` on each. Poll and get report.
→ Report: risk level, detections, suspicious objects.

## Step 7: AI GUARD — always run this (not optional)
Run `ai_guard_evaluate` with a summary of the project's purpose and key code patterns. \
Also check any AI prompts, templates, or system instructions found in the project.
→ This detects hardcoded credentials, PII, harmful content, and prompt injection.
→ Report: Allow/Block, categories flagged, confidence scores.

## Step 8: FINAL REPORT
After completing ALL steps, produce a structured report with:
- Files scanned and malware detections
- URLs checked and risk levels
- Threat intelligence matches
- IaC misconfigurations
- CVEs and severity
- Sandbox results
- AI Guard results
- Prioritized remediation recommendations"""


@mcp.prompt()
def scan_project(project_path: str = ".") -> str:
    """Quick malware scan of all files in a project.

    Scans every code file, script, and binary for malware using the fast
    File Security SDK. Use for a quick health check.
    """
    return f"""Scan all files in the project at: {project_path}

Use the v1vibe `scan_file` tool on every file in the project that could potentially
contain or deliver malware. This includes:

- All source code files (.py, .js, .ts, .java, .go, .rs, .c, .cpp, .rb, .php, etc.)
- Scripts (.sh, .bash, .ps1, .bat, .cmd)
- Config files (.json, .yaml, .yml, .toml, .xml, .ini)
- Documents (.pdf, .doc, .docx, .xls, .xlsx)
- Archives (.zip, .tar, .gz, .jar, .war)
- Binaries and executables
- Any other files that could be vectors

For each file, call `scan_file` with the absolute path.
The scan is fast (seconds per file) — scan everything, don't skip files.

Report:
- Total files scanned
- Any detections (scanResult != 0) with malware names
- SHA256 hashes of all scanned files
- Clean bill of health if nothing found"""


@mcp.prompt()
def check_urls(project_path: str = ".") -> str:
    """Find and validate all URLs referenced in a project's code.

    Extracts URLs from source code, configs, and documentation, then submits
    them to the Vision One sandbox for analysis.
    """
    return f"""Find and security-check all URLs in the project at: {project_path}

## Step 1: Extract URLs
Search all files in the project for URLs. Look in:
- Source code (API endpoints, download URLs, webhook targets)
- Config files (service endpoints, dependency sources)
- Package files (registry URLs, repository URLs)
- Documentation and README files
- Environment example files

Collect all unique URLs.

## Step 2: Check threat intelligence first
For each unique domain found, use `check_suspicious_objects` with type "domain"
to see if it's already flagged in threat intelligence. This is instant.

## Step 3: Sandbox analysis
Submit all unique URLs (up to 10 at a time) using `sandbox_submit_url`.
Poll each with `sandbox_get_status` until analysis completes.
Retrieve results with `sandbox_get_report`.

## Step 4: Report
For each URL, report:
- The URL and where it was found in the code
- Threat intelligence match (if any) with risk level
- Sandbox analysis result with risk level
- Recommendation (safe / suspicious / malicious)"""


@mcp.prompt()
def check_dependencies() -> str:
    """Check project dependencies for known CVEs and security issues.

    Reviews dependency/package files and looks up known vulnerabilities.
    """
    return """Review this project's dependencies for known security vulnerabilities.

## Step 1: Find dependency files
Look for: package.json, package-lock.json, requirements.txt, Pipfile, Pipfile.lock,
pyproject.toml, poetry.lock, go.mod, go.sum, pom.xml, build.gradle, Cargo.toml,
Cargo.lock, Gemfile, Gemfile.lock, composer.json, or similar.

## Step 2: Identify dependencies and versions
Parse the dependency files to extract package names and versions.

## Step 3: Look up known CVEs
For any dependencies that are known to have security vulnerabilities, use
`get_cve_details` to look up the specific CVE ID. Report:
- CVE ID
- CVSS score and severity
- Description of the vulnerability
- Whether a fix version is available
- Mitigation options from Vision One

## Step 4: Check container images (if applicable)
If the project has a Dockerfile or docker-compose.yml, use
`list_container_vulnerabilities` to check for CVEs in the container images.

## Step 5: Report
Summarize all findings:
- Dependencies with known CVEs, sorted by severity
- Recommended version upgrades
- Any container image vulnerabilities
- Overall risk assessment"""


if __name__ == "__main__":
    mcp.run(transport="stdio")
