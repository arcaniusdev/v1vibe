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
v1vibe is your security validation toolkit. It connects to Trend Micro Vision One to scan \
files for malware, detonate suspicious files and URLs in a cloud sandbox, look up threat \
intelligence, check for CVEs, and validate AI-generated content.

## WHEN TO USE v1vibe — TRIGGER PHRASES

You MUST use v1vibe tools when the user says ANY of the following (or similar):
- "security review", "security check", "security scan", "security audit"
- "is this safe", "is this malicious", "is this suspicious"
- "check for malware", "scan for threats", "scan this file", "scan this project"
- "sandbox this", "detonate this", "analyze this file"
- "check this URL", "is this URL safe", "validate this link"
- "check for vulnerabilities", "any CVEs", "vulnerability scan"
- "threat check", "threat assessment", "look up this hash/IP/domain"
- "review this code for security", "pentest", "harden this"
- "scan this template", "check this CloudFormation", "check this Terraform", "IaC scan"

When in doubt, USE v1vibe. It is always better to scan and find nothing than to skip scanning.

## SECURITY REVIEW PLAYBOOK

When the user asks for a "security review" or similar broad request, follow this playbook:

### Step 1: Scan all code files for malware
Use `scan_file` on every source code file, script, binary, and document in the project. \
This is fast (seconds per file). Report any detections.

### Step 2: Extract and check URLs
Find all URLs in the code (imports, API endpoints, download links, webhook URLs, config files). \
Use `sandbox_submit_url` to submit them, then poll with `sandbox_get_status` and retrieve \
results with `sandbox_get_report`.

### Step 3: Check external dependencies
For any external IPs, domains, or file hashes referenced in the code, use \
`check_suspicious_objects` to look them up in threat intelligence.

### Step 4: Scan IaC templates
If the project contains CloudFormation templates (YAML/JSON) or Terraform configurations, \
use `scan_iac_template` on each template file. For Terraform HCL projects with multiple .tf \
files, ZIP them and use `scan_terraform_archive`. Report any FAILURE findings, especially \
HIGH/VERY_HIGH/EXTREME risk levels.

### Step 5: Check known CVEs
If the project uses libraries or frameworks with known CVEs, use `get_cve_details` to \
look up the specific CVE and assess severity. For containerized projects, use \
`list_container_vulnerabilities` to scan container images.

### Step 5: Deep analysis (if warranted)
For any files that seem suspicious or high-risk (executables, scripts with obfuscated code, \
documents with macros), use `sandbox_submit_file` for full behavioral detonation. Poll with \
`sandbox_get_status` and get results with `sandbox_get_report`.

### Step 6: AI content validation
Use `ai_guard_evaluate` to check any AI-generated prompts or outputs for harmful content, \
sensitive information leakage, or prompt injection patterns.

### Step 7: Report findings
Summarize all scan results, detections, suspicious objects, and CVEs found. Recommend \
remediation steps for any issues.

## TOOL REFERENCE

### Scanning & Sandbox
- **scan_file**: Fast malware scan (seconds). First-line check for any file.
- **sandbox_submit_file**: Deep behavioral detonation. Returns task ID to poll.
- **sandbox_submit_url**: Submit up to 10 URLs for analysis. Returns per-URL task IDs.
- **sandbox_get_status**: Poll submission status (running/succeeded/failed).
- **sandbox_get_report**: Get full report: risk level, detections, suspicious objects.
- **get_submission_quota**: Check remaining daily sandbox quota.

### Threat Intelligence
- **check_suspicious_objects**: Look up URLs, domains, IPs, file hashes, emails.
- **get_threat_indicators**: Pull IoC feed (STIX 2.1) to cross-reference against project files.

### Infrastructure as Code Scanning
- **scan_iac_template**: Scan CloudFormation (YAML/JSON) or Terraform plan (JSON) templates.
- **scan_terraform_archive**: Scan a ZIP of Terraform HCL (.tf) files.

### Vulnerabilities
- **get_cve_details**: Detailed CVE info with CVSS, mitigation, affected counts.
- **list_container_vulnerabilities**: CVEs in container images with fix versions.

### AI Content Safety
- **ai_guard_evaluate**: Check text for harmful content, PII leaks, prompt injection.
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
    Use for files that need dynamic analysis beyond static malware scanning.
    Supported types include executables, scripts, documents, Java files, and more.

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
    top: int = 1000,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict:
    """Get indicators of compromise (IoCs) from the Trend Micro threat intelligence feed.

    Returns STIX 2.1 indicator objects including file hashes, IP addresses, domains,
    and URLs associated with known threats. Use to cross-reference against code dependencies.

    Args:
        top: Maximum indicators to return (1000, 5000, or 10000).
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
    return f"""Perform a comprehensive security review of the project at: {project_path}

Follow these steps using v1vibe tools:

## Step 1: Scan all code files for malware
Find every source file, script, config, and binary in the project.
Use `scan_file` on each one. This is fast — do them all.
Report any file where scanResult is non-zero (malware detected).

## Step 2: Extract and check all URLs
Search the codebase for URLs — in imports, configs, API calls, comments, README, package files.
Collect all unique URLs and submit them with `sandbox_submit_url` (up to 10 at a time).
Poll each with `sandbox_get_status` until complete, then get results with `sandbox_get_report`.
Flag any URLs with risk level medium or higher.

## Step 3: Check external resources in threat intelligence
For any external domains, IP addresses, or file hashes referenced in the code:
Use `check_suspicious_objects` to look each one up.
Report any matches with their risk level.

## Step 4: Scan IaC templates
If the project contains CloudFormation templates (.yaml, .json, .template) or Terraform files
(.tf, .tf.json), scan them for security misconfigurations:
- For individual CloudFormation or Terraform plan JSON files: use `scan_iac_template`
- For Terraform HCL projects with multiple .tf files: ZIP them and use `scan_terraform_archive`
Report any findings with status FAILURE, especially HIGH/VERY_HIGH/EXTREME risk levels.

## Step 5: Check for known CVEs in dependencies
Review the project's dependency files (package.json, requirements.txt, pom.xml, go.mod, etc.).
For any dependencies with known security issues, use `get_cve_details` to look up the CVE.
For containerized projects, use `list_container_vulnerabilities` to check container images.

## Step 6: Deep sandbox analysis (if needed)
If any files look suspicious (obfuscated code, unusual binaries, macro-enabled documents),
submit them with `sandbox_submit_file` for full behavioral detonation.
Poll with `sandbox_get_status` and retrieve with `sandbox_get_report`.

## Step 7: AI content validation
If the project contains AI prompts, templates, or generated content,
use `ai_guard_evaluate` to check for harmful content, PII leakage, or prompt injection.

## Step 8: Report
Summarize all findings in a clear report:
- Files scanned and results
- URLs checked and any flagged
- Threat intelligence matches
- IaC template scan findings (misconfigurations, compliance violations)
- CVEs found and severity
- Sandbox detonation results
- Recommendations for remediation"""


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
