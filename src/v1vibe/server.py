from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from v1vibe.clients import AppContext, app_lifespan
from v1vibe.tools import (
    ai_guard,
    attack_surface,
    endpoint,
    file_security,
    sandbox,
    search,
    threat_intel,
    vulnerabilities,
    yara_rules,
)

SERVER_INSTRUCTIONS = """\
v1vibe provides security validation tools powered by Trend Micro Vision One.
Use these tools to validate the security of code, files, URLs, and infrastructure.

## File & Code Security

- **scan_file**: Fast malware scan (seconds). Use for any file you create, modify, or download.
- **sandbox_submit_file**: Deep behavioral analysis via detonation. Use for suspicious files. \
Follow up with sandbox_get_status and sandbox_get_report.
- **sandbox_submit_url**: Submit up to 10 URLs for sandbox analysis.
- **ai_guard_evaluate**: Check text for harmful content, PII leakage, and prompt injection.
- **get_submission_quota**: Check daily sandbox quota before batch submissions.

## Threat Intelligence

- **check_suspicious_objects**: Look up URLs, domains, IPs, file hashes, or emails.
- **add_suspicious_objects / remove_suspicious_objects**: Manage the blocklist.
- **get_threat_indicators**: Get IoCs (STIX 2.1) from Trend threat feeds.
- **get_threat_reports**: Get intelligence reports filtered by location/industry.

## Detection & Response

- **search_detections**: Query detection logs by file hash, process, IP, malware name, etc.
- **list_alerts**: List workbench alerts filtered by status and severity.
- **start_malware_scan**: Trigger a remote malware scan on managed endpoints.
- **list_yara_rules / run_yara_rules**: List and execute YARA rules on endpoints.

## Attack Surface & Vulnerabilities

- **discover_assets**: Find devices, cloud assets, public IPs, FQDNs, apps, or domain accounts with risk scores.
- **get_cve_details**: Get detailed CVE info including CVSS, mitigation, and affected asset counts.
- **list_vulnerabilities**: List CVEs across devices, internal/internet-facing assets, containers, cloud VMs, serverless.
- **list_container_vulnerabilities**: List CVEs in container images with package and fix details.

## Workflow patterns

1. **Quick validation**: scan_file → done (if clean)
2. **Deep analysis**: scan_file → sandbox_submit_file → sandbox_get_status (poll) → sandbox_get_report
3. **URL check**: sandbox_submit_url → sandbox_get_status (poll) → sandbox_get_report
4. **Threat intel**: check_suspicious_objects or get_threat_indicators
5. **Vuln check**: get_cve_details or list_vulnerabilities
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


# --- Threat Intelligence (write + feeds) ---


@mcp.tool()
async def add_suspicious_objects(
    ctx: Context,
    objects: list[dict],
) -> dict:
    """Add indicators (URLs, domains, IPs, file hashes, emails) to the Vision One suspicious object blocklist.

    Each object dict must include a type-specific key (e.g., {"url": "http://evil.com"})
    and can optionally include: description, scanAction (block/log), riskLevel (high/medium/low),
    daysToExpiration (1-365, or -1 for no expiration, default 30).

    Args:
        objects: List of objects to add. Each must have one of: url, domain, ip, fileSha1, fileSha256, senderMailAddress.
    """
    return await threat_intel.add_suspicious_objects(_ctx(ctx), objects)


@mcp.tool()
async def remove_suspicious_objects(
    ctx: Context,
    objects: list[dict],
) -> dict:
    """Remove indicators from the Vision One suspicious object blocklist.

    Each object dict needs only the type-specific key (e.g., {"url": "http://evil.com"}).

    Args:
        objects: List of objects to remove. Each must have one of: url, domain, ip, fileSha1, fileSha256, senderMailAddress.
    """
    return await threat_intel.remove_suspicious_objects(_ctx(ctx), objects)


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


@mcp.tool()
async def get_threat_reports(
    ctx: Context,
    top_report: int = 10,
    location: str | None = None,
    industry: str | None = None,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
) -> dict:
    """Get threat intelligence reports with related STIX objects (campaigns, malware, CVEs).

    Returns detailed threat reports filtered by geography and industry. Useful for
    understanding the current threat landscape relevant to your deployment.

    Args:
        top_report: Maximum reports to return (5, 10, or 20).
        location: Filter by geography (e.g., "United States of America", "Canada").
        industry: Filter by industry (e.g., "Technology", "Finance", "Health").
        start_date_time: ISO 8601 start of time range.
        end_date_time: ISO 8601 end of time range.
    """
    return await threat_intel.get_threat_reports(
        _ctx(ctx), top_report, location, industry, start_date_time, end_date_time
    )


# --- Detection & Alert Search ---


@mcp.tool()
async def search_detections(
    ctx: Context,
    query: str,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
    top: int = 50,
    fields: list[str] | None = None,
) -> dict:
    """Search Vision One detection logs using query syntax.

    Query supports fields like: fileName, fileHash, fileHashSha256, processCmd,
    src, dst, malName, eventName, suser, duser, and 40+ more.
    Operators: ':' (equals), 'and', 'or', 'not', 'contains'.

    Args:
        query: Detection query (e.g., "malName:Ransom* and dst:10.0.0.0/8").
        start_date_time: ISO 8601 start of time range.
        end_date_time: ISO 8601 end of time range.
        top: Maximum results (up to 10000).
        fields: Optional list of fields to include in results.
    """
    return await search.search_detections(
        _ctx(ctx), query, start_date_time, end_date_time, top, fields
    )


@mcp.tool()
async def list_alerts(
    ctx: Context,
    status: str | None = None,
    severity: str | None = None,
    start_date_time: str | None = None,
    end_date_time: str | None = None,
    top: int = 50,
) -> dict:
    """List workbench alerts from Vision One with filtering.

    Returns alerts with matched detection rules, indicators, and impact scope
    including affected endpoints, accounts, and containers.

    Args:
        status: Filter by status — one of: Open, In Progress, Closed.
        severity: Filter by severity — one of: critical, high, medium, low.
        start_date_time: ISO 8601 start of time range.
        end_date_time: ISO 8601 end of time range.
        top: Maximum alerts to return.
    """
    return await search.list_alerts(
        _ctx(ctx), status, severity, start_date_time, end_date_time, top
    )


# --- Endpoint Actions ---


@mcp.tool()
async def start_malware_scan(
    ctx: Context,
    endpoints: list[dict],
) -> dict:
    """Trigger a malware scan on one or more managed endpoints.

    Each endpoint dict must have either 'agent_guid' (UUID of the installed agent)
    or 'endpoint_name' (computer name), and optionally 'description'.

    Args:
        endpoints: List of endpoints to scan (e.g., [{"endpoint_name": "WORKSTATION-01"}]).
    """
    return await endpoint.start_malware_scan(_ctx(ctx), endpoints)


# --- YARA Rules ---


@mcp.tool()
async def list_yara_rules(
    ctx: Context,
    name_filter: str | None = None,
    top: int = 50,
) -> dict:
    """List available YARA rule files in Vision One.

    Args:
        name_filter: Filter by exact rule file name.
        top: Maximum results to return.
    """
    return await yara_rules.list_yara_rules(_ctx(ctx), name_filter, top)


@mcp.tool()
async def run_yara_rules(
    ctx: Context,
    endpoint_name: str | None = None,
    agent_guid: str | None = None,
    rule_content: str | None = None,
    rule_file_id: str | None = None,
    rule_file_name: str | None = None,
    target_file_path: str | None = None,
    target_process_name: str | None = None,
    description: str | None = None,
) -> dict:
    """Run a YARA rule on an endpoint, targeting a specific file or process.

    Provide the YARA rule as raw content, a file ID, or file name.
    Target either a file path or process name on the endpoint.

    Args:
        endpoint_name: Computer name of the target endpoint.
        agent_guid: UUID of the agent on the target endpoint (alternative to endpoint_name).
        rule_content: Raw YARA rule content (max 2048 chars).
        rule_file_id: ID of an existing YARA rule file in Vision One.
        rule_file_name: Name of an existing YARA rule file in Vision One.
        target_file_path: File path to scan on the endpoint (e.g., "C:\\Windows\\System32\\calc.exe").
        target_process_name: Process name to scan on the endpoint.
        description: Optional description for this task.
    """
    return await yara_rules.run_yara_rules(
        _ctx(ctx), endpoint_name, agent_guid,
        rule_content, rule_file_id, rule_file_name,
        target_file_path, target_process_name, description,
    )


# --- Attack Surface Discovery ---


@mcp.tool()
async def discover_assets(
    ctx: Context,
    asset_type: str,
    filter_expr: str | None = None,
    top: int = 50,
    order_by: str | None = None,
) -> dict:
    """Discover assets in the organization's attack surface with risk scores.

    Returns devices, cloud assets, public IPs, FQDNs, local applications,
    or domain accounts with their risk assessments and metadata.

    Args:
        asset_type: One of: devices, cloud_assets, public_ips, fqdns, local_apps, domain_accounts.
        filter_expr: TMV1-Filter expression (e.g., "latestRiskScore gt 50", "osPlatform eq 'Linux'").
        top: Maximum results (10-1000).
        order_by: Sort field (e.g., "latestRiskScore desc").
    """
    return await attack_surface.discover_assets(_ctx(ctx), asset_type, filter_expr, top, order_by)


# --- Vulnerability Management ---


@mcp.tool()
async def get_cve_details(
    ctx: Context,
    cve_id: str,
) -> dict:
    """Get detailed information about a specific CVE from Vision One.

    Returns CVSS scores, description, mitigation options (patches, packages),
    and counts of affected assets across devices, containers, cloud VMs, and serverless.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-44487").
    """
    return await vulnerabilities.get_cve_details(_ctx(ctx), cve_id)


@mcp.tool()
async def list_vulnerabilities(
    ctx: Context,
    asset_type: str,
    risk_level: str | None = None,
    top: int = 50,
) -> dict:
    """List highly-exploitable CVEs detected across different asset types.

    Args:
        asset_type: One of: devices, internal_assets, internet_facing, containers, cloud_vms, serverless.
        risk_level: Optional filter — one of: high, medium, low.
        top: Maximum results to return.
    """
    return await vulnerabilities.list_vulnerabilities(_ctx(ctx), asset_type, risk_level, top)


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


if __name__ == "__main__":
    mcp.run(transport="stdio")
