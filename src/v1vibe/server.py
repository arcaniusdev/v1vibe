from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from v1vibe.clients import AppContext, app_lifespan
from v1vibe.tools import ai_guard, file_security, sandbox, threat_intel

SERVER_INSTRUCTIONS = """\
v1vibe provides security validation tools powered by Trend Micro Vision One.
Use these tools to validate the security of code, files, and URLs during development.

## When to use these tools

- **scan_file**: Use WHENEVER you create, modify, or download a file that could contain \
executable code or be a vector for malware. This includes scripts (Python, JS, shell), \
compiled binaries, Office documents, PDFs, Java .class/.jar files, and archives. The scan \
is fast (seconds) and should be your first-line check.

- **sandbox_submit_file**: Use for deeper behavioral analysis when scan_file flags something \
suspicious, or for file types that benefit from dynamic analysis (executables, scripts with \
complex logic, documents with macros). This detonates the file in a sandbox and provides a \
full behavioral report. Follow up with sandbox_get_status and sandbox_get_report.

- **sandbox_submit_url**: Use when code references external URLs — dependency sources, API \
endpoints, download links, webhook targets, or redirect URLs. Submit them to verify they \
are not malicious, phishing, or hosting malware.

- **sandbox_get_status / sandbox_get_report**: Use after sandbox submissions to poll for \
completion and retrieve the full analysis report including risk level and threat details.

- **ai_guard_evaluate**: Use to check AI-generated text for harmful content, sensitive \
information leakage (PII, credentials, secrets), and prompt injection patterns.

- **check_suspicious_objects**: Use to look up specific indicators — file hashes (SHA1/SHA256), \
URLs, domains, IP addresses, or email addresses — against Trend Micro threat intelligence. \
Useful when you encounter an unfamiliar external resource in code.

- **get_submission_quota**: Check before doing batch sandbox submissions to ensure you have \
enough quota remaining for the day.

## Workflow patterns

1. **Quick validation**: scan_file → done (if clean)
2. **Deep analysis**: scan_file → sandbox_submit_file → sandbox_get_status (poll) → sandbox_get_report
3. **URL check**: sandbox_submit_url → sandbox_get_status (poll) → sandbox_get_report
4. **Threat intel lookup**: check_suspicious_objects (for known indicators)
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


if __name__ == "__main__":
    mcp.run(transport="stdio")
