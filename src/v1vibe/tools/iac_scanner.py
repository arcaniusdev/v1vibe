"""Infrastructure as Code (IaC) security scanning.

Scans CloudFormation and Terraform templates for security misconfigurations,
compliance violations, and best practice deviations. Checks against hundreds
of rules covering AWS, Azure, GCP, and multi-cloud environments.

Supports compliance framework mapping (CIS, NIST, AWS Well-Architected, etc.)
to show which regulatory requirements each finding violates.
"""

from __future__ import annotations

import os
from typing import Any

from v1vibe import api_endpoints
from v1vibe.clients import AppContext
from v1vibe.utils import check_response, format_error

# Valid template types for scan_template endpoint
VALID_TEMPLATE_TYPES = {"cloudformation-template", "terraform-template"}


async def list_compliance_standards(ctx: AppContext) -> dict[str, Any]:
    """List all available compliance standards for IaC scanning.

    Returns compliance frameworks like CIS Benchmarks, NIST, AWS Well-Architected,
    PCI-DSS, HIPAA, ISO 27001, etc. Each standard includes supported cloud providers
    (AWS, Azure, GCP) and version information.

    Use this to discover which compliance frameworks are available for template
    scanning. The returned IDs can be used to filter findings by compliance
    framework or to understand which standards a finding violates.

    Args:
        ctx: Application context with HTTP client

    Returns:
        dict: List of compliance standards with id, name, version, providers,
              or error dict

    Example response:
        {
            "count": 10,
            "items": [
                {
                    "id": "CIS-V8",
                    "name": "CIS Benchmarks",
                    "version": "v8.0",
                    "providers": ["aws", "azure", "gcp"]
                },
                {
                    "id": "NIST4",
                    "name": "NIST Cybersecurity Framework",
                    "version": "2.0",
                    "providers": ["aws", "azure", "gcp"]
                }
            ]
        }
    """
    try:
        resp = await ctx.http.get(api_endpoints.IAC_GET_COMPLIANCE_STANDARDS)
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def list_compliance_profiles(ctx: AppContext, limit: int = 100) -> dict[str, Any]:
    """List available compliance profiles for IaC scanning.

    Compliance profiles group rules by framework (CIS, NIST, etc.) and can be
    used to scan templates against specific compliance requirements. Each profile
    has a unique ID that can be passed to scan_template() for targeted scanning.

    Profiles are pre-configured rule sets optimized for specific compliance
    standards. Using a profile ensures you only get findings relevant to that
    framework's requirements.

    Args:
        ctx: Application context with HTTP client
        limit: Maximum profiles to return (50-200, default 100)

    Returns:
        dict: List of compliance profiles with id, name, description,
              associated compliance standards, or error dict

    Example response:
        {
            "count": 5,
            "items": [
                {
                    "id": "3PfYLfW",
                    "name": "CIS AWS Foundations",
                    "description": "CIS Benchmark for AWS",
                    "complianceStandards": [
                        {"id": "CIS-V8"}
                    ]
                }
            ]
        }
    """
    try:
        if not 50 <= limit <= 200:
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"limit must be between 50 and 200, got {limit}",
                }
            }

        resp = await ctx.http.get(api_endpoints.IAC_GET_PROFILES, params={"top": limit})
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def scan_template(
    ctx: AppContext,
    file_path: str,
    template_type: str,
    profile_id: str | None = None,
) -> dict[str, Any]:
    """Scan CloudFormation or Terraform template for security issues.

    Validates template syntax and checks for security misconfigurations,
    compliance violations, and best practice deviations. Automatically maps
    findings to applicable compliance standards (CIS, NIST, AWS Well-Architected,
    PCI-DSS, etc.) across ALL frameworks.

    Each finding includes a 'complianceStandards' array showing which regulatory
    requirements it violates, enabling compliance-driven remediation prioritization.

    Args:
        ctx: Application context with HTTP client
        file_path: Absolute path to template file
        template_type: Type of template - "cloudformation-template" (YAML/JSON)
                      or "terraform-template" (Terraform plan JSON)
        profile_id: Optional compliance profile ID to scan against specific
                   framework rules (e.g., CIS-only checks). Use
                   list_compliance_profiles() to find available profiles.
                   If omitted, uses default rules but still returns compliance
                   mappings for all applicable frameworks.

    Returns:
        dict: Scan results with findings array. Each finding includes:
              - riskLevel: HIGH, MEDIUM, LOW, INFORMATIONAL
              - ruleId: Rule identifier (e.g., "RDS-003")
              - ruleTitle: Human-readable rule name
              - description: Finding details
              - resource: Affected resource name
              - resourceType: Resource type (e.g., "rds-dbinstance")
              - complianceStandards: Array of compliance frameworks this
                violates (e.g., [{"id": "CIS-V8"}, {"id": "NIST4"}])
              - resolutionReferenceLink: Remediation documentation
              or error dict

    Example finding with compliance mapping:
        {
            "ruleId": "S3-001",
            "ruleTitle": "S3 Bucket Public Access Block",
            "riskLevel": "HIGH",
            "resource": "my-bucket",
            "complianceStandards": [
                {"id": "CIS-V8"},
                {"id": "NIST4"},
                {"id": "AWAF-2025"}
            ]
        }
    """
    try:
        if template_type not in VALID_TEMPLATE_TYPES:
            return {
                "error": {
                    "code": "InvalidInput",
                    "message": f"Invalid template_type '{template_type}'. Must be one of: {', '.join(sorted(VALID_TEMPLATE_TYPES))}",
                }
            }

        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        with open(file_path, "r") as f:
            content = f.read()

        body: dict[str, Any] = {
            "type": template_type,
            "content": content,
        }

        # Add profile_id if specified for targeted compliance scanning
        if profile_id:
            body["profileId"] = profile_id

        resp = await ctx.http.post(
            api_endpoints.IAC_SCAN_TEMPLATE,
            json=body,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)


async def scan_terraform_archive(
    ctx: AppContext,
    file_path: str,
    profile_id: str | None = None,
) -> dict[str, Any]:
    """Scan a ZIP archive containing Terraform HCL (.tf) files.

    Scans Terraform configurations with a single root module. The ZIP should
    contain .tf files at the root level (not nested in subdirectories).
    Automatically maps findings to applicable compliance standards (CIS, NIST,
    etc.) across ALL frameworks.

    Args:
        ctx: Application context with HTTP client
        file_path: Absolute path to ZIP file containing .tf files
        profile_id: Optional compliance profile ID to scan against specific
                   framework rules. Use list_compliance_profiles() to find
                   available profiles. If omitted, uses default rules but
                   still returns compliance mappings for all applicable
                   frameworks.

    Returns:
        dict: Scan results with findings array (same structure as scan_template),
              including complianceStandards array for each finding, or error dict
    """
    try:
        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        # Read file contents first, then close before HTTP upload
        with open(file_path, "rb") as f:
            file_content = f.read()

        data = {"type": "terraform-archive"}

        # Add profile_id if specified for targeted compliance scanning
        if profile_id:
            data["profileId"] = profile_id

        resp = await ctx.http.post(
            api_endpoints.IAC_SCAN_ARCHIVE,
            files={"file": (os.path.basename(file_path), file_content, "application/zip")},
            data=data,
        )
        return check_response(resp)
    except Exception as exc:
        return format_error(exc)
