"""Artifact scanning using TMAS CLI for vulnerabilities, malware, and secrets."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from v1vibe.clients import AppContext


async def scan_artifact(
    ctx: AppContext,
    artifact: str,
    scan_types: list[str] | None = None,
    additional_args: str | None = None,
) -> dict:
    """Scans artifact using TMAS CLI for vulnerabilities, malware, and secrets.

    Generates SBOM for vulnerability scanning, uploads to Vision One, and returns
    comprehensive security analysis including CVEs, malware detections, and exposed secrets.

    Supported artifacts:
    - Directories: "dir:/path/to/project" or just "/path/to/project"
    - Container images: "registry:myrepo/image:tag", "docker:image:tag"
    - Archives: "docker-archive:image.tar", "oci-archive:image.tar"

    Args:
        artifact: Path to artifact to scan (directory, image reference, or archive).
        scan_types: List of scan types to run. Options: "vulnerability", "malware", "secrets".
                   Default: ["vulnerability", "secrets"]
        additional_args: Extra CLI arguments (e.g., "--region us-east-1").

    Returns:
        dict: Scan results including vulnerabilities, malware, secrets, or error.
    """
    # Default scan types
    if scan_types is None:
        scan_types = ["vulnerability", "secrets"]

    # Validate scan types
    valid_types = {"vulnerability", "malware", "secrets"}
    invalid = set(scan_types) - valid_types
    if invalid:
        return {
            "error": {
                "code": "InvalidScanType",
                "message": f"Invalid scan types: {', '.join(invalid)}. Valid: vulnerability, malware, secrets",
            }
        }

    # Find TMAS binary
    tmas_path = ctx.settings.tmas_binary_path or shutil.which("tmas")
    if not tmas_path:
        return {
            "error": {
                "code": "TmasNotInstalled",
                "message": "TMAS CLI not installed. Run: v1vibe setup",
            }
        }

    if not Path(tmas_path).exists():
        return {
            "error": {
                "code": "TmasBinaryNotFound",
                "message": f"TMAS binary not found at {tmas_path}. Run: v1vibe setup",
            }
        }

    # Build command
    cmd = [tmas_path, "scan", artifact]

    # Add scan type flags
    if "vulnerability" in scan_types:
        cmd.append("-V")
    if "malware" in scan_types:
        cmd.append("-M")
    if "secrets" in scan_types:
        cmd.append("-S")

    # Add region if not in additional args
    if additional_args and "--region" not in additional_args:
        cmd.extend(["--region", ctx.settings.region])
    elif not additional_args:
        cmd.extend(["--region", ctx.settings.region])

    # Create temp directory for output
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "tmas_scan_report.json"

        # Add output format args
        cmd.extend(["--redacted", f"--output=json={output_file}"])

        # Add any additional arguments
        if additional_args:
            cmd.extend(additional_args.split())

        # Set environment variable for API key
        env = {"TMAS_API_KEY": ctx.settings.api_token}

        try:
            # Run TMAS CLI
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                env=env,
            )

            # Read output file if it exists
            if output_file.exists():
                scan_results = json.loads(output_file.read_text())

                # Add metadata
                response = {
                    "artifact": artifact,
                    "scanTypes": scan_types,
                    "exitCode": result.returncode,
                    "results": scan_results,
                }

                # Add stderr if there were warnings
                if result.stderr.strip():
                    response["warnings"] = result.stderr.strip()

                return response
            else:
                # No output file - return stderr/stdout
                return {
                    "error": {
                        "code": "ScanFailed",
                        "message": "TMAS scan did not produce output file",
                        "exitCode": result.returncode,
                        "stdout": result.stdout.strip(),
                        "stderr": result.stderr.strip(),
                    }
                }

        except subprocess.TimeoutExpired:
            return {
                "error": {
                    "code": "ScanTimeout",
                    "message": "TMAS scan exceeded 10 minute timeout",
                }
            }
        except Exception as e:
            return {
                "error": {
                    "code": "ScanError",
                    "message": f"Failed to run TMAS scan: {e}",
                }
            }
