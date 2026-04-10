"""Artifact scanning using TMAS CLI for vulnerabilities, malware, and secrets."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from v1vibe.clients import AppContext

# TMAS version - single source of truth for both binary and Docker modes
TMAS_VERSION = "2.221.0"

# Docker image for TMAS execution on macOS
DOCKER_IMAGE = "ubuntu:22.04"

# Scan timeout (10 minutes)
SCAN_TIMEOUT_SECONDS = 600

# Forbidden paths to prevent scanning system directories
# Note: macOS symlinks like /etc -> /private/etc are handled by including both
FORBIDDEN_PATHS = [
    "/etc", "/private/etc",
    "/sys",
    "/proc",
    "/dev",
    "/boot",
    "/root", "/var/root",
    "/bin", "/sbin",
    "/usr/bin", "/usr/sbin",
    "/System",  # macOS system directory
]


def _validate_artifact_path(artifact: str) -> str:
    """Validate artifact path to prevent path traversal attacks.

    Args:
        artifact: Path to validate

    Returns:
        Validated absolute path

    Raises:
        ValueError: If path is forbidden
    """
    # Handle container image references (don't validate as filesystem paths)
    if any(artifact.startswith(prefix) for prefix in ["registry:", "docker:", "docker-archive:", "oci-archive:"]):
        return artifact

    # Handle dir: prefix
    if artifact.startswith("dir:"):
        artifact = artifact[4:]

    # Resolve to absolute path
    try:
        resolved = Path(artifact).resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")

    # Check if path exists
    if not resolved.exists():
        raise ValueError(f"Path does not exist: {resolved}")

    # Prevent access to system directories
    resolved_str = str(resolved)
    for forbidden in FORBIDDEN_PATHS:
        if resolved_str.startswith(forbidden):
            raise ValueError(f"Access to {forbidden} is not allowed for security reasons")

    return resolved_str


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
    - Container images: "registry:myrepo/image:tag", "docker:image:tag", "podman:image:tag"
    - OCI directories: "oci-dir:/path/to/oci"
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

    # Validate artifact path to prevent path traversal
    try:
        artifact_validated = _validate_artifact_path(artifact)
    except ValueError as e:
        return {
            "error": {
                "code": "InvalidPath",
                "message": str(e),
            }
        }

    # Check TMAS availability
    tmas_path = ctx.settings.tmas_binary_path
    use_docker = False

    if not tmas_path:
        return {
            "error": {
                "code": "TmasNotInstalled",
                "message": "TMAS CLI not installed. Run: v1vibe setup",
            }
        }

    # Check if we're using Docker mode (macOS)
    if tmas_path == "docker":
        use_docker = True
        # Verify Docker is available
        if not shutil.which("docker"):
            return {
                "error": {
                    "code": "DockerNotFound",
                    "message": "Docker not found. Install Docker Desktop for artifact scanning on macOS.",
                }
            }
    else:
        # Using binary directly (Linux/Windows)
        if not Path(tmas_path).exists():
            return {
                "error": {
                    "code": "TmasBinaryNotFound",
                    "message": f"TMAS binary not found at {tmas_path}. Run: v1vibe setup",
                }
            }

    # Create temp directory for output
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "tmas_scan_report.json"

        if use_docker:
            # Docker mode for macOS
            # Use validated path
            artifact_abs = artifact_validated

            # Validate additional_args to prevent command injection
            validated_extra_args = []
            if additional_args:
                # Reject any additional_args with shell metacharacters
                if any(char in additional_args for char in [";", "|", "&", "$", "`", "(", ")", "<", ">"]):
                    return {
                        "error": {
                            "code": "InvalidArguments",
                            "message": "additional_args contains unsafe shell metacharacters",
                        }
                    }
                # Quote each argument for safe shell usage
                for arg in additional_args.split():
                    validated_extra_args.append(shlex.quote(arg))

            # Determine artifact type and how to scan it
            is_directory = not any(
                artifact_validated.startswith(p)
                for p in ["registry:", "docker:", "docker-archive:", "oci-archive:", "oci-dir:", "podman:"]
            )

            # Build Docker command base
            cmd = ["docker", "run", "--rm"]

            # Configure volume mounts based on artifact type
            if is_directory:
                # Mount directory for scanning
                cmd.extend(["-v", f"{artifact_abs}:/scan:ro"])
                scan_target = "dir:/scan"
            elif artifact_validated.startswith("docker:"):
                # Mount Docker socket for docker: images (needs access to Docker daemon)
                cmd.extend(["-v", "/var/run/docker.sock:/var/run/docker.sock"])
                scan_target = shlex.quote(artifact_validated)
            elif artifact_validated.startswith(("docker-archive:", "oci-archive:")):
                # Mount archive file's parent directory
                archive_path = artifact_validated.split(":", 1)[1]
                archive_dir = str(Path(archive_path).parent)
                archive_name = Path(archive_path).name
                cmd.extend(["-v", f"{archive_dir}:/archives:ro"])
                # Reconstruct the archive reference with mounted path
                archive_prefix = artifact_validated.split(":", 1)[0]
                scan_target = shlex.quote(f"{archive_prefix}:/archives/{archive_name}")
            else:
                # registry:, oci-dir:, podman: - pass through directly (network access only)
                scan_target = shlex.quote(artifact_validated)

            # Common mounts and environment
            cmd.extend([
                "-v", f"{tmpdir}:/output",  # Mount output directory
                "-e", f"TMAS_API_KEY={ctx.settings.api_token}",
                "-w", "/tmp",
                DOCKER_IMAGE,
                "sh", "-c",
            ])

            # Build the shell command to run inside container with proper escaping
            tmas_flags = []
            if "vulnerability" in scan_types:
                tmas_flags.append("-V")
            if "malware" in scan_types:
                tmas_flags.append("-M")
            if "secrets" in scan_types:
                tmas_flags.append("-S")

            # Region is already validated by Settings, but quote it for safety
            region_quoted = shlex.quote(ctx.settings.region)

            # Skip region if it's in additional_args (avoid duplication)
            include_region = not (additional_args and "--region" in additional_args)

            # Build shell command with proper quoting
            # Note: Internal shell variables like $ARCH are intentionally not quoted
            # The URL is safe because we control TMAS_VERSION and the base URL is hardcoded
            tmas_url = f"https://ast-cli.xdr.trendmicro.com/tmas-cli/{TMAS_VERSION}/tmas-cli_Linux_$ARCH.tar.gz"

            shell_cmd_parts = [
                "apt-get update -qq && apt-get install -y -qq curl > /dev/null 2>&1 &&",
                "ARCH=$(uname -m); [ \"$ARCH\" = \"aarch64\" ] && ARCH=\"arm64\" || true;",
                f"curl -sL {tmas_url} | tar xz &&",
                f"./tmas scan {scan_target}",
                " ".join(tmas_flags),
            ]

            if include_region:
                shell_cmd_parts.append(f"--region {region_quoted}")

            shell_cmd_parts.extend([
                "--redacted",
                "--output=json=/output/tmas_scan_report.json",
            ])

            if validated_extra_args:
                shell_cmd_parts.extend(validated_extra_args)

            shell_cmd = " ".join(shell_cmd_parts)
            cmd.append(shell_cmd)
            env = None  # Docker -e flag handles API key
        else:
            # Binary mode for Linux/Windows
            cmd = [tmas_path, "scan", artifact_validated]

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

            # Add output format args
            cmd.extend(["--redacted", f"--output=json={output_file}"])

            # Add any additional arguments (validated)
            if additional_args:
                # Validate additional_args to prevent command injection
                # Note: subprocess.run with list args (not shell=True) prevents injection,
                # but we still validate to prevent unexpected behavior
                if any(char in additional_args for char in [";", "|", "&", "$", "`", "(", ")", "<", ">"]):
                    return {
                        "error": {
                            "code": "InvalidArguments",
                            "message": "additional_args contains unsafe shell metacharacters",
                        }
                    }
                # Add arguments (no escaping needed since we use list format)
                cmd.extend(additional_args.split())

            # Set environment variable for API key
            env = {"TMAS_API_KEY": ctx.settings.api_token}

        try:
            # Run TMAS CLI
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
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
                    "message": f"TMAS scan exceeded {SCAN_TIMEOUT_SECONDS} second timeout",
                }
            }
        except Exception as e:
            return {
                "error": {
                    "code": "ScanError",
                    "message": f"Failed to run TMAS scan: {e}",
                }
            }
