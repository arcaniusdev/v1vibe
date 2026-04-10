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
from typing import Set

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

# Directories to exclude from scanning (symlinks, dependencies, build artifacts)
# These cause issues with Docker mounting and symlink resolution
EXCLUDED_DIRS = [
    ".venv",           # Python virtual environments (symlinks to system Python)
    "venv",            # Alternative Python venv name
    "node_modules",    # Node.js dependencies
    ".git",            # Git repository data
    "__pycache__",     # Python bytecode cache
    ".pytest_cache",   # Pytest cache
    "dist",            # Build distributions
    "build",           # Build artifacts
    ".tox",            # Tox testing environments
    ".mypy_cache",     # MyPy type checker cache
    ".ruff_cache",     # Ruff linter cache
]


def _create_filtered_copy(source_dir: str, dest_dir: str, excluded_dirs: Set[str]) -> None:
    """Create a filtered copy of source_dir excluding specified directories and symlinks.

    This avoids symlink issues by excluding directories like .venv that contain
    symlinks pointing outside the project (e.g., to /opt/homebrew).

    Args:
        source_dir: Source directory to copy from
        dest_dir: Destination directory to copy to
        excluded_dirs: Set of directory names to exclude (e.g., {'.venv', 'node_modules'})
    """
    source_path = Path(source_dir)
    dest_path = Path(dest_dir)

    def should_exclude(path: Path) -> bool:
        """Check if path or any of its parents should be excluded."""
        try:
            relative = path.relative_to(source_path)
            # Check if any part of the path is in excluded_dirs
            return any(part in excluded_dirs for part in relative.parts)
        except ValueError:
            return True

    # Walk the directory tree manually for better control
    for root, dirs, files in os.walk(source_dir, followlinks=False):
        root_path = Path(root)

        # Filter out excluded directories from traversal
        dirs[:] = [d for d in dirs if not should_exclude(root_path / d)]

        # Skip if current directory is excluded
        if should_exclude(root_path):
            continue

        # Create corresponding directory in dest
        try:
            relative_root = root_path.relative_to(source_path)
            dest_root = dest_path / relative_root
            dest_root.mkdir(parents=True, exist_ok=True)

            # Copy files (skip symlinks)
            for file in files:
                src_file = root_path / file
                # Skip symlinks entirely
                if src_file.is_symlink():
                    continue

                dest_file = dest_root / file
                try:
                    shutil.copy2(src_file, dest_file)
                except (OSError, PermissionError):
                    # Skip files we can't read/copy
                    pass
        except (OSError, PermissionError, ValueError):
            # Skip directories we can't process
            pass


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

    Exclusions (automatic on macOS Docker mode):
    - Virtual environments (.venv, venv), node_modules, .git, and build artifacts are
      automatically excluded when scanning directories to avoid symlink issues (e.g.,
      .venv/bin/python -> /opt/homebrew) and reduce scan time. Container images are
      scanned in full.

    Known Limitations:
    - **Malware scanning:** Only works on container images, not directories. Use scan_file
      for file-by-file malware scanning.
    - **Secret scanning with .venv:** TMAS secret scanner aggressively follows symlinks and may
      fail on project roots containing .venv. Workarounds: (1) scan source directory only
      (e.g., 'src/'), (2) run vulnerability scan separately, or (3) use grep for manual
      secret detection.

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

            # Security: Validate additional_args to prevent command injection
            validated_extra_args = []
            if additional_args:
                # First pass: reject any args with shell metacharacters that could break out
                # Even with shlex.quote, we're extra cautious since this runs in Docker
                if any(char in additional_args for char in [";", "|", "&", "$", "`", "(", ")", "<", ">"]):
                    return {
                        "error": {
                            "code": "InvalidArguments",
                            "message": "additional_args contains unsafe shell metacharacters",
                        }
                    }
                # Second pass: quote each argument individually for safe shell usage
                for arg in additional_args.split():
                    validated_extra_args.append(shlex.quote(arg))

            # Determine artifact type - directories need volume mounts, images don't
            is_directory = not any(
                artifact_validated.startswith(p)
                for p in ["registry:", "docker:", "docker-archive:", "oci-archive:", "oci-dir:", "podman:"]
            )

            # Build Docker command - we'll run TMAS inside an Ubuntu container
            cmd = ["docker", "run", "--rm"]

            # Configure volume mounts based on artifact type
            # Each type needs different access (filesystem, Docker socket, etc.)
            if is_directory:
                # Create filtered copy to avoid symlink issues
                # This prevents errors from symlinks pointing outside the project (e.g., .venv -> /opt/homebrew)
                filtered_dir = Path(tmpdir) / "filtered_scan"
                filtered_dir.mkdir()
                _create_filtered_copy(artifact_abs, str(filtered_dir), set(EXCLUDED_DIRS))

                # Mount filtered directory for scanning
                cmd.extend(["-v", f"{filtered_dir}:/scan:ro"])
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

            # Common mounts and environment for all artifact types
            cmd.extend([
                "-v", f"{tmpdir}:/output",  # Mount temp dir for TMAS output JSON
                "-e", f"TMAS_API_KEY={ctx.settings.api_token}",  # Pass API key securely
                "-w", "/tmp",  # Working directory inside container
                DOCKER_IMAGE,
                "sh", "-c",  # Run shell command inside container
            ])

            # Build scan flags based on requested scan types
            tmas_flags = []
            if "vulnerability" in scan_types:
                tmas_flags.append("-V")
            if "malware" in scan_types:
                tmas_flags.append("-M")
            if "secrets" in scan_types:
                tmas_flags.append("-S")

            # Region is already validated by Settings class, but quote for defense in depth
            region_quoted = shlex.quote(ctx.settings.region)

            # Avoid --region duplication if user already specified it
            include_region = not (additional_args and "--region" in additional_args)

            # Build shell command to run inside container
            # Note: $ARCH is a shell variable expanded inside the container, not here
            # The URL is safe - TMAS_VERSION is a constant and base URL is hardcoded
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
                # No output file - analyze error and provide helpful guidance
                stderr = result.stderr.strip()

                # Check for specific known issues
                error_message = "TMAS scan did not produce output file"
                suggestions = []

                if "InvalidMalwareScanArtifactTypeError" in stderr or "not supported by malware scanning" in stderr:
                    error_message = "Malware scanning is not supported for directory artifacts"
                    suggestions.append("Use scan_file tool to scan individual files for malware")
                    suggestions.append("Malware scanning via scan_artifact only works for container images")

                if "unable to follow symlink" in stderr or "no such file or directory" in stderr:
                    # Secret scanning is particularly aggressive about following symlinks
                    # Even with filtering, it can encounter issues on project roots
                    error_message = "TMAS secret scan encountered broken symlinks (known limitation with .venv)"
                    suggestions.append("Workaround 1: Scan source code directory only (e.g., 'src/', 'app/', 'lib/')")
                    suggestions.append("Workaround 2: Run vulnerability and secret scans separately - vulnerability scanning works on full projects")
                    suggestions.append("Workaround 3: Temporarily move/rename .venv before scanning")
                    suggestions.append("Note: scan_file tool can scan individual files without symlink issues")

                error_response = {
                    "error": {
                        "code": "ScanFailed",
                        "message": error_message,
                        "exitCode": result.returncode,
                        "stdout": result.stdout.strip(),
                        "stderr": stderr,
                    }
                }

                if suggestions:
                    error_response["error"]["suggestions"] = suggestions

                return error_response

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
