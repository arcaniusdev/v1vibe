"""File malware scanning using TrendAI File Security SDK or CLI.

Fast malware scanning via gRPC API (SDK) or subprocess (CLI fallback).
Accepts any file type and returns scan results with malware names,
file hashes (SHA1/SHA256), and optional Predictive Machine Learning (PML).

The CLI fallback is used when the SDK is incompatible (e.g., Python 3.14+
where grpcio version constraints prevent SDK installation).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from v1vibe.clients import AppContext, FILE_SECURITY_AVAILABLE
from v1vibe.config import SCAN_TIMEOUT
from v1vibe.utils import format_error

# Import File Security SDK if available
try:
    import amaas.grpc.aio as amaas_aio
except ImportError:
    amaas_aio = None


def _scan_file_cli(
    tmfs_path: str,
    file_path: str,
    region: str,
    api_token: str,
    tags: list[str] | None = None,
    pml: bool = False,
) -> dict[str, Any]:
    """Scan a file using File Security CLI (tmfs binary).

    Fallback method when SDK is unavailable (e.g., Python 3.14+ compatibility).

    Args:
        tmfs_path: Path to tmfs binary
        file_path: Absolute path to file to scan
        region: Vision One region (us-east-1, eu-central-1, etc.)
        api_token: Vision One API token (set as TMFS_API_KEY env var)
        tags: Optional list of tags for organizing scan results
        pml: Enable Predictive Machine Learning detection

    Returns:
        dict: Scan result matching SDK format, or error dict on failure
    """
    try:
        cmd = [tmfs_path, "scan", f"file:{file_path}", "--region", region]

        # Add tags if provided
        if tags:
            for tag in tags[:8]:  # Max 8 tags
                if len(tag) <= 63:  # Max 63 chars per tag
                    cmd.extend(["--tag", tag])

        # Add PML flag if enabled
        if pml:
            cmd.extend(["--pml", "true"])

        # Set TMFS_API_KEY environment variable (required by tmfs CLI)
        env = os.environ.copy()
        env["TMFS_API_KEY"] = api_token

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            env=env,
        )

        if result.returncode != 0:
            return {
                "error": {
                    "code": "CLIScanFailed",
                    "message": f"tmfs CLI scan failed: {result.stderr or result.stdout}"
                }
            }

        # Parse JSON output from CLI
        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        return {
            "error": {
                "code": "ScanTimeout",
                "message": f"File scan timed out after {SCAN_TIMEOUT} seconds"
            }
        }
    except json.JSONDecodeError as e:
        return {
            "error": {
                "code": "InvalidCLIOutput",
                "message": f"Failed to parse tmfs CLI output: {e}"
            }
        }
    except Exception as exc:
        return format_error(exc)


async def scan_file(
    ctx: AppContext,
    file_path: str,
    tags: list[str] | None = None,
    pml: bool = False,
) -> dict[str, Any]:
    """Scan a file for malware using File Security SDK or CLI fallback.

    Automatically uses SDK (gRPC) if available, or falls back to CLI (tmfs binary)
    if SDK is incompatible (e.g., Python 3.14+ where grpcio constraints prevent it).

    Fast malware scan (seconds). Supports any file type.

    Args:
        ctx: Application context with gRPC handle or tmfs_binary_path
        file_path: Absolute path to file to scan
        tags: Optional list of tags for organizing scan results (max 8, 63 chars each)
        pml: Enable Predictive Machine Learning for detecting novel malware variants

    Returns:
        dict: Scan result with scanResult (0=clean, 1=malicious), foundMalwares list,
              fileSHA1, fileSHA256, or error dict on failure
    """
    try:
        if not os.path.isfile(file_path):
            return {"error": {"code": "FileNotFound", "message": f"File not found: {file_path}"}}

        # Try SDK first if available
        if ctx.grpc_handle and amaas_aio:
            result_json = await amaas_aio.scan_file(
                ctx.grpc_handle,
                file_name=file_path,
                tags=tags or [],
                pml=pml,
            )
            return json.loads(result_json)

        # Fall back to CLI if available
        tmfs_path = getattr(ctx.settings, 'tmfs_binary_path', None)
        if tmfs_path and Path(tmfs_path).exists():
            return _scan_file_cli(
                tmfs_path=tmfs_path,
                file_path=file_path,
                region=ctx.settings.region,
                api_token=ctx.settings.api_token,
                tags=tags,
                pml=pml,
            )

        # Neither SDK nor CLI available
        return {
            "error": {
                "code": "FileSecurityUnavailable",
                "message": "File Security SDK and CLI both unavailable. "
                           "SDK may be incompatible with Python 3.14+. "
                           "Run 'v1vibe setup' to install CLI fallback, or 'v1vibe status' for details."
            }
        }

    except Exception as exc:
        return format_error(exc)
