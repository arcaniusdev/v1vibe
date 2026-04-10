"""Configuration management for v1vibe.

Handles loading/saving Vision One API credentials and settings from:
1. Environment variables (V1_API_TOKEN, V1_REGION) — highest priority
2. Config file (~/.v1vibe/config.json) — fallback

The config file is created with 0600 permissions to protect the API token.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# User configuration directory and file (can be overridden with V1_CONFIG_DIR)
CONFIG_DIR = Path(os.getenv("V1_CONFIG_DIR", str(Path.home() / ".v1vibe")))
CONFIG_FILE = CONFIG_DIR / "config.json"

# Mapping of Vision One regions to their API base URLs
REGION_TO_BASE_URL: dict[str, str] = {
    "us-east-1": "https://api.xdr.trendmicro.com",
    "eu-central-1": "https://api.eu.xdr.trendmicro.com",
    "ap-southeast-1": "https://api.sg.xdr.trendmicro.com",
    "ap-northeast-1": "https://api.xdr.trendmicro.co.jp",
    "ap-southeast-2": "https://api.au.xdr.trendmicro.com",
    "ap-south-1": "https://api.in.xdr.trendmicro.com",
    "me-south-1": "https://api.mea.xdr.trendmicro.com",
    "eu-west-2": "https://api.uk.xdr.trendmicro.com",
    "ca-central-1": "https://api.ca.xdr.trendmicro.com",
}

# Configurable timeouts (can be overridden with environment variables)
# HTTP timeout for Vision One API calls (seconds)
HTTP_TIMEOUT = float(os.getenv("V1_HTTP_TIMEOUT", "60.0"))
# TMAS artifact scan timeout (seconds) - 10 minutes default
SCAN_TIMEOUT = int(os.getenv("V1_SCAN_TIMEOUT", "600"))
# AI Scanner timeout (seconds) - 1 hour default for comprehensive scans
AI_SCAN_TIMEOUT = int(os.getenv("V1_AI_SCAN_TIMEOUT", "3600"))


@dataclass(frozen=True)
class Settings:
    """Immutable configuration settings for v1vibe.

    Attributes:
        api_token: Vision One API token for authentication
        region: Vision One region (e.g., "us-east-1", "eu-central-1")
        base_url: Full API base URL derived from region
        tmas_binary_path: Path to TMAS CLI binary, or "docker" for Docker mode
    """

    api_token: str
    region: str
    base_url: str
    tmas_binary_path: str | None = None


def load_config_file() -> dict:
    """Load configuration from ~/.v1vibe/config.json.

    Returns:
        dict: Configuration dict, or empty dict if file doesn't exist or is invalid
    """
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_config_file(api_token: str, region: str, tmas_binary_path: str | None = None) -> None:
    """Save configuration to ~/.v1vibe/config.json with secure permissions.

    The file is created with 0600 permissions (read/write for owner only)
    to protect the API token.

    Args:
        api_token: Vision One API token
        region: Vision One region
        tmas_binary_path: Optional path to TMAS CLI binary

    Raises:
        RuntimeError: If config file cannot be written
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config = {
            "api_token": api_token,
            "region": region,
        }
        if tmas_binary_path:
            config["tmas_binary_path"] = tmas_binary_path

        CONFIG_FILE.write_text(json.dumps(config, indent=2))
        CONFIG_FILE.chmod(0o600)
    except OSError as exc:
        raise RuntimeError(f"Failed to save config to {CONFIG_FILE}: {exc}") from exc


def load_settings() -> Settings:
    """Load settings from environment variables or config file.

    Priority order:
    1. Environment variables (V1_API_TOKEN, V1_REGION)
    2. Config file (~/.v1vibe/config.json)

    Returns:
        Settings: Validated configuration with API token, region, and base URL

    Raises:
        RuntimeError: If API token or region is missing, or region is invalid
    """
    file_config = load_config_file()

    # Env vars take priority over config file
    api_token = os.environ.get("V1_API_TOKEN", "").strip() or file_config.get("api_token", "")
    if not api_token:
        raise RuntimeError(
            "Vision One API token not found. Set V1_API_TOKEN env var or run: v1vibe setup"
        )

    region = os.environ.get("V1_REGION", "").strip() or file_config.get("region", "")
    if not region:
        raise RuntimeError(
            "Vision One region not found. Set V1_REGION env var or run: v1vibe setup"
        )

    base_url = REGION_TO_BASE_URL.get(region)
    if not base_url:
        valid = ", ".join(sorted(REGION_TO_BASE_URL))
        raise RuntimeError(f"Unknown region '{region}'. Valid regions: {valid}")

    tmas_binary_path = file_config.get("tmas_binary_path")

    return Settings(
        api_token=api_token,
        region=region,
        base_url=base_url,
        tmas_binary_path=tmas_binary_path,
    )
