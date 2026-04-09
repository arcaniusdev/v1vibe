from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

CONFIG_DIR = Path.home() / ".v1vibe"
CONFIG_FILE = CONFIG_DIR / "config.json"

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


@dataclass(frozen=True)
class Settings:
    api_token: str
    region: str
    base_url: str


def load_config_file() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_config_file(api_token: str, region: str) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps({"api_token": api_token, "region": region}, indent=2))
    CONFIG_FILE.chmod(0o600)


def load_settings() -> Settings:
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

    return Settings(api_token=api_token, region=region, base_url=base_url)
