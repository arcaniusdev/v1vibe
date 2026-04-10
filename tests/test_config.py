"""Tests for configuration management."""

import json
import os
import pytest
from pathlib import Path
from v1vibe.config import (
    Settings,
    load_config_file,
    save_config_file,
    load_settings,
    REGION_TO_BASE_URL,
)


def test_settings_immutable():
    """Settings should be immutable (frozen dataclass)."""
    settings = Settings(
        api_token="test-token",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
    )
    with pytest.raises(AttributeError):
        settings.api_token = "new-token"


def test_load_config_file_missing(tmp_path, monkeypatch):
    """load_config_file returns empty dict when file doesn't exist."""
    monkeypatch.setattr("v1vibe.config.CONFIG_FILE", tmp_path / "nonexistent.json")
    result = load_config_file()
    assert result == {}


def test_load_config_file_invalid_json(tmp_path, monkeypatch):
    """load_config_file returns empty dict for invalid JSON."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{invalid json")
    monkeypatch.setattr("v1vibe.config.CONFIG_FILE", bad_file)
    result = load_config_file()
    assert result == {}


def test_save_and_load_config_file(tmp_path, monkeypatch):
    """save_config_file creates file with correct permissions and content."""
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("v1vibe.config.CONFIG_FILE", config_file)
    monkeypatch.setattr("v1vibe.config.CONFIG_DIR", tmp_path)

    save_config_file(
        api_token="test-token-123",
        region="eu-central-1",
        tmas_binary_path="/opt/tmas",
    )

    # Check file exists and has correct permissions
    assert config_file.exists()
    assert oct(config_file.stat().st_mode)[-3:] == "600"

    # Check content
    loaded = load_config_file()
    assert loaded["api_token"] == "test-token-123"
    assert loaded["region"] == "eu-central-1"
    assert loaded["tmas_binary_path"] == "/opt/tmas"


def test_load_settings_from_env(monkeypatch):
    """load_settings prioritizes environment variables."""
    monkeypatch.setenv("V1_API_TOKEN", "env-token")
    monkeypatch.setenv("V1_REGION", "ap-southeast-1")
    monkeypatch.setattr("v1vibe.config.load_config_file", lambda: {})

    settings = load_settings()
    assert settings.api_token == "env-token"
    assert settings.region == "ap-southeast-1"
    assert settings.base_url == REGION_TO_BASE_URL["ap-southeast-1"]


def test_load_settings_from_file(monkeypatch):
    """load_settings falls back to config file."""
    monkeypatch.delenv("V1_API_TOKEN", raising=False)
    monkeypatch.delenv("V1_REGION", raising=False)
    monkeypatch.setattr(
        "v1vibe.config.load_config_file",
        lambda: {"api_token": "file-token", "region": "ca-central-1"},
    )

    settings = load_settings()
    assert settings.api_token == "file-token"
    assert settings.region == "ca-central-1"
    assert settings.base_url == REGION_TO_BASE_URL["ca-central-1"]


def test_load_settings_missing_token(monkeypatch):
    """load_settings raises error if API token is missing."""
    monkeypatch.delenv("V1_API_TOKEN", raising=False)
    monkeypatch.setattr("v1vibe.config.load_config_file", lambda: {})

    with pytest.raises(RuntimeError, match="API token not found"):
        load_settings()


def test_load_settings_missing_region(monkeypatch):
    """load_settings raises error if region is missing."""
    monkeypatch.setenv("V1_API_TOKEN", "test-token")
    monkeypatch.delenv("V1_REGION", raising=False)
    monkeypatch.setattr("v1vibe.config.load_config_file", lambda: {})

    with pytest.raises(RuntimeError, match="region not found"):
        load_settings()


def test_load_settings_invalid_region(monkeypatch):
    """load_settings raises error for invalid region."""
    monkeypatch.setenv("V1_API_TOKEN", "test-token")
    monkeypatch.setenv("V1_REGION", "invalid-region")
    monkeypatch.setattr("v1vibe.config.load_config_file", lambda: {})

    with pytest.raises(RuntimeError, match="Unknown region"):
        load_settings()


def test_all_regions_have_urls():
    """All defined regions have corresponding base URLs."""
    assert len(REGION_TO_BASE_URL) == 9  # Update count if regions change
    for region, url in REGION_TO_BASE_URL.items():
        assert url.startswith("https://")
        assert "trendmicro.com" in url or "trendmicro.co.jp" in url
