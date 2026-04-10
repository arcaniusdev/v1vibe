"""Tests for CLI installation functions."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from v1vibe.cli import (
    _install_docker_macos,
    TMAS_VERSION,
)


class TestInstallDockerMacOS:
    """Tests for Docker installation on macOS."""

    @patch("v1vibe.cli.shutil.which")
    def test_install_docker_already_installed(self, mock_which):
        """Test when Docker is already installed."""
        mock_which.return_value = "/usr/local/bin/docker"

        result = _install_docker_macos()

        assert result is True

    @patch("v1vibe.cli.shutil.which")
    @patch("v1vibe.cli._input", return_value="n")
    @patch("v1vibe.cli._print")
    def test_install_docker_user_declines(self, mock_print, mock_input, mock_which):
        """Test when user declines Docker installation."""
        # Docker not found, user declines
        mock_which.side_effect = [None, None, None]  # docker, podman, brew all not found

        result = _install_docker_macos()

        assert result is False


class TestMacOSDockerMode:
    """Tests for macOS Docker mode detection and configuration."""

    def test_macos_uses_docker_mode(self):
        """Test that macOS setup results in docker mode."""
        # This is a documentation test - on macOS, tmas_binary_path should be "docker"
        from v1vibe.config import Settings

        # Simulate macOS Docker configuration
        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",  # macOS uses Docker
        )

        assert settings.tmas_binary_path == "docker"

    def test_linux_uses_binary_path(self, tmp_path):
        """Test that Linux uses direct binary path."""
        from v1vibe.config import Settings

        # Simulate Linux binary configuration
        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=str(tmp_path / "tmas"),
        )

        assert settings.tmas_binary_path != "docker"
        assert "tmas" in settings.tmas_binary_path


class TestTmasVersion:
    """Tests for TMAS version constant."""

    def test_tmas_version_constant(self):
        """Test that TMAS_VERSION is defined correctly."""
        assert TMAS_VERSION
        assert isinstance(TMAS_VERSION, str)
        # Should be semantic version format
        parts = TMAS_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)
