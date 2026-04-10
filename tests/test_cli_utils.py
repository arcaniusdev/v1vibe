"""Tests for CLI utility functions."""

import pytest
import platform
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from v1vibe.cli import (
    _mask_token,
    _get_platform_info,
    _get_tmas_version,
    _check_docker_running,
    TMAS_VERSION,
    CLAUDE_MD_SNIPPET,
)


class TestTokenMasking:
    """Tests for API token masking."""

    def test_mask_short_token(self):
        """Test masking tokens shorter than 20 chars."""
        result = _mask_token("short")
        assert result == "***"

    def test_mask_long_token(self):
        """Test masking long tokens."""
        token = "abcdefghij" + "x" * 20 + "123456"
        result = _mask_token(token)
        assert result == "abcdefghij...123456"
        assert len(result) < len(token)

    def test_mask_exactly_20_chars(self):
        """Test masking token with exactly 20 characters."""
        token = "a" * 20
        result = _mask_token(token)
        assert result == "***"


class TestPlatformInfo:
    """Tests for platform detection."""

    @patch("v1vibe.cli.platform.system", return_value="Darwin")
    @patch("v1vibe.cli.platform.machine", return_value="arm64")
    def test_get_platform_macos_arm(self, mock_machine, mock_system):
        """Test macOS ARM64 detection (uses Linux binary)."""
        os_name, arch, ext = _get_platform_info()
        assert os_name == "Linux"  # macOS uses Linux binary
        assert arch == "arm64"
        assert ext == "tar.gz"

    @patch("v1vibe.cli.platform.system", return_value="Darwin")
    @patch("v1vibe.cli.platform.machine", return_value="x86_64")
    def test_get_platform_macos_intel(self, mock_machine, mock_system):
        """Test macOS Intel detection (uses Linux binary)."""
        os_name, arch, ext = _get_platform_info()
        assert os_name == "Linux"  # macOS uses Linux binary
        assert arch == "x86_64"
        assert ext == "tar.gz"

    @patch("v1vibe.cli.platform.system", return_value="Linux")
    @patch("v1vibe.cli.platform.machine", return_value="x86_64")
    def test_get_platform_linux_amd64(self, mock_machine, mock_system):
        """Test Linux AMD64 detection."""
        os_name, arch, ext = _get_platform_info()
        assert os_name == "Linux"
        assert arch == "x86_64"
        assert ext == "tar.gz"

    @patch("v1vibe.cli.platform.system", return_value="Linux")
    @patch("v1vibe.cli.platform.machine", return_value="aarch64")
    def test_get_platform_linux_arm(self, mock_machine, mock_system):
        """Test Linux ARM detection."""
        os_name, arch, ext = _get_platform_info()
        assert os_name == "Linux"
        assert arch == "arm64"
        assert ext == "tar.gz"

    @patch("v1vibe.cli.platform.system", return_value="Windows")
    @patch("v1vibe.cli.platform.machine", return_value="AMD64")
    def test_get_platform_windows(self, mock_machine, mock_system):
        """Test Windows detection."""
        os_name, arch, ext = _get_platform_info()
        assert os_name == "Windows"
        assert arch == "x86_64"
        assert ext == "zip"


class TestTmasVersion:
    """Tests for TMAS version detection."""

    def test_get_tmas_version_success(self):
        """Test getting TMAS version from binary."""
        mock_result = MagicMock()
        mock_result.stdout = "TMAS CLI version 2.221.0\n"
        mock_result.returncode = 0

        with patch("v1vibe.cli.subprocess.run", return_value=mock_result):
            version = _get_tmas_version("/usr/local/bin/tmas")

        # Function returns full stdout stripped
        assert version == "TMAS CLI version 2.221.0"

    def test_get_tmas_version_command_failed(self):
        """Test handling TMAS version command failure."""
        with patch("v1vibe.cli.subprocess.run", side_effect=FileNotFoundError()):
            version = _get_tmas_version("/nonexistent/tmas")

        assert version is None

    def test_get_tmas_version_nonzero_exit(self):
        """Test handling command with non-zero exit code."""
        mock_result = MagicMock()
        mock_result.stdout = "error output"
        mock_result.returncode = 1

        with patch("v1vibe.cli.subprocess.run", return_value=mock_result):
            version = _get_tmas_version("/usr/local/bin/tmas")

        assert version is None


class TestDockerCheck:
    """Tests for Docker availability checking."""

    def test_check_docker_running_success(self):
        """Test checking Docker when it's running."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("v1vibe.cli.subprocess.run", return_value=mock_result):
            result = _check_docker_running()

        assert result is True

    def test_check_docker_not_running(self):
        """Test checking Docker when it's not running."""
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch("v1vibe.cli.subprocess.run", return_value=mock_result):
            result = _check_docker_running()

        assert result is False

    def test_check_docker_not_installed(self):
        """Test checking Docker when it's not installed."""
        with patch("v1vibe.cli.subprocess.run", side_effect=FileNotFoundError()):
            result = _check_docker_running()

        assert result is False


class TestConstants:
    """Tests for CLI constants."""

    def test_tmas_version_format(self):
        """Test TMAS_VERSION is properly formatted."""
        assert TMAS_VERSION
        # Should be semantic version
        parts = TMAS_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_claude_md_snippet_content(self):
        """Test CLAUDE.md snippet contains required sections."""
        assert "v1vibe" in CLAUDE_MD_SNIPPET
        assert "MALWARE SCAN" in CLAUDE_MD_SNIPPET
        assert "URL CHECK" in CLAUDE_MD_SNIPPET
        assert "THREAT INTEL" in CLAUDE_MD_SNIPPET
        assert "IAC SCAN" in CLAUDE_MD_SNIPPET
        assert "ARTIFACT SCAN" in CLAUDE_MD_SNIPPET
        assert "scan_file" in CLAUDE_MD_SNIPPET
        assert "check_suspicious_objects" in CLAUDE_MD_SNIPPET
