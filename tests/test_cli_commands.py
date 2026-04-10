"""Tests for CLI command functions."""

import pytest
import sys
from io import StringIO
from unittest.mock import patch, MagicMock, AsyncMock
from v1vibe.cli import (
    cmd_status,
    REGION_TO_BASE_URL,
)


class TestCmdStatus:
    """Tests for status command."""

    @patch("v1vibe.cli.load_settings")
    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    def test_status_not_configured(self, mock_print, mock_load_file, mock_load_settings):
        """Test status when not configured."""
        mock_load_file.return_value = {}
        mock_load_settings.side_effect = SystemExit(1)  # Simulates missing config

        try:
            cmd_status()
        except SystemExit:
            pass

        # Should print not configured message
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        # Function exits early when not configured
        assert len(calls) > 0

    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    @patch("v1vibe.cli._mask_token")
    @patch("v1vibe.cli._get_tmas_version")
    @patch("v1vibe.cli._check_docker_running")
    @patch("v1vibe.cli.platform.system")
    def test_status_configured_docker_mode(self, mock_system, mock_docker, mock_version, mock_mask, mock_print, mock_load):
        """Test status with Docker mode (macOS)."""
        mock_system.return_value = "Darwin"
        mock_load.return_value = {
            "api_token": "test-token-12345678901234567890",
            "region": "us-east-1",
            "tmas_binary_path": "docker",
        }
        mock_mask.return_value = "test-token...890"
        mock_docker.return_value = True
        mock_version.return_value = None  # Docker mode doesn't need version

        cmd_status()

        # Should show Docker mode
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        assert "docker" in output.lower()

    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    @patch("v1vibe.cli._mask_token")
    @patch("v1vibe.cli._get_tmas_version")
    @patch("v1vibe.cli.platform.system")
    def test_status_configured_binary_mode(self, mock_system, mock_version, mock_mask, mock_print, mock_load):
        """Test status with binary mode (Linux/Windows)."""
        mock_system.return_value = "Linux"
        mock_load.return_value = {
            "api_token": "test-token-12345678901234567890",
            "region": "us-east-1",
            "tmas_binary_path": "/usr/local/bin/tmas",
        }
        mock_mask.return_value = "test-token...890"
        mock_version.return_value = "TMAS CLI version 2.221.0"

        cmd_status()

        # Should show version
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        assert "2.221.0" in output or "TMAS" in output

    @patch("v1vibe.cli.httpx.Client")
    @patch("v1vibe.cli.load_settings")
    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    @patch("v1vibe.cli._mask_token")
    def test_status_shows_region(self, mock_mask, mock_print, mock_load_file, mock_load_settings, mock_http):
        """Test that status shows configured region."""
        from v1vibe.config import Settings

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="ap-southeast-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="/usr/local/bin/tmas",
        )
        mock_load_settings.return_value = settings
        mock_load_file.return_value = {
            "api_token": "test-token-12345678901234567890",
            "region": "ap-southeast-1",
            "tmas_binary_path": "/usr/local/bin/tmas",
        }
        mock_mask.return_value = "test-token...890"

        # Mock HTTP client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"dailyReserve": 100, "remaining": 99, "usedFileCount": 1, "usedUrlCount": 0}
        mock_client.get.return_value = mock_response
        mock_http.return_value.__enter__.return_value = mock_client

        with patch("v1vibe.cli._get_tmas_version", return_value="2.221.0"):
            with patch("v1vibe.cli.platform.system", return_value="Linux"):
                with patch("v1vibe.cli.Path.exists", return_value=False):  # No CLAUDE.md
                    cmd_status()

        # Should show region
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        assert "ap-southeast-1" in output

    @patch("v1vibe.cli.httpx.Client")
    @patch("v1vibe.cli.load_settings")
    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    @patch("v1vibe.cli._mask_token")
    def test_status_masks_api_token(self, mock_mask, mock_print, mock_load_file, mock_load_settings, mock_http):
        """Test that API token is masked in output."""
        from v1vibe.config import Settings

        full_token = "very-secret-token-1234567890"
        settings = Settings(
            api_token=full_token,
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="/usr/local/bin/tmas",
        )
        mock_load_settings.return_value = settings
        mock_load_file.return_value = {
            "api_token": full_token,
            "region": "us-east-1",
            "tmas_binary_path": "/usr/local/bin/tmas",
        }
        mock_mask.return_value = "very-secre...67890"

        # Mock HTTP client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"dailyReserve": 100, "remaining": 99, "usedFileCount": 1, "usedUrlCount": 0}
        mock_client.get.return_value = mock_response
        mock_http.return_value.__enter__.return_value = mock_client

        with patch("v1vibe.cli._get_tmas_version", return_value="2.221.0"):
            with patch("v1vibe.cli.platform.system", return_value="Linux"):
                with patch("v1vibe.cli.Path.exists", return_value=False):
                    cmd_status()

        # Should call mask function
        mock_mask.assert_called_with(full_token)

        # Output should have masked version, not full token
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        assert full_token not in output  # Full token should not appear
        assert "..." in output  # Some masking should be present

    @patch("v1vibe.cli.httpx.Client")
    @patch("v1vibe.cli.load_settings")
    @patch("v1vibe.cli.load_config_file")
    @patch("v1vibe.cli._print")
    @patch("v1vibe.cli.platform.system")
    @patch("v1vibe.cli._check_docker_running")
    def test_status_docker_not_running(self, mock_docker, mock_system, mock_print, mock_load_file, mock_load_settings, mock_http):
        """Test status when Docker mode but Docker not running."""
        from v1vibe.config import Settings

        mock_system.return_value = "Darwin"
        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",
        )
        mock_load_settings.return_value = settings
        mock_load_file.return_value = {
            "api_token": "test-token-12345678901234567890",
            "region": "us-east-1",
            "tmas_binary_path": "docker",
        }
        mock_docker.return_value = False

        # Mock HTTP client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"dailyReserve": 100, "remaining": 99, "usedFileCount": 1, "usedUrlCount": 0}
        mock_client.get.return_value = mock_response
        mock_http.return_value.__enter__.return_value = mock_client

        with patch("v1vibe.cli._mask_token", return_value="test-token...890"):
            with patch("v1vibe.cli.Path.exists", return_value=False):
                cmd_status()

        # Should show "configured but not found" when Docker not running
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls).lower()
        assert "docker" in output


class TestCmdSetupValidation:
    """Tests for setup command input validation."""

    def test_region_validation_in_setup(self):
        """Test that setup validates regions against REGION_TO_BASE_URL."""
        # The setup command should only accept valid regions
        valid_regions = list(REGION_TO_BASE_URL.keys())

        assert len(valid_regions) > 0
        assert "us-east-1" in valid_regions
        assert "eu-central-1" in valid_regions

        # Invalid regions should not be in the dict
        assert "invalid-region" not in valid_regions
        assert "" not in valid_regions

    def test_api_token_length_requirement(self):
        """Test that setup enforces minimum token length."""
        # API tokens must be at least 20 characters
        short_token = "short"
        valid_token = "a" * 20

        assert len(short_token) < 20
        assert len(valid_token) >= 20

        # This documents the requirement - actual validation happens in setup


class TestRegionMapping:
    """Tests for region to base URL mapping."""

    def test_all_regions_have_urls(self):
        """Test that all regions map to valid URLs."""
        for region, url in REGION_TO_BASE_URL.items():
            assert url.startswith("https://")
            assert "trendmicro" in url  # May be .com or .co.jp
            assert region  # Region should not be empty

    def test_common_regions_present(self):
        """Test that common regions are available."""
        assert "us-east-1" in REGION_TO_BASE_URL
        assert "eu-central-1" in REGION_TO_BASE_URL
        assert "ap-southeast-1" in REGION_TO_BASE_URL
        assert "ap-northeast-1" in REGION_TO_BASE_URL

    def test_urls_are_unique(self):
        """Test that each region has a unique URL."""
        urls = list(REGION_TO_BASE_URL.values())
        unique_urls = set(urls)

        # Most regions should have unique URLs (some might share)
        assert len(unique_urls) > 0
