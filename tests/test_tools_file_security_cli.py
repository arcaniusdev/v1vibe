"""Tests for File Security CLI (tmfs) fallback functionality.

Tests the subprocess-based CLI fallback used on Python 3.14+ when
the File Security SDK is incompatible.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from v1vibe.config import Settings
from v1vibe.clients import AppContext
from v1vibe.tools.file_security import scan_file


@pytest.fixture
def mock_app_context_cli(tmp_path: Path) -> AppContext:
    """AppContext with tmfs CLI configured (no SDK)."""
    tmfs_binary = tmp_path / "tmfs"
    tmfs_binary.write_text("#!/bin/bash\necho 'tmfs v1.7.3'")
    tmfs_binary.chmod(0o755)

    settings = Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path=None,
        tmfs_binary_path=str(tmfs_binary),
    )

    # No gRPC handle (SDK unavailable)
    return AppContext(
        settings=settings,
        grpc_handle=None,
        http=MagicMock(),
    )


class TestScanFileCLI:
    """Test _scan_file_cli() subprocess wrapper."""

    @pytest.mark.asyncio
    async def test_scan_file_cli_clean(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI scan returns clean result."""
        test_file = tmp_path / "clean.txt"
        test_file.write_text("This is a clean file")

        cli_output = {
            "scannerVersion": "1.0.0-237",
            "schemaVersion": "1.0.0",
            "scanResult": 0,
            "scanId": "test-scan-id",
            "scanTimestamp": "2026-04-11T12:00:00Z",
            "fileName": str(test_file),
            "foundMalwares": [],
            "fileSHA1": "abc123",
            "fileSHA256": "def456",
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(cli_output)
            mock_run.return_value.stderr = ""

            result = await scan_file(mock_app_context_cli, str(test_file))

        assert result["scanResult"] == 0
        assert result["foundMalwares"] == []
        assert result["fileSHA1"] == "abc123"

        # Verify subprocess was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0][0] == mock_app_context_cli.settings.tmfs_binary_path
        assert call_args[0][0][1] == "scan"
        assert call_args[0][0][2] == f"file:{test_file}"
        assert call_args[0][0][3] == "--region"
        assert call_args[0][0][4] == "us-east-1"

        # Verify TMFS_API_KEY was set
        env = call_args[1]["env"]
        assert env["TMFS_API_KEY"] == "test-token-12345678901234567890"

    @pytest.mark.asyncio
    async def test_scan_file_cli_malware(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI scan detects malware."""
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"EICAR-TEST-FILE")

        cli_output = {
            "scanResult": 1,
            "foundMalwares": [
                {"malwareName": "EICAR_test_file", "fileName": str(test_file)}
            ],
            "fileSHA1": "malware-sha1",
            "fileSHA256": "malware-sha256",
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(cli_output)

            result = await scan_file(mock_app_context_cli, str(test_file))

        assert result["scanResult"] == 1
        assert len(result["foundMalwares"]) == 1
        assert result["foundMalwares"][0]["malwareName"] == "EICAR_test_file"

    @pytest.mark.asyncio
    async def test_scan_file_cli_with_tags(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI scan includes tags."""
        test_file = tmp_path / "tagged.txt"
        test_file.write_text("test")

        cli_output = {"scanResult": 0, "foundMalwares": [], "fileSHA1": "abc", "fileSHA256": "def"}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(cli_output)

            await scan_file(mock_app_context_cli, str(test_file), tags=["test-tag", "security-scan"])

        # Verify tags were passed to CLI
        call_args = mock_run.call_args[0][0]
        assert "--tag" in call_args
        assert "test-tag" in call_args
        assert "security-scan" in call_args

    @pytest.mark.asyncio
    async def test_scan_file_cli_with_pml(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI scan enables PML."""
        test_file = tmp_path / "pml.txt"
        test_file.write_text("test")

        cli_output = {"scanResult": 0, "foundMalwares": [], "fileSHA1": "abc", "fileSHA256": "def"}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(cli_output)

            await scan_file(mock_app_context_cli, str(test_file), pml=True)

        # Verify PML flag was passed
        call_args = mock_run.call_args[0][0]
        assert "--pml" in call_args
        assert "true" in call_args

    @pytest.mark.asyncio
    async def test_scan_file_cli_timeout(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI scan times out."""
        test_file = tmp_path / "timeout.txt"
        test_file.write_text("test")

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tmfs", 120)):
            result = await scan_file(mock_app_context_cli, str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "ScanTimeout"
        assert "timed out" in result["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_scan_file_cli_invalid_json(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI returns invalid JSON."""
        test_file = tmp_path / "json.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "not valid json"

            result = await scan_file(mock_app_context_cli, str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "InvalidCLIOutput"

    @pytest.mark.asyncio
    async def test_scan_file_cli_command_failed(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI command fails with non-zero exit."""
        test_file = tmp_path / "fail.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = "tmfs: error: invalid file"

            result = await scan_file(mock_app_context_cli, str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "CLIScanFailed"
        assert "invalid file" in result["error"]["message"]


class TestScanFileFallback:
    """Test automatic SDK → CLI fallback logic."""

    @pytest.mark.asyncio
    async def test_fallback_sdk_available(self, tmp_path: Path):
        """SDK available - uses SDK (not CLI)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
        )

        mock_grpc_handle = MagicMock()
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=MagicMock())

        sdk_output = {
            "scanResult": 0,
            "foundMalwares": [],
            "fileSHA1": "sdk-sha1",
            "fileSHA256": "sdk-sha256",
        }

        # Mock the SDK scan
        with patch("v1vibe.tools.file_security.amaas_aio") as mock_amaas:
            mock_amaas.scan_file = AsyncMock(return_value=json.dumps(sdk_output))

            result = await scan_file(ctx, str(test_file))

        assert result["scanResult"] == 0
        assert result["fileSHA1"] == "sdk-sha1"

        # Verify SDK was called
        mock_amaas.scan_file.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_cli_when_no_sdk(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """SDK unavailable - falls back to CLI."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        cli_output = {"scanResult": 0, "foundMalwares": [], "fileSHA1": "cli-sha1", "fileSHA256": "cli-sha256"}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(cli_output)

            result = await scan_file(mock_app_context_cli, str(test_file))

        assert result["scanResult"] == 0
        assert result["fileSHA1"] == "cli-sha1"

        # Verify subprocess was called (CLI used)
        mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_neither_available(self, tmp_path: Path):
        """Neither SDK nor CLI available - returns error."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmfs_binary_path=None,  # No CLI configured
        )

        # No SDK, no CLI
        ctx = AppContext(settings=settings, grpc_handle=None, http=MagicMock())

        result = await scan_file(ctx, str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "FileSecurityUnavailable"
        assert "v1vibe setup" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_fallback_cli_not_found(self, tmp_path: Path):
        """CLI path configured but binary doesn't exist."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmfs_binary_path="/nonexistent/tmfs",  # Binary doesn't exist
        )

        ctx = AppContext(settings=settings, grpc_handle=None, http=MagicMock())

        result = await scan_file(ctx, str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "FileSecurityUnavailable"

    @pytest.mark.asyncio
    async def test_file_not_found(self, mock_app_context_cli: AppContext):
        """Scan non-existent file."""
        result = await scan_file(mock_app_context_cli, "/nonexistent/file.txt")

        assert "error" in result
        assert result["error"]["code"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_cli_generic_exception(self, mock_app_context_cli: AppContext, tmp_path: Path):
        """CLI subprocess raises unexpected exception."""
        test_file = tmp_path / "exception.txt"
        test_file.write_text("test")

        with patch("subprocess.run", side_effect=PermissionError("Access denied")):
            result = await scan_file(mock_app_context_cli, str(test_file))

        assert "error" in result
        # Should be formatted by format_error()
        assert "message" in result["error"]
