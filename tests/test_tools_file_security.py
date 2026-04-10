"""Tests for file security scanning tools."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from v1vibe.tools.file_security import scan_file


class TestFileSecurity:
    """Tests for file security scanning."""

    @pytest.mark.asyncio
    async def test_scan_file_clean(self, mock_app_context, tmp_path):
        """Test scanning a clean file."""
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("clean content")

        # Mock the gRPC scan_file function
        scan_result = {
            "scanResult": 0,
            "foundMalwares": [],
            "fileSHA1": "abc123",
            "fileSHA256": "def456",
        }

        # Import and patch amaas module
        import amaas.grpc.aio as amaas_aio
        original_scan = amaas_aio.scan_file
        amaas_aio.scan_file = AsyncMock(return_value=json.dumps(scan_result))

        try:
            result = await scan_file(
                mock_app_context,
                file_path=str(test_file),
            )

            assert result["scanResult"] == 0
            assert result["foundMalwares"] == []
            assert "fileSHA1" in result
            assert "fileSHA256" in result
        finally:
            # Restore original
            amaas_aio.scan_file = original_scan

    @pytest.mark.asyncio
    async def test_scan_file_malicious(self, mock_app_context, tmp_path):
        """Test scanning a malicious file."""
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"malware content")

        scan_result = {
            "scanResult": 1,
            "foundMalwares": [
                {
                    "malwareName": "Trojan.Generic",
                    "type": "trojan",
                }
            ],
            "fileSHA1": "bad123",
            "fileSHA256": "bad456",
        }

        import amaas.grpc.aio as amaas_aio
        original_scan = amaas_aio.scan_file
        amaas_aio.scan_file = AsyncMock(return_value=json.dumps(scan_result))

        try:
            result = await scan_file(
                mock_app_context,
                file_path=str(test_file),
            )

            assert result["scanResult"] == 1
            assert len(result["foundMalwares"]) == 1
            assert result["foundMalwares"][0]["malwareName"] == "Trojan.Generic"
        finally:
            amaas_aio.scan_file = original_scan

    @pytest.mark.asyncio
    async def test_scan_file_not_found(self, mock_app_context):
        """Test scanning a non-existent file returns error."""
        result = await scan_file(
            mock_app_context,
            file_path="/nonexistent/file.txt",
        )

        assert "error" in result
        assert result["error"]["code"] == "FileNotFound"
        assert "/nonexistent/file.txt" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_file_with_tags(self, mock_app_context, tmp_path):
        """Test scanning with tags."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        scan_result = {
            "scanResult": 0,
            "foundMalwares": [],
            "fileSHA1": "abc",
            "fileSHA256": "def",
        }

        import amaas.grpc.aio as amaas_aio
        original_scan = amaas_aio.scan_file
        amaas_aio.scan_file = AsyncMock(return_value=json.dumps(scan_result))

        try:
            result = await scan_file(
                mock_app_context,
                file_path=str(test_file),
                tags=["test", "ci"],
            )

            assert result["scanResult"] == 0
            # Verify tags were passed to gRPC call
            amaas_aio.scan_file.assert_called_once()
            call_kwargs = amaas_aio.scan_file.call_args[1]
            assert call_kwargs["tags"] == ["test", "ci"]
        finally:
            amaas_aio.scan_file = original_scan

    @pytest.mark.asyncio
    async def test_scan_file_with_pml(self, mock_app_context, tmp_path):
        """Test scanning with PML (Predictive Machine Learning) enabled."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"executable")

        scan_result = {
            "scanResult": 1,
            "foundMalwares": [
                {
                    "malwareName": "PML.Suspicious",
                    "type": "pml",
                }
            ],
            "fileSHA1": "pml123",
            "fileSHA256": "pml456",
        }

        import amaas.grpc.aio as amaas_aio
        original_scan = amaas_aio.scan_file
        amaas_aio.scan_file = AsyncMock(return_value=json.dumps(scan_result))

        try:
            result = await scan_file(
                mock_app_context,
                file_path=str(test_file),
                pml=True,
            )

            assert result["scanResult"] == 1
            # Verify PML was enabled
            call_kwargs = amaas_aio.scan_file.call_args[1]
            assert call_kwargs["pml"] is True
        finally:
            amaas_aio.scan_file = original_scan

    @pytest.mark.asyncio
    async def test_scan_file_grpc_error(self, mock_app_context, tmp_path):
        """Test handling gRPC errors."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        import amaas.grpc.aio as amaas_aio
        original_scan = amaas_aio.scan_file
        amaas_aio.scan_file = AsyncMock(side_effect=Exception("gRPC connection failed"))

        try:
            result = await scan_file(
                mock_app_context,
                file_path=str(test_file),
            )

            assert "error" in result
            assert "code" in result["error"]
            assert "message" in result["error"]
        finally:
            amaas_aio.scan_file = original_scan
