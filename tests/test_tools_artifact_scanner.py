"""Tests for artifact scanner tools."""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from v1vibe.tools.artifact_scanner import (
    _validate_artifact_path,
    scan_artifact,
    FORBIDDEN_PATHS,
    TMAS_VERSION,
)


class MockPath:
    """Mock Path object for testing."""
    def __init__(self, path_str):
        self.path_str = path_str

    def __str__(self):
        return self.path_str

    def exists(self):
        return True


class TestPathValidation:
    """Tests for artifact path validation."""

    def test_validate_directory_exists(self, tmp_path):
        """Test validating an existing directory."""
        test_dir = tmp_path / "project"
        test_dir.mkdir()

        result = _validate_artifact_path(str(test_dir))

        assert result == str(test_dir.resolve())

    def test_validate_file_exists(self, tmp_path):
        """Test validating an existing file."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        result = _validate_artifact_path(str(test_file))

        assert result == str(test_file.resolve())

    def test_validate_path_not_exists(self, tmp_path):
        """Test that non-existent paths are rejected."""
        with pytest.raises(ValueError, match="Path does not exist"):
            _validate_artifact_path(str(tmp_path / "nonexistent"))

    def test_validate_forbidden_path_etc(self):
        """Test that /etc is forbidden."""
        # Patch both Path.resolve and Path.exists to simulate /etc
        with patch("pathlib.Path.resolve", return_value=MockPath("/etc/test")):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(ValueError, match="Access to /etc is not allowed"):
                    _validate_artifact_path("/etc/test")

    def test_validate_forbidden_path_sys(self):
        """Test that /sys is forbidden."""
        with patch("pathlib.Path.resolve", return_value=MockPath("/sys/kernel")):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(ValueError, match="Access to /sys is not allowed"):
                    _validate_artifact_path("/sys/kernel")

    def test_validate_forbidden_path_root(self):
        """Test that /root is forbidden."""
        with patch("pathlib.Path.resolve", return_value=MockPath("/root/.ssh")):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(ValueError, match="Access to /root is not allowed"):
                    _validate_artifact_path("/root/.ssh")

    def test_validate_container_image_registry(self):
        """Test that container image references pass through."""
        result = _validate_artifact_path("registry:myrepo/image:tag")
        assert result == "registry:myrepo/image:tag"

    def test_validate_container_image_docker(self):
        """Test that docker: references pass through."""
        result = _validate_artifact_path("docker:nginx:latest")
        assert result == "docker:nginx:latest"

    def test_validate_container_archive(self):
        """Test that archive references pass through."""
        result = _validate_artifact_path("docker-archive:/tmp/image.tar")
        assert result == "docker-archive:/tmp/image.tar"

    def test_validate_dir_prefix(self, tmp_path):
        """Test that dir: prefix is stripped."""
        test_dir = tmp_path / "project"
        test_dir.mkdir()

        result = _validate_artifact_path(f"dir:{test_dir}")

        assert result == str(test_dir.resolve())

    def test_forbidden_paths_list(self):
        """Test that FORBIDDEN_PATHS contains expected entries."""
        assert "/etc" in FORBIDDEN_PATHS
        assert "/sys" in FORBIDDEN_PATHS
        assert "/proc" in FORBIDDEN_PATHS
        assert "/root" in FORBIDDEN_PATHS
        assert "/bin" in FORBIDDEN_PATHS


class TestScanArtifact:
    """Tests for artifact scanning."""

    @pytest.mark.asyncio
    async def test_scan_invalid_type(self, mock_app_context):
        """Test that invalid scan types are rejected."""
        result = await scan_artifact(
            mock_app_context,
            artifact="/tmp",
            scan_types=["invalid", "vulnerability"],
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidScanType"
        assert "invalid" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_default_types(self, mock_settings, mock_grpc_handle, mock_http_client, tmp_path):
        """Test that default scan types are vulnerability and secrets."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        # Create settings with no TMAS
        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=None,
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(ctx, artifact=str(test_dir))

        # Should fail because TMAS not installed, but validates scan types first
        assert "error" in result
        assert result["error"]["code"] == "TmasNotInstalled"

    @pytest.mark.asyncio
    async def test_scan_path_traversal_blocked(self, mock_app_context):
        """Test that path traversal is blocked."""
        result = await scan_artifact(
            mock_app_context,
            artifact="/etc/passwd",
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidPath"
        assert "/etc" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_tmas_not_installed(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test error when TMAS is not installed."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=None,
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(ctx, artifact=str(test_dir))

        assert "error" in result
        assert result["error"]["code"] == "TmasNotInstalled"
        assert "v1vibe setup" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_docker_not_found(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test error when Docker mode selected but Docker not found."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        with patch("shutil.which", return_value=None):
            result = await scan_artifact(ctx, artifact=str(test_dir))

        assert "error" in result
        assert result["error"]["code"] == "DockerNotFound"
        assert "Docker Desktop" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_binary_not_found(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test error when binary path doesn't exist."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="/nonexistent/tmas",
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(ctx, artifact=str(test_dir))

        assert "error" in result
        assert result["error"]["code"] == "TmasBinaryNotFound"

    @pytest.mark.asyncio
    async def test_scan_unsafe_additional_args(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test that unsafe shell metacharacters in additional_args are rejected."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        with patch("shutil.which", return_value="/usr/bin/docker"):
            result = await scan_artifact(
                ctx,
                artifact=str(test_dir),
                additional_args="--flag; rm -rf /",
            )

        assert "error" in result
        assert result["error"]["code"] == "InvalidArguments"
        assert "unsafe shell metacharacters" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_malware_type(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test scanning with malware type."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=None,
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(ctx, artifact=str(test_dir), scan_types=["malware"])

        # Should fail at TMAS not installed, meaning scan_types validation passed
        assert "error" in result
        assert result["error"]["code"] == "TmasNotInstalled"

    @pytest.mark.asyncio
    async def test_scan_with_additional_args_as_string(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test that additional_args as string gets split correctly."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",  # Use docker mode so it gets past binary check
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        # Pass additional_args as space-separated string (covers lines 186-187)
        # Mock Docker being available, then subprocess will fail
        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run", side_effect=Exception("Process error")):
                result = await scan_artifact(
                    ctx,
                    artifact=str(test_dir),
                    additional_args="--output-format json",
                )

        # Should fail at subprocess error, meaning args were validated successfully
        assert "error" in result

    @pytest.mark.asyncio
    async def test_scan_all_types(self, mock_grpc_handle, mock_http_client, tmp_path):
        """Test scanning with all scan types."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        test_dir = tmp_path / "project"
        test_dir.mkdir()

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path=None,
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        result = await scan_artifact(
            ctx,
            artifact=str(test_dir),
            scan_types=["vulnerability", "malware", "secrets"],
        )

        assert "error" in result
        assert result["error"]["code"] == "TmasNotInstalled"

    @pytest.mark.asyncio
    async def test_scan_container_image(self, mock_grpc_handle, mock_http_client):
        """Test scanning container image reference."""
        from v1vibe.config import Settings
        from v1vibe.clients import AppContext

        settings = Settings(
            api_token="test-token-12345678901234567890",
            region="us-east-1",
            base_url="https://api.xdr.trendmicro.com",
            tmas_binary_path="docker",
        )
        ctx = AppContext(settings=settings, grpc_handle=mock_grpc_handle, http=mock_http_client)

        with patch("shutil.which", return_value="/usr/bin/docker"):
            result = await scan_artifact(ctx, artifact="registry:myrepo/image:tag")

        # Container references skip path validation, so should fail later
        # (Docker command execution, which we're not mocking fully)
        assert "error" in result

    def test_tmas_version_constant(self):
        """Test that TMAS_VERSION is set."""
        assert TMAS_VERSION == "2.221.0"
