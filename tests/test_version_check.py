"""Tests for SDK version compatibility checking."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from v1vibe.version_check import (
    check_file_security_compatibility,
    check_package_version,
    parse_version,
)


class TestParseVersion:
    """Test version string parsing."""

    def test_parse_standard_version(self):
        """Parse standard semver."""
        assert parse_version("1.4.4") == (1, 4, 4)

    def test_parse_version_three_parts(self):
        """Parse version with three parts."""
        assert parse_version("1.75.1") == (1, 75, 1)


class TestCheckPackageVersion:
    """Test individual package version checking."""

    def test_check_compatible_version(self):
        """Package version meets minimum."""
        with patch("v1vibe.version_check.version", return_value="1.75.1"):
            result = check_package_version("grpcio", "1.71.0")

        assert result.package == "grpcio"
        assert result.installed == "1.75.1"
        assert result.minimum == "1.71.0"
        assert result.compatible is True

    def test_check_incompatible_version(self):
        """Package version below minimum."""
        with patch("v1vibe.version_check.version", return_value="1.71.2"):
            result = check_package_version("grpcio", "1.75.1")

        assert result.installed == "1.71.2"
        assert result.minimum == "1.75.1"
        assert result.compatible is False

    def test_check_exact_minimum_version(self):
        """Package version exactly matches minimum."""
        with patch("v1vibe.version_check.version", return_value="1.75.1"):
            result = check_package_version("grpcio", "1.75.1")

        assert result.compatible is True

    def test_check_package_not_installed(self):
        """Package not installed."""
        from importlib.metadata import PackageNotFoundError

        with patch("v1vibe.version_check.version", side_effect=PackageNotFoundError("grpcio")):
            result = check_package_version("grpcio", "1.75.1")

        assert result.installed is None
        assert result.compatible is False


class TestCheckFileSecurityCompatibility:
    """Test File Security SDK compatibility checking."""

    def test_all_compatible(self):
        """All packages meet minimum versions."""
        with patch("v1vibe.version_check.version") as mock_version:
            mock_version.side_effect = lambda pkg: {
                "visionone-filesecurity": "1.4.4",
                "grpcio": "1.75.1",
                "protobuf": "5.29.0",
            }[pkg]

            compatible, results = check_file_security_compatibility()

        assert compatible is True
        assert len(results) == 3
        assert all(r.compatible for r in results)

    def test_grpcio_incompatible(self):
        """grpcio version too old (Python 3.14 scenario)."""
        with patch("v1vibe.version_check.version") as mock_version:
            mock_version.side_effect = lambda pkg: {
                "visionone-filesecurity": "1.4.4",
                "grpcio": "1.71.2",  # Too old for Python 3.14
                "protobuf": "4.25.3",  # Also too old
            }[pkg]

            compatible, results = check_file_security_compatibility()

        assert compatible is False
        assert len(results) == 3

        # Check individual results
        fs_result = results[0]
        assert fs_result.package == "visionone-filesecurity"
        assert fs_result.compatible is True

        grpc_result = results[1]
        assert grpc_result.package == "grpcio"
        assert grpc_result.compatible is False

        protobuf_result = results[2]
        assert protobuf_result.package == "protobuf"
        assert protobuf_result.compatible is False

    def test_filesecurity_not_installed(self):
        """File Security SDK not installed at all."""
        from importlib.metadata import PackageNotFoundError

        with patch("v1vibe.version_check.version", side_effect=PackageNotFoundError("visionone-filesecurity")):
            compatible, results = check_file_security_compatibility()

        assert compatible is False
        assert len(results) == 1  # Only File Security checked
        assert results[0].installed is None
