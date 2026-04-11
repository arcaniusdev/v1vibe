"""Version compatibility checking for File Security SDK and dependencies.

Detects incompatible versions of visionone-filesecurity, grpcio, and protobuf
and offers to upgrade them automatically.
"""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version, PackageNotFoundError
from typing import NamedTuple


class VersionInfo(NamedTuple):
    """Package version information."""
    package: str
    installed: str | None
    minimum: str
    compatible: bool


# Minimum compatible versions - Python version aware
# Python 3.14+ requires grpcio>=1.75.1, but earlier versions work with grpcio>=1.71.0
# When Trend Micro updates visionone-filesecurity to support Python 3.14, this will
# automatically detect it as compatible (no code changes needed).
def get_min_versions() -> dict[str, str]:
    """Get minimum required versions based on current Python version."""
    if sys.version_info >= (3, 14):
        # Python 3.14+ requires newer grpcio/protobuf
        return {
            "visionone-filesecurity": "1.4.0",
            "grpcio": "1.75.1",  # Required for Python 3.14's C API changes
            "protobuf": "5.29.0",  # Required for grpcio 1.75.1+
        }
    else:
        # Python 3.13 and earlier - standard requirements
        return {
            "visionone-filesecurity": "1.4.0",
            "grpcio": "1.71.0",  # Works fine on Python 3.13
            "protobuf": "4.25.0",  # Works fine on Python 3.13
        }


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to tuple for comparison."""
    return tuple(int(x) for x in version_str.split(".")[:3])


def check_package_version(package: str, minimum: str) -> VersionInfo:
    """Check if installed package meets minimum version requirement.

    Args:
        package: Package name
        minimum: Minimum required version string

    Returns:
        VersionInfo with compatibility status
    """
    try:
        installed = version(package)
        compatible = parse_version(installed) >= parse_version(minimum)
        return VersionInfo(package, installed, minimum, compatible)
    except PackageNotFoundError:
        return VersionInfo(package, None, minimum, False)


def check_file_security_compatibility() -> tuple[bool, list[VersionInfo]]:
    """Check File Security SDK and dependencies for compatibility.

    Uses Python-version-aware requirements to avoid false positives on Python 3.13
    while still detecting incompatibility on Python 3.14+.

    Returns:
        Tuple of (all_compatible, list of VersionInfo for each package)
    """
    results = []
    min_versions = get_min_versions()

    # Check File Security SDK first
    fs_info = check_package_version("visionone-filesecurity", min_versions["visionone-filesecurity"])
    results.append(fs_info)

    # Only check dependencies if File Security is installed
    if fs_info.installed:
        results.append(check_package_version("grpcio", min_versions["grpcio"]))
        results.append(check_package_version("protobuf", min_versions["protobuf"]))

    all_compatible = all(info.compatible for info in results)
    return all_compatible, results


def upgrade_file_security() -> bool:
    """Upgrade visionone-filesecurity and dependencies to compatible versions.

    Returns:
        True if upgrade succeeded, False otherwise
    """
    try:
        print("\n  Upgrading File Security SDK and dependencies...")

        # Upgrade visionone-filesecurity which will pull in updated grpcio/protobuf
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "visionone-filesecurity"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            print("  ✓ Upgrade completed successfully!")
            return True
        else:
            print(f"  ✗ Upgrade failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("  ✗ Upgrade timed out after 2 minutes")
        return False
    except Exception as e:
        print(f"  ✗ Upgrade failed: {e}")
        return False


def prompt_upgrade_if_needed() -> bool:
    """Check versions and prompt user to upgrade if incompatible.

    Returns:
        True if File Security is available and compatible (or user declined upgrade),
        False if not available or upgrade failed
    """
    compatible, results = check_file_security_compatibility()

    # If everything is compatible, no action needed
    if compatible:
        return True

    # Show incompatibility report
    print("\n⚠️  File Security SDK Compatibility Issue")
    print("=" * 52)

    has_incompatible = False
    for info in results:
        if info.installed is None:
            print(f"  {info.package}: NOT INSTALLED (required: >={info.minimum})")
        elif not info.compatible:
            print(f"  {info.package}: {info.installed} (required: >={info.minimum}) ❌")
            has_incompatible = True
        else:
            print(f"  {info.package}: {info.installed} ✓")

    print()

    if not has_incompatible and results[0].installed is None:
        # File Security not installed at all - skip
        print("  File Security SDK not installed. Skipping (optional component).")
        return False

    # Prompt for upgrade
    print("  Incompatible versions detected. These may cause crashes on Windows")
    print("  or with newer Python versions.")
    print()
    response = input("  Upgrade to compatible versions? [Y/n]: ").strip().lower()

    if response in ("", "y", "yes"):
        success = upgrade_file_security()
        if success:
            # Verify upgrade worked
            compatible_after, _ = check_file_security_compatibility()
            return compatible_after
        return False
    else:
        print("  Skipping upgrade. File scanning may not work correctly.")
        return False
