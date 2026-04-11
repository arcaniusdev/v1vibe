"""Application-wide constants for v1vibe.

Contains version numbers, URLs, and other immutable values used across modules.
"""

# TMAS CLI version - single source of truth for both binary and Docker modes
TMAS_VERSION = "2.221.0"

# Base URL for TMAS CLI downloads
TMAS_BASE_URL = "https://ast-cli.xdr.trendmicro.com/tmas-cli"

# Docker image for TMAS execution (macOS artifact scanning)
TMAS_DOCKER_IMAGE = "ubuntu:22.04"

# File Security CLI configuration
# Provides fallback for Python 3.14+ where grpcio SDK is incompatible.
# Check https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli/metadata.json for latest version
TMFS_BASE_URL = "https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli"
TMFS_METADATA_URL = f"{TMFS_BASE_URL}/metadata.json"
