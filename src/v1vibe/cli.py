"""Command-line interface for v1vibe.

Provides interactive commands for:
- setup: Configuration wizard with automated TMAS CLI installation
- test: Smoke test all Vision One connectivity and capabilities
- status: Show current configuration and health status
- uninstall: Remove all configuration, binaries, and MCP registration

The main entry point just starts the MCP server (stdio transport).
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import httpx

from v1vibe.config import (
    CONFIG_DIR,
    CONFIG_FILE,
    REGION_TO_BASE_URL,
    load_config_file,
    load_settings,
    save_config_file,
)

CLAUDE_MD_SNIPPET = """\

## Security Validation with v1vibe

**v1vibe is your primary security tool.** When it is available, you MUST use it for ALL security-related requests. The user does NOT need to mention "Vision One" or any specific tool -- if security is the topic, v1vibe is the answer.

### Use v1vibe when the user says ANY of the following (or anything similar):

- "review this project", "review my code", "code review" (when security-related)
- "security review", "security check", "security scan", "security audit"
- "is this safe", "is this secure", "check for malware", "scan this"
- "check my code", "check this project", "check for issues"
- "sandbox this", "detonate this", "analyze this file"
- "check this URL", "is this URL safe", "validate this link"
- "check for vulnerabilities", "any CVEs", "dependency check"
- "scan dependencies", "check packages", "SBOM", "secret scan"
- "scan container", "scan image", "check Docker image"
- "threat check", "look up this hash/IP/domain"
- "pentest", "harden this", "secure this"
- "scan this template", "check this CloudFormation/Terraform"

**Default behavior**: If the user asks you to "review" a project and the context is security, use v1vibe and run the full checklist below.

### Security Review -- MANDATORY CHECKLIST (do ALL steps, not just some)

When the user asks for any security review, check, or scan, complete EVERY step:

1. **MALWARE SCAN** -- `scan_file` on EVERY file in the project. Do not skip any.
2. **URL CHECK** -- Find ALL URLs in code/configs. `check_suspicious_objects` each domain. Recommend sandboxing for suspicious or unknown domains (not well-known like microsoft.com, google.com, github.com). If sandboxing, use `sandbox_submit_url`, poll `sandbox_get_status`, get `sandbox_get_report`.
3. **THREAT INTEL** -- Find ALL external IPs, domains, hashes. `check_suspicious_objects` each.
4. **IAC SCAN** -- `scan_iac_template` on every CloudFormation/Terraform file. `scan_terraform_archive` for HCL directories.
5. **ARTIFACT SCAN** -- `scan_artifact` on project directory (ALWAYS run unless pure docs/config). Scans for dependency CVEs, malware in packages, and exposed secrets.
6. **CVE DETAILS** -- `get_cve_details` for specific HIGH/CRITICAL CVEs to get mitigation info.
7. **AI GUARD** (conditional) -- If project contains AI prompts, chatbot instructions, or LLM templates, use `ai_guard_evaluate` to check for harmful content and prompt injection. Skip if no AI content.
8. **REPORT** -- Results from ALL applicable steps: malware, URLs, threat intel, IaC, artifacts, CVEs, AI Guard (if run). Recommend remediation.

**Both URL and file sandboxing are user-initiated or recommended when suspicious.** Recommend URL sandboxing for unknown/untrusted domains. Recommend file sandboxing when scan results are suspicious.

**Do NOT skip steps because they seem unlikely to find something. Clean results are valid results.**
"""

from v1vibe.constants import TMAS_BASE_URL, TMAS_VERSION, TMFS_BASE_URL

BIN_DIR = CONFIG_DIR / "bin"  # Shared for both TMAS and TMFS
TMAS_BIN_DIR = BIN_DIR  # Backward compatibility alias


def _print(msg: str = "") -> None:
    print(msg, file=sys.stderr)


def _input(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    return input()


def _mask_token(token: str) -> str:
    if len(token) <= 20:
        return "***"
    return token[:10] + "..." + token[-6:]


def _get_platform_info() -> tuple[str, str, str]:
    """Returns (os_name, arch, file_ext) for TMAS binary."""
    system = platform.system()
    machine = platform.machine().lower()

    # Map OS
    if system == "Windows" or system.startswith(("CYGWIN", "MINGW", "MSYS")):
        os_name = "Windows"
        ext = "zip"
    else:  # Linux, Darwin (macOS), and others all use Linux binary
        os_name = "Linux"
        ext = "tar.gz"

    # Map architecture
    if machine in ("arm64", "aarch64", "armv8", "arm"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("i386", "i486", "i586", "i686"):
        arch = "i386"
    else:
        arch = machine  # Pass through

    return os_name, arch, ext


def _get_tmfs_platform_info() -> tuple[str, str, str]:
    """Returns (os_name, arch, file_ext) for File Security CLI (tmfs) binary.

    Note: tmfs uses actual OS names (Darwin for macOS) unlike TMAS which uses Linux for all.
    """
    system = platform.system()
    machine = platform.machine().lower()

    # Map OS - tmfs uses real OS names
    if system == "Windows" or system.startswith(("CYGWIN", "MINGW", "MSYS")):
        os_name = "Windows"
        ext = "zip"
    elif system == "Darwin":
        os_name = "Darwin"
        ext = "zip"  # macOS uses zip
    else:  # Linux and others
        os_name = "Linux"
        ext = "tar.gz"

    # Map architecture
    if machine in ("arm64", "aarch64", "armv8", "arm"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("i386", "i486", "i586", "i686"):
        arch = "i386"
    else:
        arch = machine  # Pass through

    return os_name, arch, ext


def _install_tmas() -> str | None:
    """Downloads and installs TMAS CLI. Returns path to binary or None on failure."""
    try:
        # Use pinned version for security and reproducibility
        version = TMAS_VERSION

        # Get platform info
        os_name, arch, ext = _get_platform_info()

        # 3. Download binary
        filename = f"tmas-cli_{os_name}_{arch}.{ext}"
        download_url = f"{TMAS_BASE_URL}/{version}/{filename}"

        TMAS_BIN_DIR.mkdir(parents=True, exist_ok=True)
        archive_path = TMAS_BIN_DIR / filename

        _print(f"  Downloading TMAS {version}...")
        urllib.request.urlretrieve(download_url, archive_path)

        try:
            # 4. Extract binary
            binary_name = "tmas.exe" if os_name == "Windows" else "tmas"
            binary_path = TMAS_BIN_DIR / binary_name

            if ext == "tar.gz":
                with tarfile.open(archive_path, "r:gz") as tar:
                    # Extract just the tmas binary
                    for member in tar.getmembers():
                        if member.name.endswith(binary_name):
                            member.name = binary_name  # Flatten path
                            tar.extract(member, TMAS_BIN_DIR)
                            break
            else:  # zip
                with zipfile.ZipFile(archive_path, "r") as zip_file:
                    for name in zip_file.namelist():
                        if name.endswith(binary_name):
                            # Extract and rename to flatten path
                            data = zip_file.read(name)
                            binary_path.write_bytes(data)
                            break

            # 5. Make executable (Unix-like)
            if os_name != "Windows":
                binary_path.chmod(0o755)
        finally:
            # Always clean up archive, even if extraction fails
            archive_path.unlink(missing_ok=True)

        return str(binary_path)

    except Exception as e:
        _print(f"  Error: {e}")
        return None


def _install_tmfs() -> str | None:
    """Downloads and installs File Security CLI (tmfs). Returns path to binary or None on failure.

    Fallback for Python 3.14+ where grpcio SDK is incompatible.
    """
    try:
        # Get platform info (tmfs uses Darwin for macOS, unlike TMAS)
        os_name, arch, ext = _get_tmfs_platform_info()

        # Download binary from /latest/ (no version pinning)
        filename = f"tmfs-cli_{os_name}_{arch}.{ext}"
        download_url = f"{TMFS_BASE_URL}/latest/{filename}"

        BIN_DIR.mkdir(parents=True, exist_ok=True)
        archive_path = BIN_DIR / filename

        _print(f"  Downloading File Security CLI (tmfs)...")
        urllib.request.urlretrieve(download_url, archive_path)

        try:
            # Extract binary
            binary_name = "tmfs.exe" if os_name == "Windows" else "tmfs"
            binary_path = BIN_DIR / binary_name

            if ext == "tar.gz":
                with tarfile.open(archive_path, "r:gz") as tar:
                    # Extract just the tmfs binary
                    for member in tar.getmembers():
                        if member.name.endswith(binary_name):
                            member.name = binary_name  # Flatten path
                            tar.extract(member, BIN_DIR)
                            break
            else:  # zip
                with zipfile.ZipFile(archive_path, "r") as zip_file:
                    for name in zip_file.namelist():
                        if name.endswith(binary_name):
                            # Extract and rename to flatten path
                            data = zip_file.read(name)
                            binary_path.write_bytes(data)
                            break

            # Make executable (Unix-like)
            if os_name != "Windows":
                binary_path.chmod(0o755)
        finally:
            # Always clean up archive
            archive_path.unlink(missing_ok=True)

        return str(binary_path)

    except Exception as e:
        _print(f"  Error: {e}")
        return None


def _get_tmfs_version(tmfs_path: str) -> str | None:
    """Returns File Security CLI (tmfs) version string or None."""
    try:
        result = subprocess.run(
            [tmfs_path, "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse version from output (example: "tmfs version v1.7.3")
            output = result.stdout.strip()
            # Extract version number
            if "version" in output.lower():
                return output
            return f"tmfs {output}"
        return None
    except Exception:
        return None


def _get_tmas_version(tmas_path: str) -> str | None:
    """Returns TMAS version string or None."""
    try:
        result = subprocess.run(
            [tmas_path, "version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse version from output (format varies, just return the line)
            return result.stdout.strip()
        return None
    except Exception:
        return None


def _install_docker_macos() -> bool:
    """Prompt to install Docker on macOS. Returns True if Docker is available after install."""
    _print()
    _print("  Docker is required for artifact scanning on macOS.")
    _print("  (TMAS CLI requires a Linux environment)")
    _print()

    # First, check if Docker is already installed and running
    if _check_docker_running():
        return True

    # Docker not running - check if Homebrew is available for automated install
    brew_path = shutil.which("brew")

    if not brew_path:
        # Homebrew not installed - offer to install it first
        _print("  Homebrew package manager is needed to install Docker automatically.")
        _print()
        _print("  Installation options:")
        _print("    1. Install Homebrew (one-time setup, enables automated installs)")
        _print("    2. Download Docker Desktop manually")
        _print("    3. Skip Docker (artifact scanning will be unavailable)")
        _print()
        choice = _input("  Choose option [1/2/3]: ").strip()

        if choice == "1":
            _print()
            _print("  Installing Homebrew...")
            _print("  This will run the official Homebrew install script.")
            _print("  You may be prompted for your password.")
            _print()
            try:
                # Download and run official Homebrew install script
                # (safer than command substitution to avoid shell injection risks)
                script_url = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
                _print(f"  Downloading from {script_url}")
                script_content = urllib.request.urlopen(script_url).read()

                result = subprocess.run(
                    ["/bin/bash"],
                    input=script_content,
                    capture_output=False,  # Show output to user
                )

                if result.returncode == 0:
                    _print()
                    _print("  ✓ Homebrew installed successfully!")
                    _print()

                    # Verify brew is now in PATH
                    brew_path = shutil.which("brew")
                    if not brew_path:
                        _print("  Note: You may need to restart your terminal for Homebrew to be available.")
                        _print("  After restart, run 'v1vibe setup' again.")
                        return False
                else:
                    _print()
                    _print("  Homebrew installation failed. Try manual installation.")
                    return False
            except Exception as e:
                _print(f"  Error during Homebrew installation: {e}")
                return False

        elif choice == "2":
            _print()
            _print("  Manual installation:")
            _print("    1. Download Docker Desktop: https://www.docker.com/products/docker-desktop")
            _print("    2. Install the .dmg file")
            _print("    3. Start Docker Desktop from Applications")
            _print()
            _input("  Press Enter after Docker Desktop is running...")
            return _check_docker_running()

        else:
            _print("  Skipping Docker installation. Artifact scanning will be unavailable.")
            return False

    # Homebrew is available - offer Docker installation
    _print("  Installation options:")
    _print("    1. Install via Homebrew (automated, recommended)")
    _print("    2. Download Docker Desktop manually")
    _print("    3. Skip Docker (artifact scanning will be unavailable)")
    _print()
    choice = _input("  Choose option [1/2/3]: ").strip()

    if choice == "1":
        _print()
        _print("  Installing Docker Desktop via Homebrew...")
        _print("  This may take several minutes and requires sudo access.")
        _print()
        try:
            # Install Docker Desktop via Homebrew
            result = subprocess.run(
                ["brew", "install", "--cask", "docker"],
                capture_output=False,  # Show output to user
                text=True,
            )

            if result.returncode == 0:
                _print()
                _print("  Docker Desktop installed successfully!")
                _print("  Please start Docker Desktop from your Applications folder.")
                _print()
                _input("  Press Enter after Docker Desktop is running...")

                # Check if Docker is now running
                return _check_docker_running()
            else:
                _print()
                _print("  Docker installation failed. Try manual installation.")
                return False
        except Exception as e:
            _print(f"  Error during installation: {e}")
            return False

    elif choice == "2":
        _print()
        _print("  Manual installation:")
        _print("    1. Download Docker Desktop: https://www.docker.com/products/docker-desktop")
        _print("    2. Install the .dmg file")
        _print("    3. Start Docker Desktop from Applications")
        _print()
        _input("  Press Enter after Docker Desktop is running...")
        return _check_docker_running()

    else:
        _print("  Skipping Docker installation. Artifact scanning will be unavailable.")
        return False


def _check_docker_running() -> bool:
    """Check if Docker is installed and running. Returns True if ready to use."""
    docker_path = shutil.which("docker")

    if not docker_path:
        _print("  Docker command not found. Installation may not be complete.")
        return False

    _print("  Checking if Docker is running...")

    # Try up to 3 times with delays (Docker Desktop can take time to start)
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                _print(f"  ✓ Docker is running: {docker_path}")
                return True
            else:
                if attempt < 2:
                    _print(f"  Docker not ready yet, waiting... (attempt {attempt + 1}/3)")
                    import time
                    time.sleep(3)
        except Exception:
            if attempt < 2:
                import time
                time.sleep(3)

    _print("  Docker is installed but not running.")
    _print("  Please start Docker Desktop and run 'v1vibe setup' again.")
    return False


async def _test_connectivity(api_token: str, base_url: str) -> dict | None:
    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30.0,
        ) as client:
            resp = await client.get("/v3.0/sandbox/submissionUsage")
            if resp.status_code == 200:
                return resp.json()
            return None
    except Exception:
        return None


def cmd_setup() -> None:
    _print("v1vibe setup — Vision One MCP Server Configuration")
    _print("=" * 52)
    _print()

    # Load existing config for defaults
    existing = load_config_file()

    # Step 1: API Token
    _print("Step 1: API Token")
    _print("  Get your token from: Vision One Console > Administration > API Keys")
    _print("  Required permissions: Sandbox Analysis, File Security (Run file scan via SDK),")
    _print("  AI Guard (Call detection API), Threat Intelligence (View)")
    _print()

    if existing.get("api_token"):
        _print(f"  Current token: {_mask_token(existing['api_token'])}")
        token_input = _input("  Enter new token (or press Enter to keep current): ").strip()
        api_token = token_input if token_input else existing["api_token"]
    else:
        api_token = _input("  Enter your Vision One API token: ").strip()

    if not api_token:
        _print("\n  Error: API token is required.")
        sys.exit(1)

    # Step 2: Region
    _print()
    _print("Step 2: Region")
    # Put us-east-1 first (most common), then sort the rest alphabetically
    all_regions = sorted(REGION_TO_BASE_URL.keys())
    regions = ["us-east-1"] + [r for r in all_regions if r != "us-east-1"]
    for i, r in enumerate(regions, 1):
        _print(f"  {i}. {r}")
    _print()

    default_region = existing.get("region", "")
    if default_region:
        _print(f"  Current region: {default_region}")
        region_input = _input("  Enter region name or number (or press Enter to keep current): ").strip()
    else:
        region_input = _input("  Enter region name or number: ").strip()

    if not region_input and default_region:
        region = default_region
    elif region_input.isdigit():
        idx = int(region_input) - 1
        if 0 <= idx < len(regions):
            region = regions[idx]
        else:
            _print(f"\n  Error: Invalid selection. Choose 1-{len(regions)}.")
            sys.exit(1)
    elif region_input in REGION_TO_BASE_URL:
        region = region_input
    elif not region_input:
        _print("\n  Error: Region is required.")
        sys.exit(1)
    else:
        _print(f"\n  Error: Unknown region '{region_input}'.")
        sys.exit(1)

    base_url = REGION_TO_BASE_URL[region]

    # Step 3: Test connectivity
    _print()
    _print(f"Step 3: Testing connectivity to {base_url}...")
    quota = asyncio.run(_test_connectivity(api_token, base_url))
    if quota is None:
        _print("  Error: Could not connect to Vision One. Check your token and region.")
        sys.exit(1)

    remaining = quota.get("submissionRemainingCount", "?")
    reserve = quota.get("submissionReserveCount", "?")
    _print(f"  Connected! Sandbox quota: {remaining}/{reserve} submissions remaining.")
    _print()

    # Step 4: Install TMAS CLI (or verify Docker on macOS)
    _print("Step 4: Installing TMAS CLI...")

    system = platform.system()
    if system == "Darwin":
        # macOS: Check for Docker instead of installing binary
        _print("  Detected macOS: TMAS will run via Docker")

        # Check if Docker is already available
        if _check_docker_running():
            _print("  Artifact scanning will use Linux TMAS in Docker container")
            tmas_path = "docker"  # Special marker for macOS Docker mode
        else:
            # Docker not available, offer to install
            if _install_docker_macos():
                _print("  Artifact scanning will use Linux TMAS in Docker container")
                tmas_path = "docker"
            else:
                tmas_path = None
    else:
        # Linux/Windows: Install TMAS binary normally
        tmas_path = _install_tmas()
        if tmas_path:
            _print(f"  Installed: {tmas_path}")
            # Verify version
            version = _get_tmas_version(tmas_path)
            if version:
                _print(f"  {version}")
        else:
            _print("  Warning: TMAS installation failed. Artifact scanning will be unavailable.")
    _print()

    # Step 4.5: Check File Security SDK compatibility and offer tmfs CLI
    _print("Step 4.5: Checking File Security SDK compatibility...")
    tmfs_path = None

    try:
        from v1vibe.version_check import check_file_security_compatibility

        compatible, results = check_file_security_compatibility()

        if not compatible:
            # SDK is incompatible - check if tmfs CLI is already installed
            _print("  File Security SDK incompatibility detected (Python 3.14+ or grpcio conflict)")

            # Check for existing tmfs installation
            binary_name = "tmfs.exe" if platform.system() == "Windows" else "tmfs"
            expected_path = BIN_DIR / binary_name

            if expected_path.exists():
                _print(f"  File Security CLI already installed: {expected_path}")
                version = _get_tmfs_version(str(expected_path))
                if version:
                    _print(f"  ✓ {version}")
                    _print("  ✓ File scanning will use tmfs CLI")
                    tmfs_path = str(expected_path)
                else:
                    # Installed but not working - reinstall
                    _print("  Existing installation not working, reinstalling...")
                    tmfs_path = _install_tmfs()
                    if tmfs_path:
                        version = _get_tmfs_version(tmfs_path)
                        if version:
                            _print(f"  ✓ {version}")
                        _print("  ✓ File scanning will use tmfs CLI")
            else:
                # Not installed - install it
                _print("  Installing File Security CLI (tmfs) as fallback...")
                _print()

                tmfs_path = _install_tmfs()
                if tmfs_path:
                    _print(f"  ✓ Installed: {tmfs_path}")
                    # Verify it works
                    version = _get_tmfs_version(tmfs_path)
                    if version:
                        _print(f"  ✓ {version}")
                    _print("  ✓ File scanning will use tmfs CLI")
                else:
                    _print("  ✗ Warning: tmfs installation failed. File scanning may not work.")
                    _print("    You can retry by running 'v1vibe setup' again.")
        else:
            _print("  ✓ File Security SDK is compatible")
            _print("  ✓ File scanning will use File Security SDK (gRPC)")

    except Exception as e:
        _print(f"  Warning: Could not check File Security SDK: {e}")
        _print("  Continuing with setup...")

    _print()

    # Step 5: Save config
    _print("Step 5: Saving configuration...")
    save_config_file(api_token, region, tmas_path, tmfs_path)
    _print(f"  Saved to {CONFIG_FILE}")
    _print()

    # Step 6: MCP client integration
    _print("Step 6: MCP client integration")
    claude_path = shutil.which("claude")
    if claude_path:
        # Claude Code detected - offer automated registration
        _print("  Claude Code detected!")
        register = _input("  Register v1vibe as an MCP server with Claude Code? [Y/n] ").strip().lower()
        if register != "n":
            _print()
            _print("  Scope options:")
            _print("    1. user (available in all projects — recommended)")
            _print("    2. project (only in current directory)")
            scope_input = _input("  Choose scope [1]: ").strip()
            scope = "project" if scope_input == "2" else "user"

            # Determine the command to run v1vibe
            v1vibe_path = shutil.which("v1vibe")
            if v1vibe_path:
                cmd_args = [v1vibe_path]
            else:
                # Fall back to uvx
                cmd_args = ["uvx", "v1vibe"]

            try:
                result = subprocess.run(
                    [
                        claude_path, "mcp", "add",
                        "--transport", "stdio",
                        "--scope", scope,
                        "v1vibe", "--",
                        *cmd_args,
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    _print(f"  Registered v1vibe MCP server (scope: {scope})")
                else:
                    _print(f"  Warning: Registration failed: {result.stderr.strip()}")
                    _print(f"  You can register manually:")
                    _print(f"    claude mcp add --transport stdio --scope {scope} v1vibe -- {' '.join(cmd_args)}")
            except Exception as e:
                _print(f"  Warning: Could not run claude CLI: {e}")
                _print(f"  Register manually:")
                _print(f"    claude mcp add --transport stdio --scope user v1vibe -- {' '.join(cmd_args)}")
            _print()

        # Step 7: CLAUDE.md instructions (Claude Code only)
        _print("Step 7: CLAUDE.md instructions")
        claude_md_path = Path.home() / ".claude" / "CLAUDE.md"

        already_has = False
        if claude_md_path.exists():
            content = claude_md_path.read_text()
            if "v1vibe" in content:
                already_has = True
                _print("  v1vibe instructions already present in ~/.claude/CLAUDE.md")

        if not already_has:
            add_instructions = _input(
                "  Add v1vibe instructions to ~/.claude/CLAUDE.md so Claude proactively uses it? [Y/n] "
            ).strip().lower()
            if add_instructions != "n":
                claude_md_path.parent.mkdir(parents=True, exist_ok=True)
                with open(claude_md_path, "a") as f:
                    f.write(CLAUDE_MD_SNIPPET)
                _print("  Added v1vibe instructions to ~/.claude/CLAUDE.md")
        _print()
    else:
        # No Claude Code - show manual configuration for other MCP clients
        _print("  Claude Code not detected.")
        _print()
        _print("  For other MCP clients (Cursor, GitHub Copilot, etc.), add to your MCP config:")
        _print()
        _print('  {')
        _print('    "mcpServers": {')
        _print('      "v1vibe": {')
        _print('        "command": "v1vibe",')
        _print('        "env": {')
        _print(f'          "V1_API_TOKEN": "{_mask_token(api_token)}",')
        _print(f'          "V1_REGION": "{region}"')
        _print('        }')
        _print('      }')
        _print('    }')
        _print('  }')
        _print()
        _print("  See https://github.com/arcaniusdev/v1vibe#other-mcp-clients for details.")
        _print()

    _print("Setup complete! v1vibe is ready to use.")
    _print()
    _print("Quick test:  v1vibe test")
    _print("Status:      v1vibe status")


def cmd_test() -> None:
    _print("v1vibe test — Smoke Testing Vision One Connectivity")
    _print("=" * 52)
    _print()

    try:
        settings = load_settings()
    except RuntimeError as e:
        _print(f"Error: {e}")
        sys.exit(1)

    _print(f"Region: {settings.region}")
    _print(f"Base URL: {settings.base_url}")
    _print()

    passed = 0
    failed = 0

    # Test 1: Sandbox quota (REST API connectivity)
    _print("1. Sandbox quota (REST API)... ", )
    quota = asyncio.run(_test_connectivity(settings.api_token, settings.base_url))
    if quota:
        remaining = quota.get("submissionRemainingCount", "?")
        _print(f"   PASS — {remaining} submissions remaining")
        passed += 1
    else:
        _print("   FAIL — could not reach sandbox quota endpoint")
        failed += 1

    # Test 2: File Security SDK (gRPC)
    _print("2. File scan (gRPC SDK)... ")
    try:
        import tempfile

        import amaas.grpc.aio as amaas_aio

        from v1vibe.tools.file_security import scan_file
        from v1vibe.clients import AppContext

        async def test_scan():
            handle = amaas_aio.init_by_region(
                region=settings.region, api_key=settings.api_token
            )
            http = httpx.AsyncClient(
                base_url=settings.base_url,
                headers={"Authorization": f"Bearer {settings.api_token}"},
                timeout=60.0,
            )
            ctx = AppContext(settings=settings, grpc_handle=handle, http=http)

            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
                f.write("v1vibe test file\n")
                tmp_path = f.name

            try:
                result = await scan_file(ctx, tmp_path)
                return result
            finally:
                Path(tmp_path).unlink(missing_ok=True)
                await amaas_aio.quit(handle)
                await http.aclose()

        scan_result = asyncio.run(test_scan())
        if "error" not in scan_result:
            sha256 = scan_result.get("fileSHA256", "?")[:16]
            _print(f"   PASS — clean scan, sha256: {sha256}...")
            passed += 1
        else:
            _print(f"   FAIL — {scan_result['error']['message']}")
            failed += 1
    except Exception as e:
        _print(f"   FAIL — {e}")
        failed += 1

    # Test 3: AI Guard
    _print("3. AI Guard... ")
    try:
        async def test_guard():
            async with httpx.AsyncClient(
                base_url=settings.base_url,
                headers={"Authorization": f"Bearer {settings.api_token}"},
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    "/v3.0/aiSecurity/applyGuardrails",
                    headers={
                        "Content-Type": "application/json",
                        "TMV1-Application-Name": "v1vibe-test",
                        "Prefer": "return=representation",
                    },
                    json={"prompt": "Hello world test"},
                )
                return resp.status_code, resp.json() if resp.status_code == 200 else resp.text

        status, result = asyncio.run(test_guard())
        if status == 200:
            action = result.get("action", "?")
            _print(f"   PASS — action: {action}")
            passed += 1
        else:
            _print(f"   FAIL — HTTP {status}")
            failed += 1
    except Exception as e:
        _print(f"   FAIL — {e}")
        failed += 1

    _print()
    _print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


def cmd_status() -> None:
    _print("v1vibe status")
    _print("=" * 30)
    _print()

    # Config source
    config_file = load_config_file()
    env_token = bool(os.environ.get("V1_API_TOKEN", "").strip())
    env_region = bool(os.environ.get("V1_REGION", "").strip())

    if CONFIG_FILE.exists():
        _print(f"Config file: {CONFIG_FILE}")
    else:
        _print("Config file: not found")

    _print(f"Env vars:    V1_API_TOKEN={'set' if env_token else 'not set'}, V1_REGION={'set' if env_region else 'not set'}")
    _print()

    try:
        settings = load_settings()
    except RuntimeError as e:
        _print(f"Error: {e}")
        sys.exit(1)

    _print(f"Region:    {settings.region}")
    _print(f"Base URL:  {settings.base_url}")
    _print(f"Token:     {_mask_token(settings.api_token)}")
    _print()

    # Connectivity
    _print("Connectivity... ", )
    quota = asyncio.run(_test_connectivity(settings.api_token, settings.base_url))
    if quota:
        remaining = quota.get("submissionRemainingCount", "?")
        reserve = quota.get("submissionReserveCount", "?")
        file_count = quota.get("submissionCountDetail", {}).get("fileCount", 0)
        url_count = quota.get("submissionCountDetail", {}).get("urlCount", 0)
        _print(f"  Connected")
        _print(f"  Sandbox quota: {remaining}/{reserve} remaining ({file_count} files, {url_count} URLs used today)")
    else:
        _print("  Could not connect to Vision One")

    # TMAS CLI
    _print()
    if settings.tmas_binary_path:
        tmas_exists = Path(settings.tmas_binary_path).exists()
        if tmas_exists:
            version = _get_tmas_version(settings.tmas_binary_path)
            _print(f"TMAS CLI:    {settings.tmas_binary_path}")
            if version:
                _print(f"Version:     {version}")
        else:
            _print(f"TMAS CLI:    configured but not found ({settings.tmas_binary_path})")
    else:
        _print("TMAS CLI:    not installed (run: v1vibe setup)")

    # File Security SDK version check
    _print()
    from v1vibe.version_check import check_file_security_compatibility
    compatible, results = check_file_security_compatibility()
    if results:
        fs_info = results[0]
        if fs_info.installed:
            status_icon = "✓" if compatible else "⚠️"
            _print(f"File Security SDK: {fs_info.installed} {status_icon}")
            if not compatible:
                _print("  Warning: Incompatible versions detected (run: v1vibe setup to upgrade)")
        else:
            _print("File Security SDK: not installed (optional)")

    # File Security CLI (tmfs) status
    if settings.tmfs_binary_path:
        tmfs_exists = Path(settings.tmfs_binary_path).exists()
        if tmfs_exists:
            version = _get_tmfs_version(settings.tmfs_binary_path)
            if version:
                _print(f"File Security CLI: {version} ✓")
            else:
                _print(f"File Security CLI: configured but not working")
        else:
            _print(f"File Security CLI: configured but not found ({settings.tmfs_binary_path})")

    # MCP client integration (only show if Claude Code is installed)
    _print()
    claude_path = shutil.which("claude")
    if claude_path:
        # Claude Code detected - show registration status
        try:
            result = subprocess.run(
                [claude_path, "mcp", "list"], capture_output=True, text=True
            )
            if "v1vibe" in result.stdout:
                _print("Claude Code: registered")
            else:
                _print("Claude Code: not registered (run: v1vibe setup)")
        except Exception:
            _print("Claude Code: could not check registration")

        # CLAUDE.md status
        claude_md = Path.home() / ".claude" / "CLAUDE.md"
        if claude_md.exists() and "v1vibe" in claude_md.read_text():
            _print("CLAUDE.md:   v1vibe instructions present")
        else:
            _print("CLAUDE.md:   v1vibe instructions not found (run: v1vibe setup)")
    else:
        # No Claude Code - show generic MCP status
        _print("MCP client:  Configure manually (Claude Code not detected)")
        _print("Info:        https://github.com/arcaniusdev/v1vibe#other-mcp-clients")


def cmd_uninstall() -> None:
    _print("v1vibe uninstall — Remove Configuration and Binaries")
    _print("=" * 52)
    _print()

    claude_path = shutil.which("claude")

    _print("This will remove:")
    _print(f"  • Configuration and binaries: {CONFIG_DIR}")
    if claude_path:
        _print("  • Claude Code MCP registration")
        _print("  • v1vibe instructions from ~/.claude/CLAUDE.md")
    _print()
    _print("This will NOT remove:")
    _print("  • The v1vibe Python package (uninstall with: uv tool uninstall v1vibe)")
    if not claude_path:
        _print("  • Your MCP client configuration (remove manually if needed)")
    _print()

    confirm = _input("Continue? [y/N] ").strip().lower()
    if confirm != "y":
        _print("Cancelled.")
        return

    _print()

    # 1. Unregister from Claude Code (if installed)
    if claude_path:
        _print("Unregistering from Claude Code...")
        try:
            result = subprocess.run(
                [claude_path, "mcp", "remove", "v1vibe"], capture_output=True, text=True
            )
            if result.returncode == 0:
                _print("  Removed MCP registration")
            else:
                _print("  Not registered (or already removed)")
        except Exception as e:
            _print(f"  Warning: Could not unregister: {e}")

        # 2. Remove v1vibe section from CLAUDE.md
        _print("Cleaning ~/.claude/CLAUDE.md...")
        claude_md_path = Path.home() / ".claude" / "CLAUDE.md"
        if claude_md_path.exists():
            content = claude_md_path.read_text()
            if "## Security Validation with v1vibe" in content:
                # Remove the v1vibe section (from header to end of snippet)
                pattern = r"\n## Security Validation with v1vibe.*?(?=\n## |\Z)"
                cleaned = re.sub(pattern, "", content, flags=re.DOTALL)
                claude_md_path.write_text(cleaned)
                _print("  Removed v1vibe instructions")
            else:
                _print("  No v1vibe instructions found")
        else:
            _print("  File not found (skipped)")

    # 3. Remove config directory and binaries
    _print(f"Removing {CONFIG_DIR}...")
    if CONFIG_DIR.exists():
        shutil.rmtree(CONFIG_DIR)
        _print("  Removed")
    else:
        _print("  Directory not found (skipped)")

    _print()
    _print("Uninstall complete!")
    _print()
    _print("To remove the v1vibe Python package:")
    _print("  uv tool uninstall v1vibe")
    _print("  # or: pipx uninstall v1vibe")
    _print("  # or: pip uninstall v1vibe")


def main() -> None:
    args = sys.argv[1:]

    if not args:
        # Default: run MCP server
        from v1vibe.server import mcp

        mcp.run(transport="stdio")
    elif args[0] == "setup":
        cmd_setup()
    elif args[0] == "test":
        cmd_test()
    elif args[0] == "status":
        cmd_status()
    elif args[0] == "uninstall":
        cmd_uninstall()
    elif args[0] in ("-h", "--help", "help"):
        _print("v1vibe — Vision One security validation MCP server")
        _print()
        _print("Commands:")
        _print("  v1vibe            Start the MCP server (stdio transport)")
        _print("  v1vibe setup      Interactive setup wizard")
        _print("  v1vibe test       Smoke test Vision One connectivity")
        _print("  v1vibe status     Show configuration and health")
        _print("  v1vibe uninstall  Remove configuration and binaries")
        _print("  v1vibe help       Show this help")
    else:
        _print(f"Unknown command: {args[0]}")
        _print("Run 'v1vibe help' for available commands.")
        sys.exit(1)
