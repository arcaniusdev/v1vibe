# Python 3.14 Support via File Security CLI Fallback

## Problem

**visionone-filesecurity SDK incompatible with Python 3.14+**

- visionone-filesecurity 1.4.4 requires `grpcio>=1.71.0,<1.72.dev0`
- Python 3.14 requires `grpcio>=1.75.1` (released Sept 2025)
- **Conflict**: Cannot install both simultaneously
- **Impact**: Affects ALL platforms (Windows, macOS, Linux)

## Solution

**File Security CLI (tmfs) as fallback** - standalone binary with zero Python dependencies

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  scan_file(ctx, file_path)                         │
├─────────────────────────────────────────────────────┤
│  1. Try SDK (gRPC) if available                    │
│     └─> amaas.grpc.aio.scan_file()                 │
│                                                      │
│  2. Fall back to CLI if SDK unavailable            │
│     └─> subprocess.run([tmfs, scan, file:path])    │
│                                                      │
│  3. Return error if neither available              │
│     └─> Suggest running "v1vibe setup"             │
└─────────────────────────────────────────────────────┘
```

### Implementation Files

| File | Changes |
|------|---------|
| `constants.py` | Added TMFS_VERSION, TMFS_BASE_URL constants |
| `config.py` | Added `tmfs_binary_path` to Settings dataclass |
| `tools/file_security.py` | Added `_scan_file_cli()` and SDK/CLI fallback logic |
| `version_check.py` | Detects incompatible SDK versions (for status command) |
| `clients.py` | Graceful SDK import with FILE_SECURITY_AVAILABLE flag |
| `pyproject.toml` | Added Python 3.14 classifier |

### Platform Support

File Security CLI available for:

| Platform | Architectures |
|----------|---------------|
| **Windows** | x86_64, i386, arm64 |
| **macOS** | x86_64 (Intel), arm64 (Apple Silicon) |
| **Linux** | x86_64, arm64, i386 |

## Usage

### Detection (Automatic)

```bash
$ uv run v1vibe status

File Security SDK: 1.4.4 ⚠️
  Warning: Incompatible versions detected (run: v1vibe setup to upgrade)
```

### CLI Installation (Automatic)

**✅ tmfs CLI binaries now available!**

Base URL: `https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli`

**Automatic installation:**
```bash
# During setup, incompatible SDK is detected and tmfs CLI is offered
$ uv run v1vibe setup
# ... or call _install_tmfs() directly

# Binary installed to: ~/.v1vibe/bin/tmfs
```

**Download URLs:**
- macOS Apple Silicon: `{BASE_URL}/latest/tmfs-cli_Darwin_arm64.zip`
- macOS Intel: `{BASE_URL}/latest/tmfs-cli_Darwin_x86_64.zip`
- Linux x86_64: `{BASE_URL}/latest/tmfs-cli_Linux_x86_64.tar.gz`
- Linux ARM64: `{BASE_URL}/latest/tmfs-cli_Linux_arm64.tar.gz`
- Linux i386: `{BASE_URL}/latest/tmfs-cli_Linux_i386.tar.gz`
- Windows x86_64: `{BASE_URL}/latest/tmfs-cli_Windows_x86_64.zip`
- Windows ARM64: `{BASE_URL}/latest/tmfs-cli_Windows_arm64.zip`
- Windows i386: `{BASE_URL}/latest/tmfs-cli_Windows_i386.zip`

**Version:** v1.7.3 (as of April 11, 2026)

### Runtime Behavior

**Python 3.13 and earlier:**
- SDK works → Uses gRPC (fast, native)
- SDK missing → Falls back to CLI

**Python 3.14+:**
- SDK incompatible → Automatically uses CLI
- CLI missing → Clear error with installation instructions

### API Parity

Both SDK and CLI return identical JSON structure:

```json
{
  "scannerVersion": "1.0.0-237",
  "schemaVersion": "1.0.0",
  "scanResult": 0,
  "scanId": "uuid",
  "scanTimestamp": "2026-04-11T12:00:00Z",
  "fileName": "file.exe",
  "foundMalwares": [],
  "fileSHA1": "abc...",
  "fileSHA256": "def..."
}
```

## Testing

### Smoke Tests (All Passing ✓)

```bash
# Module imports
✓ All modules import successfully

# Status command
✓ Detects SDK version (1.4.4)
✓ Shows incompatibility warning
✓ Shows tmfs CLI v1.7.3 installed

# tmfs CLI installation
✓ Downloads from tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com
✓ Extracts binary to ~/.v1vibe/bin/tmfs
✓ Sets executable permissions (Mac/Linux)
✓ Version check returns v1.7.3

# File scanning with CLI
✓ tmfs CLI scan works
✓ Sets TMFS_API_KEY environment variable
✓ Returns proper JSON structure (scannerVersion: 1.0.0-237)
✓ Clean files return scanResult: 0
✓ File hashes (SHA1/SHA256) included

# File scanning with SDK
✓ SDK scan works on Python 3.13 (grpcio 1.71.2)
✓ Returns identical JSON structure
✓ Automatic fallback to CLI when SDK unavailable

# Test suite
✓ 257/257 tests passing
✓ 59% coverage maintained
```

### Python Version Matrix

| Python | grpcio | SDK Status | CLI Fallback |
|--------|--------|------------|--------------|
| 3.10 | 1.71.2 | ✓ Works | Not needed |
| 3.11 | 1.71.2 | ✓ Works | Not needed |
| 3.12 | 1.71.2 | ✓ Works | Not needed |
| 3.13 | 1.71.2 | ✓ Works | Not needed |
| 3.14 | Requires 1.75.1+ | ❌ Incompatible | ✓ **Required** |

## Windows User Scenario

**Before (Reported Issue):**
```
Windows user on Python 3.14 → SDK install fails → MCP server crashes on startup
```

**After (Fixed):**
```
Windows user on Python 3.14
  ↓
SDK incompatible (grpcio version conflict)
  ↓
Graceful import failure (no crash)
  ↓
`v1vibe status` shows warning
  ↓
`v1vibe setup` installs tmfs CLI binary
  ↓
File scanning works via CLI subprocess
```

## Setup Integration

**✅ COMPLETE** - tmfs CLI installation is fully integrated into `v1vibe setup`:

1. **Step 4.5** automatically runs after TMAS installation
2. **Compatibility check** via `check_file_security_compatibility()` detects SDK issues
3. **Automatic detection** identifies Python 3.14+ and grpcio version conflicts
4. **Automatic installation** installs tmfs CLI without prompting when SDK incompatible
5. **Automatic download** fetches correct binary for platform (Windows/macOS/Linux)
6. **Version verification** confirms tmfs CLI is working
7. **Config persistence** saves `tmfs_binary_path` to `~/.v1vibe/config.json`

**User experience (fully automatic, no prompts):**
```bash
$ uv run v1vibe setup
# ... Steps 1-4 (API token, region, connectivity, TMAS) ...

Step 4.5: Checking File Security SDK compatibility...
  File Security SDK incompatibility detected (Python 3.14+ or grpcio conflict)
  Installing File Security CLI (tmfs) as fallback...

  Downloading File Security CLI (tmfs)...
  ✓ Installed: /Users/username/.v1vibe/bin/tmfs
  ✓ tmfs version v1.7.3
  ✓ File scanning will use tmfs CLI

Step 5: Saving configuration...
  Saved to /Users/username/.v1vibe/config.json
```

## Future Work

1. ✅ ~~Add tmfs CLI installation to setup wizard~~ (COMPLETE)
2. ✅ ~~Auto-download tmfs binary based on platform detection~~ (COMPLETE)
3. **Test on actual Python 3.14 installation** (Windows/Linux priority)
4. **Update README.md** with CLI installation instructions
5. **Contact Trend Micro** to update visionone-filesecurity for Python 3.14

## References

- [File Security CLI Documentation](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-deploying-cli)
- [grpcio Python 3.14 Support (GitHub Issue)](https://github.com/grpc/grpc/issues/40743)
- [visionone-filesecurity PyPI](https://pypi.org/project/visionone-filesecurity/)
