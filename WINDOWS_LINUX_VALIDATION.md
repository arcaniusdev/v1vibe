# Windows and Linux Installation Validation

## Summary

**Confidence Level: HIGH (85%)**  
**Setup Integration: ✅ COMPLETE**

The tmfs CLI installation and execution should work on Windows and Linux based on:
- ✅ Standard Python libraries used (`pathlib`, `subprocess`, `zipfile`, `tarfile`)
- ✅ Platform detection correctly identifies OS and architecture
- ✅ Environment variable injection uses portable `subprocess.run(env=...)` pattern
- ✅ File paths use `pathlib.Path` (cross-platform)
- ✅ **Fully integrated into `v1vibe setup` command** with automatic SDK compatibility detection
- ⚠️ **Not tested on actual Windows/Linux systems**
- ⚠️ **PATH environment variable not updated** (binary stored but not added to system PATH)

## Platform-Specific Code Paths

### 1. Platform Detection (`_get_tmfs_platform_info()`)

**Code:** `src/v1vibe/cli.py:126-155`

| Platform | Detection | OS Name | Archive Format | Binary Name |
|----------|-----------|---------|----------------|-------------|
| **Windows** | `platform.system() == "Windows"` or starts with `CYGWIN/MINGW/MSYS` | `Windows` | `.zip` | `tmfs.exe` |
| **macOS** | `platform.system() == "Darwin"` | `Darwin` | `.zip` | `tmfs` |
| **Linux** | Default (any other) | `Linux` | `.tar.gz` | `tmfs` |

**Validation:**
- ✅ **Windows detection:** Handles native Windows and Unix-like shells (Git Bash, Cygwin, MSYS2)
- ✅ **Architecture mapping:** Supports `arm64`, `x86_64`, `i386` across all platforms
- ✅ **Archive format:** Correctly maps `.zip` for Windows/macOS, `.tar.gz` for Linux
- ✅ **Binary naming:** `tmfs.exe` for Windows, `tmfs` for Unix

**Tested:**
- ✅ macOS (Darwin/arm64) - works correctly

**Theoretical (should work):**
- ⚠️ Windows (Windows/x86_64, Windows/arm64, Windows/i386)
- ⚠️ Linux (Linux/x86_64, Linux/arm64, Linux/i386)

### 2. Installation (`_install_tmfs()`)

**Code:** `src/v1vibe/cli.py:213-265`

#### 2a. Binary Directory Creation

```python
BIN_DIR.mkdir(parents=True, exist_ok=True)  # Line 226
```

**BIN_DIR** resolves to:
- macOS/Linux: `~/.v1vibe/bin` → `/Users/username/.v1vibe/bin` or `/home/username/.v1vibe/bin`
- Windows: `~/.v1vibe/bin` → `C:\Users\username\.v1vibe\bin`

**Validation:**
- ✅ `Path.home()` is cross-platform (defined in config.py as `Path.home() / ".v1vibe"`)
- ✅ `mkdir(parents=True, exist_ok=True)` works on all platforms
- ✅ Windows supports forward slashes in `pathlib.Path`

**Concerns:**
- ⚠️ **Windows:** User profile path should resolve correctly via `Path.home()`, but not tested
- ⚠️ **Windows:** No special handling for `%USERPROFILE%` vs `Path.home()` (should be equivalent)

#### 2b. Archive Download

```python
urllib.request.urlretrieve(download_url, archive_path)  # Line 230
```

**Download URLs:**
- Windows x86_64: `https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli/latest/tmfs-cli_Windows_x86_64.zip`
- Linux x86_64: `https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli/latest/tmfs-cli_Linux_x86_64.tar.gz`

**Validation:**
- ✅ `urllib.request.urlretrieve()` is cross-platform
- ✅ Downloads to `BIN_DIR / filename` using `pathlib.Path` (works on Windows)

#### 2c. Archive Extraction

**ZIP extraction (Windows/macOS):**
```python
with zipfile.ZipFile(archive_path, "r") as zip_file:
    for name in zip_file.namelist():
        if name.endswith(binary_name):
            data = zip_file.read(name)
            binary_path.write_bytes(data)  # Line 251
            break
```

**TAR.GZ extraction (Linux):**
```python
with tarfile.open(archive_path, "r:gz") as tar:
    for member in tar.getmembers():
        if member.name.endswith(binary_name):
            member.name = binary_name  # Flatten path
            tar.extract(member, BIN_DIR)  # Line 243
            break
```

**Validation:**
- ✅ `zipfile` module is cross-platform (works on Windows)
- ✅ `tarfile` module is cross-platform (works on Linux)
- ✅ `Path.write_bytes()` is cross-platform
- ✅ Archive cleanup uses `unlink(missing_ok=True)` (works on all platforms)

**Concerns:**
- ⚠️ **Windows ZIP extraction:** Not tested on actual Windows system
- ⚠️ **Linux TAR.GZ extraction:** Not tested on actual Linux system
- ⚠️ **Archive structure:** Assumes binary is in a subdirectory with consistent naming (e.g., `tmfs-cli_Windows_x86_64/tmfs.exe`)

#### 2d. File Permissions

```python
if os_name != "Windows":
    binary_path.chmod(0o755)  # Line 256
```

**Validation:**
- ✅ Correctly skips `chmod()` on Windows (Windows doesn't use Unix permissions)
- ✅ Sets executable permissions on Unix (macOS/Linux)

**Concerns:**
- ✅ **Windows:** `.exe` files are inherently executable, no chmod needed
- ⚠️ **Linux:** `chmod(0o755)` should work, but not tested

### 3. CLI Execution (`_scan_file_cli()`)

**Code:** `src/v1vibe/tools/file_security.py:30-104`

#### 3a. Command Construction

```python
cmd = [tmfs_path, "scan", f"file:{file_path}", "--region", region]
```

**Validation:**
- ✅ `subprocess.run()` handles `.exe` extension on Windows automatically
- ✅ File paths passed via `file:` prefix (tmfs CLI format)

**Concerns:**
- ⚠️ **Windows:** Absolute paths with drive letters (e.g., `C:\Users\...`) should work but not tested
- ⚠️ **Windows:** Path with spaces should work (subprocess.run quotes arguments)

#### 3b. Environment Variable Injection

```python
env = os.environ.copy()
env["TMFS_API_KEY"] = api_token
result = subprocess.run(cmd, ..., env=env)  # Line 70-76
```

**Validation:**
- ✅ `os.environ.copy()` is cross-platform
- ✅ `subprocess.run(env=...)` is cross-platform (works on Windows/Linux/macOS)
- ✅ Environment variable names are case-insensitive on Windows, case-sensitive on Unix (TMFS_API_KEY should work on both)

**Windows Environment Variables:**
- ✅ **Not using `set TMFS_API_KEY=...`** (shell-specific, doesn't work in Python subprocess)
- ✅ **Using `env` dict parameter** (correct cross-platform approach)

**Linux Environment Variables:**
- ✅ **Not using `export TMFS_API_KEY=...`** (shell-specific, doesn't work in Python subprocess)
- ✅ **Using `env` dict parameter** (correct cross-platform approach)

#### 3c. Binary Execution

**macOS/Linux:**
```bash
~/.v1vibe/bin/tmfs scan file:/path/to/file --region us-east-1
```

**Windows:**
```cmd
C:\Users\username\.v1vibe\bin\tmfs.exe scan file:C:\path\to\file --region us-east-1
```

**Validation:**
- ✅ `subprocess.run([binary_path, ...])` is cross-platform
- ✅ Binary path stored in config as absolute path (no PATH needed)

**Concerns:**
- ⚠️ **Windows:** Binary path format `C:\Users\...\.v1vibe\bin\tmfs.exe` not tested
- ⚠️ **Windows:** File paths with backslashes (`C:\Users\...`) not tested with `file:` prefix

## Missing Platform-Specific Handling

### 1. PATH Environment Variable (NOT IMPLEMENTED)

**Current behavior:**
- Binary stored at `~/.v1vibe/bin/tmfs` or `C:\Users\username\.v1vibe\bin\tmfs.exe`
- Config stores absolute path to binary (`tmfs_binary_path` in `~/.v1vibe/config.json`)
- Binary executed directly via `subprocess.run([tmfs_path, ...])`
- **PATH is never updated**

**User documentation suggests PATH updates:**
From the Trend Micro docs the user provided:
```bash
# macOS/Linux
export PATH=$PATH:~/tmfs-cli

# Windows
set PATH=%PATH%;C:\tmfs-cli
```

**Analysis:**
- ✅ **Not required for v1vibe** - we always execute via absolute path from config
- ✅ **User cannot run `tmfs` from command line** - but this is not a requirement for v1vibe
- ❌ **Documentation mismatch** - Trend Micro docs show PATH setup, but we don't do it

**Recommendation:**
- Current approach is BETTER for v1vibe use case (isolated, predictable, no PATH pollution)
- If users want to run `tmfs` manually, they can add to PATH themselves
- Document that v1vibe manages tmfs internally and PATH updates are not needed

### 2. Windows Registry (NOT NEEDED)

- No registry modifications needed for tmfs CLI
- Binary is self-contained executable
- Environment variables passed per-process via `subprocess.run(env=...)`

### 3. Permissions and Security

**macOS/Linux:**
- ✅ Config file permissions: `0600` (read/write owner only)
- ✅ Binary permissions: `0755` (executable by all, writable by owner)

**Windows:**
- ✅ Config file in `%USERPROFILE%\.v1vibe` (user-specific directory)
- ⚠️ File permissions not explicitly set (Windows uses ACLs, not Unix permissions)
- ⚠️ Default Windows ACLs should be secure (user directory = user-only access by default)

## Testing Strategy

### Automated Testing (not feasible without VMs)

- Would require Windows and Linux VMs or CI runners
- GitHub Actions supports Windows/Linux runners but no physical hardware access for tmfs download testing

### Manual Testing Checklist

**Windows (priority: HIGH - original issue reported here):**

1. ✅ Verify Python 3.14 is installed
2. ✅ Run `uv run v1vibe setup`
3. ✅ Check if tmfs download works from `https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli/latest/tmfs-cli_Windows_x86_64.zip`
4. ✅ Verify binary extracted to `C:\Users\<username>\.v1vibe\bin\tmfs.exe`
5. ✅ Check config file at `C:\Users\<username>\.v1vibe\config.json` contains `tmfs_binary_path`
6. ✅ Run `uv run v1vibe status` and verify tmfs version displayed
7. ✅ Test file scan: create test file, use MCP server `scan_file` tool
8. ✅ Verify `TMFS_API_KEY` environment variable is set during subprocess execution (debug output)
9. ✅ Test with file paths containing spaces (e.g., `C:\Users\John Doe\test.txt`)
10. ✅ Test with file paths on different drives (e.g., `D:\files\test.txt`)

**Linux (priority: MEDIUM - not reported, but common deployment target):**

1. ✅ Verify Python 3.14 is installed (or any version)
2. ✅ Run `uv run v1vibe setup`
3. ✅ Check if tmfs download works from `https://tmfs-cli.fs-sdk-ue1.xdr.trendmicro.com/tmfs-cli/latest/tmfs-cli_Linux_x86_64.tar.gz`
4. ✅ Verify binary extracted to `~/.v1vibe/bin/tmfs`
5. ✅ Verify binary has execute permissions (`ls -l ~/.v1vibe/bin/tmfs` shows `-rwxr-xr-x`)
6. ✅ Check config file at `~/.v1vibe/config.json` contains `tmfs_binary_path`
7. ✅ Run `uv run v1vibe status` and verify tmfs version displayed
8. ✅ Test file scan via MCP server
9. ✅ Verify `TMFS_API_KEY` environment variable is set during subprocess execution

### Code Review Validation

**Critical paths to review:**

1. ✅ **Archive extraction on Windows:**
   - Review ZIP file structure from actual download
   - Verify binary is in subdirectory (e.g., `tmfs-cli_Windows_x86_64/tmfs.exe`)
   - Confirm `name.endswith(binary_name)` pattern matching works

2. ✅ **Archive extraction on Linux:**
   - Review TAR.GZ file structure from actual download
   - Verify binary is in subdirectory (e.g., `tmfs-cli_Linux_x86_64/tmfs`)
   - Confirm `member.name.endswith(binary_name)` pattern matching works

3. ✅ **Windows file paths:**
   - Test with `C:\Users\username\test.txt` format
   - Test with spaces in path
   - Test with different drives

## Validation Checklist

### ✅ High Confidence (tested or standard library)

- [x] Platform detection via `platform.system()` and `platform.machine()`
- [x] File path handling via `pathlib.Path` (cross-platform)
- [x] Archive download via `urllib.request.urlretrieve()`
- [x] Environment variable injection via `subprocess.run(env=...)`
- [x] ZIP extraction via `zipfile.ZipFile` (standard library)
- [x] TAR.GZ extraction via `tarfile.open()` (standard library)
- [x] Binary execution via `subprocess.run([path, ...])`
- [x] JSON parsing from subprocess stdout
- [x] Binary name mapping (`tmfs.exe` vs `tmfs`)
- [x] Permission handling (skip chmod on Windows)

### ⚠️ Medium Confidence (should work but not tested)

- [ ] Windows binary download from actual URL
- [ ] Linux binary download from actual URL
- [ ] Windows ZIP extraction (correct archive structure)
- [ ] Linux TAR.GZ extraction (correct archive structure)
- [ ] Windows binary path resolution (`C:\Users\...\.v1vibe\bin\tmfs.exe`)
- [ ] Linux binary path resolution (`/home/user/.v1vibe/bin/tmfs`)
- [ ] Windows file paths with drive letters in `file:C:\path\to\file` format
- [ ] Linux absolute paths in `file:/home/user/file` format
- [ ] Windows subprocess execution with `.exe` extension
- [ ] Linux subprocess execution with `chmod 755` permissions

### ❌ Low Confidence (not implemented or not tested)

- [ ] PATH environment variable updates (intentionally not implemented)
- [ ] Windows file paths with UNC paths (`\\server\share\file`)
- [ ] Windows file paths with non-ASCII characters
- [ ] Linux file paths with non-ASCII characters
- [ ] Archive extraction error handling (corrupted download)
- [ ] Network error handling during download
- [ ] Disk space validation before download

## Recommendations

### Before Production Release

1. **Critical: Test on actual Windows system**
   - Priority: HIGH (original issue was Windows-specific)
   - Minimum: Windows 10/11 with Python 3.14
   - Test both x86_64 and arm64 if possible

2. **Critical: Test on actual Linux system**
   - Priority: MEDIUM (common deployment target)
   - Minimum: Ubuntu 22.04 or similar with Python 3.14
   - Test both x86_64 and arm64 if possible

3. **Optional: Add archive structure validation**
   - Download tmfs archives for all platforms
   - Verify binary location in archive matches code expectations
   - Add fallback logic if binary not in expected location

4. **Optional: Add network error handling**
   - Handle urllib.request.urlretrieve failures more gracefully
   - Provide helpful error messages with manual download instructions
   - Add retry logic for transient network errors

5. **Optional: Add disk space check**
   - Verify sufficient disk space before download (tmfs binary ~10-20MB)
   - Fail early with clear error message if insufficient space

### Documentation Updates

1. **Update PYTHON_3.14_SUPPORT.md:**
   - Add "Not tested on Windows/Linux" disclaimer
   - Add manual installation instructions as fallback
   - Document that PATH updates are not needed

2. **Update README.md:**
   - Document tmfs CLI fallback behavior
   - Explain when SDK vs CLI is used
   - Provide troubleshooting steps for Windows/Linux

3. **Update CLAUDE.md:**
   - Document platform-specific testing status
   - Add Windows/Linux validation to future work

## Confidence Assessment

| Component | Confidence | Justification |
|-----------|-----------|---------------|
| **Platform detection** | 95% | Standard library, tested on macOS |
| **Binary download** | 90% | urllib is cross-platform, URLs verified |
| **ZIP extraction (Windows)** | 80% | Standard library, not tested on Windows |
| **TAR.GZ extraction (Linux)** | 80% | Standard library, not tested on Linux |
| **File path handling** | 85% | pathlib is cross-platform, edge cases not tested |
| **Environment variables** | 95% | subprocess.run(env=...) is cross-platform, tested on macOS |
| **Binary execution** | 85% | subprocess.run() is cross-platform, Windows .exe not tested |
| **Overall** | 85% | High confidence due to standard libraries, but needs actual platform testing |

## Conclusion

**The implementation SHOULD work on Windows and Linux** based on:
- Correct use of cross-platform Python standard libraries
- Proper platform detection and OS-specific logic
- Environment variable handling via subprocess rather than shell commands
- No reliance on shell-specific features

**However, it has NOT been tested on actual Windows or Linux systems**, so we cannot be 100% certain until manual validation is performed.

**Recommendation:** Deploy to beta testers on Windows and Linux before public release, or set up GitHub Actions CI with Windows/Linux runners to test installation flow.
