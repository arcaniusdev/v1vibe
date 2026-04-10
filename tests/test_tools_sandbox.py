"""Tests for sandbox tools."""

import pytest
from pathlib import Path
from v1vibe.tools.sandbox import is_sandbox_supported, SANDBOX_SUPPORTED_EXTENSIONS


class TestSandboxFileTypeValidation:
    """Tests for sandbox file type validation."""

    def test_supported_executable(self):
        assert is_sandbox_supported("/path/to/file.exe")
        assert is_sandbox_supported("/path/to/file.dll")
        assert is_sandbox_supported("/path/to/file.msi")

    def test_supported_script(self):
        assert is_sandbox_supported("/path/to/script.ps1")
        assert is_sandbox_supported("/path/to/script.sh")
        assert is_sandbox_supported("/path/to/script.py")
        assert is_sandbox_supported("/path/to/script.bat")

    def test_supported_document(self):
        assert is_sandbox_supported("/path/to/doc.pdf")
        assert is_sandbox_supported("/path/to/doc.docx")
        assert is_sandbox_supported("/path/to/sheet.xlsx")

    def test_supported_archive(self):
        assert is_sandbox_supported("/path/to/archive.zip")
        assert is_sandbox_supported("/path/to/archive.tar")
        assert is_sandbox_supported("/path/to/archive.gz")

    def test_unsupported_file(self):
        assert not is_sandbox_supported("/path/to/file.txt")
        assert not is_sandbox_supported("/path/to/file.log")
        assert not is_sandbox_supported("/path/to/image.png")

    def test_case_insensitive(self):
        assert is_sandbox_supported("/path/to/FILE.EXE")
        assert is_sandbox_supported("/path/to/File.Pdf")

    def test_no_extension(self):
        assert not is_sandbox_supported("/path/to/file")

    def test_extension_list_loaded(self):
        """Sandbox extensions should be loaded from file."""
        assert len(SANDBOX_SUPPORTED_EXTENSIONS) > 50
        assert ".exe" in SANDBOX_SUPPORTED_EXTENSIONS
        assert ".pdf" in SANDBOX_SUPPORTED_EXTENSIONS
        assert ".zip" in SANDBOX_SUPPORTED_EXTENSIONS
