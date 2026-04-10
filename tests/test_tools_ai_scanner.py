"""Tests for AI Scanner LLM vulnerability testing tools."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from v1vibe.clients import AppContext
from v1vibe.config import Settings
from v1vibe.tools import ai_scanner


@pytest.fixture
def mock_settings():
    """Mock Settings with AI Scanner configuration."""
    return Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path="/usr/local/bin/tmas",
    )


@pytest.fixture
def mock_app_context(mock_settings):
    """Mock AppContext for AI Scanner tests."""
    return AppContext(
        settings=mock_settings,
        grpc_handle=MagicMock(),
        http=AsyncMock(),
    )


# ============================================================================
# detect_llm_usage Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_llm_usage_openai(tmp_path):
    """Test detection of OpenAI usage in Python files."""
    # Create test Python file with OpenAI imports
    test_file = tmp_path / "chatbot.py"
    test_file.write_text("""
import openai
from openai import ChatCompletion

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
""")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert len(detections) == 1
    assert detections[0]["provider"] == "OpenAI"
    assert detections[0]["endpoint"] == "https://api.openai.com/v1/chat/completions"
    assert detections[0]["model"] == "gpt-4"
    assert detections[0]["env_var"] == "OPENAI_API_KEY"
    assert detections[0]["confidence"] == "high"
    assert "chatbot.py" in detections[0]["files"][0]


@pytest.mark.asyncio
async def test_detect_llm_usage_anthropic(tmp_path):
    """Test detection of Anthropic usage in Python files."""
    test_file = tmp_path / "assistant.py"
    test_file.write_text("""
from anthropic import Anthropic

client = Anthropic()
message = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)
""")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert len(detections) == 1
    assert detections[0]["provider"] == "Anthropic"
    assert detections[0]["endpoint"] == "https://api.anthropic.com/v1/messages"
    assert detections[0]["model"] == "claude-3-opus-20240229"
    assert detections[0]["env_var"] == "ANTHROPIC_API_KEY"


@pytest.mark.asyncio
async def test_detect_llm_usage_google(tmp_path):
    """Test detection of Google Generative AI usage."""
    test_file = tmp_path / "genai.py"
    test_file.write_text("""
import google.generativeai as genai

genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
model = "gemini-pro"
response = genai.GenerativeModel(model).generate_content("Hello")
""")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert len(detections) == 1
    assert detections[0]["provider"] == "Google"
    assert detections[0]["model"] == "gemini-pro"
    assert detections[0]["env_var"] == "GOOGLE_API_KEY"


@pytest.mark.asyncio
async def test_detect_llm_usage_multiple_providers(tmp_path):
    """Test detection of multiple LLM providers in same project."""
    (tmp_path / "openai_bot.py").write_text("import openai\nmodel='gpt-4'")
    (tmp_path / "claude_bot.py").write_text("from anthropic import Anthropic\nmodel='claude-3-sonnet'")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert len(detections) == 2
    providers = {d["provider"] for d in detections}
    assert providers == {"OpenAI", "Anthropic"}


@pytest.mark.asyncio
async def test_detect_llm_usage_no_python_files(tmp_path):
    """Test detection returns empty list when no Python files found."""
    (tmp_path / "readme.md").write_text("# Not a Python file")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert detections == []


@pytest.mark.asyncio
async def test_detect_llm_usage_no_llm_imports(tmp_path):
    """Test detection returns empty when no LLM usage found."""
    test_file = tmp_path / "app.py"
    test_file.write_text("""
import os
import sys

def hello():
    print("Hello, world!")
""")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert detections == []


@pytest.mark.asyncio
async def test_detect_llm_usage_unreadable_file(tmp_path):
    """Test detection handles unreadable files gracefully."""
    test_file = tmp_path / "bad.py"
    test_file.write_bytes(b"\xff\xfe\x00\x01")  # Invalid UTF-8

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    # Should not crash, just skip the unreadable file
    assert isinstance(detections, list)


@pytest.mark.asyncio
async def test_detect_llm_usage_endpoint_extraction(tmp_path):
    """Test extraction of custom endpoint URLs."""
    test_file = tmp_path / "custom.py"
    test_file.write_text("""
import openai
openai.api_base = "api.openai.com/v1/completions"
""")

    detections = await ai_scanner.detect_llm_usage(str(tmp_path))

    assert len(detections) == 1
    # Should use default endpoint since pattern doesn't include https://
    assert "api.openai.com" in detections[0]["endpoint"]


# ============================================================================
# scan_llm_interactive Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scan_llm_interactive_no_tmas(mock_app_context):
    """Test interactive scan fails gracefully when TMAS not configured."""
    # Set tmas_binary_path to None
    settings = Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path=None,
    )
    ctx = AppContext(settings=settings, grpc_handle=MagicMock(), http=AsyncMock())

    result = await ai_scanner.scan_llm_interactive(ctx)

    assert "error" in result
    assert result["error"]["code"] == "TMASNotConfigured"


@pytest.mark.asyncio
async def test_scan_llm_interactive_config_file_not_found():
    """Test interactive scan with non-existent config file in Docker mode."""
    # Use Docker mode to trigger config file existence check
    settings = Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path="docker",  # Docker mode
    )
    ctx = AppContext(settings=settings, grpc_handle=MagicMock(), http=AsyncMock())

    result = await ai_scanner.scan_llm_interactive(
        ctx,
        config_file="/nonexistent/config.json"
    )

    assert "error" in result
    assert result["error"]["code"] == "ConfigFileNotFound"


@pytest.mark.asyncio
async def test_scan_llm_interactive_success(mock_app_context, tmp_path):
    """Test successful interactive scan."""
    output_file = tmp_path / "results.json"
    output_file.write_text(json.dumps({
        "scanId": "test-scan-123",
        "vulnerabilities": 5,
        "attackSuccessRate": 0.12
    }))

    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile") as mock_temp:

        # Mock temp file
        mock_file = MagicMock()
        mock_file.name = str(output_file)
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_temp.return_value = mock_file

        # Mock subprocess success
        mock_run.return_value.returncode = 0

        result = await ai_scanner.scan_llm_interactive(
            mock_app_context,
            region="us-east-1"
        )

        assert result["status"] == "completed"
        assert result["region"] == "us-east-1"
        assert "results" in result


@pytest.mark.asyncio
async def test_scan_llm_interactive_scan_failed(mock_app_context):
    """Test interactive scan with failed TMAS execution."""
    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile"):

        mock_run.return_value.returncode = 1

        result = await ai_scanner.scan_llm_interactive(mock_app_context)

        assert "error" in result
        assert result["error"]["code"] == "ScanFailed"
        assert "exitCode" in result["error"]


# ============================================================================
# scan_llm_endpoint Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scan_llm_endpoint_no_tmas(mock_app_context):
    """Test endpoint scan fails when TMAS not configured."""
    settings = Settings(
        api_token="test-token-12345678901234567890",
        region="us-east-1",
        base_url="https://api.xdr.trendmicro.com",
        tmas_binary_path=None,
    )
    ctx = AppContext(settings=settings, grpc_handle=MagicMock(), http=AsyncMock())

    result = await ai_scanner.scan_llm_endpoint(
        ctx,
        endpoint_url="https://api.openai.com/v1/chat/completions",
        model_name="gpt-4"
    )

    assert "error" in result
    assert result["error"]["code"] == "TMASNotConfigured"


@pytest.mark.asyncio
async def test_scan_llm_endpoint_success(mock_app_context, tmp_path):
    """Test successful automated endpoint scan."""
    output_file = tmp_path / "scan_results.json"
    output_file.write_text(json.dumps({
        "scanId": "endpoint-scan-456",
        "totalTests": 100,
        "vulnerabilitiesFound": 12,
        "attackSuccessRate": 0.12
    }))

    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile") as mock_temp_config, \
         patch("tempfile.TemporaryFile") as mock_temp_output:

        # Mock config file creation
        config_file = MagicMock()
        config_file.name = str(tmp_path / "config.json")
        config_file.__enter__ = MagicMock(return_value=config_file)
        config_file.__exit__ = MagicMock(return_value=False)
        mock_temp_config.return_value = config_file

        # Mock output file
        Path(config_file.name).write_text("{}")

        # Mock subprocess success
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        # Create actual output file for reading
        with patch("pathlib.Path.read_text", return_value=output_file.read_text()):
            result = await ai_scanner.scan_llm_endpoint(
                mock_app_context,
                endpoint_url="https://api.openai.com/v1/chat/completions",
                model_name="gpt-4",
                api_key="sk-test-key",
                output_file=str(output_file)
            )

        assert result["status"] == "completed"
        assert result["endpoint"] == "https://api.openai.com/v1/chat/completions"
        assert result["model"] == "gpt-4"


@pytest.mark.asyncio
async def test_scan_llm_endpoint_with_attack_objectives(mock_app_context, tmp_path):
    """Test endpoint scan with custom attack objectives."""
    output_file = tmp_path / "results.json"
    output_file.write_text(json.dumps({"status": "completed"}))

    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile"), \
         patch("pathlib.Path.read_text", return_value=output_file.read_text()), \
         patch("pathlib.Path.unlink"):

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        result = await ai_scanner.scan_llm_endpoint(
            mock_app_context,
            endpoint_url="https://api.anthropic.com/v1/messages",
            model_name="claude-3-opus",
            attack_objectives=["jailbreak", "prompt_injection"]
        )

        assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_scan_llm_endpoint_timeout(mock_app_context):
    """Test endpoint scan timeout handling."""
    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile"):

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="tmas", timeout=3600)

        result = await ai_scanner.scan_llm_endpoint(
            mock_app_context,
            endpoint_url="https://api.openai.com/v1/chat/completions"
        )

        assert "error" in result
        assert result["error"]["code"] == "ScanTimeout"


@pytest.mark.asyncio
async def test_scan_llm_endpoint_scan_failed(mock_app_context, tmp_path):
    """Test endpoint scan with failed execution."""
    with patch("subprocess.run") as mock_run, \
         patch("tempfile.NamedTemporaryFile"), \
         patch("pathlib.Path.unlink"):

        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "TMAS error message"
        mock_run.return_value.stdout = ""

        result = await ai_scanner.scan_llm_endpoint(
            mock_app_context,
            endpoint_url="https://api.openai.com/v1/chat/completions",
            model_name="gpt-4"
        )

        assert "error" in result
        assert result["error"]["code"] == "ScanFailed"
        assert "stderr" in result["error"]
