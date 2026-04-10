"""AI Scanner - LLM vulnerability testing via TMAS CLI.

Scans AI/LLM endpoints for security vulnerabilities including jailbreaks,
prompt injection, data exfiltration, and other AI-specific attack techniques.
Uses the TMAS CLI `aiscan llm` command under the hood.

Provides auto-detection of LLM usage in codebases for seamless integration
into security reviews.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from v1vibe.config import AI_SCAN_TIMEOUT
from v1vibe.utils import format_error

if TYPE_CHECKING:
    from v1vibe.clients import AppContext


# LLM provider detection patterns
LLM_PATTERNS = {
    "OpenAI": {
        "imports": [
            r"from openai import",
            r"import openai",
            r"OpenAI\(",
        ],
        "endpoints": [
            r"api\.openai\.com/v1/chat/completions",
            r"api\.openai\.com/v1/completions",
        ],
        "models": [
            r'model\s*[=:]\s*["\']?(gpt-4[^"\']*)["\']?',
            r'model\s*[=:]\s*["\']?(gpt-3\.5[^"\']*)["\']?',
        ],
        "env_vars": ["OPENAI_API_KEY"],
        "default_endpoint": "https://api.openai.com/v1/chat/completions",
    },
    "Anthropic": {
        "imports": [
            r"from anthropic import",
            r"import anthropic",
            r"Anthropic\(",
        ],
        "endpoints": [
            r"api\.anthropic\.com/v1/messages",
            r"api\.anthropic\.com/v1/complete",
        ],
        "models": [
            r'model\s*[=:]\s*["\']?(claude-[^"\']*)["\']?',
        ],
        "env_vars": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        "default_endpoint": "https://api.anthropic.com/v1/messages",
    },
    "Google": {
        "imports": [
            r"import google\.generativeai",
            r"from google\.generativeai import",
            r"genai\.GenerativeModel",
        ],
        "endpoints": [
            r"generativelanguage\.googleapis\.com",
        ],
        "models": [
            r'model\s*[=:]\s*["\']?(gemini-[^"\']*)["\']?',
            r'model\s*[=:]\s*["\']?(palm-[^"\']*)["\']?',
        ],
        "env_vars": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
        "default_endpoint": "https://generativelanguage.googleapis.com/v1beta/models",
    },
}


async def detect_llm_usage(project_path: str) -> list[dict]:
    """Auto-detect LLM usage in a project by analyzing code patterns.

    Scans Python files for LLM imports, API calls, and configurations.
    Returns structured information about detected LLM usage.

    Args:
        project_path: Path to project directory to scan

    Returns:
        list[dict]: List of detected LLM usages. Each entry contains:
            {
                "provider": "OpenAI" | "Anthropic" | "Google" | "Unknown",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "model": "gpt-4" | "claude-3-opus" | etc.,
                "env_var": "OPENAI_API_KEY",
                "files": ["src/chatbot.py", "src/api.py"],
                "confidence": "high" | "medium" | "low"
            }
    """
    detections = []
    project_root = Path(project_path).resolve()

    # Find all Python files
    py_files = list(project_root.rglob("*.py"))
    if not py_files:
        return []

    # Optimization: read all files once and cache content to reduce disk I/O (3x faster)
    file_contents: dict[Path, str] = {}
    for py_file in py_files:
        try:
            file_contents[py_file] = py_file.read_text()
        except Exception:
            # Skip files that can't be read
            continue

    # Check all providers against cached content
    for provider, patterns in LLM_PATTERNS.items():
        provider_files = []
        detected_endpoints = set()
        detected_models = set()
        confidence = "low"

        for py_file, content in file_contents.items():
            # Check for imports (high confidence)
            for import_pattern in patterns["imports"]:
                if re.search(import_pattern, content):
                    provider_files.append(str(py_file.relative_to(project_root)))
                    confidence = "high"
                    break

            # Check for endpoints
            for endpoint_pattern in patterns["endpoints"]:
                matches = re.findall(endpoint_pattern, content)
                detected_endpoints.update(matches)

            # Check for model names
            for model_pattern in patterns["models"]:
                matches = re.findall(model_pattern, content)
                detected_models.update(matches)

        # If we found this provider, add detection
        if provider_files or detected_endpoints or detected_models:
            # Determine endpoint
            if detected_endpoints:
                endpoint = f"https://{list(detected_endpoints)[0]}"
            else:
                endpoint = patterns["default_endpoint"]

            # Determine model
            if detected_models:
                model = list(detected_models)[0]
            else:
                model = None

            detections.append({
                "provider": provider,
                "endpoint": endpoint,
                "model": model,
                "env_var": patterns["env_vars"][0],
                "files": provider_files[:5],  # Limit to first 5 files
                "confidence": confidence,
                "total_files": len(provider_files),
            })

    return detections


async def scan_llm_interactive(
    ctx: AppContext,
    region: str | None = None,
    config_file: str | None = None,
) -> dict:
    """Scan an LLM/AI endpoint for security vulnerabilities (interactive mode).

    Launches an interactive wizard to configure and run AI Scanner tests against
    your LLM endpoint. Tests for jailbreaks, prompt injection, data exfiltration,
    toxic content generation, and other AI-specific attack techniques.

    The wizard will prompt you for:
    - Group name for the scan
    - Target AI API endpoint (OpenAI, Anthropic, Claude, custom, etc.)
    - Model's API key (if required)
    - JSON keys for request/response bodies
    - Attack objectives, techniques, and modifiers

    Results are saved to Vision One and returned as JSON.

    Args:
        ctx: Application context with settings and clients
        region: Optional Vision One region override (defaults to ctx.settings.region)
        config_file: Optional path to saved scan configuration for reuse

    Returns:
        dict: Scan results with vulnerabilities found, attack success rates,
              and detailed findings. Format:
              {
                  "scanId": "...",
                  "status": "completed",
                  "results": {
                      "totalTests": 100,
                      "vulnerabilitiesFound": 12,
                      "attackSuccessRate": 0.12,
                      "findings": [...]
                  },
                  "outputFile": "/path/to/results.json"
              }
              On error: {"error": {"code": "...", "message": "..."}}
    """
    try:
        # Determine TMAS binary path
        tmas_binary_path = ctx.settings.tmas_binary_path
        if not tmas_binary_path:
            return {
                "error": {
                    "code": "TMASNotConfigured",
                    "message": "TMAS CLI not installed. Run: v1vibe setup",
                }
            }

        # Build TMAS command
        if tmas_binary_path == "docker":
            # Docker mode (macOS)
            cmd = ["docker", "run", "--rm", "-it"]
            # Mount config file if provided
            if config_file:
                config_path = Path(config_file).resolve()
                if not config_path.exists():
                    return {
                        "error": {
                            "code": "ConfigFileNotFound",
                            "message": f"Configuration file not found: {config_file}",
                        }
                    }
                cmd.extend(["-v", f"{config_path.parent}:/configs:ro"])
                config_arg = f"/configs/{config_path.name}"
            else:
                config_arg = None

            # Set API key
            cmd.extend(["-e", f"TMAS_API_KEY={ctx.settings.api_token}"])
            cmd.append("trendmicro/tmas:latest")
            cmd.extend(["aiscan", "llm", "-i"])
        else:
            # Binary mode (Linux/Windows or manually installed on macOS)
            cmd = [tmas_binary_path, "aiscan", "llm", "-i"]
            config_arg = config_file

        # Add region
        scan_region = region or ctx.settings.region
        cmd.extend(["--region", scan_region])

        # Add config file if provided
        if config_arg:
            cmd.extend(["--config", config_arg])

        # Create temporary output file for JSON results
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as output_file:
            output_path = output_file.name

        # Add JSON output
        cmd.extend(["--output", f"json={output_path}"])

        try:
            # Run TMAS AI Scanner (interactive, so we can't capture output easily)
            # Note: This will launch the interactive wizard in the user's terminal
            result = subprocess.run(
                cmd,
                env={**subprocess.os.environ, "TMAS_API_KEY": ctx.settings.api_token},
                check=False,
                timeout=AI_SCAN_TIMEOUT,
            )

            if result.returncode != 0:
                return {
                    "error": {
                        "code": "ScanFailed",
                        "message": f"TMAS AI Scanner exited with code {result.returncode}",
                        "exitCode": result.returncode,
                    }
                }

            # Read JSON results
            try:
                output = Path(output_path).read_text()
                scan_results = json.loads(output)

                return {
                    "status": "completed",
                    "region": scan_region,
                    "configFile": config_file,
                    "results": scan_results,
                    "outputFile": output_path,
                }
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                return {
                    "error": {
                        "code": "OutputParseFailed",
                        "message": f"Failed to parse AI Scanner output: {exc}",
                    }
                }
        finally:
            # Always clean up temp file
            Path(output_path).unlink(missing_ok=True)

    except subprocess.TimeoutExpired:
        return {
            "error": {
                "code": "ScanTimeout",
                "message": "AI Scanner scan exceeded 1 hour timeout",
            }
        }
    except Exception as exc:
        return format_error(exc)


async def scan_llm_endpoint(
    ctx: AppContext,
    endpoint_url: str,
    model_name: str | None = None,
    api_key: str | None = None,
    region: str | None = None,
    attack_objectives: list[str] | None = None,
    output_file: str | None = None,
) -> dict:
    """Scan an LLM endpoint for vulnerabilities (automated mode).

    Tests an AI/LLM endpoint for security vulnerabilities using predefined
    attack configurations. This is the programmatic interface to AI Scanner
    for automation and CI/CD pipelines.

    This is the PRIMARY tool for AI security testing. Use this for automated
    scans discovered via detect_llm_usage().

    Args:
        ctx: Application context with settings and clients
        endpoint_url: Target LLM API endpoint (e.g., https://api.openai.com/v1/chat/completions)
        model_name: Model identifier (e.g., gpt-4, claude-3-opus, custom-model-v1).
                   Optional if endpoint has a default model.
        api_key: API key for the target LLM. If None, TMAS will look for it in environment
                (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
        region: Optional Vision One region override (defaults to ctx.settings.region)
        attack_objectives: Optional list of attack objectives to test.
                          If None, uses comprehensive defaults:
                          ["jailbreak", "prompt_injection", "data_exfiltration",
                           "toxic_content", "model_manipulation"]
        output_file: Optional path to save detailed JSON results

    Returns:
        dict: Scan results with vulnerabilities found and attack success rates.
              Format same as scan_llm_interactive().
              On error: {"error": {"code": "...", "message": "..."}}
    """
    try:
        # Determine TMAS binary path
        tmas_binary_path = ctx.settings.tmas_binary_path
        if not tmas_binary_path:
            return {
                "error": {
                    "code": "TMASNotConfigured",
                    "message": "TMAS CLI not installed. Run: v1vibe setup",
                }
            }

        # Create temporary config file for non-interactive mode
        config = {
            "endpoint": endpoint_url,
            "model": model_name,
        }
        if api_key:
            config["apiKey"] = api_key
        if attack_objectives:
            config["attackObjectives"] = attack_objectives

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as config_file:
            json.dump(config, config_file)
            config_path = config_file.name

        # Determine output path
        is_temp_output = output_file is None
        if output_file:
            output_path = Path(output_file).resolve()
        else:
            temp_output = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            )
            output_path = Path(temp_output.name)
            temp_output.close()

        try:
            # Build TMAS command
            if tmas_binary_path == "docker":
                # Docker mode
                config_dir = Path(config_path).parent
                output_dir = output_path.parent

                cmd = [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{config_dir}:/config:ro",
                    "-v",
                    f"{output_dir}:/output",
                    "-e",
                    f"TMAS_API_KEY={ctx.settings.api_token}",
                    "trendmicro/tmas:latest",
                    "aiscan",
                    "llm",
                    "--config",
                    f"/config/{Path(config_path).name}",
                    "--output",
                    f"json=/output/{output_path.name}",
                ]
            else:
                # Binary mode
                cmd = [
                    tmas_binary_path,
                    "aiscan",
                    "llm",
                    "--config",
                    config_path,
                    "--output",
                    f"json={output_path}",
                ]

            # Add region
            scan_region = region or ctx.settings.region
            cmd.extend(["--region", scan_region])

            # Run TMAS AI Scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env={**subprocess.os.environ, "TMAS_API_KEY": ctx.settings.api_token},
                check=False,
                timeout=AI_SCAN_TIMEOUT,
            )

            if result.returncode != 0:
                return {
                    "error": {
                        "code": "ScanFailed",
                        "message": "AI Scanner scan failed",
                        "exitCode": result.returncode,
                        "stderr": result.stderr,
                    }
                }

            # Read results
            try:
                scan_results = json.loads(output_path.read_text())

                return {
                    "status": "completed",
                    "endpoint": endpoint_url,
                    "model": model_name,
                    "region": scan_region,
                    "results": scan_results,
                    "outputFile": str(output_path) if output_file else None,
                }
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                return {
                    "error": {
                        "code": "OutputParseFailed",
                        "message": f"Failed to parse AI Scanner output: {exc}",
                    }
                }
        finally:
            # Always clean up temp config file
            Path(config_path).unlink(missing_ok=True)
            # Clean up temp output if not user-specified
            if is_temp_output:
                output_path.unlink(missing_ok=True)

    except subprocess.TimeoutExpired:
        return {
            "error": {
                "code": "ScanTimeout",
                "message": "AI Scanner scan exceeded 1 hour timeout",
            }
        }
    except Exception as exc:
        return format_error(exc)
