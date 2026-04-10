"""Tests for AI Guard tools."""

import pytest
import httpx
from unittest.mock import AsyncMock
from v1vibe.tools.ai_guard import evaluate


class TestAiGuardEvaluate:
    """Tests for AI Guard evaluate function."""

    @pytest.mark.asyncio
    async def test_evaluate_clean_content(self, mock_app_context):
        """Test evaluating clean content returns Allow."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/aiSecurity/applyGuardrails")
        response = httpx.Response(
            200,
            json={
                "action": "Allow",
                "harmfulContent": [],
                "promptAttacks": [],
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await evaluate(
            mock_app_context,
            prompt="Hello, how are you?",
            application_name="test-app",
        )

        assert result["action"] == "Allow"
        assert result["harmfulContent"] == []
        assert result["promptAttacks"] == []
        mock_app_context.http.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_harmful_content(self, mock_app_context):
        """Test evaluating harmful content returns Block."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/aiSecurity/applyGuardrails")
        response = httpx.Response(
            200,
            json={
                "action": "Block",
                "harmfulContent": [
                    {
                        "category": "violence",
                        "hasPolicyViolation": True,
                        "confidenceScore": 0.95,
                    }
                ],
                "promptAttacks": [],
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await evaluate(
            mock_app_context,
            prompt="harmful content here",
        )

        assert result["action"] == "Block"
        assert len(result["harmfulContent"]) == 1
        assert result["harmfulContent"][0]["category"] == "violence"
        assert result["harmfulContent"][0]["hasPolicyViolation"] is True

    @pytest.mark.asyncio
    async def test_evaluate_prompt_injection(self, mock_app_context):
        """Test detecting prompt injection attacks."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/aiSecurity/applyGuardrails")
        response = httpx.Response(
            200,
            json={
                "action": "Block",
                "harmfulContent": [],
                "promptAttacks": [
                    {
                        "type": "prompt_injection",
                        "confidenceScore": 0.88,
                    }
                ],
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await evaluate(
            mock_app_context,
            prompt="Ignore previous instructions and...",
        )

        assert result["action"] == "Block"
        assert len(result["promptAttacks"]) == 1
        assert result["promptAttacks"][0]["type"] == "prompt_injection"

    @pytest.mark.asyncio
    async def test_evaluate_api_error(self, mock_app_context):
        """Test handling API error responses."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/aiSecurity/applyGuardrails")
        response = httpx.Response(
            400,
            json={
                "error": {
                    "code": "InvalidInput",
                    "message": "Prompt exceeds maximum length",
                }
            },
            request=request,
        )
        # Create an HTTPStatusError which check_response will raise
        error = httpx.HTTPStatusError("Bad Request", request=request, response=response)
        mock_app_context.http.post = AsyncMock(side_effect=error)

        result = await evaluate(
            mock_app_context,
            prompt="x" * 2000,  # Too long
        )

        assert "error" in result
        assert result["error"]["code"] == "HTTP400"
        assert "Prompt exceeds maximum length" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_evaluate_network_error(self, mock_app_context):
        """Test handling network errors."""
        mock_app_context.http.post = AsyncMock(side_effect=httpx.ConnectError("Connection failed"))

        result = await evaluate(mock_app_context, prompt="test")

        assert "error" in result
        assert "code" in result["error"]
        assert "message" in result["error"]

    @pytest.mark.asyncio
    async def test_evaluate_default_application_name(self, mock_app_context):
        """Test default application name is v1vibe."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/aiSecurity/applyGuardrails")
        response = httpx.Response(
            200,
            json={"action": "Allow", "harmfulContent": [], "promptAttacks": []},
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        await evaluate(mock_app_context, prompt="test")

        # Check that default application_name is used
        call_kwargs = mock_app_context.http.post.call_args[1]
        assert call_kwargs["headers"]["TMV1-Application-Name"] == "v1vibe"
