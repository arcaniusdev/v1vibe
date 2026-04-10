"""Tests for CVE vulnerability tools."""

import pytest
from unittest.mock import AsyncMock
from v1vibe.tools.vulnerabilities import get_cve_details


@pytest.mark.asyncio
async def test_get_cve_details_valid_id(mock_app_context):
    """Valid CVE ID should make API call."""
    import httpx

    # Create proper request/response
    request = httpx.Request("GET", "https://api.example.com/test")
    mock_response = httpx.Response(
        200,
        json={
            "cveId": "CVE-2023-44487",
            "cvssV3Score": 7.5,
            "description": "HTTP/2 Rapid Reset",
        },
        request=request,
    )
    mock_app_context.http.get.return_value = mock_response

    result = await get_cve_details(mock_app_context, "CVE-2023-44487")

    assert "cveId" in result
    assert result["cveId"] == "CVE-2023-44487"
    mock_app_context.http.get.assert_called_once_with(
        "/v3.0/asrm/vulnerabilities/CVE-2023-44487"
    )


@pytest.mark.asyncio
async def test_get_cve_details_invalid_format(mock_app_context):
    """Invalid CVE ID format should return error without API call."""
    result = await get_cve_details(mock_app_context, "INVALID-123")

    assert "error" in result
    assert result["error"]["code"] == "InvalidInput"
    assert "Invalid CVE ID format" in result["error"]["message"]
    mock_app_context.http.get.assert_not_called()


@pytest.mark.asyncio
async def test_get_cve_details_year_format(mock_app_context):
    """CVE ID must have 4-digit year."""
    result = await get_cve_details(mock_app_context, "CVE-23-12345")

    assert "error" in result
    assert result["error"]["code"] == "InvalidInput"


@pytest.mark.asyncio
async def test_get_cve_details_number_format(mock_app_context):
    """CVE ID must have at least 4 digits after year."""
    result = await get_cve_details(mock_app_context, "CVE-2023-123")

    assert "error" in result
    assert result["error"]["code"] == "InvalidInput"


@pytest.mark.asyncio
async def test_get_cve_details_valid_formats(mock_app_context):
    """Test various valid CVE ID formats."""
    import httpx

    valid_ids = [
        "CVE-2023-1234",      # Minimum digits
        "CVE-2023-12345",     # Five digits
        "CVE-2023-123456",    # Six digits
        "CVE-2024-0001",      # Leading zeros
    ]

    for cve_id in valid_ids:
        request = httpx.Request("GET", "https://api.example.com/test")
        mock_response = httpx.Response(
            200,
            json={"cveId": cve_id},
            request=request,
        )
        mock_app_context.http.get.return_value = mock_response

        result = await get_cve_details(mock_app_context, cve_id)
        assert "error" not in result
