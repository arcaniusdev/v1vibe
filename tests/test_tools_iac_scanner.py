"""Tests for Infrastructure as Code (IaC) scanning tools."""

import pytest
import httpx
from pathlib import Path
from unittest.mock import AsyncMock
from v1vibe.tools.iac_scanner import (
    scan_template,
    scan_terraform_archive,
    VALID_TEMPLATE_TYPES,
)


class TestIacScanner:
    """Tests for IaC security scanning."""

    @pytest.mark.asyncio
    async def test_scan_template_cloudformation(self, mock_app_context, tmp_path):
        """Test scanning a CloudFormation template."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
""")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/beta/cloudPosture/scanTemplate")
        response = httpx.Response(
            200,
            json={
                "findings": [
                    {
                        "riskLevel": "MEDIUM",
                        "ruleId": "S3-001",
                        "description": "S3 bucket encryption not enabled",
                        "affectedResources": ["Bucket"],
                        "remediationUrl": "https://docs.example.com/fix",
                    }
                ]
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await scan_template(
            mock_app_context,
            file_path=str(template_file),
            template_type="cloudformation-template",
        )

        assert "findings" in result
        assert len(result["findings"]) == 1
        assert result["findings"][0]["riskLevel"] == "MEDIUM"
        assert result["findings"][0]["ruleId"] == "S3-001"

    @pytest.mark.asyncio
    async def test_scan_template_terraform(self, mock_app_context, tmp_path):
        """Test scanning a Terraform plan JSON."""
        plan_file = tmp_path / "plan.json"
        plan_file.write_text('{"terraform_version": "1.0.0", "planned_values": {}}')

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/beta/cloudPosture/scanTemplate")
        response = httpx.Response(
            200,
            json={"findings": []},
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await scan_template(
            mock_app_context,
            file_path=str(plan_file),
            template_type="terraform-template",
        )

        assert "findings" in result
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_scan_template_invalid_type(self, mock_app_context, tmp_path):
        """Test scanning with invalid template type."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text("content")

        result = await scan_template(
            mock_app_context,
            file_path=str(template_file),
            template_type="invalid-type",
        )

        assert "error" in result
        assert result["error"]["code"] == "InvalidInput"
        assert "invalid-type" in result["error"]["message"]
        assert "cloudformation-template" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_template_file_not_found(self, mock_app_context):
        """Test scanning non-existent template file."""
        result = await scan_template(
            mock_app_context,
            file_path="/nonexistent/template.yaml",
            template_type="cloudformation-template",
        )

        assert "error" in result
        assert result["error"]["code"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_scan_template_api_error(self, mock_app_context, tmp_path):
        """Test handling API errors."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text("invalid: template")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/beta/cloudPosture/scanTemplate")
        response = httpx.Response(
            400,
            json={
                "error": {
                    "code": "InvalidTemplate",
                    "message": "Template syntax error",
                }
            },
            request=request,
        )
        error = httpx.HTTPStatusError("Bad Request", request=request, response=response)
        mock_app_context.http.post = AsyncMock(side_effect=error)

        result = await scan_template(
            mock_app_context,
            file_path=str(template_file),
            template_type="cloudformation-template",
        )

        assert "error" in result
        assert result["error"]["code"] == "HTTP400"
        assert "Template syntax error" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_scan_terraform_archive(self, mock_app_context, tmp_path):
        """Test scanning a Terraform archive."""
        # Create a mock ZIP file
        archive_file = tmp_path / "terraform.zip"
        archive_file.write_bytes(b"PK\x03\x04")  # ZIP magic bytes

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/beta/cloudPosture/scanTemplateArchive")
        response = httpx.Response(
            200,
            json={
                "findings": [
                    {
                        "riskLevel": "HIGH",
                        "ruleId": "TF-002",
                        "description": "Security group allows unrestricted ingress",
                        "affectedResources": ["aws_security_group.default"],
                        "remediationUrl": "https://docs.example.com/sg",
                    }
                ]
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await scan_terraform_archive(
            mock_app_context,
            file_path=str(archive_file),
        )

        assert "findings" in result
        assert len(result["findings"]) == 1
        assert result["findings"][0]["riskLevel"] == "HIGH"

    @pytest.mark.asyncio
    async def test_scan_terraform_archive_not_found(self, mock_app_context):
        """Test scanning non-existent archive."""
        result = await scan_terraform_archive(
            mock_app_context,
            file_path="/nonexistent/terraform.zip",
        )

        assert "error" in result
        assert result["error"]["code"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_scan_terraform_archive_network_error(self, mock_app_context, tmp_path):
        """Test handling network errors."""
        archive_file = tmp_path / "terraform.zip"
        archive_file.write_bytes(b"PK\x03\x04")

        mock_app_context.http.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        result = await scan_terraform_archive(
            mock_app_context,
            file_path=str(archive_file),
        )

        assert "error" in result
        assert "code" in result["error"]

    def test_valid_template_types_constant(self):
        """Test that VALID_TEMPLATE_TYPES contains expected values."""
        assert "cloudformation-template" in VALID_TEMPLATE_TYPES
        assert "terraform-template" in VALID_TEMPLATE_TYPES
        assert len(VALID_TEMPLATE_TYPES) == 2
