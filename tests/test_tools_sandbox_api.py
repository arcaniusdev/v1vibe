"""Tests for sandbox API integration functions."""

import pytest
import httpx
from pathlib import Path
from unittest.mock import AsyncMock, patch, mock_open
from v1vibe.tools.sandbox import (
    submit_file,
    submit_url,
    get_status,
    get_report,
    get_submission_quota,
)


class TestSandboxSubmitFile:
    """Tests for sandbox file submission."""

    @pytest.mark.asyncio
    async def test_submit_file_success(self, mock_app_context, tmp_path):
        """Test successful file submission."""
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"malware")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/files/analyze")
        response = httpx.Response(
            202,
            json={
                "id": "task-12345",
                "digest": {"sha256": "abc123"},
                "action": "Analyzing",
            },
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_file(mock_app_context, file_path=str(test_file))

        assert result["id"] == "task-12345"
        assert result["action"] == "Analyzing"

    @pytest.mark.asyncio
    async def test_submit_file_unsupported_type(self, mock_app_context, tmp_path):
        """Test submitting unsupported file type."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("text content")

        result = await submit_file(mock_app_context, file_path=str(test_file))

        assert "error" in result
        assert result["error"]["code"] == "UnsupportedFileType"
        assert ".txt" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_submit_file_not_found(self, mock_app_context):
        """Test submitting non-existent file."""
        result = await submit_file(mock_app_context, file_path="/nonexistent/file.exe")

        assert "error" in result
        assert result["error"]["code"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_submit_file_with_passwords(self, mock_app_context, tmp_path):
        """Test submitting file with document and archive passwords."""
        test_file = tmp_path / "encrypted.zip"
        test_file.write_bytes(b"encrypted")

        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/files/analyze")
        response = httpx.Response(
            202,
            json={"id": "task-123", "action": "Analyzing"},
            request=request,
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_file(
            mock_app_context,
            file_path=str(test_file),
            document_password="docpass",
            archive_password="zippass",
        )

        assert "id" in result


class TestSandboxSubmitUrl:
    """Tests for sandbox URL submission."""

    @pytest.mark.asyncio
    async def test_submit_url_success(self, mock_app_context):
        """Test successful URL submission."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/urls/analyze")
        response = httpx.Response(
            207,
            json=[
                {
                    "taskId": "url-task-1",
                    "url": "http://evil.com",
                    "status": 202,
                }
            ],
            request=request,
            headers={"TMV1-Submission-Remaining-Count": "99"},
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_url(mock_app_context, urls=["http://evil.com"])

        assert "items" in result
        assert len(result["items"]) == 1
        assert result["items"][0]["taskId"] == "url-task-1"
        assert result["quotaRemaining"] == "99"

    @pytest.mark.asyncio
    async def test_submit_url_multiple(self, mock_app_context):
        """Test submitting multiple URLs."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/urls/analyze")
        response = httpx.Response(
            207,
            json=[
                {"taskId": "task-1", "url": "http://evil1.com", "status": 202},
                {"taskId": "task-2", "url": "http://evil2.com", "status": 202},
            ],
            request=request,
            headers={"TMV1-Submission-Remaining-Count": "98"},
        )
        mock_app_context.http.post = AsyncMock(return_value=response)

        result = await submit_url(
            mock_app_context,
            urls=["http://evil1.com", "http://evil2.com"],
        )

        assert len(result["items"]) == 2

    @pytest.mark.asyncio
    async def test_submit_url_too_many(self, mock_app_context):
        """Test submitting more than 10 URLs."""
        urls = [f"http://evil{i}.com" for i in range(11)]

        result = await submit_url(mock_app_context, urls=urls)

        assert "error" in result
        assert result["error"]["code"] == "InvalidInput"
        assert "Maximum 10" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_submit_url_api_error(self, mock_app_context):
        """Test handling API error."""
        request = httpx.Request("POST", "https://api.xdr.trendmicro.com/v3.0/sandbox/urls/analyze")
        response = httpx.Response(
            400,
            json={"error": {"code": "InvalidUrl", "message": "Malformed URL"}},
            request=request,
        )
        error = httpx.HTTPStatusError("Bad Request", request=request, response=response)
        mock_app_context.http.post = AsyncMock(side_effect=error)

        result = await submit_url(mock_app_context, urls=["invalid"])

        assert "error" in result


class TestSandboxGetStatus:
    """Tests for sandbox status retrieval."""

    @pytest.mark.asyncio
    async def test_get_status_running(self, mock_app_context):
        """Test getting status of running analysis."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/tasks/task-123")
        response = httpx.Response(
            200,
            json={
                "id": "task-123",
                "status": "running",
                "action": "Analyzing",
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await get_status(mock_app_context, task_id="task-123")

        assert result["status"] == "running"
        assert result["action"] == "Analyzing"

    @pytest.mark.asyncio
    async def test_get_status_succeeded(self, mock_app_context):
        """Test getting status of completed analysis."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/tasks/task-456")
        response = httpx.Response(
            200,
            json={
                "id": "task-456",
                "status": "succeeded",
                "resourceLocation": "/v3.0/sandbox/analysisResults/result-789",
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await get_status(mock_app_context, task_id="task-456")

        assert result["status"] == "succeeded"
        assert "resourceLocation" in result

    @pytest.mark.asyncio
    async def test_get_status_not_found(self, mock_app_context):
        """Test getting status of non-existent task."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/tasks/invalid")
        response = httpx.Response(
            404,
            json={"error": {"code": "NotFound", "message": "Task not found"}},
            request=request,
        )
        error = httpx.HTTPStatusError("Not Found", request=request, response=response)
        mock_app_context.http.get = AsyncMock(side_effect=error)

        result = await get_status(mock_app_context, task_id="invalid")

        assert "error" in result


class TestSandboxGetReport:
    """Tests for sandbox report retrieval."""

    @pytest.mark.asyncio
    async def test_get_report_success(self, mock_app_context):
        """Test getting analysis report."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        response = httpx.Response(
            200,
            json={
                "id": "result-123",
                "type": "file",
                "riskLevel": "high",
                "detectionNames": ["Trojan.Generic"],
                "threatTypes": ["malware"],
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await get_report(mock_app_context, result_id="result-123")

        assert result["riskLevel"] == "high"
        assert "Trojan.Generic" in result["detectionNames"]

    @pytest.mark.asyncio
    async def test_get_report_with_pdf(self, mock_app_context, tmp_path):
        """Test getting report and downloading PDF."""
        report_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        report_response = httpx.Response(
            200,
            json={
                "id": "result-123",
                "riskLevel": "low",
                "detectionNames": [],
            },
            request=report_request,
        )

        # Mock the suspicious objects call
        susp_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123/suspiciousObjects")
        susp_response = httpx.Response(
            200,
            json={"items": []},
            request=susp_request,
        )

        pdf_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123/report")
        pdf_response = httpx.Response(
            200,
            content=b"%PDF-1.4 fake pdf content",
            request=pdf_request,
        )

        # Mock three GET calls: report, suspicious objects, PDF
        mock_app_context.http.get = AsyncMock(side_effect=[report_response, susp_response, pdf_response])

        pdf_path = tmp_path / "report.pdf"
        result = await get_report(
            mock_app_context,
            result_id="result-123",
            save_pdf_to=str(pdf_path),
        )

        assert result["riskLevel"] == "low"
        assert pdf_path.exists()
        assert pdf_path.read_bytes() == b"%PDF-1.4 fake pdf content"

    @pytest.mark.asyncio
    async def test_get_report_pdf_download_failure(self, mock_app_context):
        """Test handling PDF download failure."""
        report_request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/analysisResults/result-123")
        report_response = httpx.Response(
            200,
            json={"id": "result-123", "riskLevel": "medium"},
            request=report_request,
        )

        pdf_error = httpx.ConnectError("PDF download failed")

        mock_app_context.http.get = AsyncMock(side_effect=[report_response, pdf_error])

        result = await get_report(
            mock_app_context,
            result_id="result-123",
            save_pdf_to="/tmp/report.pdf",
        )

        # Should still return the report, even if PDF fails
        assert result["riskLevel"] == "medium"


class TestSandboxGetQuota:
    """Tests for sandbox quota retrieval."""

    @pytest.mark.asyncio
    async def test_get_quota_success(self, mock_app_context):
        """Test getting submission quota."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/submissionQuota")
        response = httpx.Response(
            200,
            json={
                "dailyReserve": 100,
                "remaining": 75,
                "usedFileCount": 15,
                "usedUrlCount": 10,
            },
            request=request,
        )
        mock_app_context.http.get = AsyncMock(return_value=response)

        result = await get_submission_quota(mock_app_context)

        assert result["dailyReserve"] == 100
        assert result["remaining"] == 75
        assert result["usedFileCount"] == 15
        assert result["usedUrlCount"] == 10

    @pytest.mark.asyncio
    async def test_get_quota_api_error(self, mock_app_context):
        """Test handling API error."""
        request = httpx.Request("GET", "https://api.xdr.trendmicro.com/v3.0/sandbox/submissionQuota")
        response = httpx.Response(
            503,
            json={"error": {"code": "ServiceUnavailable", "message": "Service temporarily unavailable"}},
            request=request,
        )
        error = httpx.HTTPStatusError("Service Unavailable", request=request, response=response)
        mock_app_context.http.get = AsyncMock(side_effect=error)

        result = await get_submission_quota(mock_app_context)

        assert "error" in result
        assert result["error"]["code"] == "HTTP503"
