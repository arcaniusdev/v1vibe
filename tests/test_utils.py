"""Tests for utility functions."""

import httpx
import pytest
from v1vibe.utils import (
    sanitize_filter_value,
    format_error,
    check_response,
    check_multi_status,
)


class TestSanitizeFilterValue:
    """Tests for sanitize_filter_value function."""

    def test_removes_quotes(self):
        assert sanitize_filter_value("test'value") == "testvalue"
        assert sanitize_filter_value('test"value') == "testvalue"

    def test_removes_semicolons(self):
        assert sanitize_filter_value("test;value") == "testvalue"

    def test_removes_parentheses(self):
        assert sanitize_filter_value("test(value)") == "testvalue"

    def test_removes_backslashes(self):
        assert sanitize_filter_value("test\\value") == "testvalue"

    def test_clean_string_unchanged(self):
        assert sanitize_filter_value("clean-value_123") == "clean-value_123"

    def test_multiple_unsafe_chars(self):
        assert sanitize_filter_value("';()\\\";") == ""


class TestFormatError:
    """Tests for format_error function."""

    def test_generic_exception(self):
        exc = ValueError("test error message")
        result = format_error(exc)
        assert result["error"]["code"] == "ValueError"
        assert result["error"]["message"] == "test error message"

    def test_http_status_error_with_json(self):
        # Mock HTTP response with JSON error
        request = httpx.Request("POST", "https://api.example.com/test")
        response = httpx.Response(
            400,
            json={"error": {"message": "Bad request from API"}},
            request=request,
        )
        exc = httpx.HTTPStatusError("Bad request", request=request, response=response)
        result = format_error(exc)
        assert result["error"]["code"] == "HTTP400"
        assert result["error"]["message"] == "Bad request from API"

    def test_http_status_error_without_json(self):
        request = httpx.Request("POST", "https://api.example.com/test")
        response = httpx.Response(500, content=b"Internal Server Error", request=request)
        exc = httpx.HTTPStatusError("Server error", request=request, response=response)
        result = format_error(exc)
        assert result["error"]["code"] == "HTTP500"
        assert "HTTP 500 error" in result["error"]["message"]

    def test_http_network_error(self):
        """Network errors should not leak auth headers."""
        exc = httpx.ConnectError("Connection failed")
        result = format_error(exc)
        assert result["error"]["code"] == "ConnectError"
        assert result["error"]["message"] == "Network error: ConnectError"
        # Ensure no auth headers leaked
        assert "Bearer" not in result["error"]["message"]
        assert "Authorization" not in result["error"]["message"]

    def test_file_not_found_error(self):
        exc = FileNotFoundError("No such file: test.txt")
        result = format_error(exc)
        assert result["error"]["code"] == "FileNotFoundError"
        assert "test.txt" in result["error"]["message"]


class TestCheckResponse:
    """Tests for check_response function."""

    def test_success_with_json(self):
        # Create proper request for Response
        request = httpx.Request("GET", "https://api.example.com/test")
        response = httpx.Response(200, json={"result": "success"}, request=request)
        result = check_response(response)
        assert result == {"result": "success"}

    def test_no_content_204(self):
        request = httpx.Request("GET", "https://api.example.com/test")
        response = httpx.Response(204, request=request)
        result = check_response(response)
        assert result == {}

    def test_raises_on_error_status(self):
        request = httpx.Request("GET", "https://api.example.com/test")
        response = httpx.Response(404, content=b"Not found", request=request)
        with pytest.raises(httpx.HTTPStatusError):
            check_response(response)


class TestCheckMultiStatus:
    """Tests for check_multi_status function."""

    def test_success_200(self):
        request = httpx.Request("POST", "https://api.example.com/batch")
        response = httpx.Response(200, json=[{"id": 1}, {"id": 2}], request=request)
        result = check_multi_status(response)
        assert result == [{"id": 1}, {"id": 2}]

    def test_multi_status_207(self):
        request = httpx.Request("POST", "https://api.example.com/batch")
        response = httpx.Response(207, json=[{"status": "ok"}, {"status": "failed"}], request=request)
        result = check_multi_status(response)
        assert result == [{"status": "ok"}, {"status": "failed"}]

    def test_raises_on_other_status(self):
        request = httpx.Request("POST", "https://api.example.com/batch")
        response = httpx.Response(400, content=b"Bad request", request=request)
        with pytest.raises(httpx.HTTPStatusError):
            check_multi_status(response)
