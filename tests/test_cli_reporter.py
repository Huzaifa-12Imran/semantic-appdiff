"""tests/test_cli_reporter.py — CLI reporter and replay tests."""

from __future__ import annotations

import json
import os
import pathlib

import pytest
from rich.console import Console

from engine.models import Finding, FindingType, Severity
from reporter.cli_reporter import print_summary
from capture.replay import _retarget_url, _clean_headers
from capture.validator import validate_har_dict


# ── CLI Reporter ──────────────────────────────────────────────────────────────


def test_print_summary_no_findings(capsys) -> None:
    """print_summary with no findings should return 0."""
    code = print_summary([], "high")
    assert code == 0


def test_print_summary_critical(capsys) -> None:
    """print_summary with CRITICAL finding should return 2."""
    f = Finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL,
                "GET /users", None, "Endpoint removed", {}, {})
    code = print_summary([f], "high")
    assert code == 2


def test_print_summary_high(capsys) -> None:
    """print_summary with HIGH finding should return 1."""
    f = Finding(FindingType.ERROR_RATE_INCREASE, Severity.HIGH,
                "GET /data", None, "Error rate up", {}, {})
    code = print_summary([f], "high")
    assert code == 1


def test_print_summary_medium_with_high_threshold(capsys) -> None:
    """MEDIUM finding with 'high' threshold should return 0."""
    f = Finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM,
                "GET /items", None, "Slow", {}, {})
    code = print_summary([f], "high")
    assert code == 0


def test_print_summary_none_threshold(capsys) -> None:
    """'none' threshold always returns 0."""
    f = Finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL,
                "GET /users", None, "gone", {}, {})
    code = print_summary([f], "none")
    assert code == 0


def test_print_summary_medium_threshold(capsys) -> None:
    """MEDIUM finding with 'medium' threshold should return 1."""
    f = Finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM,
                "GET /items", None, "Slow", {}, {})
    code = print_summary([f], "medium")
    assert code == 1


# ── Replay helpers ────────────────────────────────────────────────────────────


def test_retarget_url_changes_host() -> None:
    """_retarget_url should replace scheme+host and keep path+query."""
    result = _retarget_url(
        "http://api-v1.example.com/users/1?page=2",
        "http://api-v2.example.com"
    )
    assert "api-v2.example.com" in result
    assert "/users/1" in result
    assert "page=2" in result
    assert "api-v1" not in result


def test_retarget_url_https_to_http() -> None:
    result = _retarget_url("https://old.api.com/items", "http://localhost:8080")
    assert result.startswith("http://localhost:8080")
    assert "/items" in result


def test_clean_headers_strips_auth() -> None:
    """_clean_headers should strip authorization, cookie, host headers."""
    raw = {
        "Authorization": "Bearer token123",
        "Cookie": "session=abc",
        "Host": "api.example.com",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    cleaned = _clean_headers(raw)
    assert "Authorization" not in cleaned
    assert "Cookie" not in cleaned
    assert "Host" not in cleaned
    assert "Accept" in cleaned
    assert "Content-Type" in cleaned


def test_clean_headers_case_insensitive() -> None:
    """_clean_headers should strip regardless of header name casing."""
    raw = {"authorization": "Bearer x", "COOKIE": "val", "accept": "application/json"}
    cleaned = _clean_headers(raw)
    assert "authorization" not in cleaned
    assert "COOKIE" not in cleaned
    assert "accept" in cleaned


# ── Validator dict-based ──────────────────────────────────────────────────────


def test_validate_har_dict_valid() -> None:
    """validate_har_dict with a minimal valid HAR dict should pass."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/x/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": "{}"}},
            "timings": {"receive": 10},
        }
        for i in range(25)
    ]
    result = validate_har_dict({"log": {"entries": entries}})
    assert result.is_valid


def test_validate_har_dict_too_few_entries() -> None:
    result = validate_har_dict({"log": {"entries": []}})
    assert not result.is_valid
