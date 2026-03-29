"""tests/test_capture.py — Layer 1: Traffic Capture tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from capture.proxy import HARWriter
from capture.validator import validate_har, validate_har_dict


# ── Helpers ───────────────────────────────────────────────────────────────────


class _MockRequest:
    def __init__(self, method: str, url: str, host: str, body: str = ""):
        self.method = method
        self.pretty_url = url
        self.host = host
        self.headers = {"content-type": "application/json"}
        self._body = body

    def get_text(self) -> str:
        return self._body


class _MockResponse:
    def __init__(self, status: int = 200, body: str = "{}"):
        self.status_code = status
        self.headers = {"content-type": "application/json"}
        self._body = body

    def get_text(self) -> str:
        return self._body


class _MockFlow:
    def __init__(self, method: str, url: str, host: str, status: int = 200,
                 req_body: str = "", resp_body: str = "{}"):
        self.request = _MockRequest(method, url, host, req_body)
        self.response = _MockResponse(status, resp_body)


def _make_flow(host: str = "api.example.com", url: str = "http://api.example.com/users/1") -> _MockFlow:
    return _MockFlow("GET", url, host, 200, "", '{"id": 1}')


# ── Test: HARWriter writes entries ────────────────────────────────────────────


def test_har_writer_writes_entries(tmp_path: pathlib.Path) -> None:
    """HARWriter should write exactly N entries after N response() calls."""
    out = tmp_path / "out.har"
    writer = HARWriter(str(out))

    for i in range(5):
        flow = _MockFlow("GET", f"http://api.example.com/items/{i}", "api.example.com",
                         200, "", f'{{"id": {i}}}')
        writer.response(flow)

    writer.write()

    assert out.exists(), "Output HAR file should be created"
    data = json.loads(out.read_text())
    assert "log" in data
    assert "entries" in data["log"]
    assert len(data["log"]["entries"]) == 5, f"Expected 5 entries, got {len(data['log']['entries'])}"


def test_har_writer_filters_by_host(tmp_path: pathlib.Path) -> None:
    """HARWriter with filter_host should only record matching hosts."""
    out = tmp_path / "filtered.har"
    writer = HARWriter(str(out), filter_host="api.example.com")

    # 3 matching flows
    for i in range(3):
        writer.response(_MockFlow("GET", f"http://api.example.com/users/{i}", "api.example.com"))

    # 2 non-matching flows
    for i in range(2):
        writer.response(_MockFlow("GET", f"http://other.service.com/data/{i}", "other.service.com"))

    writer.write()

    data = json.loads(out.read_text())
    entries = data["log"]["entries"]
    assert len(entries) == 3, f"Expected 3 filtered entries, got {len(entries)}"
    for entry in entries:
        assert "api.example.com" in entry["request"]["url"]


def test_har_writer_entry_structure(tmp_path: pathlib.Path) -> None:
    """Each written entry should have required HAR fields."""
    out = tmp_path / "struct.har"
    writer = HARWriter(str(out))
    writer.response(_MockFlow("POST", "http://api.example.com/users", "api.example.com",
                              201, '{"name":"X"}', '{"id":99}'))
    writer.write()

    data = json.loads(out.read_text())
    entry = data["log"]["entries"][0]

    assert "request" in entry
    assert "response" in entry
    assert "timings" in entry
    assert entry["request"]["method"] == "POST"
    assert entry["response"]["status"] == 201
    assert "receive" in entry["timings"]


# ── Test: Validator rejects empty HAR ─────────────────────────────────────────


def test_validator_rejects_empty_har(tmp_path: pathlib.Path) -> None:
    """Validator should reject a HAR file with 0 entries."""
    har_path = tmp_path / "empty.har"
    har_path.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")

    result = validate_har(str(har_path))

    assert not result.is_valid, "Empty HAR should be invalid"
    assert len(result.errors) > 0, "Should have errors"
    assert any("entries" in e.lower() or "few" in e.lower() for e in result.errors)


def test_validator_rejects_missing_log_key(tmp_path: pathlib.Path) -> None:
    """Validator should reject a HAR with no 'log' key."""
    har_path = tmp_path / "bad.har"
    har_path.write_text(json.dumps({"notlog": {}}), encoding="utf-8")

    result = validate_har(str(har_path))
    assert not result.is_valid


def test_validator_rejects_invalid_json(tmp_path: pathlib.Path) -> None:
    """Validator should return an error for non-JSON files."""
    har_path = tmp_path / "garbage.har"
    har_path.write_text("this is not json!!", encoding="utf-8")

    result = validate_har(str(har_path))
    assert not result.is_valid
    assert any("json" in e.lower() for e in result.errors)


def test_validator_accepts_valid_har() -> None:
    """Validator should accept the 30-entry sample fixture HAR."""
    sample = pathlib.Path(__file__).parent.parent / "fixtures" / "sample.har"
    assert sample.exists(), f"Fixture not found: {sample}"

    result = validate_har(str(sample))
    assert result.is_valid, f"sample.har should be valid. Errors: {result.errors}"


def test_validator_warns_low_json_fraction(tmp_path: pathlib.Path) -> None:
    """Validator should warn when <80% of responses are JSON."""
    entries = []
    # 5 JSON responses
    for i in range(5):
        entries.append({
            "request": {"method": "GET", "url": f"http://api.example.com/items/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": "{}"}},
            "timings": {"receive": 10},
        })
    # 25 HTML responses
    for i in range(25):
        entries.append({
            "request": {"method": "GET", "url": f"http://api.example.com/pages/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "text/html"},
                         "content": {"text": "<html></html>"}},
            "timings": {"receive": 10},
        })

    har_path = tmp_path / "mostly_html.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    result = validate_har(str(har_path))
    assert result.is_valid  # Still valid, just a warning
    assert len(result.warnings) > 0, "Should warn about low JSON fraction"
