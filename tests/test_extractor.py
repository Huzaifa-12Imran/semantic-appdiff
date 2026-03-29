"""tests/test_extractor.py — Layer 2: Schema Extractor tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from extractor.models import RawSchema
from extractor.normalizer import normalize_path, endpoint_key
from extractor.extractor import extract


# ── Path normalizer tests ─────────────────────────────────────────────────────


def test_normalize_path_numeric_id() -> None:
    assert normalize_path("/users/123") == "/users/{id}"


def test_normalize_path_uuid() -> None:
    assert normalize_path("/orders/550e8400-e29b-41d4-a716-446655440000") == "/orders/{uuid}"


def test_normalize_path_word_segment_kept() -> None:
    assert normalize_path("/api/v1/users") == "/api/v1/users"


def test_normalize_path_mixed() -> None:
    assert normalize_path("/users/42/orders/550e8400-e29b-41d4-a716-446655440001") == \
           "/users/{id}/orders/{uuid}"


def test_normalize_path_from_full_url() -> None:
    result = normalize_path("http://api.example.com/users/999?page=1")
    assert result == "/users/{id}"


def test_normalize_path_param_segment() -> None:
    # A segment with numbers+letters should become {param}
    result = normalize_path("/sessions/abc123def")
    assert result == "/sessions/{param}"


def test_normalize_path_version_kept() -> None:
    assert normalize_path("/v2/products") == "/v2/products"


def test_endpoint_key() -> None:
    assert endpoint_key("get", "http://api.example.com/users/99") == "GET /users/{id}"


# ── Extractor tests ───────────────────────────────────────────────────────────


def test_extractor_groups_by_endpoint() -> None:
    """The extractor should group entries by (method, normalized_path)."""
    sample = pathlib.Path(__file__).parent.parent / "fixtures" / "sample.har"
    schema = extract(str(sample), skip_validation=True)

    keys = {f"{ep.method} {ep.path_pattern}" for ep in schema.endpoints}
    # sample.har has GET /users/{id}, GET /orders/{uuid}, GET /products/{id},
    # POST /users, POST /orders, DELETE /users/{id}, PUT /users/{id}
    assert "GET /users/{id}" in keys
    assert "GET /orders/{uuid}" in keys
    assert "POST /users" in keys


def test_extractor_field_null_rate(tmp_path: pathlib.Path) -> None:
    """Null rate should be 0.3 when 3 out of 10 responses have a null email."""
    entries = []
    for i in range(10):
        email = None if i < 3 else f"user{i}@example.com"
        body = {"id": i, "email": email, "name": f"User {i}"}
        entries.append({
            "request": {"method": "GET", "url": f"http://api.example.com/users/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps(body)}},
            "timings": {"receive": 30.0},
        })

    har_path = tmp_path / "test.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    schema = extract(str(har_path), skip_validation=True)
    assert len(schema.endpoints) == 1

    ep = schema.endpoints[0]
    email_field = next((f for f in ep.fields if f.path == "email"), None)
    assert email_field is not None, "email field should be extracted"
    assert abs(email_field.null_rate - 0.3) < 0.01, f"Expected null_rate≈0.3, got {email_field.null_rate}"


def test_extractor_handles_empty_body(tmp_path: pathlib.Path) -> None:
    """Extractor should not crash when response body is empty."""
    entries = [
        {
            "request": {"method": "DELETE", "url": "http://api.example.com/items/1",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 204, "headers": {"content-type": "application/json"},
                         "content": {"text": ""}},
            "timings": {"receive": 15.0},
        },
        *[{
            "request": {"method": "GET", "url": f"http://api.example.com/items/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({"id": i, "ok": True})}},
            "timings": {"receive": 20.0},
        } for i in range(1, 10)]
    ]

    har_path = tmp_path / "empty_body.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    # Should not raise
    schema = extract(str(har_path), skip_validation=True)
    assert schema.total_requests == 10


def test_extractor_handles_non_json_body(tmp_path: pathlib.Path) -> None:
    """Extractor should skip non-JSON bodies gracefully."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/pages/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "text/html"},
                         "content": {"text": "<html><body>Hello</body></html>"}},
            "timings": {"receive": 20.0},
        }
        for i in range(5)
    ]

    har_path = tmp_path / "html_resp.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    # Should not raise
    schema = extract(str(har_path), skip_validation=True)
    assert schema.total_requests == 5


def test_extractor_is_always_present(tmp_path: pathlib.Path) -> None:
    """Fields present in all responses should have is_always_present=True."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/users/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({"id": i, "name": f"User {i}"})}},
            "timings": {"receive": 25.0},
        }
        for i in range(10)
    ]

    har_path = tmp_path / "always_present.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")
    schema = extract(str(har_path), skip_validation=True)

    ep = schema.endpoints[0]
    id_field = next((f for f in ep.fields if f.path == "id"), None)
    assert id_field is not None
    assert id_field.is_always_present, "id field should always be present"
