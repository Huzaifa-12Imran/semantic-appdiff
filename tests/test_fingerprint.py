"""tests/test_fingerprint.py — Layer 3: Fingerprint Builder tests."""

from __future__ import annotations

import json
import math
import pathlib

import pytest

from extractor.extractor import extract
from fingerprint.builder import (
    build_fingerprint,
    build_fingerprint_from_har,
    save_fingerprint,
    load_fingerprint,
    _compute_distribution,
)
from fingerprint.models import Fingerprint


# ── ValueDistribution tests ───────────────────────────────────────────────────


def test_distribution_categorical_small_cardinality() -> None:
    """Fields with ≤20 distinct values should be categorical."""
    values = ["active", "inactive", "active", "active", "inactive"] * 4
    dist = _compute_distribution(values, "status")
    assert dist is not None
    assert dist.is_categorical
    assert "active" in dist.value_counts
    assert "inactive" in dist.value_counts
    assert dist.value_counts["active"] == 12
    assert dist.value_counts["inactive"] == 8


def test_distribution_non_categorical() -> None:
    """Fields with >20 distinct values should NOT be categorical."""
    values = [str(i) for i in range(50)]  # 50 distinct values
    dist = _compute_distribution(values, "score")
    assert dist is not None
    assert not dist.is_categorical


def test_distribution_entropy_uniform() -> None:
    """A distribution with two equally likely values has entropy = 1.0 bit."""
    values = ["a", "b"] * 50  # 50/50 split
    dist = _compute_distribution(values, "field")
    assert dist is not None
    assert abs(dist.entropy - 1.0) < 0.01, f"Expected entropy≈1.0, got {dist.entropy}"


def test_distribution_entropy_single_value() -> None:
    """A distribution with only one value has entropy = 0."""
    values = ["active"] * 20
    dist = _compute_distribution(values, "field")
    assert dist is not None
    assert abs(dist.entropy - 0.0) < 0.01, f"Expected entropy≈0, got {dist.entropy}"


def test_distribution_numeric_percentiles() -> None:
    """Numeric non-categorical distributions should have percentiles computed."""
    values = list(range(1, 101))  # 100 distinct numeric values → not categorical
    dist = _compute_distribution([str(v) for v in values], "score")
    assert dist is not None
    assert not dist.is_categorical
    assert "50" in dist.numeric_percentiles
    assert abs(dist.numeric_percentiles["50"] - 50) < 2


def test_distribution_empty_values() -> None:
    """Empty value list should return None (no distribution)."""
    dist = _compute_distribution([], "field")
    assert dist is None


def test_distribution_all_null() -> None:
    """All-null value list should return None."""
    dist = _compute_distribution([None, None, None], "field")
    assert dist is None


# ── Fingerprint from RawSchema ────────────────────────────────────────────────


def test_build_fingerprint_from_schema(tmp_path: pathlib.Path) -> None:
    """build_fingerprint() should produce a Fingerprint from a RawSchema."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/items/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({"id": i, "status": "active"})}},
            "timings": {"receive": 30.0 + i},
        }
        for i in range(10)
    ]
    har_path = tmp_path / "test.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    schema = extract(str(har_path), skip_validation=True)
    fp = build_fingerprint(schema)

    assert isinstance(fp, Fingerprint)
    assert len(fp.endpoints) == 1
    assert fp.schema_hash
    assert fp.created_at


def test_fingerprint_latency_percentiles(tmp_path: pathlib.Path) -> None:
    """Latency percentiles should be computed correctly."""
    latencies = list(range(10, 110, 10))  # 10, 20, ..., 100 ms
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/data/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({"id": i})}},
            "timings": {"receive": float(latencies[i])},
        }
        for i in range(10)
    ]
    har_path = tmp_path / "latency.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    schema = extract(str(har_path), skip_validation=True)
    fp = build_fingerprint(schema)
    ep = list(fp.endpoints.values())[0]

    assert 50 <= ep.latency_p50 <= 60, f"P50 expected ~55, got {ep.latency_p50}"
    assert ep.latency_p99 >= 90, f"P99 should be high, got {ep.latency_p99}"


# ── Serialization roundtrip ───────────────────────────────────────────────────


def test_save_and_load_fingerprint(tmp_path: pathlib.Path) -> None:
    """Fingerprints should survive a save → load roundtrip."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/users/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({"id": i, "role": "user"})}},
            "timings": {"receive": 40.0},
        }
        for i in range(5)
    ]
    har_path = tmp_path / "test.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    schema = extract(str(har_path), skip_validation=True)
    fp = build_fingerprint(schema)

    out_path = str(tmp_path / "fp.json")
    save_fingerprint(fp, out_path)
    loaded = load_fingerprint(out_path)

    assert loaded.schema_hash == fp.schema_hash
    assert set(loaded.endpoints.keys()) == set(fp.endpoints.keys())


# ── Full HAR fingerprint ──────────────────────────────────────────────────────


def test_build_fingerprint_from_har_full(tmp_path: pathlib.Path) -> None:
    """build_fingerprint_from_har() should work end-to-end."""
    entries = [
        {
            "request": {"method": "GET", "url": f"http://api.example.com/accounts/{i}",
                        "headers": {}, "postData": {"text": ""}},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "content": {"text": json.dumps({
                             "id": i,
                             "type": "premium" if i % 3 == 0 else "basic",
                             "quota": 100 if i % 3 == 0 else None,
                         })}},
            "timings": {"receive": 35.0},
        }
        for i in range(1, 11)
    ]
    har_path = tmp_path / "full.har"
    har_path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")

    fp = build_fingerprint_from_har(str(har_path), skip_validation=True)
    assert isinstance(fp, Fingerprint)
    assert len(fp.endpoints) >= 1
