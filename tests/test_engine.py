"""tests/test_engine.py — Layer 4: Diff Engine tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from engine.models import Finding, FindingType, Severity
from engine.diff import diff, exit_code
from engine.detectors import (
    detect_removed_endpoints,
    detect_added_endpoints,
    detect_status_code_change,
    detect_enum_rename,
    detect_value_dist_shift,
    detect_idempotency_broken,
    detect_co_occurrence_broken,
    detect_latency_regression,
    detect_error_rate_increase,
)
from fingerprint.builder import build_fingerprint_from_har
from fingerprint.models import (
    CoOccurrence,
    EndpointFingerprint,
    Fingerprint,
    IdempotencyProfile,
    ValueDistribution,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _make_fingerprint(**endpoints) -> Fingerprint:
    """Build a minimal Fingerprint from EndpointFingerprint kwargs."""
    return Fingerprint(endpoints=endpoints, schema_hash="test", created_at="2024-01-01T00:00:00Z")


def _make_ep(
    key: str,
    status_codes: list[int] = None,
    dists: list[ValueDistribution] = None,
    latency_p99: float = 100.0,
    latency_p50: float = 50.0,
    error_rate: float = 0.0,
    co_occurrences: list[CoOccurrence] = None,
    idempotency: IdempotencyProfile = None,
) -> EndpointFingerprint:
    if idempotency is None:
        idempotency = IdempotencyProfile(endpoint_key=key, sample_size=0,
                                         is_idempotent=False, variance_rate=0.0, unknown=True)
    return EndpointFingerprint(
        endpoint_key=key,
        value_distributions=dists or [],
        co_occurrences=co_occurrences or [],
        idempotency=idempotency,
        latency_p50=latency_p50,
        latency_p99=latency_p99,
        error_rate=error_rate,
        status_codes=status_codes or [200],
    )


def _make_dist(field: str, counts: dict, categorical: bool = True) -> ValueDistribution:
    return ValueDistribution(
        field_path=field, value_counts=counts,
        numeric_percentiles={}, is_categorical=categorical, entropy=1.0
    )


# ── 1. Removed endpoints ──────────────────────────────────────────────────────

def test_detect_removed_endpoints() -> None:
    fp1 = _make_fingerprint(**{"GET /users/{id}": _make_ep("GET /users/{id}"),
                               "GET /orders": _make_ep("GET /orders")})
    fp2 = _make_fingerprint(**{"GET /users/{id}": _make_ep("GET /users/{id}")})

    findings = detect_removed_endpoints(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.ENDPOINT_REMOVED
    assert findings[0].severity == Severity.CRITICAL
    assert "GET /orders" in findings[0].endpoint


# ── 2. Added endpoints ────────────────────────────────────────────────────────

def test_detect_added_endpoints() -> None:
    fp1 = _make_fingerprint(**{"GET /users/{id}": _make_ep("GET /users/{id}")})
    fp2 = _make_fingerprint(**{"GET /users/{id}": _make_ep("GET /users/{id}"),
                               "POST /webhooks": _make_ep("POST /webhooks")})

    findings = detect_added_endpoints(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.ENDPOINT_ADDED
    assert findings[0].severity == Severity.LOW


# ── 3. Status code change ─────────────────────────────────────────────────────

def test_detect_status_code_change() -> None:
    fp1 = _make_fingerprint(**{"POST /users": _make_ep("POST /users", status_codes=[200])})
    fp2 = _make_fingerprint(**{"POST /users": _make_ep("POST /users", status_codes=[201])})

    findings = detect_status_code_change(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.STATUS_CODE_CHANGE
    assert findings[0].severity == Severity.HIGH


def test_no_status_code_change_when_same() -> None:
    fp1 = _make_fingerprint(**{"GET /items": _make_ep("GET /items", status_codes=[200, 404])})
    fp2 = _make_fingerprint(**{"GET /items": _make_ep("GET /items", status_codes=[200, 404])})
    assert detect_status_code_change(fp1, fp2) == []


# ── 4. Enum rename ────────────────────────────────────────────────────────────

def test_detect_enum_rename() -> None:
    ep_v1 = _make_ep("GET /items/{id}", dists=[
        _make_dist("status", {"active": 10, "inactive": 5})
    ])
    ep_v2 = _make_ep("GET /items/{id}", dists=[
        _make_dist("status", {"enabled": 10, "disabled": 5})
    ])
    fp1 = _make_fingerprint(**{"GET /items/{id}": ep_v1})
    fp2 = _make_fingerprint(**{"GET /items/{id}": ep_v2})

    findings = detect_enum_rename(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.ENUM_RENAME
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].field == "status"


def test_detect_enum_rename_from_fixture() -> None:
    """End-to-end: enum_rename fixtures should produce ENUM_RENAME finding."""
    fp1 = build_fingerprint_from_har(str(FIXTURES / "enum_rename/v1.har"), skip_validation=True)
    fp2 = build_fingerprint_from_har(str(FIXTURES / "enum_rename/v2.har"), skip_validation=True)
    findings = diff(fp1, fp2)
    types = {f.finding_type for f in findings}
    assert FindingType.ENUM_RENAME in types, f"Expected ENUM_RENAME in {types}"


# ── 5. Value distribution shift ───────────────────────────────────────────────

def test_detect_value_dist_shift() -> None:
    # v1: 90% active, 10% inactive  →  v2: 10% active, 90% inactive
    ep_v1 = _make_ep("GET /items/{id}", dists=[
        _make_dist("status", {"active": 90, "inactive": 10})
    ])
    ep_v2 = _make_ep("GET /items/{id}", dists=[
        _make_dist("status", {"active": 10, "inactive": 90})
    ])
    fp1 = _make_fingerprint(**{"GET /items/{id}": ep_v1})
    fp2 = _make_fingerprint(**{"GET /items/{id}": ep_v2})

    findings = detect_value_dist_shift(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.VALUE_DISTRIBUTION_SHIFT
    assert findings[0].severity == Severity.MEDIUM


# ── 6. Idempotency broken ─────────────────────────────────────────────────────

def test_detect_idempotency_broken() -> None:
    idp_ok = IdempotencyProfile("GET /item/{id}", sample_size=5,
                                is_idempotent=True, variance_rate=0.0, unknown=False)
    idp_broken = IdempotencyProfile("GET /item/{id}", sample_size=5,
                                    is_idempotent=False, variance_rate=0.8, unknown=False)
    fp1 = _make_fingerprint(**{"GET /item/{id}": _make_ep("GET /item/{id}", idempotency=idp_ok)})
    fp2 = _make_fingerprint(**{"GET /item/{id}": _make_ep("GET /item/{id}", idempotency=idp_broken)})

    findings = detect_idempotency_broken(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.IDEMPOTENCY_BROKEN
    assert findings[0].severity == Severity.CRITICAL


def test_detect_idempotency_from_fixture() -> None:
    """End-to-end: idempotency fixtures should produce IDEMPOTENCY_BROKEN finding."""
    fp1 = build_fingerprint_from_har(str(FIXTURES / "idempotency/v1.har"), skip_validation=True)
    fp2 = build_fingerprint_from_har(str(FIXTURES / "idempotency/v2.har"), skip_validation=True)
    findings = diff(fp1, fp2)
    types = {f.finding_type for f in findings}
    assert FindingType.IDEMPOTENCY_BROKEN in types, f"Expected IDEMPOTENCY_BROKEN in {types}"


# ── 7. Co-occurrence broken ───────────────────────────────────────────────────

def test_detect_co_occurrence_broken() -> None:
    co_v1 = CoOccurrence(field_a="type", field_b="quota",
                         p_b_given_a=0.98, condition_value="premium")
    co_v2 = CoOccurrence(field_a="type", field_b="quota",
                         p_b_given_a=0.40, condition_value="premium")  # dropped below 0.70
    fp1 = _make_fingerprint(**{"GET /accounts/{id}":
                               _make_ep("GET /accounts/{id}", co_occurrences=[co_v1])})
    fp2 = _make_fingerprint(**{"GET /accounts/{id}":
                               _make_ep("GET /accounts/{id}", co_occurrences=[co_v2])})

    findings = detect_co_occurrence_broken(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.CO_OCCURRENCE_BROKEN
    assert findings[0].severity == Severity.HIGH


# ── 8. Latency regression ─────────────────────────────────────────────────────

def test_detect_latency_regression() -> None:
    fp1 = _make_fingerprint(**{"GET /data/{id}": _make_ep("GET /data/{id}", latency_p99=100.0)})
    fp2 = _make_fingerprint(**{"GET /data/{id}": _make_ep("GET /data/{id}", latency_p99=200.0)})

    findings = detect_latency_regression(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.LATENCY_REGRESSION


def test_detect_latency_regression_from_fixture() -> None:
    """End-to-end: latency fixtures should produce LATENCY_REGRESSION finding."""
    fp1 = build_fingerprint_from_har(str(FIXTURES / "latency/v1.har"), skip_validation=True)
    fp2 = build_fingerprint_from_har(str(FIXTURES / "latency/v2.har"), skip_validation=True)
    findings = diff(fp1, fp2)
    types = {f.finding_type for f in findings}
    assert FindingType.LATENCY_REGRESSION in types, f"Expected LATENCY_REGRESSION in {types}"


# ── 9. Error rate increase ────────────────────────────────────────────────────

def test_detect_error_rate_increase() -> None:
    fp1 = _make_fingerprint(**{"GET /compute/{id}": _make_ep("GET /compute/{id}", error_rate=0.02)})
    fp2 = _make_fingerprint(**{"GET /compute/{id}": _make_ep("GET /compute/{id}", error_rate=0.20)})

    findings = detect_error_rate_increase(fp1, fp2)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.ERROR_RATE_INCREASE
    assert findings[0].severity == Severity.HIGH


def test_detect_error_rate_from_fixture() -> None:
    """End-to-end: error_rate fixtures should produce ERROR_RATE_INCREASE finding."""
    fp1 = build_fingerprint_from_har(str(FIXTURES / "error_rate/v1.har"), skip_validation=True)
    fp2 = build_fingerprint_from_har(str(FIXTURES / "error_rate/v2.har"), skip_validation=True)
    findings = diff(fp1, fp2)
    types = {f.finding_type for f in findings}
    assert FindingType.ERROR_RATE_INCREASE in types, f"Expected ERROR_RATE_INCREASE in {types}"


# ── Exit code logic ───────────────────────────────────────────────────────────

def test_exit_code_no_findings() -> None:
    assert exit_code([], "high") == 0


def test_exit_code_critical_with_high_threshold() -> None:
    f = Finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL,
                "GET /users", None, "desc", {}, {})
    assert exit_code([f], "high") == 2


def test_exit_code_high_with_high_threshold() -> None:
    f = Finding(FindingType.ERROR_RATE_INCREASE, Severity.HIGH,
                "GET /data", None, "desc", {}, {})
    assert exit_code([f], "high") == 1


def test_exit_code_none_threshold_always_zero() -> None:
    f = Finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL,
                "GET /users", None, "desc", {}, {})
    assert exit_code([f], "none") == 0


def test_exit_code_critical_threshold_ignores_high() -> None:
    f = Finding(FindingType.ERROR_RATE_INCREASE, Severity.HIGH,
                "GET /data", None, "desc", {}, {})
    assert exit_code([f], "critical") == 0  # only critical triggers non-zero
