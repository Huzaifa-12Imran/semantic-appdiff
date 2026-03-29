"""tests/test_reporter.py — Layer 5: Reporter tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from engine.models import Finding, FindingType, Severity
from reporter.json_reporter import findings_to_dict, write_json
from reporter.html_reporter import write_html


def _make_finding(ft: FindingType = FindingType.ENDPOINT_REMOVED,
                  sev: Severity = Severity.CRITICAL,
                  endpoint: str = "GET /users/{id}",
                  field: str | None = "status") -> Finding:
    return Finding(
        finding_type=ft, severity=sev, endpoint=endpoint, field=field,
        description="Test description.",
        v1_evidence={"key": "val1"},
        v2_evidence={"key": "val2"},
    )


# ── JSON Reporter ─────────────────────────────────────────────────────────────

def test_json_reporter_structure() -> None:
    """JSON output should have summary and findings keys with correct structure."""
    findings = [
        _make_finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL),
        _make_finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM, field=None),
    ]
    data = findings_to_dict(findings)

    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total"] == 2
    assert data["summary"]["by_severity"]["critical"] == 1
    assert data["summary"]["by_severity"]["medium"] == 1


def test_json_reporter_stable_sort() -> None:
    """Same findings should always produce the same JSON output (sorted)."""
    findings = [
        _make_finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM, endpoint="GET /b"),
        _make_finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL, endpoint="GET /a"),
    ]
    d1 = findings_to_dict(findings)
    # Reverse order
    d2 = findings_to_dict(list(reversed(findings)))
    assert d1 == d2, "JSON output should be identical regardless of input order"


def test_json_reporter_severity_sort_order() -> None:
    """CRITICAL findings should appear before HIGH before MEDIUM before LOW."""
    findings = [
        _make_finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM),
        _make_finding(FindingType.ENDPOINT_REMOVED, Severity.CRITICAL),
        _make_finding(FindingType.ERROR_RATE_INCREASE, Severity.HIGH),
    ]
    data = findings_to_dict(findings)
    sevs = [f["severity"] for f in data["findings"]]
    assert sevs == ["critical", "high", "medium"]


def test_write_json_creates_file(tmp_path: pathlib.Path) -> None:
    """write_json() should create a valid JSON file at the given path."""
    findings = [_make_finding()]
    out = tmp_path / "subdir" / "findings.json"
    write_json(findings, str(out))

    assert out.exists()
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 1


def test_json_reporter_empty_findings() -> None:
    """Empty findings list should produce valid output with total=0."""
    data = findings_to_dict([])
    assert data["summary"]["total"] == 0
    assert data["findings"] == []


# ── HTML Reporter ─────────────────────────────────────────────────────────────

def test_write_html_creates_file(tmp_path: pathlib.Path) -> None:
    """write_html() should produce a file containing expected HTML elements."""
    findings = [
        _make_finding(FindingType.ENUM_RENAME, Severity.CRITICAL, field="status"),
        _make_finding(FindingType.LATENCY_REGRESSION, Severity.MEDIUM, field=None),
    ]
    out = tmp_path / "report.html"
    write_html(findings, str(out))

    assert out.exists()
    content = out.read_text(encoding="utf-8")

    # Check basic structure
    assert "<!DOCTYPE html>" in content
    assert "apidiff" in content
    assert "__FINDINGS_JSON__" not in content  # placeholder should be replaced
    # Severity values should appear
    assert "critical" in content
    assert "medium" in content


def test_write_html_self_contained(tmp_path: pathlib.Path) -> None:
    """HTML report should be self-contained (no external script/link tags)."""
    out = tmp_path / "report.html"
    write_html([_make_finding()], str(out))
    content = out.read_text(encoding="utf-8")

    # Should not reference external resources
    assert 'src="http' not in content
    assert 'href="http' not in content
    assert 'src="https' not in content


def test_write_html_findings_json_embedded(tmp_path: pathlib.Path) -> None:
    """HTML report should contain the findings JSON as an embedded JS variable."""
    findings = [_make_finding(FindingType.ENDPOINT_ADDED, Severity.LOW, endpoint="POST /webhook")]
    out = tmp_path / "report.html"
    write_html(findings, str(out))
    content = out.read_text(encoding="utf-8")

    # The findings data should be embedded in the script
    assert "POST /webhook" in content
    assert "endpoint_added" in content
