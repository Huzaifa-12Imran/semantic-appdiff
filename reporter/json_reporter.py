"""
reporter/json_reporter.py — produces stable JSON output from findings.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import asdict

from engine.models import Finding, Severity


_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def findings_to_dict(findings: list[Finding]) -> dict:
    """Convert findings to a stable, sorted dict ready for JSON serialization."""
    sorted_findings = sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.endpoint, f.finding_type.value),
    )

    by_severity: dict[str, int] = {s.value: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        by_severity[f.severity.value] += 1

    serialized = []
    for f in sorted_findings:
        serialized.append({
            "type": f.finding_type.value,
            "severity": f.severity.value,
            "endpoint": f.endpoint,
            "field": f.field,
            "description": f.description,
            "v1_evidence": f.v1_evidence,
            "v2_evidence": f.v2_evidence,
        })

    return {
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
        },
        "findings": serialized,
    }


def write_json(findings: list[Finding], out_path: str) -> pathlib.Path:
    """Write findings to a stable JSON file.

    Args:
        findings: List of Finding objects from diff().
        out_path: Output file path.

    Returns:
        Path to the written file.
    """
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = findings_to_dict(findings)
    out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return out
