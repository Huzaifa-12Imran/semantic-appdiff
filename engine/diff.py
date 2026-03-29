"""
engine/diff.py — orchestrates all nine detectors into a single diff() call.
"""

from __future__ import annotations

import logging

from engine.detectors import (
    detect_added_endpoints,
    detect_co_occurrence_broken,
    detect_enum_rename,
    detect_error_rate_increase,
    detect_idempotency_broken,
    detect_latency_regression,
    detect_removed_endpoints,
    detect_status_code_change,
    detect_value_dist_shift,
)
from engine.models import Finding, Severity
from fingerprint.models import Fingerprint

logger = logging.getLogger(__name__)

# Ordered list of all detectors (run in this sequence)
_DETECTORS = [
    detect_removed_endpoints,
    detect_added_endpoints,
    detect_status_code_change,
    detect_enum_rename,
    detect_value_dist_shift,
    detect_idempotency_broken,
    detect_co_occurrence_broken,
    detect_latency_regression,
    detect_error_rate_increase,
]


def diff(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """Compare two Fingerprints and return all behavioral Findings.

    Runs all nine detectors in sequence and concatenates results.
    Findings are returned sorted by severity (CRITICAL first) then endpoint.

    Args:
        fp_v1: Fingerprint from the baseline (old) API version.
        fp_v2: Fingerprint from the candidate (new) API version.

    Returns:
        A list of Finding objects, sorted by severity descending.
    """
    all_findings: list[Finding] = []

    for detector in _DETECTORS:
        try:
            results = detector(fp_v1, fp_v2)
            all_findings.extend(results)
            if results:
                logger.debug("%s: %d findings", detector.__name__, len(results))
        except Exception as exc:
            logger.warning("Detector %s failed: %s", detector.__name__, exc)

    # Sort: CRITICAL first, then by endpoint for stability
    all_findings.sort(key=lambda f: (-f.severity.rank, f.endpoint))
    return all_findings


def exit_code(findings: list[Finding], fail_on: str = "high") -> int:
    """Compute the CLI exit code based on findings and the fail_on threshold.

    Exit codes:
        0 — No findings at severity >= threshold
        1 — One or more HIGH or CRITICAL findings
        2 — One or more CRITICAL findings
        3 — Tool error (handled at the CLI level)

    Args:
        findings: List of Finding objects from diff().
        fail_on: Threshold string: "critical", "high", "medium", "none".
    """
    fail_on = fail_on.lower().strip()

    if fail_on == "none":
        return 0

    severities = {f.severity for f in findings}

    has_critical = Severity.CRITICAL in severities
    has_high = Severity.HIGH in severities
    has_medium = Severity.MEDIUM in severities

    if has_critical:
        if fail_on in ("critical", "high", "medium"):
            return 2
    if has_high:
        if fail_on in ("high", "medium"):
            return 1
    if has_medium:
        if fail_on == "medium":
            return 1

    return 0
