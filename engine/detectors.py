"""
engine/detectors.py — the nine behavioral diff detectors.

Each detector is a standalone function:
    detect_*(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]

The main diff() function in diff.py calls all nine and concatenates results.
"""

from __future__ import annotations

import logging

from scipy.stats import chisquare

from engine.models import Finding, FindingType, Severity
from fingerprint.models import Fingerprint, ValueDistribution

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_CHI_SQUARED_P_THRESHOLD = 0.01     # p < 0.01 → distribution shift finding
_LATENCY_REGRESSION_THRESHOLD = 0.50  # P99 increase > 50%
_ERROR_RATE_THRESHOLD = 0.05        # error rate increase > 5pp
_CO_OCCURRENCE_BREAK_THRESHOLD = 0.70  # p_b_given_a drops below 70% in v2


# ── 1. Removed endpoints ─────────────────────────────────────────────────────


def detect_removed_endpoints(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """CRITICAL: endpoint present in v1 but absent in v2."""
    findings: list[Finding] = []
    removed = set(fp_v1.endpoints) - set(fp_v2.endpoints)
    for ep_key in sorted(removed):
        findings.append(Finding(
            finding_type=FindingType.ENDPOINT_REMOVED,
            severity=Severity.CRITICAL,
            endpoint=ep_key,
            field=None,
            description=(
                f"Endpoint '{ep_key}' was present in v1 but is missing in v2. "
                "Consumers calling this endpoint will receive 404 errors."
            ),
            v1_evidence={"endpoint": ep_key, "present": True},
            v2_evidence={"endpoint": ep_key, "present": False},
        ))
    return findings


# ── 2. Added endpoints ────────────────────────────────────────────────────────


def detect_added_endpoints(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """LOW: endpoint present in v2 but absent in v1 (informational)."""
    findings: list[Finding] = []
    added = set(fp_v2.endpoints) - set(fp_v1.endpoints)
    for ep_key in sorted(added):
        findings.append(Finding(
            finding_type=FindingType.ENDPOINT_ADDED,
            severity=Severity.LOW,
            endpoint=ep_key,
            field=None,
            description=(
                f"New endpoint '{ep_key}' was added in v2. "
                "This is informational — new endpoints are non-breaking additions."
            ),
            v1_evidence={"endpoint": ep_key, "present": False},
            v2_evidence={"endpoint": ep_key, "present": True},
        ))
    return findings


# ── 3. Status code changes ────────────────────────────────────────────────────


def detect_status_code_change(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """HIGH: observed status codes changed between versions."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)
    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]
        codes_v1 = set(ep1.status_codes)
        codes_v2 = set(ep2.status_codes)
        symmetric_diff = codes_v1.symmetric_difference(codes_v2)
        if symmetric_diff:
            findings.append(Finding(
                finding_type=FindingType.STATUS_CODE_CHANGE,
                severity=Severity.HIGH,
                endpoint=ep_key,
                field=None,
                description=(
                    f"The observed HTTP status codes for '{ep_key}' changed between versions. "
                    f"Added: {sorted(codes_v2 - codes_v1)}, "
                    f"removed: {sorted(codes_v1 - codes_v2)}."
                ),
                v1_evidence={"status_codes": sorted(codes_v1)},
                v2_evidence={"status_codes": sorted(codes_v2)},
            ))
    return findings


# ── 4. Enum renames ───────────────────────────────────────────────────────────


def detect_enum_rename(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """CRITICAL: a categorical field's set of distinct values changed."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]

        dist_map_v1 = {d.field_path: d for d in ep1.value_distributions if d.is_categorical}
        dist_map_v2 = {d.field_path: d for d in ep2.value_distributions if d.is_categorical}

        common_fields = set(dist_map_v1) & set(dist_map_v2)
        for field_path in sorted(common_fields):
            d1 = dist_map_v1[field_path]
            d2 = dist_map_v2[field_path]

            values_v1 = set(d1.value_counts.keys())
            values_v2 = set(d2.value_counts.keys())
            sym_diff = values_v1.symmetric_difference(values_v2)

            if sym_diff:
                # Only report if values were REPLACED (both removed and added)
                # If values were only added, that's less severe — handled by dist shift
                removed_values = values_v1 - values_v2
                added_values = values_v2 - values_v1
                if removed_values and added_values:
                    severity = Severity.CRITICAL  # rename: old values gone
                elif removed_values:
                    severity = Severity.HIGH  # values removed
                else:
                    severity = Severity.MEDIUM  # values added only

                findings.append(Finding(
                    finding_type=FindingType.ENUM_RENAME,
                    severity=severity,
                    endpoint=ep_key,
                    field=field_path,
                    description=(
                        f"The categorical field '{field_path}' on '{ep_key}' changed its set "
                        f"of values. Removed: {sorted(removed_values)}, "
                        f"added: {sorted(added_values)}. "
                        "Consumers checking for specific values will break."
                    ),
                    v1_evidence={"values": sorted(values_v1)},
                    v2_evidence={"values": sorted(values_v2)},
                ))
    return findings


# ── 5. Value distribution shift ───────────────────────────────────────────────


def detect_value_dist_shift(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """MEDIUM: a categorical field's distribution shifted significantly (chi-squared)."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]

        dist_map_v1 = {d.field_path: d for d in ep1.value_distributions if d.is_categorical}
        dist_map_v2 = {d.field_path: d for d in ep2.value_distributions if d.is_categorical}

        common_fields = set(dist_map_v1) & set(dist_map_v2)
        for field_path in sorted(common_fields):
            d1 = dist_map_v1[field_path]
            d2 = dist_map_v2[field_path]

            try:
                p_value = _compare_distributions(d1, d2)
            except Exception as exc:
                logger.debug("Chi-squared failed for %s.%s: %s", ep_key, field_path, exc)
                continue

            if p_value is not None and p_value < _CHI_SQUARED_P_THRESHOLD:
                findings.append(Finding(
                    finding_type=FindingType.VALUE_DISTRIBUTION_SHIFT,
                    severity=Severity.MEDIUM,
                    endpoint=ep_key,
                    field=field_path,
                    description=(
                        f"The distribution of values for '{field_path}' on '{ep_key}' "
                        f"shifted significantly (chi-squared p={p_value:.4f}, threshold=0.01). "
                        "The relative frequency of values has changed."
                    ),
                    v1_evidence={"value_counts": d1.value_counts, "entropy": d1.entropy},
                    v2_evidence={"value_counts": d2.value_counts, "entropy": d2.entropy},
                ))
    return findings


def _compare_distributions(dist_v1: ValueDistribution, dist_v2: ValueDistribution) -> float | None:
    """Run a chi-squared test comparing two categorical distributions.

    Returns the p-value, or None if the test cannot be run (e.g. all zeros).
    """
    all_values = sorted(set(dist_v1.value_counts) | set(dist_v2.value_counts))
    if len(all_values) < 2:
        return None  # Chi-squared requires at least 2 categories

    counts_v1 = [dist_v1.value_counts.get(v, 0) for v in all_values]
    counts_v2 = [dist_v2.value_counts.get(v, 0) for v in all_values]

    total_v1 = sum(counts_v1)
    total_v2 = sum(counts_v2)

    if total_v1 == 0 or total_v2 == 0:
        return None

    # Normalize v2 counts to same total as v1
    expected = [c * total_v1 / total_v2 for c in counts_v2]

    # Chi-squared requires all expected > 0
    if any(e == 0 for e in expected):
        # Add a small smoothing to avoid division by zero
        expected = [max(e, 0.01) for e in expected]

    _stat, p_value = chisquare(counts_v1, f_exp=expected)
    return float(p_value)


# ── 6. Idempotency broken ─────────────────────────────────────────────────────


def detect_idempotency_broken(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """CRITICAL: endpoint was idempotent in v1 but is not idempotent in v2."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]
        idp1 = ep1.idempotency
        idp2 = ep2.idempotency

        if (not idp1.unknown and idp1.is_idempotent
                and idp1.sample_size > 0
                and not idp2.unknown
                and not idp2.is_idempotent):
            findings.append(Finding(
                finding_type=FindingType.IDEMPOTENCY_BROKEN,
                severity=Severity.CRITICAL,
                endpoint=ep_key,
                field=None,
                description=(
                    f"Endpoint '{ep_key}' was idempotent in v1 "
                    f"(variance_rate={idp1.variance_rate:.2%}, n={idp1.sample_size}) "
                    f"but is NOT idempotent in v2 "
                    f"(variance_rate={idp2.variance_rate:.2%}). "
                    "Identical requests now produce different responses."
                ),
                v1_evidence={
                    "is_idempotent": True,
                    "variance_rate": idp1.variance_rate,
                    "sample_size": idp1.sample_size,
                },
                v2_evidence={
                    "is_idempotent": False,
                    "variance_rate": idp2.variance_rate,
                    "sample_size": idp2.sample_size,
                },
            ))
    return findings


# ── 7. Co-occurrence broken ───────────────────────────────────────────────────


def detect_co_occurrence_broken(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """HIGH: a co-occurrence invariant from v1 is violated in v2."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]

        # Build lookup: (field_a, field_b, condition_value) → p_b_given_a
        v2_lookup: dict[tuple[str, str, str], float] = {}
        for co in ep2.co_occurrences:
            v2_lookup[(co.field_a, co.field_b, co.condition_value)] = co.p_b_given_a

        for co_v1 in ep1.co_occurrences:
            key_tuple = (co_v1.field_a, co_v1.field_b, co_v1.condition_value)
            p_v2 = v2_lookup.get(key_tuple, 0.0)  # 0 if invariant completely gone

            if p_v2 < _CO_OCCURRENCE_BREAK_THRESHOLD:
                findings.append(Finding(
                    finding_type=FindingType.CO_OCCURRENCE_BROKEN,
                    severity=Severity.HIGH,
                    endpoint=ep_key,
                    field=co_v1.field_b,
                    description=(
                        f"Co-occurrence invariant broken on '{ep_key}': "
                        f"when '{co_v1.field_a}' == '{co_v1.condition_value}', "
                        f"field '{co_v1.field_b}' was present {co_v1.p_b_given_a:.0%} of the time in v1 "
                        f"but only {p_v2:.0%} in v2. "
                        "Consumers relying on this field being present will encounter KeyErrors."
                    ),
                    v1_evidence={
                        "field_a": co_v1.field_a,
                        "condition_value": co_v1.condition_value,
                        "p_b_given_a": co_v1.p_b_given_a,
                    },
                    v2_evidence={
                        "field_a": co_v1.field_a,
                        "condition_value": co_v1.condition_value,
                        "p_b_given_a": p_v2,
                    },
                ))
    return findings


# ── 8. Latency regression ─────────────────────────────────────────────────────


def detect_latency_regression(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """MEDIUM: P99 latency increased by more than 50%."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]

        p99_v1 = ep1.latency_p99
        p99_v2 = ep2.latency_p99

        if p99_v1 <= 0:
            continue  # No baseline to compare against

        increase = (p99_v2 - p99_v1) / p99_v1

        if increase > _LATENCY_REGRESSION_THRESHOLD:
            findings.append(Finding(
                finding_type=FindingType.LATENCY_REGRESSION,
                severity=Severity.MEDIUM,
                endpoint=ep_key,
                field=None,
                description=(
                    f"P99 latency for '{ep_key}' increased by {increase:.0%} "
                    f"(from {p99_v1:.1f}ms in v1 to {p99_v2:.1f}ms in v2, "
                    f"threshold: >{_LATENCY_REGRESSION_THRESHOLD:.0%})."
                ),
                v1_evidence={"p99_ms": p99_v1, "p50_ms": ep1.latency_p50},
                v2_evidence={"p99_ms": p99_v2, "p50_ms": ep2.latency_p50},
            ))
    return findings


# ── 9. Error rate increase ────────────────────────────────────────────────────


def detect_error_rate_increase(fp_v1: Fingerprint, fp_v2: Fingerprint) -> list[Finding]:
    """HIGH: error rate (4xx/5xx) increased by more than 5 percentage points."""
    findings: list[Finding] = []
    common = set(fp_v1.endpoints) & set(fp_v2.endpoints)

    for ep_key in sorted(common):
        ep1 = fp_v1.endpoints[ep_key]
        ep2 = fp_v2.endpoints[ep_key]

        delta = ep2.error_rate - ep1.error_rate
        if delta > _ERROR_RATE_THRESHOLD:
            findings.append(Finding(
                finding_type=FindingType.ERROR_RATE_INCREASE,
                severity=Severity.HIGH,
                endpoint=ep_key,
                field=None,
                description=(
                    f"Error rate (4xx/5xx) for '{ep_key}' increased by "
                    f"{delta:.1%} (from {ep1.error_rate:.1%} in v1 to "
                    f"{ep2.error_rate:.1%} in v2, threshold: >5pp)."
                ),
                v1_evidence={"error_rate": ep1.error_rate},
                v2_evidence={"error_rate": ep2.error_rate},
            ))
    return findings
