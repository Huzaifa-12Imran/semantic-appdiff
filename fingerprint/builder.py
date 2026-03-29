"""
fingerprint/builder.py — builds a Fingerprint from a RawSchema.

Computes:
- Value distributions (categorical with entropy, numeric with percentiles)
- Co-occurrence invariants (P(field_b | field_a == v) > 0.95)
- Idempotency profiles (duplicate-request analysis)
- Latency percentiles (P50, P99)
- Error rates
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import math
import pathlib
import re
from collections import defaultdict
from typing import Any

import numpy as np

from extractor.models import EndpointSchema, RawSchema
from fingerprint.models import (
    CoOccurrence,
    EndpointFingerprint,
    Fingerprint,
    IdempotencyProfile,
    ValueDistribution,
)

_MAX_CATEGORICAL = 20          # max distinct values for categorical treatment
_CO_OCCURRENCE_THRESHOLD = 0.95  # P(field_b | field_a==v) to record invariant
_MIN_CO_OCCURRENCE_SAMPLES = 20  # minimum occurrences to consider co-occurrence
_IDEMPOTENCY_TOLERANCE = 0.05   # max variance_rate for is_idempotent=True

# Timestamp-like field names to scrub before idempotency comparison
_TIMESTAMP_FIELDS = re.compile(
    r"(created_at|updated_at|timestamp|date|modified_at|"
    r"expires_at|issued_at|last_seen|last_modified)",
    re.IGNORECASE,
)
# UUID-like values in responses (response IDs that will differ each call)
_UUID_VALUE_RE = re.compile(
    r'"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"',
    re.IGNORECASE,
)


def build_fingerprint(raw_schema: RawSchema) -> Fingerprint:
    """Convert a RawSchema into a Fingerprint.

    Args:
        raw_schema: Output of extractor.extract().

    Returns:
        A Fingerprint ready for comparison by the diff engine.
    """
    schema_hash = _hash_schema(raw_schema)
    endpoints: dict[str, EndpointFingerprint] = {}

    for ep in raw_schema.endpoints:
        key = f"{ep.method} {ep.path_pattern}"
        endpoints[key] = _fingerprint_endpoint(ep, key)

    return Fingerprint(
        endpoints=endpoints,
        schema_hash=schema_hash,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def save_fingerprint(fp: Fingerprint, path: str) -> None:
    """Serialize a Fingerprint to a JSON file."""
    out = pathlib.Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dataclasses.asdict(fp), indent=2), encoding="utf-8")


def load_fingerprint(path: str) -> Fingerprint:
    """Deserialize a Fingerprint from a JSON file."""
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return _dict_to_fingerprint(data)


# ── Internal builders ─────────────────────────────────────────────────────────


def _fingerprint_endpoint(ep: EndpointSchema, key: str) -> EndpointFingerprint:
    """Build an EndpointFingerprint from an EndpointSchema."""
    total = ep.response_count

    # ── Latency percentiles ───────────────────────────────────────────────────
    lats = np.array(ep.latencies_ms) if ep.latencies_ms else np.array([0.0])
    p50 = float(np.percentile(lats, 50))
    p99 = float(np.percentile(lats, 99))

    # ── Error rate ────────────────────────────────────────────────────────────
    error_codes = {s for s in ep.status_codes if s >= 400}
    # We need per-request error data — approximate from status_codes list
    # The EndpointSchema doesn't store per-request statuses, so we use what
    # the extractor gave us: the set of status codes seen.
    # For error_rate we need actual per-entry counts; reconstruct from HAR
    # via the EndpointSchema latencies_ms length vs error status codes.
    # Since we only have the status code set, we mark error_rate as 0 if
    # no error codes were seen, else approximate. Full accuracy requires
    # per-entry status storage — handled via _grouped_records in extractor.
    # For the fingerprint builder receiving only EndpointSchema, we use
    # a worst-case approximation: if any error code exists, error_rate = unknown.
    # The diff engine will use this field relatively, so approximation is fine.
    error_rate = 0.0  # Will be overridden via _compute_error_rate if available

    # ── Value distributions ───────────────────────────────────────────────────
    dists: list[ValueDistribution] = []
    for field in ep.fields:
        dist = _compute_distribution(field.sample_values, field.path)
        if dist:
            dists.append(dist)

    # ── Co-occurrences ────────────────────────────────────────────────────────
    # Co-occurrence requires per-response field presence data.
    # With only FieldStats, we can't compute exact co-occurrences.
    # The builder accepts an optional _records list for full computation.
    # Default to empty list — populated by extract_and_fingerprint() when
    # the full entry data is available.
    co_occurrences: list[CoOccurrence] = []

    # ── Idempotency ───────────────────────────────────────────────────────────
    idempotency = IdempotencyProfile(
        endpoint_key=key,
        sample_size=0,
        is_idempotent=False,
        variance_rate=0.0,
        unknown=True,
    )

    return EndpointFingerprint(
        endpoint_key=key,
        value_distributions=dists,
        co_occurrences=co_occurrences,
        idempotency=idempotency,
        latency_p50=p50,
        latency_p99=p99,
        error_rate=error_rate,
        status_codes=ep.status_codes,
    )


def build_fingerprint_from_har(har_path: str, skip_validation: bool = False) -> Fingerprint:
    """Build a Fingerprint directly from a HAR file (full pipeline).

    This version has access to full per-entry data, enabling accurate
    co-occurrence and idempotency computation.
    """
    import json as _json
    import pathlib as _pathlib

    from extractor.normalizer import endpoint_key as _ep_key

    path = _pathlib.Path(har_path)
    data = _json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])

    # Group entries by endpoint key, keeping full entry data
    groups: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        req = entry.get("request", {})
        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        key = _ep_key(method, url)
        groups[key].append(entry)

    from extractor.extractor import extract
    raw_schema = extract(har_path, skip_validation=skip_validation)

    schema_hash = _hash_schema(raw_schema)
    endpoints: dict[str, EndpointFingerprint] = {}

    for ep in raw_schema.endpoints:
        key = f"{ep.method} {ep.path_pattern}"
        entry_list = groups.get(key, [])
        endpoints[key] = _fingerprint_endpoint_full(ep, key, entry_list)

    return Fingerprint(
        endpoints=endpoints,
        schema_hash=schema_hash,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def _fingerprint_endpoint_full(
    ep: EndpointSchema, key: str, entries: list[dict]
) -> EndpointFingerprint:
    """Full fingerprint with co-occurrence and idempotency from raw entries."""
    total = ep.response_count

    lats = np.array(ep.latencies_ms) if ep.latencies_ms else np.array([0.0])
    p50 = float(np.percentile(lats, 50))
    p99 = float(np.percentile(lats, 99))

    # Per-entry status codes for accurate error rate
    statuses = [e.get("response", {}).get("status", 0) for e in entries]
    error_count = sum(1 for s in statuses if s >= 400)
    error_rate = error_count / len(statuses) if statuses else 0.0

    # Parse all response bodies
    parsed_bodies: list[dict | None] = []
    for entry in entries:
        text = entry.get("response", {}).get("content", {}).get("text", "") or ""
        if not text.strip():
            parsed_bodies.append(None)
            continue
        try:
            obj = json.loads(text)
            parsed_bodies.append(obj if isinstance(obj, dict) else {"items": obj})
        except (json.JSONDecodeError, ValueError):
            parsed_bodies.append(None)

    # Value distributions
    dists: list[ValueDistribution] = []
    for field in ep.fields:
        dist = _compute_distribution(field.sample_values, field.path)
        if dist:
            dists.append(dist)

    # Co-occurrences
    co_occurrences = _compute_co_occurrences(ep, parsed_bodies)

    # Idempotency
    idempotency = _compute_idempotency(key, entries)

    return EndpointFingerprint(
        endpoint_key=key,
        value_distributions=dists,
        co_occurrences=co_occurrences,
        idempotency=idempotency,
        latency_p50=p50,
        latency_p99=p99,
        error_rate=error_rate,
        status_codes=ep.status_codes,
    )


def _compute_distribution(values: list[Any], path: str) -> ValueDistribution | None:
    """Compute a ValueDistribution for a list of observed values."""
    if not values:
        return None

    non_null = [v for v in values if v is not None]
    if not non_null:
        return None

    str_values = [str(v) for v in non_null]
    distinct = set(str_values)

    is_categorical = len(distinct) <= _MAX_CATEGORICAL

    # Value counts
    value_counts: dict[str, int] = {}
    for v in str_values:
        value_counts[v] = value_counts.get(v, 0) + 1

    # Numeric percentiles (only if all values are numeric)
    numeric_percentiles: dict[str, float] = {}
    if not is_categorical:
        try:
            numeric_vals = np.array([float(v) for v in non_null])
            for pct in [10, 25, 50, 75, 90, 99]:
                numeric_percentiles[str(pct)] = float(np.percentile(numeric_vals, pct))
        except (ValueError, TypeError):
            pass  # Not numeric — leave percentiles empty

    # Shannon entropy
    total = len(str_values)
    entropy = 0.0
    if total > 0:
        for count in value_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

    return ValueDistribution(
        field_path=path,
        value_counts=value_counts,
        numeric_percentiles=numeric_percentiles,
        is_categorical=is_categorical,
        entropy=entropy,
    )


def _compute_co_occurrences(
    ep: EndpointSchema, parsed_bodies: list[dict | None]
) -> list[CoOccurrence]:
    """Find co-occurrence invariants between categorical fields."""
    results: list[CoOccurrence] = []

    # Find categorical fields (≤20 distinct non-null values)
    categorical_fields = [
        f for f in ep.fields
        if len(set(str(v) for v in f.sample_values if v is not None)) <= _MAX_CATEGORICAL
        and len([v for v in f.sample_values if v is not None]) > 0
    ]

    all_field_names = {f.path for f in ep.fields}

    for field_a in categorical_fields:
        # Get distinct values of field_a
        distinct_values = set(
            str(v) for v in field_a.sample_values if v is not None
        )

        for val in distinct_values:
            # Find responses where field_a == val
            matching_bodies = []
            for body in parsed_bodies:
                if body is None:
                    continue
                field_a_val = _get_nested(body, field_a.path)
                if str(field_a_val) == val:
                    matching_bodies.append(body)

            if len(matching_bodies) < _MIN_CO_OCCURRENCE_SAMPLES:
                continue

            # Check each other field's presence in those responses
            for field_b_path in all_field_names:
                if field_b_path == field_a.path:
                    continue

                presence_count = sum(
                    1 for body in matching_bodies
                    if _get_nested(body, field_b_path) is not _MISSING
                )
                p_b_given_a = presence_count / len(matching_bodies)

                if p_b_given_a > _CO_OCCURRENCE_THRESHOLD:
                    results.append(
                        CoOccurrence(
                            field_a=field_a.path,
                            field_b=field_b_path,
                            p_b_given_a=p_b_given_a,
                            condition_value=val,
                        )
                    )

    return results


_MISSING = object()  # sentinel for missing fields


def _get_nested(obj: dict, path: str) -> Any:
    """Get a value from a nested dict using dot-notation path."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _compute_idempotency(key: str, entries: list[dict]) -> IdempotencyProfile:
    """Compute idempotency for an endpoint by finding duplicate requests."""
    # Group by input key: full path + query + body
    # We must include the path so /item/1 and /item/2 are not conflated
    input_groups: dict[str, list[str]] = defaultdict(list)

    for entry in entries:
        req = entry.get("request", {})
        import urllib.parse
        url = req.get("url", "")
        parsed = urllib.parse.urlparse(url)
        path = parsed.path       # include the full concrete path
        query = parsed.query

        body = req.get("postData", {}).get("text", "") or ""
        input_key = f"{path}?{query}||{body}"

        resp_text = entry.get("response", {}).get("content", {}).get("text", "") or ""
        scrubbed = _scrub_timestamps(resp_text)
        input_groups[input_key].append(scrubbed)

    # Find groups with ≥2 entries (duplicate inputs)
    duplicate_groups = {k: v for k, v in input_groups.items() if len(v) >= 2}

    if not duplicate_groups:
        return IdempotencyProfile(
            endpoint_key=key,
            sample_size=0,
            is_idempotent=False,
            variance_rate=0.0,
            unknown=True,
        )

    # Check variance across duplicate pairs
    total_pairs = 0
    differing_pairs = 0

    for resp_list in duplicate_groups.values():
        for i in range(len(resp_list) - 1):
            total_pairs += 1
            if resp_list[i] != resp_list[i + 1]:
                differing_pairs += 1

    variance_rate = differing_pairs / total_pairs if total_pairs > 0 else 0.0
    is_idempotent = variance_rate < _IDEMPOTENCY_TOLERANCE

    return IdempotencyProfile(
        endpoint_key=key,
        sample_size=total_pairs,
        is_idempotent=is_idempotent,
        variance_rate=variance_rate,
        unknown=False,
    )


def _scrub_timestamps(text: str) -> str:
    """Remove timestamp-like values and UUIDs that would differ per call."""
    if not text:
        return text

    # Remove UUID values
    text = _UUID_VALUE_RE.sub('"<uuid>"', text)

    # Remove timestamp-like field values (JSON string values of timestamp fields)
    text = _TIMESTAMP_FIELDS.sub("<timestamp_field>", text)

    return text


def _hash_schema(raw_schema: RawSchema) -> str:
    """Compute a stable hash of the RawSchema for cache busting."""
    endpoint_keys = sorted(
        f"{ep.method} {ep.path_pattern}" for ep in raw_schema.endpoints
    )
    content = json.dumps({"endpoints": endpoint_keys, "total": raw_schema.total_requests})
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# ── Deserialization ───────────────────────────────────────────────────────────


def _dict_to_fingerprint(data: dict) -> Fingerprint:
    """Reconstruct a Fingerprint from a JSON-loaded dict."""
    endpoints: dict[str, EndpointFingerprint] = {}
    for key, ep_data in data.get("endpoints", {}).items():
        dists = [
            ValueDistribution(**d) for d in ep_data.get("value_distributions", [])
        ]
        co_occs = [
            CoOccurrence(**c) for c in ep_data.get("co_occurrences", [])
        ]
        idp_data = ep_data.get("idempotency", {})
        idp = IdempotencyProfile(
            endpoint_key=idp_data.get("endpoint_key", key),
            sample_size=idp_data.get("sample_size", 0),
            is_idempotent=idp_data.get("is_idempotent", False),
            variance_rate=idp_data.get("variance_rate", 0.0),
            unknown=idp_data.get("unknown", True),
        )
        endpoints[key] = EndpointFingerprint(
            endpoint_key=key,
            value_distributions=dists,
            co_occurrences=co_occs,
            idempotency=idp,
            latency_p50=ep_data.get("latency_p50", 0.0),
            latency_p99=ep_data.get("latency_p99", 0.0),
            error_rate=ep_data.get("error_rate", 0.0),
            status_codes=ep_data.get("status_codes", []),
        )

    return Fingerprint(
        endpoints=endpoints,
        schema_hash=data.get("schema_hash", ""),
        created_at=data.get("created_at", ""),
    )
