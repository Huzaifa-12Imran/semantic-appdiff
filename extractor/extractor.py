"""
extractor/extractor.py — extracts a RawSchema from a HAR file.

Processing pipeline:
    HAR file → group by (method, normalized_path) → parse JSON bodies
    → recursive field walker → FieldStats → EndpointSchema → RawSchema
"""

from __future__ import annotations

import json
import logging
import math
import pathlib
import time
from collections import defaultdict
from typing import Any

from capture.validator import validate_har
from extractor.models import EndpointSchema, FieldStats, RawSchema
from extractor.normalizer import endpoint_key, normalize_path

logger = logging.getLogger(__name__)

_MAX_DEPTH = 10           # max JSON recursion depth
_MAX_SAMPLES = 50         # max distinct sample values to keep
_HIGH_CARDINALITY = 1000  # field cardinality threshold


def extract(har_path: str, skip_validation: bool = False) -> RawSchema:
    """Extract a RawSchema from a HAR file.

    Args:
        har_path: Path to the HAR file.
        skip_validation: If True, skip the minimum-entry validation check
                         (useful for small fixture files in tests).

    Returns:
        A RawSchema describing all observed endpoints and field statistics.
    """
    path = pathlib.Path(har_path)
    if not path.exists():
        raise FileNotFoundError(f"HAR file not found: {har_path}")

    if not skip_validation:
        result = validate_har(har_path)
        if not result.is_valid:
            raise ValueError(f"Invalid HAR file: {'; '.join(result.errors)}")
        for warn in result.warnings:
            logger.warning(warn)

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])

    t0 = time.monotonic()

    # ── Group entries by endpoint key ─────────────────────────────────────────
    # endpoint_key → list of (status, response_text, latency_ms)
    groups: dict[str, list[tuple[int, str, float]]] = defaultdict(list)

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        timings = entry.get("timings", {})

        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        status = resp.get("status", 0)
        body_text = resp.get("content", {}).get("text", "") or ""
        latency = float(timings.get("receive", 0))

        key = endpoint_key(method, url)
        groups[key].append((status, body_text, latency))

    # ── Build EndpointSchema per group ────────────────────────────────────────
    endpoint_schemas: list[EndpointSchema] = []

    for key, records in groups.items():
        method, path_pattern = key.split(" ", 1)
        status_codes = sorted({r[0] for r in records})
        latencies = [r[2] for r in records]

        # Aggregate field data across all response bodies
        field_data = _aggregate_fields(records)
        field_stats = _build_field_stats(field_data, total=len(records))

        endpoint_schemas.append(
            EndpointSchema(
                method=method,
                path_pattern=path_pattern,
                status_codes=status_codes,
                fields=field_stats,
                response_count=len(records),
                latencies_ms=latencies,
            )
        )

    elapsed = time.monotonic() - t0
    return RawSchema(
        endpoints=endpoint_schemas,
        total_requests=len(entries),
        capture_duration_s=elapsed,
    )


# ── Field aggregation ─────────────────────────────────────────────────────────


def _aggregate_fields(
    records: list[tuple[int, str, float]],
) -> dict[str, dict]:
    """Walk all response bodies and aggregate field data.

    Returns a dict: field_path → {
        'values': list of observed values,
        'null_count': int,
        'presence_count': int,   # how many responses included this field
        'types': set of type name strings,
    }
    """
    # Track which fields appeared in each response
    all_fields: dict[str, dict] = defaultdict(
        lambda: {"values": [], "null_count": 0, "presence_count": 0, "types": set()}
    )
    total = len(records)

    for _status, body_text, _latency in records:
        if not body_text or not body_text.strip():
            continue  # Empty body – skip field extraction

        try:
            parsed = json.loads(body_text)
        except (json.JSONDecodeError, ValueError):
            logger.debug("Non-JSON response body, skipping field extraction")
            continue

        # Root-level arrays: treat as {items: [...]}
        if isinstance(parsed, list):
            parsed = {"items": parsed}

        if not isinstance(parsed, dict):
            continue  # Scalar root — uncommon, skip

        # Walk the JSON tree and record fields seen in this response
        seen_in_this = set()
        _walk(parsed, "", all_fields, seen_in_this, depth=0)

        # Increment presence count for each field seen in this response
        for field_path in seen_in_this:
            all_fields[field_path]["presence_count"] += 1

    return all_fields


def _walk(
    obj: Any,
    prefix: str,
    accumulator: dict[str, dict],
    seen_in_this: set[str],
    depth: int,
) -> None:
    """Recursively walk a JSON object and record field paths and values."""
    if depth > _MAX_DEPTH:
        logger.debug("Max recursion depth reached at prefix='%s'", prefix)
        return

    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            _record_value(path, v, accumulator, seen_in_this)
            if isinstance(v, (dict, list)):
                _walk(v, path, accumulator, seen_in_this, depth + 1)

    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                _walk(item, prefix, accumulator, seen_in_this, depth + 1)
            elif item is not None:
                _record_value(prefix, item, accumulator, seen_in_this)


def _record_value(
    path: str,
    value: Any,
    accumulator: dict[str, dict],
    seen_in_this: set[str],
) -> None:
    """Record a single field value into the accumulator."""
    entry = accumulator[path]
    type_name = type(value).__name__

    entry["types"].add(type_name)
    seen_in_this.add(path)

    if value is None:
        entry["null_count"] += 1
    else:
        if len(entry["values"]) < _MAX_SAMPLES * 20:  # collect generously, trim later
            entry["values"].append(value)


def _build_field_stats(
    field_data: dict[str, dict],
    total: int,
) -> list[FieldStats]:
    """Convert raw aggregated field data into FieldStats objects."""
    stats: list[FieldStats] = []

    for path, data in field_data.items():
        presence_count = data["presence_count"]
        null_count = data["null_count"]
        values_raw = data["values"]
        types = data["types"]

        presence_rate = presence_count / total if total > 0 else 0.0
        null_rate = null_count / presence_count if presence_count > 0 else 0.0

        # Deduplicate sample values
        seen: set[str] = set()
        distinct: list[Any] = []
        for v in values_raw:
            key = repr(v)
            if key not in seen:
                seen.add(key)
                distinct.append(v)

        high_cardinality = len(distinct) > _HIGH_CARDINALITY
        sample_values = distinct[:_MAX_SAMPLES]

        stats.append(
            FieldStats(
                path=path,
                observed_types=sorted(types),
                sample_values=sample_values,
                null_rate=null_rate,
                presence_rate=presence_rate,
                is_always_present=(presence_rate == 1.0),
                high_cardinality=high_cardinality,
            )
        )

    return stats
