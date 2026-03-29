"""
capture/validator.py — validates HAR files before they enter the pipeline.

Every HAR file must pass validation before being processed by Layer 2.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """Result of HAR file validation."""

    is_valid: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"Valid: {self.is_valid}"]
        for err in self.errors:
            lines.append(f"  ERROR: {err}")
        for warn in self.warnings:
            lines.append(f"  WARN:  {warn}")
        return "\n".join(lines)


_MIN_ENTRIES = 20
_MIN_JSON_FRACTION = 0.80


def validate_har(har_path: str) -> ValidationResult:
    """Validate a HAR file at the given path.

    Checks:
    - File exists and is valid JSON.
    - Top-level structure has log.entries as a list.
    - Each entry has required fields.
    - Minimum 20 entries.
    - Warns if <80% of responses have application/json content-type.

    Returns:
        A ValidationResult with is_valid, warnings, and errors.
    """
    errors: list[str] = []
    warnings: list[str] = []
    path = pathlib.Path(har_path)

    # ── File existence ────────────────────────────────────────────────────────
    if not path.exists():
        return ValidationResult(
            is_valid=False,
            errors=[f"File not found: {har_path}"],
        )

    # ── JSON parse ────────────────────────────────────────────────────────────
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ValidationResult(
            is_valid=False,
            errors=[f"Invalid JSON: {exc}"],
        )

    # ── Top-level structure ───────────────────────────────────────────────────
    if "log" not in data:
        errors.append("Missing top-level 'log' key")
        return ValidationResult(is_valid=False, errors=errors)

    if "entries" not in data["log"] or not isinstance(data["log"]["entries"], list):
        errors.append("'log.entries' must be a list")
        return ValidationResult(is_valid=False, errors=errors)

    entries: list[dict] = data["log"]["entries"]

    # ── Minimum size ──────────────────────────────────────────────────────────
    if len(entries) < _MIN_ENTRIES:
        errors.append(
            f"Too few entries: {len(entries)} (minimum {_MIN_ENTRIES} required for "
            "statistical analysis)"
        )

    # ── Per-entry field check ─────────────────────────────────────────────────
    json_content_count = 0
    for i, entry in enumerate(entries):
        _check_entry(entry, i, errors)

        # Check content-type
        content_type = ""
        resp_headers = entry.get("response", {}).get("headers", {})
        if isinstance(resp_headers, dict):
            for k, v in resp_headers.items():
                if k.lower() == "content-type":
                    content_type = v
                    break
        elif isinstance(resp_headers, list):
            for h in resp_headers:
                if isinstance(h, dict) and h.get("name", "").lower() == "content-type":
                    content_type = h.get("value", "")
                    break

        if "application/json" in content_type:
            json_content_count += 1

    # ── JSON content-type warning ─────────────────────────────────────────────
    if entries:
        json_fraction = json_content_count / len(entries)
        if json_fraction < _MIN_JSON_FRACTION:
            warnings.append(
                f"Only {json_fraction:.0%} of responses have application/json "
                f"content-type (found {json_content_count}/{len(entries)}). "
                "Non-JSON responses will be skipped during extraction."
            )

    return ValidationResult(
        is_valid=len(errors) == 0,
        warnings=warnings,
        errors=errors,
    )


def validate_har_dict(data: dict) -> ValidationResult:
    """Validate a HAR already loaded as a dict (for in-memory validation)."""
    errors: list[str] = []
    warnings: list[str] = []

    if "log" not in data:
        return ValidationResult(is_valid=False, errors=["Missing top-level 'log' key"])

    if "entries" not in data["log"] or not isinstance(data["log"]["entries"], list):
        return ValidationResult(
            is_valid=False, errors=["'log.entries' must be a list"]
        )

    entries: list[dict] = data["log"]["entries"]

    if len(entries) < _MIN_ENTRIES:
        errors.append(
            f"Too few entries: {len(entries)} (minimum {_MIN_ENTRIES} required)"
        )

    for i, entry in enumerate(entries):
        _check_entry(entry, i, errors)

    return ValidationResult(
        is_valid=len(errors) == 0,
        warnings=warnings,
        errors=errors,
    )


def _check_entry(entry: dict, index: int, errors: list[str]) -> None:
    """Check a single HAR entry has required fields."""
    prefix = f"Entry[{index}]"
    if "request" not in entry:
        errors.append(f"{prefix}: missing 'request'")
        return
    if "response" not in entry:
        errors.append(f"{prefix}: missing 'response'")
        return

    req = entry["request"]
    resp = entry["response"]

    if not req.get("url"):
        errors.append(f"{prefix}: missing request.url")
    if not req.get("method"):
        errors.append(f"{prefix}: missing request.method")
    if resp.get("status") is None:
        errors.append(f"{prefix}: missing response.status")
    if "content" not in resp or resp["content"].get("text") is None:
        errors.append(f"{prefix}: missing response.content.text")
