"""
extractor/normalizer.py — normalizes dynamic URL path segments to patterns.

Examples:
    /users/123           → /users/{id}
    /orders/550e8400-... → /orders/{uuid}
    /items/xyz           → /items/{param}
    /api/v1/users        → /api/v1/users   (kept as-is; segments are valid words)
"""

from __future__ import annotations

import re
import urllib.parse

# UUID pattern: 8-4-4-4-12 hex chars
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Pure numeric segment
_NUMERIC_RE = re.compile(r"^\d+$")

# Looks like a word (only letters, length > 1) — treat as a known path segment
_WORD_RE = re.compile(r"^[a-zA-Z]{2,}$")

# Version segment like v1, v2, v3
_VERSION_RE = re.compile(r"^v\d+$", re.IGNORECASE)


def normalize_path(url: str) -> str:
    """Return a normalized path pattern from a full URL or path string.

    Replaces dynamic path segments:
        - Numeric IDs        → {id}
        - UUIDs              → {uuid}
        - Other dynamic segs → {param}

    Static word-based segments and version segments are kept as-is.
    Query strings are stripped.
    """
    # Strip query string and fragment, keep only path
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or url  # fall back to raw string if no scheme

    # Normalize double slashes
    path = re.sub(r"/{2,}", "/", path)

    segments = path.split("/")
    normalized: list[str] = []

    for seg in segments:
        if not seg:
            # Keep empty segments (leading/trailing slash)
            normalized.append(seg)
        elif _NUMERIC_RE.match(seg):
            normalized.append("{id}")
        elif _UUID_RE.match(seg):
            normalized.append("{uuid}")
        elif _VERSION_RE.match(seg):
            normalized.append(seg)  # v1, v2, etc. are static
        elif _WORD_RE.match(seg):
            normalized.append(seg)  # static segment like "users", "orders"
        else:
            normalized.append("{param}")

    return "/".join(normalized)


def endpoint_key(method: str, url: str) -> str:
    """Return a canonical endpoint key like 'GET /users/{id}'."""
    return f"{method.upper()} {normalize_path(url)}"
