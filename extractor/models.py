"""
extractor/models.py — data models for the Schema Extractor layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FieldStats:
    """Statistical summary of a single field observed across many responses."""

    path: str                          # dot-notation, e.g. "user.address.city"
    observed_types: list[str]          # e.g. ['str', 'NoneType']
    sample_values: list[Any]           # up to 50 distinct values seen
    null_rate: float                   # fraction of observations that were None
    presence_rate: float               # fraction of responses that include this field
    is_always_present: bool            # True if presence_rate == 1.0
    high_cardinality: bool = False     # True if >1000 distinct values observed


@dataclass
class EndpointSchema:
    """All observed data for a single (method, path) endpoint."""

    method: str                        # "GET", "POST", etc.
    path_pattern: str                  # normalized, e.g. "/users/{id}"
    status_codes: list[int]            # all observed status codes
    fields: list[FieldStats]
    response_count: int                # total responses observed
    latencies_ms: list[float]          # all recorded response times in ms


@dataclass
class RawSchema:
    """Complete inferred schema for all endpoints in a HAR file."""

    endpoints: list[EndpointSchema]
    total_requests: int
    capture_duration_s: float
