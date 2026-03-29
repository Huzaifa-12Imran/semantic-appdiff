"""
fingerprint/models.py — data models for the Fingerprint layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ValueDistribution:
    """Statistical distribution of a single field's values."""

    field_path: str
    value_counts: dict[str, int]           # value → count (categoricals)
    numeric_percentiles: dict[str, float]  # '10','25','50','75','90','99'
    is_categorical: bool                   # True if <= 20 distinct values
    entropy: float                         # Shannon entropy (bits)


@dataclass
class CoOccurrence:
    """A co-occurrence invariant: field_b appears when field_a == condition_value."""

    field_a: str
    field_b: str
    p_b_given_a: float     # P(field_b present | field_a == condition_value)
    condition_value: str   # the specific value of field_a triggering the invariant


@dataclass
class IdempotencyProfile:
    """Idempotency measurement for a single endpoint."""

    endpoint_key: str
    sample_size: int       # number of duplicate-input pairs tested
    is_idempotent: bool
    variance_rate: float   # fraction of duplicate pairs with different responses
    unknown: bool = False  # True if no duplicate requests were found


@dataclass
class EndpointFingerprint:
    """Full behavioral fingerprint for a single endpoint."""

    endpoint_key: str                           # e.g. 'GET /users/{id}'
    value_distributions: list[ValueDistribution]
    co_occurrences: list[CoOccurrence]
    idempotency: IdempotencyProfile
    latency_p50: float
    latency_p99: float
    error_rate: float                           # fraction of 4xx/5xx responses
    status_codes: list[int]                     # all observed status codes


@dataclass
class Fingerprint:
    """Complete fingerprint for all endpoints in a HAR file."""

    endpoints: dict[str, EndpointFingerprint]  # keyed by endpoint_key
    schema_hash: str                            # hash of the RawSchema
    created_at: str                             # ISO timestamp
