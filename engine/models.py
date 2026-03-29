"""
engine/models.py — data models for the Diff Engine layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingType(Enum):
    VALUE_DISTRIBUTION_SHIFT = "value_distribution_shift"
    ENUM_RENAME              = "enum_rename"
    IDEMPOTENCY_BROKEN       = "idempotency_broken"
    CO_OCCURRENCE_BROKEN     = "co_occurrence_broken"
    LATENCY_REGRESSION       = "latency_regression"
    ERROR_RATE_INCREASE      = "error_rate_increase"
    ENDPOINT_REMOVED         = "endpoint_removed"
    ENDPOINT_ADDED           = "endpoint_added"
    STATUS_CODE_CHANGE       = "status_code_change"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


@dataclass
class Finding:
    """A single behavioral difference detected between two API versions."""

    finding_type: FindingType
    severity: Severity
    endpoint: str           # endpoint key, e.g. "GET /users/{id}"
    field: str | None       # field path if applicable, else None
    description: str        # plain English, 1-2 sentences
    v1_evidence: dict       # raw data from fingerprint v1
    v2_evidence: dict       # raw data from fingerprint v2
