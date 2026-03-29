# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2024-01-01

### Added
- **Layer 1 — Traffic Capture**: `proxy` (mitmproxy), `replay` (seed HAR re-fire), and `import` modes
- **Layer 2 — Schema Extractor**: statistical schema inference from HAR files; recursive JSON walker; path normalization (numeric `{id}`, UUID `{uuid}`, dynamic `{param}`)
- **Layer 3 — Fingerprint Builder**: value distributions with Shannon entropy, co-occurrence invariants (P(field_b | field_a==v) > 0.95), idempotency profiling with timestamp scrubbing, latency percentiles (P50/P99), error rates
- **Layer 4 — Diff Engine**: nine behavioral detectors:
  - `detect_removed_endpoints` (CRITICAL)
  - `detect_added_endpoints` (LOW)
  - `detect_status_code_change` (HIGH)
  - `detect_enum_rename` (CRITICAL)
  - `detect_value_dist_shift` (MEDIUM, chi-squared)
  - `detect_idempotency_broken` (CRITICAL)
  - `detect_co_occurrence_broken` (HIGH)
  - `detect_latency_regression` (MEDIUM)
  - `detect_error_rate_increase` (HIGH)
- **Layer 5 — Reporter**: stable JSON output, self-contained HTML report (dark theme, sortable/filterable table, expandable evidence), Rich CLI output
- **CLI**: `apidiff capture | extract | fingerprint | diff | report | run`
- **CI/CD**: GitHub Actions workflow, Dockerfile (python:3.11-slim)
- **Test suite**: 71 tests, 90%+ code coverage
