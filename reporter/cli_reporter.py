"""
reporter/cli_reporter.py — Rich CLI output table and exit code logic.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from engine.models import Finding, FindingType, Severity
from engine.diff import exit_code as compute_exit_code

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange1",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "dim white",
}

_FINDING_TYPE_LABELS = {
    FindingType.ENDPOINT_REMOVED:          "Endpoint Removed",
    FindingType.ENDPOINT_ADDED:            "Endpoint Added",
    FindingType.STATUS_CODE_CHANGE:        "Status Code Change",
    FindingType.ENUM_RENAME:               "Enum Rename",
    FindingType.VALUE_DISTRIBUTION_SHIFT:  "Distribution Shift",
    FindingType.IDEMPOTENCY_BROKEN:        "Idempotency Broken",
    FindingType.CO_OCCURRENCE_BROKEN:      "Co-occurrence Broken",
    FindingType.LATENCY_REGRESSION:        "Latency Regression",
    FindingType.ERROR_RATE_INCREASE:       "Error Rate Increase",
}


def print_summary(findings: list[Finding], fail_on: str = "high") -> int:
    """Print a Rich summary table and return the CLI exit code.

    Args:
        findings: Findings from diff().
        fail_on: Severity threshold string.

    Returns:
        Exit code (0, 1, 2, or 3).
    """
    if not findings:
        console.print("\n[bold green]✓ No behavioral differences detected.[/bold green]\n")
        return 0

    # ── Summary panel ─────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold]apidiff — Semantic API Diff Report[/bold]")
    console.print()

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if counts[sev] > 0:
            color = _SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{counts[sev]} {sev.value.upper()}[/{color}]")

    console.print(f"  Total findings: [bold]{len(findings)}[/bold]  |  " + "  ".join(summary_parts))
    console.print()

    # ── Findings table ─────────────────────────────────────────────────────────
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Type", width=22, no_wrap=True)
    table.add_column("Endpoint", min_width=20)
    table.add_column("Field", min_width=10)
    table.add_column("Description")

    for f in findings:
        color = _SEVERITY_COLORS[f.severity]
        sev_text = Text(f.severity.value.upper(), style=color)
        type_label = _FINDING_TYPE_LABELS.get(f.finding_type, f.finding_type.value)
        field_str = f.field or "—"
        # Truncate description for table display
        desc = f.description if len(f.description) <= 80 else f.description[:77] + "..."
        table.add_row(sev_text, type_label, f.endpoint, field_str, desc)

    console.print(table)
    console.print()

    code = compute_exit_code(findings, fail_on)
    if code == 0:
        console.print(f"[bold green]✓ No findings at or above '{fail_on}' threshold. Exit 0.[/bold green]")
    elif code == 2:
        console.print(f"[bold red]✗ CRITICAL findings detected. Exit 2.[/bold red]")
    elif code == 1:
        console.print(f"[bold orange1]✗ HIGH findings detected. Exit 1.[/bold orange1]")

    console.print()
    return code
