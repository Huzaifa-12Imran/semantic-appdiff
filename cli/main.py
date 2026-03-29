"""
cli/main.py — Typer CLI entry point for apidiff.

Commands:
    capture     — Capture HAR traffic (proxy/replay/import modes)
    extract     — Extract RawSchema from a HAR file
    fingerprint — Build Fingerprint from a RawSchema or HAR file
    diff        — Compare two Fingerprints and output findings
    report      — Generate HTML report from findings.json
    run         — Full pipeline: extract → fingerprint → diff → report
"""

from __future__ import annotations

import json
import logging
import pathlib
import sys
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="apidiff",
    help=(
        "Semantic API diff tool — detects behavioral regressions between API versions, "
        "not just schema changes."
    ),
    no_args_is_help=True,
)

console = Console()
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


# ─────────────────────────────────────────────────────────────────────────────
# capture
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def capture(
    mode: str = typer.Option(..., help="Capture mode: proxy | replay | import"),
    out: str = typer.Option("capture.har", help="Output HAR file path"),
    port: int = typer.Option(8080, help="[proxy] Port to listen on"),
    filter_host: Optional[str] = typer.Option(None, help="[proxy] Only capture this host"),
    seed: Optional[str] = typer.Option(None, help="[replay] Path to seed HAR file"),
    target: Optional[str] = typer.Option(None, help="[replay] Target base URL"),
    delay_ms: int = typer.Option(50, help="[replay] Delay between requests in ms"),
    file: Optional[str] = typer.Option(None, help="[import] Path to existing HAR file"),
) -> None:
    """Capture API traffic and write a HAR file.

    Modes:
      proxy   — Run a local mitmproxy intercepting live traffic (requires apidiff[proxy])
      replay  — Replay a seed HAR file against a target URL (best for CI)
      import  — Validate and import an existing HAR file
    """
    mode = mode.lower().strip()

    if mode == "proxy":
        try:
            from capture.proxy import start_proxy
        except ImportError:
            console.print("[red]Error: proxy mode requires mitmproxy.[/red]")
            console.print("Install it with: [bold]pip install 'apidiff[proxy]'[/bold]")
            raise typer.Exit(3)
        console.print(f"[cyan]Starting proxy on port {port} → {out}[/cyan]")
        start_proxy(out_path=out, filter_host=filter_host, port=port)

    elif mode == "replay":
        if not seed:
            console.print("[red]Error: --seed is required for replay mode.[/red]")
            raise typer.Exit(3)
        if not target:
            console.print("[red]Error: --target is required for replay mode.[/red]")
            raise typer.Exit(3)
        from capture.replay import replay
        console.print(f"[cyan]Replaying {seed} → {target} → {out}[/cyan]")
        try:
            replay(seed_har_path=seed, target_base_url=target, out_path=out, delay_ms=delay_ms)
        except Exception as exc:
            console.print(f"[red]Replay failed: {exc}[/red]")
            raise typer.Exit(3)

    elif mode == "import":
        if not file:
            console.print("[red]Error: --file is required for import mode.[/red]")
            raise typer.Exit(3)
        from capture.validator import validate_har
        import shutil
        result = validate_har(file)
        for w in result.warnings:
            console.print(f"[yellow]WARN: {w}[/yellow]")
        if not result.is_valid:
            for e in result.errors:
                console.print(f"[red]ERROR: {e}[/red]")
            raise typer.Exit(3)
        shutil.copy2(file, out)
        console.print(f"[green]Imported {file} → {out}[/green]")

    else:
        console.print(f"[red]Unknown mode '{mode}'. Use: proxy | replay | import[/red]")
        raise typer.Exit(3)


# ─────────────────────────────────────────────────────────────────────────────
# extract
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def extract(
    har: str = typer.Argument(..., help="Path to HAR file"),
    out: str = typer.Option("raw_schema.json", help="Output RawSchema JSON path"),
    skip_validation: bool = typer.Option(False, help="Skip minimum-entry validation"),
) -> None:
    """Extract a RawSchema from a HAR file.

    Parses all response bodies, groups by endpoint, and computes field statistics.
    Output is a JSON file suitable for the fingerprint command.
    """
    import dataclasses
    from extractor.extractor import extract as _extract

    console.print(f"[cyan]Extracting schema from {har}...[/cyan]")
    try:
        schema = _extract(har, skip_validation=skip_validation)
    except Exception as exc:
        console.print(f"[red]Extraction failed: {exc}[/red]")
        raise typer.Exit(3)

    out_path = pathlib.Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dataclasses.asdict(schema), indent=2), encoding="utf-8")
    console.print(
        f"[green]Extracted {schema.total_requests} requests across "
        f"{len(schema.endpoints)} endpoints → {out}[/green]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# fingerprint
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def fingerprint(
    har: str = typer.Argument(..., help="Path to HAR file (used for full fingerprinting)"),
    out: str = typer.Option("fingerprint.json", help="Output Fingerprint JSON path"),
    skip_validation: bool = typer.Option(False, help="Skip minimum-entry validation"),
) -> None:
    """Build a Fingerprint JSON from a HAR file.

    Computes value distributions, co-occurrence invariants, idempotency profiles,
    latency percentiles, and error rates.
    """
    from fingerprint.builder import build_fingerprint_from_har, save_fingerprint

    console.print(f"[cyan]Building fingerprint from {har}...[/cyan]")
    try:
        fp = build_fingerprint_from_har(har, skip_validation=skip_validation)
    except Exception as exc:
        console.print(f"[red]Fingerprinting failed: {exc}[/red]")
        raise typer.Exit(3)

    save_fingerprint(fp, out)
    console.print(
        f"[green]Fingerprint built for {len(fp.endpoints)} endpoints → {out}[/green]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# diff
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def diff(
    fp_v1: str = typer.Argument(..., help="Path to v1 Fingerprint JSON"),
    fp_v2: str = typer.Argument(..., help="Path to v2 Fingerprint JSON"),
    out_dir: str = typer.Option("./apidiff-report", help="Output directory for findings"),
    fail_on: str = typer.Option(
        "high", help="Exit code threshold: critical | high | medium | none"
    ),
) -> None:
    """Compare two Fingerprints and generate findings.

    Runs all 9 behavioral detectors and outputs findings.json + report.html.

    Exit codes:
      0 — No findings above threshold
      1 — HIGH findings detected
      2 — CRITICAL findings detected
      3 — Tool error
    """
    from fingerprint.builder import load_fingerprint
    from engine.diff import diff as _diff
    from reporter.json_reporter import write_json
    from reporter.html_reporter import write_html
    from reporter.cli_reporter import print_summary

    try:
        fp1 = load_fingerprint(fp_v1)
        fp2 = load_fingerprint(fp_v2)
    except Exception as exc:
        console.print(f"[red]Failed to load fingerprints: {exc}[/red]")
        raise typer.Exit(3)

    findings = _diff(fp1, fp2)

    out = pathlib.Path(out_dir)
    write_json(findings, str(out / "findings.json"))
    write_html(findings, str(out / "report.html"))
    console.print(f"[dim]Findings: {out / 'findings.json'}[/dim]")
    console.print(f"[dim]Report:   {out / 'report.html'}[/dim]")

    code = print_summary(findings, fail_on)
    raise typer.Exit(code)


# ─────────────────────────────────────────────────────────────────────────────
# report
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def report(
    findings_json: str = typer.Argument(..., help="Path to findings.json"),
    out: str = typer.Option("report.html", help="Output HTML report path"),
) -> None:
    """Generate an HTML report from a findings.json file."""
    from engine.models import Finding, FindingType, Severity
    from reporter.html_reporter import write_html

    try:
        data = json.loads(pathlib.Path(findings_json).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read findings.json: {exc}[/red]")
        raise typer.Exit(3)

    # Reconstruct Finding objects from JSON
    findings: list[Finding] = []
    for f in data.get("findings", []):
        try:
            findings.append(Finding(
                finding_type=FindingType(f["type"]),
                severity=Severity(f["severity"]),
                endpoint=f["endpoint"],
                field=f.get("field"),
                description=f["description"],
                v1_evidence=f.get("v1_evidence", {}),
                v2_evidence=f.get("v2_evidence", {}),
            ))
        except (KeyError, ValueError) as exc:
            console.print(f"[yellow]Warning: skipped malformed finding: {exc}[/yellow]")

    write_html(findings, out)
    console.print(f"[green]Report written to {out}[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# run (all-in-one)
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def run(
    v1_har: str = typer.Option(..., help="Path to v1 HAR file"),
    v2_har: str = typer.Option(..., help="Path to v2 HAR file"),
    out_dir: str = typer.Option("./apidiff-report", help="Output directory"),
    fail_on: str = typer.Option(
        "high", help="Exit code threshold: critical | high | medium | none"
    ),
    skip_validation: bool = typer.Option(
        False, help="Skip HAR minimum-entry validation (useful for small test HARs)"
    ),
) -> None:
    """Run the full pipeline: HAR → extract → fingerprint → diff → report.

    This is the main command for CI usage. Provide two HAR files (v1 and v2)
    and get a complete behavioral difference report.

    Exit codes:
      0 — No findings above threshold
      1 — HIGH findings detected
      2 — CRITICAL findings detected
      3 — Tool error
    """
    from fingerprint.builder import build_fingerprint_from_har, save_fingerprint
    from engine.diff import diff as _diff
    from reporter.json_reporter import write_json
    from reporter.html_reporter import write_html
    from reporter.cli_reporter import print_summary

    out = pathlib.Path(out_dir)

    console.print(f"\n[bold cyan]apidiff[/bold cyan] — Semantic API Diff")
    console.print(f"  v1: {v1_har}")
    console.print(f"  v2: {v2_har}")
    console.print(f"  out: {out_dir}\n")

    # Extract + fingerprint v1
    console.print("[dim]Step 1/4: Building v1 fingerprint...[/dim]")
    try:
        fp_v1 = build_fingerprint_from_har(v1_har, skip_validation=skip_validation)
    except Exception as exc:
        console.print(f"[red]Failed to fingerprint v1: {exc}[/red]")
        raise typer.Exit(3)

    save_fingerprint(fp_v1, str(out / "fp_v1.json"))

    # Extract + fingerprint v2
    console.print("[dim]Step 2/4: Building v2 fingerprint...[/dim]")
    try:
        fp_v2 = build_fingerprint_from_har(v2_har, skip_validation=skip_validation)
    except Exception as exc:
        console.print(f"[red]Failed to fingerprint v2: {exc}[/red]")
        raise typer.Exit(3)

    save_fingerprint(fp_v2, str(out / "fp_v2.json"))

    # Diff
    console.print("[dim]Step 3/4: Running diff engine...[/dim]")
    findings = _diff(fp_v1, fp_v2)

    # Report
    console.print("[dim]Step 4/4: Writing reports...[/dim]")
    write_json(findings, str(out / "findings.json"))
    write_html(findings, str(out / "report.html"))

    console.print(f"\n[dim]Fingerprints: {out}/fp_v1.json, fp_v2.json[/dim]")
    console.print(f"[dim]Findings:     {out}/findings.json[/dim]")
    console.print(f"[dim]Report:       {out}/report.html[/dim]\n")

    code = print_summary(findings, fail_on)
    raise typer.Exit(code)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
