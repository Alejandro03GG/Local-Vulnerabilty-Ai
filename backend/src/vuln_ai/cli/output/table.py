"""Rich terminal table and panel rendering for CLI outputs."""

from __future__ import annotations

import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vuln_ai.core.models import Applicability, ScanResultSummary
from vuln_ai.risk.models import RiskLevel

# Standard consoles: stdout for clean output, stderr for warnings/errors
console_stdout = Console(no_color=bool(os.environ.get("NO_COLOR")))
console_stderr = Console(stderr=True, no_color=bool(os.environ.get("NO_COLOR")))


def _get_applicability_style(applicability: str) -> str:
    app_lower = applicability.lower()
    if app_lower == Applicability.LIKELY_AFFECTED.value:
        return "[bold red]LIKELY_AFFECTED[/bold red]"
    if app_lower == Applicability.REQUIRES_REVIEW.value:
        return "[bold yellow]REQUIRES_REVIEW[/bold yellow]"
    if app_lower == Applicability.DETECTED.value:
        return "[yellow]DETECTED[/yellow]"
    if app_lower == Applicability.LIKELY_NOT_AFFECTED.value:
        return "[green]LIKELY_NOT_AFFECTED[/green]"
    return "[dim]UNKNOWN[/dim]"


def _get_risk_style(risk_level: str) -> str:
    lvl_lower = risk_level.lower()
    if lvl_lower == RiskLevel.CRITICAL.value:
        return "[bold red]CRITICAL[/bold red]"
    if lvl_lower == RiskLevel.HIGH.value:
        return "[red]HIGH[/red]"
    if lvl_lower == RiskLevel.MEDIUM.value:
        return "[yellow]MEDIUM[/yellow]"
    if lvl_lower == RiskLevel.LOW.value:
        return "[blue]LOW[/blue]"
    if lvl_lower == RiskLevel.INFO.value:
        return "[dim cyan]INFO[/dim cyan]"
    return "[dim]UNKNOWN[/dim]"


def render_scan_table(
    summary: ScanResultSummary,
    output_file: str | Path | None = None,
    ai_status: str = "enabled",
) -> None:
    """Render structured scan summary and match tables to console."""
    # Use recording console if output file is specified
    console = (
        Console(record=True, no_color=bool(os.environ.get("NO_COLOR")))
        if output_file
        else console_stdout
    )

    # 1. Summary Header
    status_style = "bold green" if summary.scan_status.value == "completed" else "bold red"
    lockfiles_str = ", ".join(summary.lockfiles_detected) if summary.lockfiles_detected else "none"
    header_text = (
        f"[bold cyan]Local Vulnerability AI[/bold cyan]\n"
        f"Project:     [bold]{summary.project_name}[/bold] ([dim]{summary.project_path}[/dim])\n"
        f"Status:      [{status_style}]{summary.scan_status.value.upper()}[/{status_style}]\n"
        f"Duration:    {summary.duration_seconds:.2f}s | AI Pipeline: [bold]{ai_status}[/bold]\n"
        f"Components:  {summary.components_found} detected "
        f"([bold cyan]{summary.direct_components_count} direct[/bold cyan], "
        f"[magenta]{summary.transitive_components_count} transitive[/magenta]) | "
        f"Edges: {summary.dependency_edges_count} | Lockfiles: [dim]{lockfiles_str}[/dim]"
    )
    console.print(Panel(header_text, border_style="cyan", expand=False))

    # 2. Risk & Review metrics
    risk_counts = {level.value: 0 for level in RiskLevel}
    requires_review_count = 0
    for match in summary.matches:
        risk_lvl = "unknown"
        if match.risk_assessment:
            risk_lvl = getattr(match.risk_assessment, "risk_level", "unknown")
            if hasattr(risk_lvl, "value"):
                risk_lvl = risk_lvl.value
            if getattr(match.risk_assessment, "requires_human_review", False):
                requires_review_count += 1
        elif match.applicability.value == "requires_review":
            requires_review_count += 1

        if risk_lvl in risk_counts:
            risk_counts[risk_lvl] += 1
        else:
            risk_counts["unknown"] += 1

    summary_line = (
        f"Risk Findings: "
        f"[bold red]CRITICAL: {risk_counts['critical']}[/bold red]  "
        f"[red]HIGH: {risk_counts['high']}[/red]  "
        f"[yellow]MEDIUM: {risk_counts['medium']}[/yellow]  "
        f"[blue]LOW: {risk_counts['low']}[/blue]  "
        f"[dim]INFO/UNKNOWN: {risk_counts['info'] + risk_counts['unknown']}[/dim] | "
        f"Requires Review: [bold yellow]{requires_review_count}[/bold yellow] | "
        f"KEV Matches: [bold red]{summary.kev_matches}[/bold red]"
    )
    console.print(summary_line)
    console.print()

    # 3. Match Findings Table
    if not summary.matches:
        console.print("[bold green]✔ No vulnerability matches found.[/bold green]\n")
    else:
        table = Table(
            title="Detected Vulnerability Matches", show_header=True, header_style="bold magenta"
        )
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Version", style="white")
        table.add_column("Type", justify="center")
        table.add_column("Origin", style="dim")
        table.add_column("Vulnerability ID", style="bold yellow")
        table.add_column("Source", style="dim")
        table.add_column("Applicability")
        table.add_column("Risk")
        table.add_column("KEV", justify="center")
        table.add_column("Review", justify="center")
        table.add_column("Action / Rationale", style="dim")

        for m in summary.matches:
            pkg_name = m.component.name
            pkg_ver = m.component.version or "unknown"
            vuln_id = m.vulnerability.canonical_id or m.vulnerability.cve_id
            src_name = m.vulnerability.source_name

            # Dependency provenance
            is_direct = getattr(m.component, "is_direct", True)
            type_styled = (
                "[bold cyan]DIRECT[/bold cyan]" if is_direct else "[magenta]TRANSITIVE[/magenta]"
            )
            raw_origin = getattr(m.component, "lockfile_source", None) or getattr(
                m.component, "source_file", ""
            )
            origin_name = Path(raw_origin).name if raw_origin else "manifest"
            parent = getattr(m.component, "parent_name", None)
            if parent and not is_direct:
                origin_name = f"{origin_name} (via {parent})"

            app_styled = _get_applicability_style(m.applicability.value)

            risk_val = "unknown"
            rev_val = False
            action_text = ""
            if m.risk_assessment:
                risk_val = getattr(m.risk_assessment, "risk_level", "unknown")
                if hasattr(risk_val, "value"):
                    risk_val = risk_val.value
                rev_val = getattr(m.risk_assessment, "requires_human_review", False)
                action_text = getattr(m.risk_assessment, "recommended_action", "") or getattr(
                    m.risk_assessment, "rationale", ""
                )
            elif m.applicability.value == "requires_review":
                rev_val = True

            risk_styled = _get_risk_style(risk_val)
            has_kev = getattr(m.vulnerability, "has_kev_evidence", False) or (
                m.vulnerability.source_name == "CISA KEV"
            )
            kev_styled = "[bold red]YES[/bold red]" if has_kev else "[dim]-[/dim]"
            review_styled = "[bold yellow]YES[/bold yellow]" if rev_val else "[dim]-[/dim]"

            if len(action_text) > 40:
                action_text = action_text[:37] + "..."

            table.add_row(
                pkg_name,
                pkg_ver,
                type_styled,
                origin_name,
                vuln_id,
                src_name,
                app_styled,
                risk_styled,
                kev_styled,
                review_styled,
                action_text,
            )

        console.print(table)
        console.print()

    # If output file requested, save recorded text
    if output_file and hasattr(console, "export_text"):
        path = Path(output_file).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(console.export_text(), encoding="utf-8")
        if not output_file:
            pass
