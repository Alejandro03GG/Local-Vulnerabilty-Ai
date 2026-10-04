"""Scan command implementation for Local Vulnerability AI CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from vuln_ai.cli.context import (
    build_ai_registry,
    build_scanner_registry,
    build_source_registry,
    get_cli_session,
    is_db_schema_ready,
    run_async_cli,
)
from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.output.json_out import format_scan_summary_dict, output_json_payload
from vuln_ai.cli.output.table import console_stderr, console_stdout, render_scan_table
from vuln_ai.config import get_settings
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.db.repositories import SuppressionRepository
from vuln_ai.export.service import ExportService
from vuln_ai.matching.conflict import ConflictResolver
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.policy.clock import SystemClock
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.errors import PolicyError, PolicyParseError, PolicyValidationError
from vuln_ai.policy.parser import load_policy_file
from vuln_ai.policy.service import get_default_policy
from vuln_ai.risk.engine import DeterministicRiskEngine

SEVERITY_WEIGHTS = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

VALID_FORMATS = ("table", "json", "sarif", "cyclonedx", "spdx")
MACHINE_READABLE_FORMATS = ("json", "sarif", "cyclonedx", "spdx")


def _render_policy_compliance_table(policy_eval: Any, show_suppressions: bool = False) -> None:
    """Render a dedicated Rich table summarizing policy decisions and compliance."""
    from rich.panel import Panel
    from rich.table import Table

    status_text = (
        "VIOLATION"
        if policy_eval.violations_count > 0
        else ("REQUIRES_REVIEW" if policy_eval.requires_review_count > 0 else "ALLOWED")
    )
    status_color = (
        "red"
        if policy_eval.violations_count > 0
        else ("yellow" if policy_eval.requires_review_count > 0 else "green")
    )
    summary_text = (
        f"[bold]Policy:[/bold] {policy_eval.policy_name} ({policy_eval.policy_id})\n"
        f"[bold]Status:[/bold] [{status_color}]{status_text}[/{status_color}] | "
        f"[bold]Violations:[/bold] [red]{policy_eval.violations_count}[/red] | "
        f"[bold]Suppressed:[/bold] [cyan]{policy_eval.suppressed_count}[/cyan] | "
        f"[bold]Allowed:[/bold] [green]{policy_eval.allowed_count}[/green]"
    )
    console_stdout.print(
        Panel(summary_text, title="Policy & Compliance Evaluation", border_style="cyan")
    )

    if policy_eval.violations:
        viol_table = Table(title="Policy Violations", show_header=True, border_style="red")
        viol_table.add_column("Component", style="cyan", no_wrap=True)
        viol_table.add_column("Vulnerability", style="bold red")
        viol_table.add_column("Matched Rules", style="yellow")
        viol_table.add_column("Reason")
        for v in policy_eval.violations:
            viol_table.add_row(
                f"{v.component_name} @ {v.component_version or 'any'}",
                v.vulnerability_id,
                ", ".join(v.matched_rules) or "threshold",
                v.reason,
            )
        console_stdout.print(viol_table)

    if show_suppressions and getattr(policy_eval, "suppressions_applied", None):
        sup_table = Table(title="Applied Suppressions", show_header=True, border_style="blue")
        sup_table.add_column("Suppression ID", style="cyan")
        sup_table.add_column("Target Finding")
        sup_table.add_column("Owner", style="dim")
        sup_table.add_column("Expires At", justify="right")
        sup_table.add_column("Reason")
        for s in policy_eval.suppressions_applied:
            sup_table.add_row(
                s.get("suppression_id", "")[:8],
                s.get("finding_id", ""),
                s.get("owner", ""),
                s.get("expires_at") or "NEVER",
                s.get("reason", ""),
            )
        console_stdout.print(sup_table)


async def _execute_scan_async(
    target_path: Path,
    output_format: str,
    no_ai: bool,
    output_file: Path | None,
    fail_on: str,
    fail_on_review: bool,
    policy_file: Path | None = None,
    no_policy: bool = False,
    show_policy: bool = False,
    show_suppressions: bool = False,
) -> int:
    """Run async scan workflow and return exit code."""
    settings = get_settings()

    async with get_cli_session(settings) as session:
        # 1. Verify DB schema is ready
        if not await is_db_schema_ready(session):
            console_stderr.print(
                "[bold red]Error:[/bold red] Local database schema is not initialized.\n"
                "Please run '[bold cyan]alembic upgrade head[/bold cyan]' in backend/ to set up database tables."
            )
            return CLIExitCode.USAGE_ERROR

        # 2. Wire registries and components
        scanner_registry = build_scanner_registry()
        source_registry = build_source_registry(settings)
        ai_registry = build_ai_registry(settings, enabled=not no_ai)
        matcher = VulnerabilityMatcher()
        conflict_resolver = ConflictResolver()
        risk_engine = DeterministicRiskEngine()

        engine = ScanEngine(
            session=session,
            scanner_registry=scanner_registry,
            source_registry=source_registry,
            matcher=matcher,
            conflict_resolver=conflict_resolver,
            ai_registry=ai_registry,
            risk_engine=risk_engine,
            ai_enabled=not no_ai,
            decision_enabled=not no_ai,
        )

        # 3. Execute scan
        try:
            summary = await engine.scan(target_path)
        except Exception as exc:
            console_stderr.print(f"[bold red]Internal scan error:[/bold red] {exc}")
            return CLIExitCode.INTERNAL_ERROR

        if summary.scan_status == ScanStatus.FAILED:
            console_stderr.print(f"[bold red]Scan failed:[/bold red] {summary.error}")
            return CLIExitCode.INTERNAL_ERROR

        # 4. Policy & Suppression Engine evaluation
        policy_eval = None
        is_explicit_policy = False
        if not no_policy:
            try:
                policy_obj = None
                if policy_file is not None:
                    p_path = policy_file.resolve()
                    if not p_path.exists() or not p_path.is_file():
                        console_stderr.print(
                            f"[bold red]Error:[/bold red] Policy file does not exist: {policy_file}"
                        )
                        return CLIExitCode.USAGE_ERROR
                    policy_obj = load_policy_file(p_path)
                    is_explicit_policy = True
                else:
                    for fname in (".vuln-ai.yaml", ".vuln-ai.yml"):
                        cand = target_path / fname
                        if cand.exists() and cand.is_file():
                            policy_obj = load_policy_file(cand)
                            is_explicit_policy = True
                            break
                    if policy_obj is None:
                        policy_obj = get_default_policy()
                        if fail_on == "none":
                            policy_obj.thresholds.fail_on = []

                # If CLI passed explicit threshold overrides, merge them into policy
                if fail_on != "none":
                    weight_target = SEVERITY_WEIGHTS[fail_on]
                    sev_levels = [
                        lvl.upper()
                        for lvl, w in SEVERITY_WEIGHTS.items()
                        if w >= weight_target and lvl != "none"
                    ]
                    policy_obj.thresholds.fail_on = sev_levels
                if fail_on_review:
                    policy_obj.thresholds.fail_on_review = True

                # Gather Suppressions (from DB + inline policy suppressions)
                sup_repo = SuppressionRepository(session)
                db_sups = await sup_repo.list_all()
                combined_sups = list(policy_obj.suppressions)
                existing_ids = {s.id for s in combined_sups}
                for ds in db_sups:
                    dom_s = sup_repo.to_domain(ds)
                    if dom_s.id not in existing_ids:
                        combined_sups.append(dom_s)
                        existing_ids.add(dom_s.id)

                p_engine = PolicyEngine(
                    policy=policy_obj,
                    suppressions=combined_sups,
                    clock=SystemClock(),
                )
                policy_eval = p_engine.evaluate(summary.matches)

            except (PolicyParseError, PolicyValidationError, PolicyError) as exc:
                console_stderr.print(f"[bold red]Policy error:[/bold red] {exc}")
                return CLIExitCode.USAGE_ERROR
            except Exception as exc:
                console_stderr.print(f"[bold red]Policy evaluation error:[/bold red] {exc}")
                return CLIExitCode.INTERNAL_ERROR

        # 5. Render output
        if output_format == "json":
            payload = format_scan_summary_dict(summary, policy_evaluation=policy_eval)
            json_text = output_json_payload(payload, output_file=output_file)
            # H15: when -o is set, write only to file; keep stdout clean.
            if not output_file:
                sys.stdout.write(json_text + "\n")
                sys.stdout.flush()
            else:
                console_stderr.print(f"[dim]Wrote JSON export to {output_file}[/dim]")
        elif output_format in ("sarif", "cyclonedx", "spdx"):
            try:
                export_text = ExportService.export_summary(
                    summary=summary,
                    export_format=output_format,
                    output_path=output_file,
                    policy_evaluation=policy_eval,
                )
                if not output_file:
                    sys.stdout.write(export_text + "\n")
                    sys.stdout.flush()
                else:
                    console_stderr.print(
                        f"[dim]Wrote {output_format} export to {output_file}[/dim]"
                    )
            except Exception as exc:
                console_stderr.print(f"[bold red]Export error:[/bold red] {exc}")
                return CLIExitCode.INTERNAL_ERROR
        else:
            ai_status = (
                "disabled" if no_ai else ("enabled" if settings.ai.enabled else "not configured")
            )
            render_scan_table(summary, output_file=output_file, ai_status=ai_status)
            if policy_eval is not None and (
                show_policy or show_suppressions or policy_eval.violations_count > 0
            ):
                _render_policy_compliance_table(policy_eval, show_suppressions=show_suppressions)

        # 6. Evaluate exit code
        if policy_eval is not None:
            should_enforce = is_explicit_policy or (fail_on != "none") or fail_on_review
            if should_enforce and (
                policy_eval.violations_count > 0 or policy_eval.ci_exit_code != 0
            ):
                if output_format not in MACHINE_READABLE_FORMATS:
                    console_stderr.print(
                        f"[bold yellow]Policy violation:[/bold yellow] {policy_eval.violations_count} violation(s) detected."
                    )
                return CLIExitCode.THRESHOLD_VIOLATED
            return CLIExitCode.SUCCESS

        # Fallback if policy evaluation was disabled with --no-policy
        threshold_weight = SEVERITY_WEIGHTS[fail_on]
        threshold_violated = False

        if threshold_weight > 0:
            for m in summary.matches:
                risk_lvl = "unknown"
                if m.risk_assessment:
                    risk_lvl = getattr(m.risk_assessment, "risk_level", "unknown")
                    if hasattr(risk_lvl, "value"):
                        risk_lvl = risk_lvl.value
                match_weight = SEVERITY_WEIGHTS.get(str(risk_lvl).lower(), 0)
                if match_weight >= threshold_weight:
                    threshold_violated = True
                    break

        if fail_on_review and not threshold_violated:
            for m in summary.matches:
                rev = False
                if m.risk_assessment:
                    rev = getattr(m.risk_assessment, "requires_human_review", False)
                if rev or m.applicability.value == "requires_review":
                    threshold_violated = True
                    break

        if threshold_violated:
            if output_format not in MACHINE_READABLE_FORMATS:
                console_stderr.print(
                    "[bold yellow]Policy violation:[/bold yellow] findings met or exceeded threshold criteria."
                )
            return CLIExitCode.THRESHOLD_VIOLATED

        return CLIExitCode.SUCCESS


def scan_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to project directory to scan",
            show_default=False,
        ),
    ] = Path("."),
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: table, json, sarif, cyclonedx, spdx",
        ),
    ] = "table",
    no_ai: Annotated[
        bool,
        typer.Option(
            "--no-ai",
            help="Disable Ollama contextual analysis and SystemOne decisions",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="File path to save the scan report",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Fail with exit code 1 on threshold: none, low, medium, high, critical",
        ),
    ] = "none",
    fail_on_review: Annotated[
        bool,
        typer.Option(
            "--fail-on-review",
            help="Fail with exit code 1 if any match requires human review",
        ),
    ] = False,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            "-p",
            help="Path to declarative policy file (.vuln-ai.yaml)",
        ),
    ] = None,
    no_policy: Annotated[
        bool,
        typer.Option(
            "--no-policy",
            help="Disable policy evaluation and suppressions",
        ),
    ] = False,
    show_policy: Annotated[
        bool,
        typer.Option(
            "--show-policy",
            help="Display policy evaluation summary and rules in output",
        ),
    ] = False,
    show_suppressions: Annotated[
        bool,
        typer.Option(
            "--show-suppressions",
            help="Display active and expired suppressions in output",
        ),
    ] = False,
) -> None:
    """Scan a project directory for dependency vulnerabilities."""
    # Validate target path
    target = path.resolve()
    if not target.exists():
        console_stderr.print(f"[bold red]Error:[/bold red] Project path does not exist: {path}")
        raise typer.Exit(CLIExitCode.USAGE_ERROR)
    if not target.is_dir():
        console_stderr.print(
            f"[bold red]Error:[/bold red] Project path is not a directory: {path}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    # Validate output format
    fmt = format.lower().strip()
    if fmt not in VALID_FORMATS:
        console_stderr.print(
            f"[bold red]Error:[/bold red] Invalid --format '{format}'. Choices are: {', '.join(VALID_FORMATS)}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    # Validate fail-on threshold
    fol = fail_on.lower().strip()
    if fol not in SEVERITY_WEIGHTS:
        console_stderr.print(
            f"[bold red]Error:[/bold red] Invalid --fail-on '{fail_on}'. Choices are: {', '.join(SEVERITY_WEIGHTS.keys())}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    exit_code = run_async_cli(
        _execute_scan_async(
            target_path=target,
            output_format=fmt,
            no_ai=no_ai,
            output_file=output,
            fail_on=fol,
            fail_on_review=fail_on_review,
            policy_file=policy,
            no_policy=no_policy,
            show_policy=show_policy,
            show_suppressions=show_suppressions,
        )
    )

    if exit_code != CLIExitCode.SUCCESS:
        raise typer.Exit(exit_code)
