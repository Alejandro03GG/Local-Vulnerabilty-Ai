"""CLI commands for container and image scanning."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.table import Table

from vuln_ai.cli.commands.scan import _render_policy_compliance_table
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
from vuln_ai.container.dockerfile import parse_dockerfile_file
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

image_app = typer.Typer(
    name="image",
    help="Container image and Dockerfile security inspection.",
    no_args_is_help=True,
)

VALID_FORMATS = ("table", "json", "sarif", "cyclonedx", "spdx")
MACHINE_READABLE_FORMATS = ("json", "sarif", "cyclonedx", "spdx")


def _render_dockerfile_table(doc: Any) -> None:
    """Render Rich table for Dockerfile AST and static findings."""
    stages_info = ", ".join(
        f"{s.name} ({s.base_image.name}:{s.base_image.tag})" for s in doc.stages
    )
    summary_text = (
        f"[bold]Source:[/bold] {doc.source_file}\n"
        f"[bold]Stages:[/bold] {len(doc.stages)} ({stages_info})\n"
        f"[bold]Base Images:[/bold] {len(doc.base_images)}\n"
        f"[bold]Detected Manifests:[/bold] {', '.join(doc.dependency_manifests) or 'None'}\n"
        f"[bold]Package Install Commands:[/bold] {len(doc.package_installations)}"
    )
    console_stdout.print(
        Panel(summary_text, title="Dockerfile Static Inspection", border_style="cyan")
    )

    if doc.package_installations:
        inst_table = Table(title="Detected Package Manager Invocations", show_header=True)
        inst_table.add_column("Line", style="dim", justify="right")
        inst_table.add_column("Stage", style="cyan")
        inst_table.add_column("Manager", style="bold yellow")
        inst_table.add_column("Packages", style="green")
        inst_table.add_column("Command")

        for inst in doc.package_installations:
            pkgs = ", ".join(inst.get("packages", []))
            inst_table.add_row(
                str(inst.get("line", "")),
                inst.get("stage", "default"),
                inst.get("manager", ""),
                pkgs,
                inst.get("raw_command", "")[:60],
            )
        console_stdout.print(inst_table)

    if doc.copied_files:
        copy_table = Table(title="Copied Files / Manifests", show_header=True)
        copy_table.add_column("Line", style="dim", justify="right")
        copy_table.add_column("Source", style="cyan")
        copy_table.add_column("Destination")
        copy_table.add_column("From Stage", style="yellow")
        for cp in doc.copied_files:
            copy_table.add_row(
                str(cp.get("line", "")),
                cp.get("source", ""),
                cp.get("destination", ""),
                cp.get("from_stage") or "host",
            )
        console_stdout.print(copy_table)


@image_app.command(name="scan")
def scan_image_command(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to container image archive (.tar) or Dockerfile.",
            show_default=False,
        ),
    ],
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: table, json, sarif, cyclonedx, spdx.",
        ),
    ] = "table",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write results to file instead of stdout.",
        ),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            "-p",
            help="Path to declarative security policy file (.vuln-ai.yaml).",
        ),
    ] = None,
    reference: Annotated[
        str | None,
        typer.Option(
            "--reference",
            "-r",
            help="Custom image reference/tag (e.g. my-app:1.0).",
        ),
    ] = None,
    no_ai: Annotated[
        bool,
        typer.Option(
            "--no-ai",
            help="Disable optional AI-assisted analysis and decisions.",
        ),
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Severities or risk levels that trigger CI/CD failure (e.g. 'HIGH,CRITICAL').",
        ),
    ] = None,
    fail_on_review: Annotated[
        bool,
        typer.Option(
            "--fail-on-review",
            help="Trigger CI/CD violation if any finding requires human review.",
        ),
    ] = False,
    show_suppressions: Annotated[
        bool,
        typer.Option(
            "--show-suppressions",
            help="Display applied suppressions in console output.",
        ),
    ] = False,
) -> None:
    """Scan a local container image archive or Dockerfile statically without execution."""
    fmt = format.lower().strip()
    if fmt not in VALID_FORMATS:
        console_stderr.print(
            f"[red]Error: Invalid format '{format}'. Valid: {', '.join(VALID_FORMATS)}[/red]"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    if not target.exists():
        console_stderr.print(f"[red]Error: Target not found: {target}[/red]")
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    # 1. Handle Dockerfile target
    if target.name.lower() in ("dockerfile", "containerfile") or target.suffix.lower() in (
        ".dockerfile",
    ):
        try:
            doc = parse_dockerfile_file(target)
            if fmt == "json":
                out_bytes = doc.model_dump_json(indent=2).encode("utf-8")
                if output:
                    output.write_bytes(out_bytes)
                else:
                    sys.stdout.write(out_bytes.decode("utf-8") + "\n")
            else:
                _render_dockerfile_table(doc)
            raise typer.Exit(CLIExitCode.SUCCESS)
        except (typer.Exit, typer.Abort):
            raise
        except Exception as e:
            console_stderr.print(f"[red]Dockerfile analysis error: {e}[/red]")
            raise typer.Exit(CLIExitCode.INTERNAL_ERROR) from e

    # 2. Handle Container Image Archive
    async def _async_run() -> int:
        async with get_cli_session() as session:
            if not await is_db_schema_ready(session):
                console_stderr.print("[red]Database not initialized. Run: vuln-ai doctor[/red]")
                return CLIExitCode.USAGE_ERROR

            # Resolve policy
            eval_policy = None
            if policy:
                if not policy.exists():
                    console_stderr.print(f"[red]Error: Policy file not found: {policy}[/red]")
                    return CLIExitCode.USAGE_ERROR
                try:
                    eval_policy = load_policy_file(policy)
                except (PolicyParseError, PolicyValidationError, PolicyError) as e:
                    console_stderr.print(f"[red]Policy Error: {e}[/red]")
                    return CLIExitCode.USAGE_ERROR
            else:
                eval_policy = get_default_policy()

            # Apply CLI threshold overrides
            if fail_on:
                sevs = [s.strip().upper() for s in fail_on.split(",") if s.strip()]
                eval_policy.thresholds.fail_on = sevs
            if fail_on_review:
                eval_policy.thresholds.fail_on_review = True

            # Load active suppressions
            sup_repo = SuppressionRepository(session)
            sup_dbs = await sup_repo.list_all(enabled_only=True)
            suppressions = [sup_repo.to_domain(s) for s in sup_dbs]

            settings = get_settings()
            ai_registry = None
            if not no_ai:
                ai_registry = build_ai_registry(settings)

            scan_engine = ScanEngine(
                session=session,
                scanner_registry=build_scanner_registry(),
                source_registry=build_source_registry(settings),
                matcher=VulnerabilityMatcher(),
                conflict_resolver=ConflictResolver(),
                ai_registry=ai_registry,
                risk_engine=DeterministicRiskEngine(),
                ai_enabled=not no_ai,
                decision_enabled=not no_ai,
            )

            try:
                summary, container_image, os_pkgs, _graph = await scan_engine.scan_container_image(
                    archive_path=target,
                    reference=reference,
                )
            except Exception as e:
                console_stderr.print(f"[red]Container scan failed: {e}[/red]")
                return CLIExitCode.INTERNAL_ERROR

            if summary.scan_status == ScanStatus.FAILED:
                console_stderr.print(f"[red]Scan failed: {summary.error}[/red]")
                return CLIExitCode.INTERNAL_ERROR

            # Evaluate Policy & Suppressions
            policy_engine = PolicyEngine(
                policy=eval_policy,
                suppressions=suppressions,
                clock=SystemClock(),
            )
            policy_eval = policy_engine.evaluate_scan(
                scan_result=summary,
                scan_id=summary.scan_id,
            )

            # Output formatting
            if fmt == "table":
                # Render Image Header Panel
                img_panel = (
                    f"[bold]Image:[/bold] {container_image.reference}\n"
                    f"[bold]Digest:[/bold] {container_image.digest or 'unknown'}\n"
                    f"[bold]OS:[/bold] {container_image.os} ({container_image.operating_system.name if container_image.operating_system else 'Linux'})\n"
                    f"[bold]Architecture:[/bold] {container_image.architecture} | "
                    f"[bold]Layers:[/bold] {len(container_image.layers)} | "
                    f"[bold]Components:[/bold] {summary.components_found} ({len(os_pkgs)} OS, {summary.components_found - len(os_pkgs)} App)"
                )
                console_stdout.print(
                    Panel(img_panel, title="Container Image Inspection", border_style="green")
                )

                # Render findings table
                render_scan_table(summary)

                # Render policy evaluation table
                _render_policy_compliance_table(policy_eval, show_suppressions=show_suppressions)

            elif fmt == "json":
                payload = format_scan_summary_dict(summary, policy_evaluation=policy_eval)
                json_text = output_json_payload(payload, output_file=output)
                sys.stdout.write(json_text + "\n")
                sys.stdout.flush()

            elif fmt in ("sarif", "cyclonedx", "spdx"):
                try:
                    export_text = ExportService.export_summary(
                        summary=summary,
                        export_format=fmt,
                        output_path=output,
                        policy_evaluation=policy_eval,
                    )
                    if not output:
                        sys.stdout.write(export_text + "\n")
                        sys.stdout.flush()
                except Exception as exc:
                    console_stderr.print(f"[bold red]Export error:[/bold red] {exc}")
                    return CLIExitCode.INTERNAL_ERROR

            return policy_eval.ci_exit_code

    code = run_async_cli(_async_run())
    raise typer.Exit(code)
