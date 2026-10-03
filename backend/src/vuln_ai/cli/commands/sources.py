"""Sources subcommands for Local Vulnerability AI CLI."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from vuln_ai.api.services.source_service import SourceService
from vuln_ai.cli.context import (
    build_source_registry,
    get_cli_session,
    is_db_schema_ready,
    run_async_cli,
)
from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.output.table import console_stderr, console_stdout
from vuln_ai.config import get_settings
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository

sources_app = typer.Typer(
    name="sources",
    help="Manage vulnerability catalog sources (CISA KEV, OSV, NVD).",
    no_args_is_help=True,
)


async def _list_sources_async() -> int:
    settings = get_settings()
    async with get_cli_session(settings) as session:
        if not await is_db_schema_ready(session):
            console_stderr.print(
                "[bold red]Error:[/bold red] Local database schema is not initialized.\n"
                "Please run '[bold cyan]alembic upgrade head[/bold cyan]' in backend/."
            )
            return CLIExitCode.USAGE_ERROR

        registry = build_source_registry(settings)
        source_repo = SourceRepository(session)
        vuln_repo = VulnerabilityRepository(session)
        service = SourceService(source_repo, vuln_repo, registry)

        sources = await service.list_sources()

        table = Table(
            title="Configured Vulnerability Sources", show_header=True, header_style="bold magenta"
        )
        table.add_column("Source Name", style="bold cyan")
        table.add_column("Type", style="white")
        table.add_column("Status")
        table.add_column("Records", justify="right", style="green")
        table.add_column("Last Sync", style="dim")
        table.add_column("URL", style="dim")

        for s in sources:
            st = s.status.value if hasattr(s.status, "value") else str(s.status)
            status_style = (
                "[green]ACTIVE[/green]"
                if st == "active"
                else (
                    "[yellow]SYNCING[/yellow]"
                    if st == "syncing"
                    else (
                        "[dim]NEVER_SYNCED[/dim]"
                        if st == "never_synced"
                        else f"[red]{st.upper()}[/red]"
                    )
                )
            )
            table.add_row(
                s.name,
                s.source_type,
                status_style,
                str(s.record_count),
                str(s.last_sync) if s.last_sync else "-",
                s.url,
            )

        console_stdout.print(table)
        console_stdout.print()
        return CLIExitCode.SUCCESS


async def _sync_sources_async(source_name: str | None = None) -> int:
    settings = get_settings()
    async with get_cli_session(settings) as session:
        if not await is_db_schema_ready(session):
            console_stderr.print(
                "[bold red]Error:[/bold red] Local database schema is not initialized.\n"
                "Please run '[bold cyan]alembic upgrade head[/bold cyan]' in backend/."
            )
            return CLIExitCode.USAGE_ERROR

        registry = build_source_registry(settings)
        source_repo = SourceRepository(session)
        vuln_repo = VulnerabilityRepository(session)
        service = SourceService(source_repo, vuln_repo, registry)

        all_sources = await service.list_sources()

        if source_name:
            target_sources = [
                s
                for s in all_sources
                if s.name.lower() == source_name.lower() or s.id == source_name
            ]
            if not target_sources:
                console_stderr.print(
                    f"[bold red]Error:[/bold red] Source '{source_name}' not found. "
                    f"Available sources: {', '.join(s.name for s in all_sources)}"
                )
                return CLIExitCode.USAGE_ERROR
        else:
            target_sources = all_sources

        console_stdout.print(
            f"Synchronizing [bold]{len(target_sources)}[/bold] vulnerability source(s)...\n"
        )

        table = Table(
            title="Synchronization Results", show_header=True, header_style="bold magenta"
        )
        table.add_column("Source", style="bold cyan")
        table.add_column("Status")
        table.add_column("Records Synced", justify="right", style="green")
        table.add_column("Duration", justify="right", style="dim")
        table.add_column("Details", style="dim")

        has_failure = False
        for s in target_sources:
            console_stdout.print(f"Syncing [bold]{s.name}[/bold]...")
            sync_res = await service.sync_source(s.id)
            if sync_res.success:
                table.add_row(
                    sync_res.source,
                    "[bold green]SUCCESS[/bold green]",
                    str(sync_res.records),
                    f"{sync_res.duration:.2f}s",
                    "OK",
                )
            else:
                has_failure = True
                table.add_row(
                    sync_res.source,
                    "[bold red]FAILED[/bold red]",
                    str(sync_res.records),
                    f"{sync_res.duration:.2f}s",
                    str(sync_res.error or "Sync failed"),
                )

        console_stdout.print()
        console_stdout.print(table)
        console_stdout.print()
        return CLIExitCode.INTERNAL_ERROR if has_failure else CLIExitCode.SUCCESS


@sources_app.command(name="list")
def list_sources() -> None:
    """List all configured vulnerability sources and their local status."""
    code = run_async_cli(_list_sources_async())
    if code != CLIExitCode.SUCCESS:
        raise typer.Exit(code)


@sources_app.command(name="sync")
def sync_sources(
    source: Annotated[
        str | None,
        typer.Option(
            "--source",
            "-s",
            help="Specific source to sync (e.g. 'CISA KEV', 'OSV', 'NVD')",
        ),
    ] = None,
) -> None:
    """Download fresh advisory data from configured vulnerability catalogs."""
    code = run_async_cli(_sync_sources_async(source_name=source))
    if code != CLIExitCode.SUCCESS:
        raise typer.Exit(code)
