"""Suppression CLI commands for Local Vulnerability AI."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from vuln_ai.cli.context import get_cli_session, run_async_cli
from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.output.table import console_stdout
from vuln_ai.config import get_settings
from vuln_ai.db.repositories import SuppressionRepository
from vuln_ai.policy.clock import SystemClock
from vuln_ai.policy.models import SuppressionStatus

suppression_app = typer.Typer(
    name="suppression",
    help="Manage, inspect, and validate vulnerability suppressions.",
    no_args_is_help=True,
)


async def _list_suppressions_async(as_json: bool = False) -> int:
    settings = get_settings()
    clock = SystemClock()

    async with get_cli_session(settings) as session:
        repo = SuppressionRepository(session)
        db_sups = await repo.list_all()

        if as_json:
            import json
            import sys

            items = []
            for db_sup in db_sups:
                domain_sup = repo.to_domain(db_sup)
                items.append(
                    {
                        "id": domain_sup.id,
                        "status": domain_sup.status(clock).value,
                        "reason": domain_sup.reason,
                        "owner": domain_sup.owner,
                        "reference": domain_sup.reference,
                        "expires_at": domain_sup.expires_at.isoformat()
                        if domain_sup.expires_at
                        else None,
                        "match_criteria": domain_sup.match_criteria.model_dump(exclude_unset=True),
                    }
                )
            sys.stdout.write(json.dumps(items, indent=2) + "\n")
            sys.stdout.flush()
            return CLIExitCode.SUCCESS

        if not db_sups:
            console_stdout.print("[dim]No suppressions recorded in database.[/dim]")
            return CLIExitCode.SUCCESS

        table = Table(title="Auditable Vulnerability Suppressions", show_header=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold")
        table.add_column("Target (Vuln / Pkg)")
        table.add_column("Owner", style="dim")
        table.add_column("Reference")
        table.add_column("Expires At", justify="right")
        table.add_column("Reason")

        for db_sup in db_sups:
            domain_sup = repo.to_domain(db_sup)
            st = domain_sup.status(clock)
            st_style = (
                "green"
                if st == SuppressionStatus.ACTIVE
                else "red"
                if st == SuppressionStatus.EXPIRED
                else "dim"
            )

            target_parts = []
            if domain_sup.match_criteria.vulnerability_id:
                target_parts.append(domain_sup.match_criteria.vulnerability_id)
            if domain_sup.match_criteria.package_name:
                target_parts.append(domain_sup.match_criteria.package_name)
            target = " / ".join(target_parts) or "GLOBAL"

            exp_str = (
                domain_sup.expires_at.strftime("%Y-%m-%d") if domain_sup.expires_at else "NEVER"
            )

            table.add_row(
                domain_sup.id[:8],
                f"[{st_style}]{st.value}[/{st_style}]",
                target,
                domain_sup.owner,
                domain_sup.reference,
                exp_str,
                domain_sup.reason,
            )

        console_stdout.print(table)
        return CLIExitCode.SUCCESS


@suppression_app.command(
    name="list", help="List all registered suppressions and their lifecycle status."
)
def suppression_list_command(
    as_json: Annotated[
        bool, typer.Option("--json", help="Output suppressions list as JSON.")
    ] = False,
) -> None:
    """List suppressions stored in local database."""
    exit_code = run_async_cli(_list_suppressions_async(as_json=as_json))
    if exit_code != CLIExitCode.SUCCESS:
        raise typer.Exit(exit_code)
