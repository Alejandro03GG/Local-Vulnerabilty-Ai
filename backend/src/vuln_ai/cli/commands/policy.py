"""Policy CLI commands for Local Vulnerability AI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.output.table import console_stderr, console_stdout
from vuln_ai.policy.errors import PolicyError, PolicyParseError, PolicyValidationError
from vuln_ai.policy.parser import load_policy_file

policy_app = typer.Typer(
    name="policy",
    help="Manage and validate declarative security policies.",
    no_args_is_help=True,
)


@policy_app.command(
    name="validate", help="Validate syntax, schema, and safety of a policy YAML file."
)
def policy_validate_command(
    policy_file: Annotated[
        Path,
        typer.Argument(
            help="Path to policy YAML file (e.g. .vuln-ai.yaml)",
            show_default=False,
        ),
    ],
) -> None:
    """Validate a declarative policy YAML file."""
    path = policy_file.resolve()
    if not path.exists():
        console_stderr.print(
            f"[bold red]Error:[/bold red] Policy file does not exist: {policy_file}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)
    if not path.is_file():
        console_stderr.print(
            f"[bold red]Error:[/bold red] Policy path is not a file: {policy_file}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    try:
        policy = load_policy_file(path)
    except (PolicyParseError, PolicyValidationError, PolicyError) as exc:
        console_stderr.print(f"[bold red]Policy validation error:[/bold red] {exc}")
        raise typer.Exit(CLIExitCode.USAGE_ERROR) from exc
    except Exception as exc:
        console_stderr.print(f"[bold red]Unexpected error parsing policy:[/bold red] {exc}")
        raise typer.Exit(CLIExitCode.INTERNAL_ERROR) from exc

    console_stdout.print(
        f"[bold green]✓[/bold green] Policy file '[bold cyan]{policy_file.name}[/bold cyan]' is valid."
    )
    console_stdout.print(f"  [dim]Name:[/dim] {policy.name}")
    console_stdout.print(f"  [dim]Version:[/dim] {policy.version}")
    console_stdout.print(f"  [dim]Rules defined:[/dim] {len(policy.rules)}")
    console_stdout.print(f"  [dim]Inline suppressions:[/dim] {len(policy.suppressions)}")
    console_stdout.print(f"  [dim]Fail-on thresholds:[/dim] {policy.thresholds.fail_on or 'None'}")
    console_stdout.print(f"  [dim]Default action:[/dim] {policy.default_action.value}")


@policy_app.command(name="check", help="Inspect and display rules and conditions of a policy.")
def policy_check_command(
    policy_file: Annotated[
        Path,
        typer.Argument(
            help="Path to policy YAML file (e.g. .vuln-ai.yaml)",
            show_default=False,
        ),
    ],
) -> None:
    """Display rules and criteria of a policy file."""
    path = policy_file.resolve()
    if not path.exists() or not path.is_file():
        console_stderr.print(
            f"[bold red]Error:[/bold red] Invalid policy file path: {policy_file}"
        )
        raise typer.Exit(CLIExitCode.USAGE_ERROR)

    try:
        policy = load_policy_file(path)
    except Exception as exc:
        console_stderr.print(f"[bold red]Policy error:[/bold red] {exc}")
        raise typer.Exit(CLIExitCode.USAGE_ERROR) from exc

    table = Table(title=f"Policy Rules: {policy.name} (v{policy.version})", show_header=True)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Action", style="bold")
    table.add_column("Priority", justify="right")
    table.add_column("Description")

    for rule in policy.rules:
        action_style = (
            "red"
            if rule.action.value == "BLOCK"
            else "yellow"
            if rule.action.value == "REQUIRE_REVIEW"
            else "green"
        )
        table.add_row(
            rule.id,
            f"[{action_style}]{rule.action.value}[/{action_style}]",
            str(rule.priority),
            rule.description,
        )

    console_stdout.print(table)
