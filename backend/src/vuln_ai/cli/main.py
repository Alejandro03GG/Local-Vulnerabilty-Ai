"""Main CLI application entry point for Local Vulnerability AI."""

from __future__ import annotations

import typer

from vuln_ai.cli.commands.doctor import doctor_command
from vuln_ai.cli.commands.image import image_app
from vuln_ai.cli.commands.policy import policy_app
from vuln_ai.cli.commands.scan import scan_command
from vuln_ai.cli.commands.sources import sources_app
from vuln_ai.cli.commands.suppression import suppression_app
from vuln_ai.cli.commands.version import version_command

app = typer.Typer(
    name="vuln-ai",
    help="Local Vulnerability AI — local-first vulnerability scanning and intelligence.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        version_command()
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=_version_callback,
        is_eager=True,
        help="Show application version and exit.",
    ),
) -> None:
    """Local Vulnerability AI command-line interface."""


# Register commands
app.command(name="version", help="Show application version and exit.")(version_command)
app.command(name="scan", help="Scan a project directory for dependency vulnerabilities.")(
    scan_command
)
app.command(name="doctor", help="Run diagnostic health checks on database and services.")(
    doctor_command
)
app.add_typer(sources_app, name="sources")
app.add_typer(policy_app, name="policy")
app.add_typer(suppression_app, name="suppression")
app.add_typer(image_app, name="image")


if __name__ == "__main__":
    app()
