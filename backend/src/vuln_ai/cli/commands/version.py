"""Version command for Local Vulnerability AI CLI."""

from __future__ import annotations

from rich.console import Console

from vuln_ai import __version__

console = Console()


def version_command() -> None:
    """Print the version of Local Vulnerability AI."""
    console.print(f"Local Vulnerability AI {__version__}")
