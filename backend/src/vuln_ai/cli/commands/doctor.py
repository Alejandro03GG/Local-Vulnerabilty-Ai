"""Doctor diagnostic command for Local Vulnerability AI CLI."""

from __future__ import annotations

import platform
import sys

import httpx
import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import text

from vuln_ai.cli.context import (
    build_scanner_registry,
    get_cli_session,
    is_db_schema_ready,
    run_async_cli,
)
from vuln_ai.cli.errors import CLIExitCode
from vuln_ai.cli.output.table import console_stdout
from vuln_ai.config import get_settings

console = Console()


async def _check_ollama(url: str, model: str) -> tuple[bool, str]:
    """Test connection to Ollama server and verify model availability."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url.rstrip('/')}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                model_base = model.split(":")[0]
                has_model = any(model_base in m for m in models)
                if has_model:
                    return True, f"Online ({len(models)} models available, '{model}' installed)"
                return True, f"Online (reachable, but '{model}' not found in installed models)"
            return False, f"Server responded with status {resp.status_code}"
    except httpx.ConnectError:
        return False, "Connection refused (Ollama service is not running on localhost)"
    except Exception as exc:
        return False, f"Network error: {exc}"


async def _run_doctor_async() -> int:
    settings = get_settings()

    table = Table(
        title="System & Environment Diagnostics", show_header=True, header_style="bold magenta"
    )
    table.add_column("Diagnostic Item", style="bold cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    overall_healthy = True

    # 1. Python runtime
    py_version = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 12)
    table.add_row(
        "Python Runtime",
        "[bold green]OK[/bold green]" if py_ok else "[bold red]FAIL[/bold red]",
        f"v{py_version} on {platform.system()} ({platform.machine()})",
    )
    if not py_ok:
        overall_healthy = False

    # 2. Database & Schema
    db_ok = False
    vuln_count = 0
    alembic_head = "unknown"
    try:
        async with get_cli_session(settings) as session:
            schema_ok = await is_db_schema_ready(session)
            if schema_ok:
                db_ok = True
                res = await session.execute(text("SELECT count(*) FROM vulnerabilities"))
                vuln_count = res.scalar() or 0

                try:
                    res_alem = await session.execute(
                        text("SELECT version_num FROM alembic_version")
                    )
                    alembic_head = res_alem.scalar() or "none"
                except Exception:
                    alembic_head = "no alembic table"
    except Exception as exc:
        table.add_row("Database Connection", "[bold red]FAIL[/bold red]", str(exc))
        overall_healthy = False
    else:
        if db_ok:
            table.add_row(
                "SQLite Database",
                "[bold green]OK[/bold green]",
                f"Schema ready (Alembic head: {alembic_head})",
            )
            table.add_row(
                "Vulnerability Catalog",
                "[bold green]OK[/bold green]" if vuln_count > 0 else "[yellow]EMPTY[/yellow]",
                f"{vuln_count} records stored locally",
            )
        else:
            table.add_row(
                "SQLite Database",
                "[bold red]FAIL[/bold red]",
                "Database exists but schema is not initialized (run 'alembic upgrade head')",
            )
            overall_healthy = False

    # 3. AI & SystemOne Status
    if settings.ai.enabled:
        ollama_ok, ollama_detail = await _check_ollama(
            settings.ai.ollama.base_url, settings.ai.ollama.model
        )
        table.add_row(
            "Ollama LLM Provider",
            "[bold green]ONLINE[/bold green]" if ollama_ok else "[yellow]OFFLINE[/yellow]",
            f"{settings.ai.ollama.base_url} ({ollama_detail})",
        )

        decision_ok, decision_detail = await _check_ollama(
            settings.ai.decision.base_url, settings.ai.decision.model
        )
        table.add_row(
            "SystemOne Decision Provider",
            "[bold green]ONLINE[/bold green]" if decision_ok else "[yellow]OFFLINE[/yellow]",
            f"{settings.ai.decision.base_url} ({decision_detail})",
        )
    else:
        table.add_row("AI Providers", "[dim]DISABLED[/dim]", "AI is turned off in configuration")

    # 4. Scanners
    scanner_reg = build_scanner_registry()
    scanner_names = ", ".join(s.name for s in scanner_reg.list_scanners())
    table.add_row(
        "Supported Scanners",
        "[bold green]OK[/bold green]",
        f"{len(scanner_reg)} scanners ({scanner_names})",
    )

    console_stdout.print(table)
    console_stdout.print()

    if not overall_healthy:
        console_stdout.print(
            "[bold red]Warning:[/bold red] System diagnostics detected issues requiring attention.\n"
        )
        return CLIExitCode.USAGE_ERROR

    console_stdout.print(
        "[bold green]✔ Local Vulnerability AI diagnostics passed successfully.[/bold green]\n"
    )
    return CLIExitCode.SUCCESS


def doctor_command() -> None:
    """Run environmental, database, and service health checks."""
    code = run_async_cli(_run_doctor_async())
    if code != CLIExitCode.SUCCESS:
        raise typer.Exit(code)
