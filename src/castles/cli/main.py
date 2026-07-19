from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Never

import typer
from rich.console import Console

from castles import __version__, wiring
from castles.app.doctor import healthy
from castles.app.scan import ScanRequest
from castles.app.show import show as find
from castles.cli import view
from castles.core.error import CastlesError, ConfigurationError, InputError

app = typer.Typer(
    name="castles",
    help="Discover mailbox entities locally and privately.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
console = Console()
errors = Console(stderr=True)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"Castles {__version__}")
        raise typer.Exit


def _call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except CastlesError as exc:
        errors.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1) from None
    except Exception:
        errors.print("[red]Error:[/] Castles encountered an unexpected failure.")
        raise typer.Exit(1) from None


def _raise(error: CastlesError) -> Never:
    raise error


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True),
) -> None:
    """Discover mailbox entities locally and privately."""


@app.command()
def setup(
    client: Path | None = typer.Argument(None, help="Google desktop OAuth client JSON."),
    force: bool = typer.Option(False, "--force", help="Replace saved authorization."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Print the authorization URL."),
) -> None:
    """Configure and authorize Gmail read-only access."""
    source = client or wiring.find_client()
    if source is None:
        _call(lambda: _raise(ConfigurationError("supply a Google desktop OAuth client JSON path")))
        return
    _call(lambda: wiring.setup_usecase().execute(source, force=force, no_browser=no_browser))
    console.print("Authorized Gmail with read-only access.")
    console.print("Next: [bold]castles scan[/bold]")


def _since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise InputError("--since must be an ISO-8601 date-time with a timezone") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise InputError("--since must include a timezone")
    return result


@app.command()
def scan(
    full: bool = typer.Option(False, "--full", help="Replace active state after a complete scan."),
    since: str | None = typer.Option(
        None, "--since", help="Scan mail after an aware ISO-8601 date-time."
    ),
) -> None:
    """Scan Gmail and rebuild local entity findings."""
    request = _call(lambda: ScanRequest(full=full, since=_since(since)))
    result = _call(lambda: wiring.scan(request))
    console.print(
        f"{result.status.value.capitalize()} {result.mode.value} scan: "
        f"{result.discovered} discovered, {result.processed} processed, "
        f"{result.skipped} skipped, {result.finding_count} findings."
    )
    if result.stale_fallback:
        console.print("The provider checkpoint was stale; Castles used a bounded overlap scan.")


@app.command()
def results() -> None:
    """Show local findings without Gmail or network access."""
    view.results(console, _call(wiring.local_results))


@app.command()
def show(entity: str = typer.Argument(..., help="Canonical entity domain.")) -> None:
    """Show one local finding and its explanations."""
    values = _call(wiring.local_results)
    matches = find(values, entity)
    if not matches:
        _call(lambda: _raise(InputError("entity is not present in local results")))
        return
    for finding in matches:
        view.finding(console, finding)


@app.command("export")
def export_command(
    format: str = typer.Option("json", "--format", help="Export format: json or csv."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Destination file."),
) -> None:
    """Export local findings as Castles JSON schema 1 or fixed-column CSV."""
    normalized = format.casefold()
    if normalized not in {"json", "csv"}:
        _call(lambda: _raise(InputError("export format must be json or csv")))
        return
    destination = output or Path(f"castles.{normalized}")
    _call(lambda: wiring.export(destination, normalized))
    console.print(f"Wrote {normalized.upper()} export to {destination}")


@app.command()
def doctor(
    provider: bool = typer.Option(False, "--provider", help="Also validate Gmail online."),
) -> None:
    """Check local resources, permissions, schema, and optional provider access."""
    checks = _call(lambda: wiring.doctor(provider=provider))
    view.doctor(console, checks)
    if not healthy(checks):
        raise typer.Exit(1)


@app.command()
def logout() -> None:
    """Remove saved Castles Gmail authorization only."""
    removed = _call(wiring.logout)
    console.print(
        "Saved Gmail authorization removed."
        if removed
        else "No saved Gmail authorization was present."
    )
