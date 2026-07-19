from __future__ import annotations

from rich.console import Console
from rich.table import Table

from castles.app.doctor import Check, Health
from castles.app.results import ResultSet
from castles.core.finding import Finding


def results(console: Console, values: tuple[ResultSet, ...]) -> None:
    if not values:
        console.print("No Castles mailbox state exists. Run [bold]castles scan[/bold].")
        return
    for value in values:
        console.print(f"[bold]{value.provider}[/bold]")
        if not value.findings:
            console.print("No reportable entities found.")
            continue
        if console.width < 70:
            for item in value.findings:
                relations = (
                    ", ".join(
                        f"{relation.kind.value} {relation.confidence.score}/{relation.confidence.band.value}"
                        for relation in item.relationships
                    )
                    or "none"
                )
                console.print(f"[bold]{item.entity}[/bold]")
                console.print(
                    f"  Identity {item.identity.score}/{item.identity.band.value}; "
                    f"relationships: {relations}; messages: {item.message_count}; "
                    f"last seen: {item.last_seen.date().isoformat()}"
                )
            continue
        table = Table(box=None, pad_edge=False, expand=True)
        table.add_column("Entity", overflow="fold", ratio=3)
        table.add_column("Identity", justify="right", no_wrap=True)
        table.add_column("Relationships", overflow="fold", ratio=3)
        table.add_column("Msgs", justify="right", no_wrap=True)
        table.add_column("Last seen", no_wrap=True)
        for finding in value.findings:
            relations = (
                ", ".join(
                    f"{item.kind.value} {item.confidence.score}/{item.confidence.band.value}"
                    for item in finding.relationships
                )
                or "—"
            )
            table.add_row(
                finding.entity,
                f"{finding.identity.score}/{finding.identity.band.value}",
                relations,
                str(finding.message_count),
                finding.last_seen.date().isoformat(),
            )
        console.print(table)


def finding(console: Console, value: Finding) -> None:
    console.print(f"[bold]{value.entity}[/bold]")
    console.print(f"Identity: {value.identity.score} ({value.identity.band.value})")
    console.print(f"Messages: {value.message_count}")
    console.print(f"Seen: {value.first_seen.isoformat()} — {value.last_seen.isoformat()}")
    console.print("Identity evidence: " + ", ".join(value.identity.explanations))
    if value.relationships:
        table = Table("Relationship", "Strength", "Evidence", box=None)
        for item in value.relationships:
            table.add_row(
                item.kind.value,
                f"{item.confidence.score} ({item.confidence.band.value})",
                ", ".join(item.confidence.explanations),
            )
        console.print(table)


def doctor(console: Console, checks: tuple[Check, ...]) -> None:
    colors = {Health.OK: "green", Health.WARN: "yellow", Health.FAIL: "red"}
    table = Table("Check", "Status", "Detail", box=None, expand=True)
    for check in checks:
        table.add_row(check.name, f"[{colors[check.health]}]{check.health.value}[/]", check.detail)
    console.print(table)
