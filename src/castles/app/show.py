from __future__ import annotations

from castles.app.results import ResultSet
from castles.core.finding import Finding


def show(values: tuple[ResultSet, ...], entity: str) -> tuple[Finding, ...]:
    target = entity.casefold().strip().rstrip(".")
    return tuple(
        finding for result in values for finding in result.findings if finding.entity == target
    )
