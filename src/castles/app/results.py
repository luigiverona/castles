from __future__ import annotations

from dataclasses import dataclass

from castles.core.finding import Finding
from castles.core.scan import ScanResult
from castles.store.port import Reader


@dataclass(frozen=True, slots=True)
class ResultSet:
    provider: str
    address: str
    scan: ScanResult | None
    findings: tuple[Finding, ...]


def results(reader: Reader) -> tuple[ResultSet, ...]:
    return tuple(
        ResultSet(provider, address, reader.scan(account), reader.findings(account))
        for account, provider, address in reader.accounts()
    )
