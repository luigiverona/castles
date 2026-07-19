from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from castles.core.finding import Finding
from castles.core.message import Mailbox, _aware, _text
from castles.core.scan import ScanMode, ScanResult
from castles.core.signal import MessageSignals


@dataclass(frozen=True, slots=True)
class Checkpoint:
    provider: str
    kind: str
    value: str
    successful_at: datetime

    def __post_init__(self) -> None:
        _text(self.provider, "checkpoint provider")
        _text(self.kind, "checkpoint kind")
        _text(self.value, "checkpoint value")
        _aware(self.successful_at, "checkpoint successful_at")


class Store(Protocol):
    def account(self, mailbox: Mailbox) -> int: ...

    def checkpoint(self, account: int) -> Checkpoint | None: ...

    def begin(
        self, scan_id: str, account: int, mode: ScanMode, generation: str, started: datetime
    ) -> None: ...

    def seen(self, account: int, message_key: str) -> bool: ...

    def put(self, account: int, generation: str, message: MessageSignals) -> bool: ...

    def signals(self, account: int, generation: str) -> tuple[MessageSignals, ...]: ...

    def findings(self, account: int) -> tuple[Finding, ...]: ...

    def complete(
        self,
        account: int,
        result: ScanResult,
        generation: str,
        findings: tuple[Finding, ...],
        checkpoint: Checkpoint | None,
        promote: bool,
    ) -> None: ...

    def discard(self, account: int, result: ScanResult, generation: str) -> None: ...

    def fail(self, scan_id: str, account: int, generation: str, completed: datetime) -> None: ...


class Locks(Protocol):
    def acquire(self, account: str) -> AbstractContextManager[None]: ...


class Reader(Protocol):
    def accounts(self) -> tuple[tuple[int, str, str], ...]: ...

    def findings(self, account: int) -> tuple[Finding, ...]: ...

    def scan(self, account: int) -> ScanResult | None: ...
