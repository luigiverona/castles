from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from castles.core.finding import Finding
from castles.core.message import NormalizedMessage, RawMessage
from castles.core.signal import MessageSignals

Parser = Callable[[RawMessage], NormalizedMessage]
Extractor = Callable[[NormalizedMessage], MessageSignals]
Discovery = Callable[[tuple[MessageSignals, ...]], tuple[Finding, ...]]


class SetupTerminal(Protocol):
    """Minimal interactive terminal boundary used by guided setup."""

    def interactive(self) -> bool: ...

    def write(self, message: str) -> None: ...

    def confirm(self, prompt: str, *, default: bool = True) -> bool | None: ...

    def select(self, prompt: str, choices: tuple[str, ...]) -> int | None: ...

    def path(self, prompt: str) -> Path | None: ...
