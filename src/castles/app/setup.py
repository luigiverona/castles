from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from castles.core.message import Mailbox


@dataclass(frozen=True, slots=True)
class Setup:
    configure: Callable[[Path], None]
    authorize: Callable[[bool, bool], Mailbox]

    def execute(self, source: Path, *, force: bool = False, no_browser: bool = False) -> Mailbox:
        self.configure(source)
        return self.authorize(force, no_browser)
