from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from castles.core.message import Mailbox, MessageRef, RawMessage


@dataclass(frozen=True, slots=True)
class MailboxQuery:
    since: datetime | None = None
    checkpoint: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderCheck:
    available: bool
    detail: str


class MailboxProvider(Protocol):
    def identity(self) -> Mailbox: ...

    def enumerate(self, query: MailboxQuery) -> Iterable[MessageRef]: ...

    def fetch(self, ref: MessageRef) -> RawMessage: ...

    def checkpoint(self) -> str | None: ...

    def checkpoint_kind(self) -> str: ...

    def validate(self) -> ProviderCheck: ...
