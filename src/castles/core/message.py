from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


def _aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _text(value: str, field: str) -> None:
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError(f"{field} must be non-empty normalized text")


@dataclass(frozen=True, slots=True)
class Mailbox:
    provider: str
    account_id: str
    address: str

    def __post_init__(self) -> None:
        _text(self.provider, "provider")
        _text(self.account_id, "account_id")
        if "@" not in self.address or self.address != self.address.casefold():
            raise ValueError("address must be a normalized mailbox address")

    def __repr__(self) -> str:
        return f"Mailbox(provider={self.provider!r}, account_id=<private>, address=<private>)"


@dataclass(frozen=True, slots=True)
class MessageRef:
    key: str

    def __post_init__(self) -> None:
        _text(self.key, "message key")


@dataclass(frozen=True, slots=True)
class RawMessage:
    ref: MessageRef
    raw: bytes
    observed_at: datetime
    authenticated: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _aware(self.observed_at, "observed_at")
        if not self.raw:
            raise ValueError("raw message must not be empty")

    def __repr__(self) -> str:
        return (
            "RawMessage(ref=<private>, raw=<private>, "
            f"observed_at={self.observed_at!r}, authenticated=<private>)"
        )


@dataclass(frozen=True, slots=True)
class NormalizedMessage:
    key: str
    observed_at: datetime
    sender: str | None
    reply: str | None
    return_path: str | None
    authenticated: tuple[str, ...]
    subject: str
    text: str
    links: tuple[str, ...]
    unsubscribe: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.key, "message key")
        _aware(self.observed_at, "observed_at")
        object.__setattr__(self, "authenticated", tuple(sorted(set(self.authenticated))))
        object.__setattr__(self, "links", tuple(sorted(set(self.links))))
        object.__setattr__(self, "unsubscribe", tuple(sorted(set(self.unsubscribe))))

    def __repr__(self) -> str:
        return (
            f"NormalizedMessage(key=<private>, observed_at={self.observed_at!r}, content=<private>)"
        )
