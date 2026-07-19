from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from castles.core.message import _aware, _text

SIGNAL_SCHEMA_VERSION = 1
EXTRACTION_POLICY = "extract-v1"


class SignalKind(StrEnum):
    SENDER = "sender"
    REPLY = "reply"
    RETURN_PATH = "return_path"
    AUTHENTICATED = "authenticated"
    LINK = "link"
    UNSUBSCRIBE = "unsubscribe"
    AUTHENTICATION = "authentication"
    LIFECYCLE = "lifecycle"
    BILLING = "billing"
    SUBSCRIPTION = "subscription"
    COMMERCE = "commerce"
    SUPPORT = "support"
    ACTIVITY = "activity"
    MARKETING = "marketing"


class SignalSource(StrEnum):
    HEADER = "header"
    SUBJECT = "subject"
    TEXT = "text"
    URL = "url"


class Strength(StrEnum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


IDENTITY_KINDS = frozenset(
    {
        SignalKind.SENDER,
        SignalKind.REPLY,
        SignalKind.RETURN_PATH,
        SignalKind.AUTHENTICATED,
        SignalKind.LINK,
        SignalKind.UNSUBSCRIBE,
    }
)
RELATIONSHIP_KINDS = frozenset(set(SignalKind) - IDENTITY_KINDS)


@dataclass(frozen=True, slots=True)
class Signal:
    kind: SignalKind
    source: SignalSource
    value: str
    strength: Strength
    code: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SignalKind) or not isinstance(self.source, SignalSource):
            raise ValueError("signal kind and source must be enums")
        if not isinstance(self.strength, Strength):
            raise ValueError("signal strength must be an enum")
        _text(self.value, "signal value")
        _text(self.code, "signal code")

    @property
    def sort_key(self) -> tuple[str, str, str, str, str]:
        return self.kind.value, self.source.value, self.value, self.strength.value, self.code


@dataclass(frozen=True, slots=True)
class MessageSignals:
    message_key: str
    observed_at: datetime
    signals: tuple[Signal, ...]
    policy: str = EXTRACTION_POLICY
    schema: int = SIGNAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _text(self.message_key, "message key")
        _aware(self.observed_at, "observed_at")
        if self.schema != SIGNAL_SCHEMA_VERSION or self.policy != EXTRACTION_POLICY:
            raise ValueError("unsupported signal schema")
        canonical = tuple(sorted(set(self.signals), key=lambda signal: signal.sort_key))
        object.__setattr__(self, "signals", canonical)

    def __repr__(self) -> str:
        return (
            "MessageSignals(message_key=<private>, "
            f"observed_at={self.observed_at!r}, signals={len(self.signals)}, policy={self.policy!r})"
        )
