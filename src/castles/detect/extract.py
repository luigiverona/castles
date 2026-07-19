from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from castles.core.message import NormalizedMessage
from castles.core.signal import MessageSignals, Signal, SignalKind, SignalSource, Strength


@dataclass(frozen=True, slots=True)
class Phrase:
    kind: SignalKind
    code: str
    values: tuple[str, ...]


PHRASES = (
    Phrase(
        SignalKind.AUTHENTICATION,
        "auth.event",
        ("verification code", "sign in attempt", "new login", "password reset", "two factor code"),
    ),
    Phrase(
        SignalKind.LIFECYCLE,
        "lifecycle.event",
        (
            "confirm your account",
            "account was created",
            "account has been created",
            "account was closed",
            "account has been closed",
        ),
    ),
    Phrase(
        SignalKind.BILLING,
        "billing.event",
        (
            "invoice available",
            "invoice is available",
            "payment failed",
            "payment has failed",
            "billing statement",
            "payment receipt",
        ),
    ),
    Phrase(
        SignalKind.SUBSCRIPTION,
        "subscription.event",
        (
            "subscription renewed",
            "subscription has renewed",
            "subscription canceled",
            "subscription cancelled",
            "trial ending",
            "trial is ending",
        ),
    ),
    Phrase(
        SignalKind.COMMERCE,
        "commerce.event",
        ("order confirmed", "order has shipped", "order shipped", "purchase receipt"),
    ),
    Phrase(
        SignalKind.SUPPORT,
        "support.event",
        ("support request", "support ticket", "case received", "case has been received"),
    ),
    Phrase(
        SignalKind.ACTIVITY,
        "activity.event",
        ("activity summary", "recent activity", "new account activity"),
    ),
    Phrase(
        SignalKind.MARKETING,
        "marketing.event",
        ("special offer", "promotional offer", "sale ends soon", "limited time offer"),
    ),
)


def _tokens(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join("".join(char if char.isalnum() else " " for char in normalized).split())


def _language(value: str, source: SignalSource, strength: Strength) -> list[Signal]:
    padded = f" {_tokens(value)} "
    return [
        Signal(item.kind, source, item.code, strength, item.code)
        for item in PHRASES
        if any(f" {phrase} " in padded for phrase in item.values)
    ]


def extract(message: NormalizedMessage) -> MessageSignals:
    signals: list[Signal] = []
    structural = (
        (SignalKind.SENDER, message.sender, Strength.STRONG, "identity.sender"),
        (SignalKind.REPLY, message.reply, Strength.MODERATE, "identity.reply"),
        (SignalKind.RETURN_PATH, message.return_path, Strength.MODERATE, "identity.return"),
    )
    for kind, value, strength, code in structural:
        if value:
            signals.append(Signal(kind, SignalSource.HEADER, value, strength, code))
    for value in message.authenticated:
        signals.append(
            Signal(
                SignalKind.AUTHENTICATED,
                SignalSource.HEADER,
                value,
                Strength.STRONG,
                "identity.authenticated",
            )
        )
    for value in message.links:
        signals.append(
            Signal(SignalKind.LINK, SignalSource.URL, value, Strength.WEAK, "identity.link")
        )
    for value in message.unsubscribe:
        signals.append(
            Signal(
                SignalKind.UNSUBSCRIBE,
                SignalSource.URL,
                value,
                Strength.WEAK,
                "identity.unsubscribe",
            )
        )
    signals.extend(_language(message.subject, SignalSource.SUBJECT, Strength.MODERATE))
    signals.extend(_language(message.text, SignalSource.TEXT, Strength.WEAK))
    return MessageSignals(message.key, message.observed_at, tuple(signals))
