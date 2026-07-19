from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from castles.core.entity import Relationship
from castles.core.finding import Finding, RelationshipFinding
from castles.core.message import Mailbox, MessageRef, NormalizedMessage, RawMessage
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.core.score import IDENTITY_POLICY, RELATIONSHIP_POLICY, Band, Confidence, band
from castles.core.signal import MessageSignals, Signal, SignalKind, SignalSource, Strength

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def confidence(value: int, policy: str = IDENTITY_POLICY) -> Confidence:
    return Confidence(value, band(value), ("evidence.example",), policy)


def test_models_are_frozen_and_private_repr() -> None:
    mailbox = Mailbox("gmail", "person@example.com", "person@example.com")
    raw = RawMessage(MessageRef("opaque"), b"message", NOW)
    normalized = NormalizedMessage(
        "opaque", NOW, "example.com", None, None, (), "subject", "body", (), ()
    )
    assert "person@example.com" not in repr(mailbox)
    assert b"message".decode() not in repr(raw)
    assert "subject" not in repr(normalized)
    with pytest.raises(FrozenInstanceError):
        mailbox.provider = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, Band.LOW), (49, Band.LOW), (50, Band.MEDIUM), (75, Band.HIGH), (100, Band.HIGH)],
)
def test_score_bands(value: int, expected: Band) -> None:
    assert band(value) is expected
    assert confidence(value).band is expected


def test_confidence_validation() -> None:
    with pytest.raises(ValueError):
        Confidence(101, Band.HIGH, ("x",), "v1")
    with pytest.raises(ValueError):
        Confidence(20, Band.HIGH, ("x",), "v1")
    with pytest.raises(ValueError, match="enum"):
        Confidence(20, cast(Band, "low"), ("x",), "v1")
    with pytest.raises(ValueError, match="policy and explanations"):
        Confidence(20, Band.LOW, (), "v1")


def test_signals_are_deduplicated_and_sorted() -> None:
    first = Signal(SignalKind.LINK, SignalSource.URL, "b.example", Strength.WEAK, "link")
    second = Signal(SignalKind.SENDER, SignalSource.HEADER, "a.example", Strength.STRONG, "sender")
    message = MessageSignals("opaque", NOW, (first, second, first))
    assert message.signals == (first, second)
    assert "opaque" not in repr(message)


def test_finding_is_deterministic() -> None:
    billing = RelationshipFinding(Relationship.BILLING, confidence(61, RELATIONSHIP_POLICY))
    activity = RelationshipFinding(Relationship.ACTIVITY, confidence(30, RELATIONSHIP_POLICY))
    item = Finding(
        "unknown-saas.example",
        confidence(80),
        (billing, activity),
        NOW,
        NOW,
        2,
        ("z", "a", "a"),
    )
    assert [relationship.kind for relationship in item.relationships] == [
        Relationship.ACTIVITY,
        Relationship.BILLING,
    ]
    assert item.explanations == ("a", "z")


@pytest.mark.parametrize(
    "call",
    [
        lambda: Mailbox("gmail", "person", "not-an-address"),
        lambda: MessageRef(" bad "),
        lambda: RawMessage(MessageRef("x"), b"", NOW),
        lambda: NormalizedMessage("x", datetime(2026, 1, 1), None, None, None, (), "", "", (), ()),
        lambda: Finding("x.example", confidence(50), (), NOW, NOW, 0, ()),
    ],
)
def test_model_validation(call: object) -> None:
    with pytest.raises(ValueError):
        call()  # type: ignore[operator]


@pytest.mark.parametrize(
    "call",
    [
        lambda: ScanResult(
            "scan",
            ScanMode.INITIAL,
            ScanStatus.COMPLETE,
            NOW,
            NOW - timedelta(seconds=1),
            0,
            0,
            0,
            0,
        ),
        lambda: ScanResult("scan", ScanMode.INITIAL, ScanStatus.COMPLETE, NOW, NOW, -1, 0, 0, 0),
        lambda: Signal(
            cast(SignalKind, "sender"), SignalSource.HEADER, "x.example", Strength.STRONG, "x"
        ),
        lambda: Signal(
            SignalKind.SENDER,
            SignalSource.HEADER,
            "x.example",
            cast(Strength, "strong"),
            "x",
        ),
        lambda: Finding(
            "x.example", confidence(50), (), NOW, NOW - timedelta(seconds=1), 1, ("x",)
        ),
        lambda: Finding("x.example", confidence(50), (), NOW, NOW, True, ("x",)),
        lambda: Finding("x.example", confidence(50, "other"), (), NOW, NOW, 1, ("x",)),
        lambda: Finding(
            "x.example",
            confidence(50),
            (RelationshipFinding(Relationship.BILLING, confidence(20, "other")),),
            NOW,
            NOW,
            1,
            ("x",),
        ),
        lambda: Finding(
            "x.example",
            confidence(50),
            (
                RelationshipFinding(Relationship.BILLING, confidence(20, RELATIONSHIP_POLICY)),
                RelationshipFinding(Relationship.BILLING, confidence(30, RELATIONSHIP_POLICY)),
            ),
            NOW,
            NOW,
            1,
            ("x",),
        ),
    ],
)
def test_security_boundary_model_validation(call: object) -> None:
    with pytest.raises(ValueError):
        call()  # type: ignore[operator]
