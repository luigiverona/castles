from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from .judge import evaluate
from .load import load
from .schema import CORPUS_VERSION, Case, Message

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def test_corpus_baseline() -> None:
    report = evaluate()
    assert report.corpus_version == CORPUS_VERSION
    assert report.ok, report.detail()


def test_corpus_report_is_deterministic() -> None:
    assert evaluate().summary() == evaluate(tuple(reversed(load()))).summary()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Message("not-namespaced", NOW, sender="mail.example.com"),
        lambda: Message(
            "corpus/forbidden-domain",
            NOW,
            raw=b"From: synthetic@invalid.test\r\n\r\nSynthetic body",
        ),
        lambda: Message(
            "corpus/forbidden-header",
            NOW,
            raw=(
                b"From: synthetic@example.com\r\n"
                b"Authorization: Bearer synthetic\r\n\r\nSynthetic body"
            ),
        ),
    ],
)
def test_schema_rejects_non_synthetic_inputs(factory: Callable[[], Message]) -> None:
    with pytest.raises(ValueError):
        factory()


def test_schema_rejects_incomplete_case() -> None:
    with pytest.raises(ValueError, match="purpose"):
        Case("incomplete", "identity", "", ())
