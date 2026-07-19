from __future__ import annotations

from castles.core.score import IDENTITY_POLICY, RELATIONSHIP_POLICY, Confidence, band
from castles.core.signal import SignalKind, SignalSource
from castles.detect.evidence import RelationshipEvidence
from castles.detect.resolve import Candidate
from castles.detect.suffix import Rule

IDENTITY_WEIGHTS = {
    SignalKind.AUTHENTICATED: 35,
    SignalKind.SENDER: 30,
    SignalKind.RETURN_PATH: 18,
    SignalKind.REPLY: 14,
    SignalKind.UNSUBSCRIBE: 8,
    SignalKind.LINK: 6,
}


def _diminishing(weight: int, count: int) -> int:
    score = 0
    current = weight
    remaining = count
    while remaining and current > 1:
        score += current
        current //= 2
        remaining -= 1
    return score + remaining


def identity(candidate: Candidate) -> Confidence:
    by_kind: dict[SignalKind, set[str]] = {}
    explanations: set[str] = set()
    for key, signal, _boundary in candidate.evidence:
        by_kind.setdefault(signal.kind, set()).add(key)
        explanations.add(signal.code)
    score = sum(_diminishing(IDENTITY_WEIGHTS[kind], len(keys)) for kind, keys in by_kind.items())
    by_message: dict[str, set[SignalKind]] = {}
    for key, signal, _boundary in candidate.evidence:
        by_message.setdefault(key, set()).add(signal.kind)
    if any(
        {SignalKind.SENDER, SignalKind.AUTHENTICATED}.issubset(kinds)
        for kinds in by_message.values()
    ):
        score += 15
        explanations.add("identity.agreement.sender_auth")
    if any(boundary.rule is Rule.PREVAILING for _, _, boundary in candidate.evidence):
        score = min(score, 49)
        explanations.add("identity.cap.prevailing_suffix")
    score = min(score, 100)
    return Confidence(score, band(score), tuple(explanations), IDENTITY_POLICY)


def relationship(value: RelationshipEvidence) -> Confidence:
    subjects = {key for key, signal in value.signals if signal.source is SignalSource.SUBJECT}
    texts = {key for key, signal in value.signals if signal.source is SignalSource.TEXT}
    score = _diminishing(26, len(subjects)) + _diminishing(12, len(texts))
    explanations = {signal.code for _, signal in value.signals}
    explanations.add(f"relationship.{value.relationship.value}")
    score = min(score, 100)
    return Confidence(score, band(score), tuple(explanations), RELATIONSHIP_POLICY)
