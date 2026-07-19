from __future__ import annotations

from dataclasses import dataclass

from castles.core.entity import Resolution
from castles.core.signal import IDENTITY_KINDS, MessageSignals, Signal, SignalKind
from castles.detect.infra import InfraStatus, Infrastructure
from castles.detect.suffix import Boundary, Suffixes


@dataclass(frozen=True, slots=True)
class Candidate:
    entity: str
    messages: tuple[MessageSignals, ...]
    evidence: tuple[tuple[str, Signal, Boundary], ...]


@dataclass(frozen=True, slots=True)
class Decision:
    entity: str
    status: Resolution
    candidate: Candidate | None
    reasons: tuple[str, ...]


def resolve(
    messages: tuple[MessageSignals, ...], suffixes: Suffixes, infra: Infrastructure
) -> tuple[Decision, ...]:
    grouped: dict[str, list[tuple[str, Signal, Boundary]]] = {}
    ambiguous: dict[str, str] = {}
    by_key = {message.message_key: message for message in messages}
    for message in messages:
        for signal in message.signals:
            if signal.kind not in IDENTITY_KINDS:
                continue
            boundary = suffixes.boundary(signal.value)
            if boundary.entity is None:
                continue
            classification = infra.classify(boundary.hostname)
            if classification.status is InfraStatus.KNOWN:
                continue
            if classification.status is InfraStatus.AMBIGUOUS:
                ambiguous[boundary.entity] = classification.code or "infra.ambiguous"
                continue
            grouped.setdefault(boundary.entity, []).append((message.message_key, signal, boundary))
    decisions: list[Decision] = [
        Decision(entity, Resolution.AMBIGUOUS, None, (code,)) for entity, code in ambiguous.items()
    ]
    for entity, evidence in grouped.items():
        keys = sorted({item[0] for item in evidence})
        candidate = Candidate(
            entity,
            tuple(by_key[key] for key in keys),
            tuple(sorted(set(evidence), key=lambda item: (item[0], item[1].sort_key))),
        )
        kinds = {item[1].kind for item in evidence}
        resolved = bool(
            kinds
            & {
                SignalKind.SENDER,
                SignalKind.AUTHENTICATED,
                SignalKind.REPLY,
                SignalKind.RETURN_PATH,
            }
        )
        if not resolved and len(keys) >= 2 and kinds != {SignalKind.LINK}:
            resolved = True
        status = Resolution.RESOLVED if resolved else Resolution.UNRESOLVED
        reason = "resolution.domain_evidence" if resolved else "resolution.insufficient_identity"
        decisions.append(Decision(entity, status, candidate, (reason,)))
    return tuple(sorted(decisions, key=lambda item: (item.entity, item.status.value)))
