from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from castles.core.entity import Relationship, Resolution
from castles.core.signal import (
    IDENTITY_KINDS,
    RELATIONSHIP_KINDS,
    MessageSignals,
    Signal,
    SignalKind,
)
from castles.detect.infra import InfraStatus, Infrastructure
from castles.detect.resolve import Decision
from castles.detect.suffix import Suffixes

KIND_RELATIONSHIP = {
    SignalKind.AUTHENTICATION: Relationship.AUTHENTICATION,
    SignalKind.LIFECYCLE: Relationship.LIFECYCLE,
    SignalKind.BILLING: Relationship.BILLING,
    SignalKind.SUBSCRIPTION: Relationship.SUBSCRIPTION,
    SignalKind.COMMERCE: Relationship.COMMERCE,
    SignalKind.SUPPORT: Relationship.SUPPORT,
    SignalKind.ACTIVITY: Relationship.ACTIVITY,
    SignalKind.MARKETING: Relationship.MARKETING,
}


@dataclass(frozen=True, slots=True)
class RelationshipEvidence:
    entity: str
    relationship: Relationship
    signals: tuple[tuple[str, Signal], ...]


def associate(
    messages: tuple[MessageSignals, ...],
    decisions: tuple[Decision, ...],
    suffixes: Suffixes,
    infra: Infrastructure,
) -> tuple[RelationshipEvidence, ...]:
    resolved = {item.entity for item in decisions if item.status is Resolution.RESOLVED}
    grouped: dict[tuple[str, Relationship], list[tuple[str, Signal]]] = defaultdict(list)
    for message in messages:
        entities: set[str] = set()
        for signal in message.signals:
            if signal.kind not in IDENTITY_KINDS:
                continue
            boundary = suffixes.boundary(signal.value)
            if (
                boundary.entity in resolved
                and infra.classify(boundary.hostname).status is InfraStatus.NOT_LISTED
            ):
                entities.add(boundary.entity)
        if len(entities) != 1:
            continue
        entity = entities.pop()
        for signal in message.signals:
            if signal.kind in RELATIONSHIP_KINDS:
                grouped[(entity, KIND_RELATIONSHIP[signal.kind])].append(
                    (message.message_key, signal)
                )
    return tuple(
        RelationshipEvidence(
            entity,
            relationship,
            tuple(sorted(set(values), key=lambda item: (item[0], item[1].sort_key))),
        )
        for (entity, relationship), values in sorted(
            grouped.items(), key=lambda item: (item[0][0], item[0][1].value)
        )
    )
