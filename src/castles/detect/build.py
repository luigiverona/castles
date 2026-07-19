from __future__ import annotations

from collections import defaultdict

from castles.core.entity import Resolution
from castles.core.finding import Finding, RelationshipFinding
from castles.core.signal import MessageSignals
from castles.detect.assess import identity, relationship
from castles.detect.evidence import associate
from castles.detect.infra import Infrastructure
from castles.detect.resolve import resolve
from castles.detect.suffix import Suffixes

REPORTABLE_IDENTITY = 30
REPORTABLE_RELATIONSHIP = 12


def discover(
    messages: tuple[MessageSignals, ...],
    suffixes: Suffixes | None = None,
    infrastructure: Infrastructure | None = None,
) -> tuple[Finding, ...]:
    suffixes = suffixes or Suffixes()
    infrastructure = infrastructure or Infrastructure()
    decisions = resolve(messages, suffixes, infrastructure)
    associations = associate(messages, decisions, suffixes, infrastructure)
    relationships: dict[str, list[RelationshipFinding]] = defaultdict(list)
    for value in associations:
        confidence = relationship(value)
        if confidence.score >= REPORTABLE_RELATIONSHIP:
            relationships[value.entity].append(RelationshipFinding(value.relationship, confidence))
    findings: list[Finding] = []
    for decision in decisions:
        if decision.status is not Resolution.RESOLVED or decision.candidate is None:
            continue
        confidence = identity(decision.candidate)
        if confidence.score < REPORTABLE_IDENTITY:
            continue
        observed = [message.observed_at for message in decision.candidate.messages]
        findings.append(
            Finding(
                decision.entity,
                confidence,
                tuple(relationships[decision.entity]),
                min(observed),
                max(observed),
                len(decision.candidate.messages),
                decision.reasons,
            )
        )
    return tuple(sorted(findings, key=lambda item: item.sort_key))
