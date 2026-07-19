from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from castles.core.entity import Relationship
from castles.core.message import _aware, _text
from castles.core.score import IDENTITY_POLICY, RELATIONSHIP_POLICY, Confidence

FINDING_SCHEMA_VERSION = 1
REPORT_POLICY = "report-v1"


@dataclass(frozen=True, slots=True)
class RelationshipFinding:
    kind: Relationship
    confidence: Confidence

    @property
    def sort_key(self) -> str:
        return self.kind.value


@dataclass(frozen=True, slots=True)
class Finding:
    entity: str
    identity: Confidence
    relationships: tuple[RelationshipFinding, ...]
    first_seen: datetime
    last_seen: datetime
    message_count: int
    explanations: tuple[str, ...]
    policy: str = REPORT_POLICY
    schema: int = FINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _text(self.entity, "entity")
        _aware(self.first_seen, "first_seen")
        _aware(self.last_seen, "last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must not follow last_seen")
        if type(self.message_count) is not int:
            raise ValueError("message_count must be an integer")
        if self.message_count < 1:
            raise ValueError("message_count must be positive")
        if self.schema != FINDING_SCHEMA_VERSION or self.policy != REPORT_POLICY:
            raise ValueError("unsupported finding schema")
        if self.identity.policy != IDENTITY_POLICY:
            raise ValueError("unsupported identity policy")
        if any(item.confidence.policy != RELATIONSHIP_POLICY for item in self.relationships):
            raise ValueError("unsupported relationship policy")
        relationships = tuple(sorted(set(self.relationships), key=lambda item: item.sort_key))
        if len({item.kind for item in relationships}) != len(relationships):
            raise ValueError("relationship kinds must be unique")
        object.__setattr__(self, "relationships", relationships)
        object.__setattr__(self, "explanations", tuple(sorted(set(self.explanations))))

    @property
    def sort_key(self) -> tuple[int, str]:
        return -self.identity.score, self.entity
