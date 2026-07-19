from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

IDENTITY_POLICY = "identity-v1"
RELATIONSHIP_POLICY = "relationship-v1"


class Band(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def band(score: int) -> Band:
    if score >= 75:
        return Band.HIGH
    if score >= 50:
        return Band.MEDIUM
    return Band.LOW


@dataclass(frozen=True, slots=True)
class Confidence:
    score: int
    band: Band
    explanations: tuple[str, ...]
    policy: str

    def __post_init__(self) -> None:
        if type(self.score) is not int or not 0 <= self.score <= 100:
            raise ValueError("confidence score must be between 0 and 100")
        if not isinstance(self.band, Band):
            raise ValueError("confidence band must be an enum")
        if self.band is not band(self.score):
            raise ValueError("confidence band must match score")
        if (
            not isinstance(self.policy, str)
            or not self.policy
            or self.policy != self.policy.strip()
            or not self.explanations
            or any(
                not isinstance(value, str) or not value or value != value.strip()
                for value in self.explanations
            )
        ):
            raise ValueError("confidence requires policy and explanations")
        object.__setattr__(self, "explanations", tuple(sorted(set(self.explanations))))
