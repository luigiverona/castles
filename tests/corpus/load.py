from __future__ import annotations

from .cases.identity import CASES as IDENTITY
from .cases.infra import CASES as INFRA
from .cases.privacy import CASES as PRIVACY
from .cases.relation import CASES as RELATION
from .cases.resolve import CASES as RESOLVE
from .cases.score import CASES as SCORE
from .schema import Case


def load() -> tuple[Case, ...]:
    cases = tuple(
        sorted(
            (*IDENTITY, *INFRA, *RESOLVE, *RELATION, *SCORE, *PRIVACY),
            key=lambda item: item.identifier,
        )
    )
    identifiers = {case.identifier for case in cases}
    if len(identifiers) != len(cases):
        raise ValueError("corpus case identifiers must be globally unique")
    expected = {"identity", "infra", "privacy", "relation", "resolve", "score"}
    if {case.family for case in cases} != expected:
        raise ValueError("corpus case families are incomplete")
    return cases
