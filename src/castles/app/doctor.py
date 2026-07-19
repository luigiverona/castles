from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Health(StrEnum):
    OK = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    health: Health
    detail: str


def healthy(checks: tuple[Check, ...]) -> bool:
    return all(check.health is not Health.FAIL for check in checks)
