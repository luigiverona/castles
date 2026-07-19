from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files

from castles.core.error import CorruptionError
from castles.detect.suffix import hostname

CATALOG_ID = "castles.infrastructure.2026-07-14"
CATALOG_VERSION = "1"
CATALOG_SHA256 = "bab7ddc8343668493395ae6033dc9fa5512c6d4fc1914276bfee885207458a2f"
POLICY = "infra-v1"


class InfraStatus(StrEnum):
    KNOWN = "known"
    AMBIGUOUS = "ambiguous"
    NOT_LISTED = "not_listed"


@dataclass(frozen=True, slots=True)
class Classification:
    status: InfraStatus
    kind: str | None = None
    code: str | None = None


@dataclass(frozen=True, slots=True)
class _Rule:
    domain: str
    subtree: bool
    status: InfraStatus
    kind: str
    code: str


def _load() -> tuple[_Rule, ...]:
    data = files("castles.detect").joinpath("data/infra.toml").read_bytes()
    if sha256(data).hexdigest() != CATALOG_SHA256:
        raise CorruptionError("bundled infrastructure catalog checksum does not match")
    try:
        document = tomllib.loads(data.decode("utf-8"))
        if document.get("schema") != 1 or document.get("identifier") != CATALOG_ID:
            raise ValueError
        result = []
        for value in document["rules"]:
            result.append(
                _Rule(
                    hostname(value["domain"]),
                    value["match"] == "subtree",
                    InfraStatus(value["status"]),
                    value["kind"],
                    value["code"],
                )
            )
    except (UnicodeError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise CorruptionError("bundled infrastructure catalog is malformed") from exc
    return tuple(sorted(result, key=lambda item: (-len(item.domain), item.domain)))


@dataclass(frozen=True, slots=True)
class Infrastructure:
    _rules: tuple[_Rule, ...] = field(default_factory=_load, repr=False)

    def classify(self, value: str) -> Classification:
        canonical = hostname(value)
        for rule in self._rules:
            if canonical == rule.domain or (rule.subtree and canonical.endswith("." + rule.domain)):
                return Classification(rule.status, rule.kind, rule.code)
        return Classification(InfraStatus.NOT_LISTED)
