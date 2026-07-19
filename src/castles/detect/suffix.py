from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files
from ipaddress import ip_address

import idna

from castles.core.error import CorruptionError, InputError

SNAPSHOT_ID = "psl-8eb9e60139cb"
SNAPSHOT_COMMIT = "8eb9e60139cb2c62ccec664554adae3767dc1374"
SNAPSHOT_DATE = "2026-07-13T21:14:21Z"
SNAPSHOT_SHA256 = "29497fc30946618d0f01903f1854bc35c7662f221ad8ed3beb1b3738b8ca0fdf"
NORMALIZATION_POLICY = "domain-v1"
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Section(StrEnum):
    ICANN = "icann"
    PRIVATE = "private"
    NONE = "none"


class Rule(StrEnum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    EXCEPTION = "exception"
    PREVAILING = "prevailing"


@dataclass(frozen=True, slots=True)
class Boundary:
    hostname: str
    suffix: str
    entity: str | None
    section: Section
    rule: Rule
    prevailing: str
    private: bool


@dataclass(frozen=True, slots=True)
class _Rules:
    exact: frozenset[str]
    wildcard: frozenset[str]
    exception: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Index:
    icann: _Rules
    private: _Rules


@dataclass(frozen=True, slots=True)
class _Match:
    section: Section
    rule: Rule
    text: str
    suffix_labels: int
    specificity: int


def hostname(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate or len(candidate) > 253 or candidate.endswith(".local"):
        raise InputError("hostname is malformed")
    try:
        ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        raise InputError("IP addresses are not entity hostnames") from None
    try:
        canonical = idna.encode(candidate, uts46=True).decode("ascii")
    except idna.IDNAError:
        raise InputError("hostname is malformed") from None
    labels = canonical.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise InputError("hostname is malformed")
    return canonical


def _load() -> _Index:
    data = files("castles.detect").joinpath("data/suffix.dat").read_bytes()
    if sha256(data).hexdigest() != SNAPSHOT_SHA256:
        raise CorruptionError("bundled Public Suffix List checksum does not match")
    values: dict[Section, dict[str, set[str]]] = {
        Section.ICANN: {"exact": set(), "wildcard": set(), "exception": set()},
        Section.PRIVATE: {"exact": set(), "wildcard": set(), "exception": set()},
    }
    current: Section | None = None
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CorruptionError("bundled Public Suffix List is not UTF-8") from exc
    for raw in lines:
        line = raw.strip()
        if line == "// ===BEGIN ICANN DOMAINS===":
            current = Section.ICANN
            continue
        if line == "// ===BEGIN PRIVATE DOMAINS===":
            current = Section.PRIVATE
            continue
        if line in {"// ===END ICANN DOMAINS===", "// ===END PRIVATE DOMAINS==="}:
            current = None
            continue
        if not line or line.startswith("//"):
            continue
        if current is None:
            raise CorruptionError("bundled Public Suffix List has a rule outside a section")
        target = "exact"
        if line.startswith("!"):
            target, line = "exception", line[1:]
        elif line.startswith("*."):
            target, line = "wildcard", line[2:]
        try:
            canonical = idna.encode(line, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise CorruptionError("bundled Public Suffix List contains a malformed rule") from exc
        values[current][target].add(canonical)

    def freeze(section: Section) -> _Rules:
        item = values[section]
        return _Rules(
            frozenset(item["exact"]), frozenset(item["wildcard"]), frozenset(item["exception"])
        )

    return _Index(freeze(Section.ICANN), freeze(Section.PRIVATE))


def _matches(labels: tuple[str, ...], rules: _Rules, section: Section) -> list[_Match]:
    result: list[_Match] = []
    for start in range(len(labels)):
        suffix = ".".join(labels[start:])
        size = len(labels) - start
        if suffix in rules.exception:
            result.append(_Match(section, Rule.EXCEPTION, "!" + suffix, size - 1, size))
        if suffix in rules.exact:
            result.append(_Match(section, Rule.EXACT, suffix, size, size))
        if start > 0 and suffix in rules.wildcard:
            result.append(_Match(section, Rule.WILDCARD, "*." + suffix, size + 1, size + 1))
    return result


def _select(labels: tuple[str, ...], index: _Index, private: bool) -> _Match:
    matches = _matches(labels, index.icann, Section.ICANN)
    if private:
        matches.extend(_matches(labels, index.private, Section.PRIVATE))
    exceptions = [item for item in matches if item.rule is Rule.EXCEPTION]
    if exceptions:
        return max(exceptions, key=lambda item: (item.specificity, item.section.value))
    if matches:
        return max(
            matches,
            key=lambda item: (
                item.specificity,
                item.rule is Rule.EXACT,
                item.section is Section.PRIVATE,
            ),
        )
    return _Match(Section.NONE, Rule.PREVAILING, "*", 1, 1)


@dataclass(frozen=True, slots=True)
class Suffixes:
    _index: _Index = field(default_factory=_load, repr=False)

    def boundary(self, value: str) -> Boundary:
        canonical = hostname(value)
        labels = tuple(canonical.split("."))
        selected = _select(labels, self._index, True)
        suffix = ".".join(labels[-selected.suffix_labels :])
        entity = (
            None
            if len(labels) == selected.suffix_labels
            else ".".join(labels[-(selected.suffix_labels + 1) :])
        )
        return Boundary(
            canonical,
            suffix,
            entity,
            selected.section,
            selected.rule,
            selected.text,
            selected.section is Section.PRIVATE,
        )
