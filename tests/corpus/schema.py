from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from castles.core.entity import Relationship, Resolution
from castles.core.message import MessageRef, NormalizedMessage, RawMessage
from castles.core.score import Band
from castles.parse.mime import parse

CORPUS_VERSION = 1
_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ADDRESS = re.compile(r"[a-z0-9._+-]+@([a-z0-9.-]+)", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_CATALOG_DOMAINS = (
    "amazonses.com",
    "cloudfront.net",
    "github.io",
    "mailchi.mp",
    "mandrillapp.com",
    "mtasv.net",
    "sendgrid.info",
    "sendgrid.me",
    "sendgrid.net",
)


def _allowed_domain(value: str) -> bool:
    candidate = value.casefold().rstrip(".")
    return (
        candidate.endswith((".example", ".example.com", ".example.net", ".example.org"))
        or candidate in {"example.com", "example.net", "example.org", "www.ck"}
        or candidate.endswith(".ck")
        or any(candidate == item or candidate.endswith("." + item) for item in _CATALOG_DOMAINS)
    )


@dataclass(frozen=True, slots=True)
class Range:
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not 0 <= self.minimum <= self.maximum <= 100:
            raise ValueError("score range must be within 0..100")

    @classmethod
    def exact(cls, value: int) -> Range:
        return cls(value, value)

    def contains(self, value: int) -> bool:
        return self.minimum <= value <= self.maximum


@dataclass(frozen=True, slots=True)
class Message:
    key: str
    observed_at: datetime
    sender: str | None = None
    reply: str | None = None
    return_path: str | None = None
    authenticated: tuple[str, ...] = ()
    subject: str = ""
    text: str = ""
    links: tuple[str, ...] = ()
    unsubscribe: tuple[str, ...] = ()
    raw: bytes | None = None

    def __post_init__(self) -> None:
        if not self.key.startswith("corpus/") or self.key != self.key.strip():
            raise ValueError("corpus message keys must be synthetic and namespaced")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("corpus timestamps must be timezone-aware")
        normalized = (
            self.sender,
            self.reply,
            self.return_path,
            *self.authenticated,
            *self.links,
            *self.unsubscribe,
        )
        if self.raw is not None and any(value for value in (*normalized, self.subject, self.text)):
            raise ValueError("raw and normalized message inputs are mutually exclusive")
        values = [value for value in normalized if value]
        for value in values:
            if not _allowed_domain(value):
                raise ValueError(f"non-synthetic corpus domain: {value}")
        if self.raw is not None:
            text = self.raw.decode("utf-8", errors="strict")
            if re.search(r"(?im)^(authorization|authentication-results):", text):
                raise ValueError("authentication and authorization headers are forbidden")
            domains = [match.group(1) for match in _ADDRESS.finditer(text)]
            domains.extend(match.split("/", 3)[2].split(":", 1)[0] for match in _URL.findall(text))
            negative_hosts = {"127.0.0.1", "localhost", "printer.local"}
            if any(
                not _allowed_domain(domain) and domain not in negative_hosts for domain in domains
            ):
                raise ValueError("raw corpus messages may use only reserved or catalog domains")

    def normalize(self) -> NormalizedMessage:
        if self.raw is not None:
            return parse(RawMessage(MessageRef(self.key), self.raw, self.observed_at))
        return NormalizedMessage(
            self.key,
            self.observed_at,
            self.sender,
            self.reply,
            self.return_path,
            self.authenticated,
            self.subject,
            self.text,
            self.links,
            self.unsubscribe,
        )

    def private(self) -> tuple[str, ...]:
        values = [self.key, self.subject, self.text]
        if self.raw is not None:
            text = self.raw.decode("utf-8")
            addresses = tuple(match.group(0) for match in _ADDRESS.finditer(text))
            values.extend(addresses)
            values.extend(address.split("@", 1)[0] for address in addresses)
            urls = tuple(match.group(0) for match in _URL.finditer(text))
            values.extend(urls)
            for url in urls:
                parts = urlsplit(url)
                values.extend((parts.path, parts.query))
            subject = re.search(r"(?im)^subject:\s*(.+)$", text)
            if subject:
                values.append(subject.group(1).strip())
            body = text.partition("\r\n\r\n")[2] or text.partition("\n\n")[2]
            values.append(body.strip())
        return tuple(sorted({value for value in values if len(value) >= 4}))


@dataclass(frozen=True, slots=True)
class Relation:
    kind: Relationship
    score: Range
    band: Band
    explanations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.explanations:
            raise ValueError("relationship explanations must be declared")


@dataclass(frozen=True, slots=True)
class Finding:
    entity: str
    identity: Range
    band: Band
    identity_explanations: tuple[str, ...]
    relationships: tuple[Relation, ...]
    explanations: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    message_count: int

    def __post_init__(self) -> None:
        if self.first_seen > self.last_seen or self.message_count < 1:
            raise ValueError("finding observation bounds are invalid")
        if len({item.kind for item in self.relationships}) != len(self.relationships):
            raise ValueError("expected relationship kinds must be unique")


@dataclass(frozen=True, slots=True)
class Decision:
    entity: str
    state: Resolution
    identity: Range | None = None
    explanations: tuple[str, ...] = ("resolution.domain_evidence",)


@dataclass(frozen=True, slots=True)
class Case:
    identifier: str
    family: str
    purpose: str
    messages: tuple[Message, ...]
    findings: tuple[Finding, ...] = ()
    suppressed: tuple[str, ...] = ()
    decisions: tuple[Decision, ...] = ()
    private: tuple[str, ...] = ()
    deterministic: bool = True
    version: int = CORPUS_VERSION

    def __post_init__(self) -> None:
        if self.version != CORPUS_VERSION:
            raise ValueError("unsupported corpus case version")
        if not _ID.fullmatch(self.identifier) or not _ID.fullmatch(self.family):
            raise ValueError("case identifiers and families must use stable kebab-case")
        if not self.purpose.strip() or not self.messages:
            raise ValueError("cases require a purpose and at least one message")
        if len({item.key for item in self.messages}) != len(self.messages):
            raise ValueError("message keys must be unique within a case")
        entities = {item.entity for item in self.findings}
        if len(entities) != len(self.findings) or entities & set(self.suppressed):
            raise ValueError("finding and suppression expectations must be disjoint")
        if len({item.entity for item in self.decisions}) != len(self.decisions):
            raise ValueError("decision expectations must be unique")
        derived = {value for item in self.messages for value in item.private()}
        object.__setattr__(self, "private", tuple(sorted(derived | set(self.private))))


def msg(
    identifier: str,
    observed_at: datetime,
    *,
    sender: str | None = None,
    reply: str | None = None,
    return_path: str | None = None,
    authenticated: tuple[str, ...] = (),
    subject: str = "",
    text: str = "",
    links: tuple[str, ...] = (),
    unsubscribe: tuple[str, ...] = (),
    raw: bytes | None = None,
) -> Message:
    return Message(
        f"corpus/{identifier}",
        observed_at,
        sender,
        reply,
        return_path,
        authenticated,
        subject,
        text,
        links,
        unsubscribe,
        raw,
    )


def relation(kind: Relationship, score: int, code: str) -> Relation:
    return Relation(
        kind,
        Range.exact(score),
        _band(score),
        tuple(sorted((code, f"relationship.{kind.value}"))),
    )


def finding(
    entity: str,
    score: int,
    first_seen: datetime,
    last_seen: datetime,
    count: int,
    *,
    relationships: tuple[Relation, ...] = (),
    explanations: tuple[str, ...] = ("resolution.domain_evidence",),
    identity_explanations: tuple[str, ...] = ("identity.sender",),
) -> Finding:
    return Finding(
        entity,
        Range.exact(score),
        _band(score),
        identity_explanations,
        relationships,
        explanations,
        first_seen,
        last_seen,
        count,
    )


def _band(score: int) -> Band:
    if score < 50:
        return Band.LOW
    if score < 75:
        return Band.MEDIUM
    return Band.HIGH
