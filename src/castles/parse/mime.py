from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from ipaddress import ip_address

import idna

from castles.core.error import ParsingError
from castles.core.message import NormalizedMessage, RawMessage
from castles.parse.html import extract
from castles.parse.url import hostnames

MAX_RAW_BYTES = 25 * 1024 * 1024
MAX_PARTS = 200
MAX_DEPTH = 12
MAX_TEXT_BYTES = 512 * 1024
MAX_TEXT_CHARS = 256 * 1024
MAX_SUBJECT = 1000


def _domain(value: str | None) -> str | None:
    if not value:
        return None
    addresses = getaddresses([value])
    if not addresses or "@" not in addresses[0][1]:
        return None
    candidate = addresses[0][1].rsplit("@", 1)[1].strip().rstrip(".")
    try:
        ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        return None
    try:
        result = idna.encode(candidate, uts46=True).decode("ascii").casefold()
    except (UnicodeError, idna.IDNAError):
        return None
    return (
        result if "." in result and len(result) <= 253 and not result.endswith(".local") else None
    )


def _decode(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes) or len(payload) > MAX_TEXT_BYTES:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")[:MAX_TEXT_CHARS]
    except LookupError:
        return payload.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS]


def _parts(root: Message) -> tuple[list[str], list[str], list[str]]:
    plain: list[str] = []
    rendered: list[str] = []
    links: list[str] = []
    stack: list[tuple[Message, int]] = [(root, 0)]
    count = 0
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > MAX_PARTS or depth > MAX_DEPTH:
            raise ParsingError("message MIME structure exceeds safe limits")
        if part.is_multipart():
            children = list(part.iter_parts()) if hasattr(part, "iter_parts") else []
            stack.extend((child, depth + 1) for child in reversed(children))
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        content = _decode(part)
        if not content:
            continue
        if part.get_content_type() == "text/plain":
            plain.append(content)
        elif part.get_content_type() == "text/html":
            text, urls = extract(content)
            rendered.append(text)
            links.extend(urls)
    return plain, rendered, links


def parse(raw: RawMessage) -> NormalizedMessage:
    if len(raw.raw) > MAX_RAW_BYTES:
        raise ParsingError("message exceeds the safe byte limit")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw.raw)
    except (ValueError, TypeError, IndexError):
        raise ParsingError("message could not be parsed safely") from None
    plain, rendered, html_links = _parts(message)
    text = " ".join(" ".join((*plain, *rendered)).split())[:MAX_TEXT_CHARS]
    unsubscribe = hostnames(str(message.get("List-Unsubscribe", "")))
    return NormalizedMessage(
        key=raw.ref.key,
        observed_at=raw.observed_at,
        sender=_domain(str(message.get("From", ""))),
        reply=_domain(str(message.get("Reply-To", ""))),
        return_path=_domain(str(message.get("Return-Path", ""))),
        authenticated=raw.authenticated,
        subject=str(message.get("Subject", ""))[:MAX_SUBJECT],
        text=text,
        links=hostnames(text, tuple(html_links)),
        unsubscribe=unsubscribe,
    )
