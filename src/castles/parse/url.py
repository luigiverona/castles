from __future__ import annotations

import re
from ipaddress import ip_address
from itertools import chain, islice
from urllib.parse import urlsplit

import idna

MAX_URL_LENGTH = 4096
MAX_URLS = 200
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def hostname(value: str) -> str | None:
    if not value or len(value) > MAX_URL_LENGTH:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme.casefold() not in {"http", "https"} or parts.username or parts.password:
            return None
        raw = parts.hostname
        if raw is None:
            return None
        try:
            ip_address(raw)
        except ValueError:
            pass
        else:
            return None
        result = idna.encode(raw.rstrip("."), uts46=True).decode("ascii").casefold()
    except (ValueError, UnicodeError, idna.IDNAError):
        return None
    if "." not in result or len(result) > 253 or result.endswith(".local"):
        return None
    return result


def hostnames(text: str, extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    found = (match.group(0).rstrip(".,);]") for match in _URL.finditer(text))
    values = islice(chain(found, extra), MAX_URLS)
    return tuple(sorted({host for value in values if (host := hostname(value)) is not None}))
