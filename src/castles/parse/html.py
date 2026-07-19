from __future__ import annotations

import re
from collections.abc import Iterable

from bs4 import BeautifulSoup, Tag
from bs4.exceptions import ParserRejectedMarkup

from castles.core.error import ParsingError

MAX_HTML_LINKS = 200
BLOCKED_TAGS = ("script", "style", "noscript", "template", "svg", "canvas")
HIDDEN_STYLE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
    re.IGNORECASE,
)


def _decompose(elements: Iterable[Tag]) -> None:
    # BeautifulSoup recursively invalidates descendants when an ancestor is decomposed. Every
    # destructive snapshot must therefore be consumed from descendants to ancestors.
    for element in reversed(tuple(elements)):
        if element.parent is not None and isinstance(element.attrs, dict):
            element.decompose()


def _extract(value: str) -> tuple[str, tuple[str, ...]]:
    soup = BeautifulSoup(value, "html.parser")
    _decompose(soup(BLOCKED_TAGS))
    _decompose(soup.select('[hidden], [aria-hidden="true"]'))

    styled = tuple(
        element
        for element in soup.find_all(style=True)
        if isinstance(element.attrs, dict)
        and HIDDEN_STYLE.search(str(element.attrs.get("style", "")))
    )
    _decompose(styled)

    links: list[str] = []
    for node in soup.find_all("a", href=True, limit=MAX_HTML_LINKS):
        if not isinstance(node.attrs, dict):
            continue
        href = str(node.attrs.get("href", ""))
        if href.casefold().startswith(("http://", "https://")):
            links.append(href)
    return " ".join(soup.get_text(" ", strip=True).split()), tuple(links)


def extract(value: str) -> tuple[str, tuple[str, ...]]:
    # HTML is untrusted mailbox input. Known BeautifulSoup/parser data-shape failures reject only
    # this message; programming, storage, provider, locking, and discovery failures still escape.
    try:
        return _extract(value)
    except (AttributeError, ParserRejectedMarkup, RecursionError, TypeError, ValueError):
        raise ParsingError("message HTML content could not be parsed safely") from None
