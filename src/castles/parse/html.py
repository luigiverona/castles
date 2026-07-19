from __future__ import annotations

import re

from bs4 import BeautifulSoup

MAX_HTML_LINKS = 200


def extract(value: str) -> tuple[str, tuple[str, ...]]:
    soup = BeautifulSoup(value, "html.parser")
    for element in soup(["script", "style", "noscript", "template", "svg", "canvas"]):
        element.decompose()
    for element in soup.select('[hidden], [aria-hidden="true"]'):
        element.decompose()
    for element in soup.find_all(style=True):
        if re.search(
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
            str(element.get("style", "")),
            re.IGNORECASE,
        ):
            element.decompose()
    links = tuple(
        str(node.get("href"))
        for node in soup.find_all("a", href=True, limit=MAX_HTML_LINKS)
        if str(node.get("href")).casefold().startswith(("http://", "https://"))
    )
    return " ".join(soup.get_text(" ", strip=True).split()), links
