from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parents[1]
SITE = ROOT / "site"
PAGES = {
    "index.html": "https://castles.luigiverona.dev/",
    "privacy.html": "https://castles.luigiverona.dev/privacy.html",
    "support.html": "https://castles.luigiverona.dev/support.html",
}
FILES = {
    "CNAME",
    "favicon.svg",
    "index.html",
    "install",
    "logo.svg",
    "privacy.html",
    "style.css",
    "support.html",
}
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.end_tags: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, {key: value or "" for key, value in attrs}))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self.end_tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def documents() -> dict[str, Document]:
    result = {}
    for name in PAGES:
        parser = Document()
        parser.feed((SITE / name).read_text())
        parser.close()
        result[name] = parser
    return result


def test_static_site_file_contract_and_public_contact_gate() -> None:
    assert {path.name for path in SITE.iterdir() if path.is_file()} == FILES
    assert not any(path.is_symlink() for path in SITE.rglob("*"))
    assert (SITE / "CNAME").read_text() == "castles.luigiverona.dev\n"
    content = "\n".join(path.read_text() for path in SITE.iterdir() if path.is_file())
    assert not EMAIL.search(content)
    assert "<script" not in content.casefold()
    assert "<form" not in content.casefold()
    assert "analytics" in content.casefold()
    assert "no analytics" in content.casefold()


def test_pages_are_semantic_accessible_and_canonical() -> None:
    parsed = documents()
    identifiers: dict[str, set[str]] = {}
    for name, document in parsed.items():
        tags = [tag for tag, _ in document.tags]
        assert tags.count("html") == 1
        assert next(attrs for tag, attrs in document.tags if tag == "html")["lang"] == "en"
        assert tags.count("title") == 1
        assert tags.count("h1") == 1
        assert tags.count("main") == 1
        assert tags.count("header") == 1
        assert tags.count("footer") == 1
        assert tags.count("nav") >= 2
        assert "title" in document.end_tags
        assert any(
            tag == "meta" and attrs.get("name") == "viewport" for tag, attrs in document.tags
        )
        assert any(
            tag == "meta"
            and attrs.get("http-equiv") == "Content-Security-Policy"
            and "script-src 'none'" in attrs.get("content", "")
            and "connect-src 'none'" in attrs.get("content", "")
            and "form-action 'none'" in attrs.get("content", "")
            for tag, attrs in document.tags
        )
        canonical = [
            attrs.get("href")
            for tag, attrs in document.tags
            if tag == "link" and attrs.get("rel") == "canonical"
        ]
        assert canonical == [PAGES[name]]
        images = [attrs for tag, attrs in document.tags if tag == "img"]
        assert images
        assert all(
            attrs.get("alt") and attrs.get("width") and attrs.get("height") for attrs in images
        )
        ids = [attrs["id"] for _, attrs in document.tags if attrs.get("id")]
        assert len(ids) == len(set(ids))
        identifiers[name] = set(ids)
        skip = [
            attrs for tag, attrs in document.tags if tag == "a" and attrs.get("class") == "skip"
        ]
        assert skip == [{"class": "skip", "href": "#main"}]

    for name, document in parsed.items():
        for tag, attrs in document.tags:
            if tag == "img":
                assert not urlsplit(attrs["src"]).scheme
                assert (SITE / attrs["src"]).is_file()
            if tag == "link" and attrs.get("rel") in {"icon", "stylesheet"}:
                assert not urlsplit(attrs["href"]).scheme
                assert (SITE / attrs["href"]).is_file()
            if tag != "a" or "href" not in attrs:
                continue
            target = attrs["href"]
            parsed_target = urlsplit(target)
            if parsed_target.scheme:
                assert parsed_target.scheme == "https"
                continue
            destination = parsed_target.path or name
            assert (SITE / destination).is_file()
            if parsed_target.fragment:
                assert parsed_target.fragment in identifiers[destination]


def test_no_automatic_outbound_resources_or_active_content() -> None:
    for document in documents().values():
        assert all(
            tag not in {"script", "form", "iframe", "object", "embed"} for tag, _ in document.tags
        )
        for tag, attrs in document.tags:
            if tag in {"img", "script", "iframe", "object", "embed"} and "src" in attrs:
                assert not urlsplit(attrs["src"]).scheme
            if tag == "link" and attrs.get("rel") in {"icon", "stylesheet", "preload"}:
                assert not urlsplit(attrs["href"]).scheme
    stylesheet = (SITE / "style.css").read_text().casefold()
    assert "@import" not in stylesheet
    assert "url(" not in stylesheet


def test_privacy_disclosures_cover_gmail_data_lifecycle() -> None:
    text = (SITE / "privacy.html").read_text().casefold()
    required = (
        "https://www.googleapis.com/auth/gmail.readonly",
        "metadata-only access is insufficient",
        "cannot send, modify, delete, label, move, draft, or compose",
        "raw rfc message bytes",
        "ephemerally",
        "local sqlite",
        "access and refresh tokens",
        "does not otherwise sell",
        "no human access",
        "has no advertising, tracking pixels, analytics, telemetry",
        "no castles-operated backend receiving gmail data",
        "limited use requirements",
        "castles logout",
        "third-party connections",
        "delete <code>castles.db</code>",
    )
    for value in required:
        assert value in text


def test_support_page_prohibits_private_reports() -> None:
    text = (SITE / "support.html").read_text().casefold()
    required = (
        "email addresses or local parts",
        "message subjects or bodies",
        "complete urls, message ids, or headers",
        "oauth urls, callback parameters, authorization codes, tokens, or state values",
        "google client json or client secrets",
        "databases, exports, token files, or raw mailbox data",
        "reserved domains",
        "private vulnerability-reporting flow",
    )
    assert all(value in text for value in required)


def test_svg_branding_is_local_and_passive() -> None:
    for name in ("logo.svg", "favicon.svg"):
        document = Document()
        document.feed((SITE / name).read_text())
        document.close()
        assert document.tags[0][0] == "svg"
        assert document.tags[0][1].get("viewbox")
        assert any(tag == "title" for tag, _ in document.tags)
        assert not any(tag == "script" for tag, _ in document.tags)
        assert not any("href" in attrs for _, attrs in document.tags)


def _luminance(value: str) -> float:
    channels = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_text_color_pairs_meet_wcag_aa() -> None:
    pairs = (
        ("#14213d", "#fffdf8"),
        ("#3f4d67", "#fffdf8"),
        ("#155d91", "#fffdf8"),
        ("#8a5b00", "#fffdf8"),
        ("#b9e3ff", "#0b1530"),
        ("#ffffff", "#0b1530"),
        ("#7c1f2a", "#fff2f1"),
    )
    assert all(_contrast(foreground, background) >= 4.5 for foreground, background in pairs)


def test_pages_workflow_is_pinned_and_main_only() -> None:
    workflow = (ROOT / ".github/workflows/pages.yml").read_text()
    assert "branches: [main]" in workflow
    assert "pull_request:" not in workflow
    assert "workflow_dispatch:" not in workflow
    assert "contents: read" in workflow
    assert "pages: write" in workflow
    assert "id-token: write" in workflow
    uses = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert uses and all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in uses)
