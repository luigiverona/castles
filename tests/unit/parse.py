from __future__ import annotations

from datetime import UTC, datetime
from email.message import EmailMessage

import pytest
from bs4 import BeautifulSoup, Tag

from castles.core.error import ParsingError
from castles.core.message import MessageRef, RawMessage
from castles.parse import html as html_parser
from castles.parse.html import MAX_HTML_LINKS, extract
from castles.parse.mime import MAX_RAW_BYTES, parse
from castles.parse.url import MAX_URLS, hostname, hostnames

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def raw(content: bytes) -> RawMessage:
    return RawMessage(MessageRef("opaque"), content, NOW, ("auth.example",))


def test_plain_message_normalization() -> None:
    result = parse(
        raw(
            b"From: Billing <billing@unknown-saas.example>\r\n"
            b"Reply-To: help@support.example\r\n"
            b"Return-Path: <bounce@mailer.example>\r\n"
            b"List-Unsubscribe: <https://leave.news.example/u/secret?q=x>\r\n"
            b"Subject: Invoice available\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            b"See https://account.unknown-saas.example/private?token=secret"
        )
    )
    assert result.sender == "unknown-saas.example"
    assert result.reply == "support.example"
    assert result.return_path == "mailer.example"
    assert result.authenticated == ("auth.example",)
    assert result.links == ("account.unknown-saas.example",)
    assert result.unsubscribe == ("leave.news.example",)
    assert "token" not in repr(result)


def test_html_excludes_active_hidden_and_attachment_content() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message.set_content("Visible plain")
    message.add_alternative(
        '<script>bad</script><p>Visible HTML</p><a href="https://site.example/path?q=1">go</a><span hidden>hidden</span>',
        subtype="html",
    )
    message.add_attachment(b"private", maintype="text", subtype="plain", filename="secret.txt")
    result = parse(raw(message.as_bytes()))
    assert "Visible plain" in result.text
    assert "Visible HTML" in result.text
    assert "bad" not in result.text
    assert "hidden" not in result.text
    assert "private" not in result.text
    assert result.links == ("site.example",)


def test_html_standalone() -> None:
    text, links = extract(
        '<div style="display:none">no</div><p>yes</p><a href="mailto:x@y">mail</a>'
    )
    assert text == "yes mail"
    assert links == ()


def test_html_nested_hidden_style_does_not_invalidate_descendant() -> None:
    text, links = extract(
        '<div style="display:none">'
        '<span style="color:red">secret</span>'
        '<a href="https://hidden.example/private">hidden link</a>'
        "</div><p>visible</p>"
    )
    assert text == "visible"
    assert links == ()


@pytest.mark.parametrize(
    "hidden",
    [
        '<div style="display:none"><span style="display:none">secret</span></div>',
        '<div style="visibility:hidden"><span style="color:red">secret</span></div>',
        "<div hidden><span hidden>secret</span></div>",
        '<div aria-hidden="true"><span aria-hidden="true">secret</span></div>',
        '<template><svg><span style="color:red">secret</span></svg></template>',
        '<svg><a href="https://hidden.example/private">secret</a><canvas>x</canvas></svg>',
    ],
)
def test_html_nested_removals_preserve_only_visible_tree(hidden: str) -> None:
    text, links = extract(
        hidden + '<p>visible</p><a href="https://visible.example/path">visible link</a>'
    )
    assert text == "visible visible link"
    assert links == ("https://visible.example/path",)


def test_html_destructive_snapshots_are_processed_descendant_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    original = Tag.decompose

    def tracked(element: Tag) -> None:
        if isinstance(element.attrs, dict) and "data-order" in element.attrs:
            order.append(str(element.attrs["data-order"]))
        original(element)

    monkeypatch.setattr(Tag, "decompose", tracked)
    text, links = extract(
        '<div hidden data-order="parent">'
        '<span hidden data-order="child">secret</span>'
        "</div><p>visible</p>"
    )
    assert order == ["child", "parent"]
    assert text == "visible"
    assert links == ()


def test_html_destructive_snapshot_skips_an_already_decomposed_tag() -> None:
    soup = BeautifulSoup("<div hidden>secret</div><p>visible</p>", "html.parser")
    element = soup.find("div")
    assert isinstance(element, Tag)
    html_parser._decompose((element, element))
    assert soup.get_text(" ", strip=True) == "visible"


def test_html_malformed_anchors_and_mixed_visibility() -> None:
    text, links = extract(
        '<div hidden><a href="https://hidden.example/private">hidden</a></div>'
        '<a href="https://first.example/path"><span>first</span>'
        '<a href="https://second.example/path">second</a></a>'
        '<a href=>broken</a><a href="mailto:private@example.com">mail</a>'
    )
    assert "hidden" not in text
    assert "first" in text and "second" in text and "broken" in text and "mail" in text
    assert links == ("https://first.example/path", "https://second.example/path")


def test_html_link_cap_remains_exact() -> None:
    value = "".join(
        f'<a href="https://visible{index}.example/path">link</a>'
        for index in range(MAX_HTML_LINKS + 1)
    )
    _, links = extract(value)
    assert len(links) == MAX_HTML_LINKS
    assert links[0] == "https://visible0.example/path"
    assert links[-1] == f"https://visible{MAX_HTML_LINKS - 1}.example/path"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("<!-- fragment only -->", ""),
        ("</div><span>fragment</span>", "fragment"),
        ("<>broken fragment", "<>broken fragment"),
    ],
)
def test_html_empty_and_fragment_inputs(value: str, expected: str) -> None:
    text, links = extract(value)
    assert text == expected
    assert links == ()


def test_html_deeply_nested_bounded_fragment() -> None:
    value = "<div>" * 100 + '<a href="https://visible.example/path">visible</a>' + "</div>" * 100
    assert extract(value) == ("visible", ("https://visible.example/path",))


def test_mime_nested_hidden_html_is_sanitized() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message.set_content("plain")
    message.add_alternative(
        '<div style="display:none"><span style="color:red">secret</span>'
        '<a href="https://hidden.example/private">hidden</a></div>'
        '<p>visible</p><a href="https://visible.example/path">visible link</a>',
        subtype="html",
    )
    result = parse(raw(message.as_bytes()))
    assert "secret" not in result.text and "hidden" not in result.text
    assert "visible" in result.text
    assert result.links == ("visible.example",)


def test_mime_translates_html_library_failure_without_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = "synthetic-private-html-content"

    def broken(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AttributeError(private)

    monkeypatch.setattr(html_parser, "BeautifulSoup", broken)
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message.add_alternative(f"<p>{private}</p>", subtype="html")
    with pytest.raises(ParsingError) as caught:
        parse(raw(message.as_bytes()))
    assert str(caught.value) == "message HTML content could not be parsed safely"
    assert private not in str(caught.value)


def test_html_boundary_does_not_hide_programming_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("synthetic programming failure")

    monkeypatch.setattr(html_parser, "BeautifulSoup", broken)
    with pytest.raises(RuntimeError, match="programming"):
        extract("<p>synthetic</p>")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://EXAMPLE.com:443/a?q=secret", "example.com"),
        ("https://münich.example/a", "xn--mnich-kva.example"),
        ("ftp://example.com", None),
        ("https://user:pass@example.com", None),
        ("http://localhost", None),
        ("http://127.0.0.1/private", None),
        ("https://printer.local/status", None),
        ("not a url", None),
    ],
)
def test_url_hostname(value: str, expected: str | None) -> None:
    assert hostname(value) == expected


def test_url_limit_and_deduplication() -> None:
    text = " ".join(["https://b.example/x", "https://a.example/y", "https://b.example/z"])
    assert hostnames(text) == ("a.example", "b.example")
    assert hostname("https://example.com/" + "x" * 5000) is None
    text = " ".join(f"https://text{index}.example/path" for index in range(MAX_URLS))
    extra = tuple(f"https://html{index}.example/path" for index in range(MAX_URLS))
    assert len(hostnames(text, extra)) == MAX_URLS
    assert not any(value.startswith("html") for value in hostnames(text, extra))


def test_address_ip_and_local_domains_are_excluded() -> None:
    message = (
        b"From: sender@127.0.0.1\r\n"
        b"Reply-To: sender@printer.local\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"http://127.0.0.1/private https://printer.local/private"
    )
    result = parse(raw(message))
    assert result.sender is None
    assert result.reply is None
    assert result.links == ()


def test_raw_size_limit() -> None:
    with pytest.raises(ParsingError, match="byte limit"):
        parse(raw(b"x" * (MAX_RAW_BYTES + 1)))


def test_mime_part_limit() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message.make_mixed()
    for index in range(201):
        child = EmailMessage()
        child.set_content(f"part {index}")
        message.attach(child)
    with pytest.raises(ParsingError, match="structure"):
        parse(raw(message.as_bytes()))
