from __future__ import annotations

from datetime import UTC, datetime, timedelta

from castles.core.entity import Resolution

from ..schema import Case, Decision, Range, finding, msg

NOW = datetime(2026, 7, 14, 12, tzinfo=UTC)


def _at(minutes: int) -> datetime:
    return NOW + timedelta(minutes=minutes)


CASES = (
    Case(
        "identity-sender",
        "identity",
        "A sender domain is reportable at the identity threshold.",
        (msg("identity-sender", NOW, sender="account.example.com"),),
        (finding("example.com", 30, NOW, NOW, 1),),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "identity-reply",
        "identity",
        "Reply-to alone resolves but remains below the reportable threshold.",
        (msg("identity-reply", NOW, reply="help.example.com"),),
        suppressed=("example.com",),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(14)),),
    ),
    Case(
        "identity-return",
        "identity",
        "Return-path alone resolves but remains below the reportable threshold.",
        (msg("identity-return", NOW, return_path="bounce.example.com"),),
        suppressed=("example.com",),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(18)),),
    ),
    Case(
        "identity-link",
        "identity",
        "Link-only evidence is unresolved.",
        (msg("identity-link", NOW, links=("portal.example.com",)),),
        suppressed=("example.com",),
        decisions=(
            Decision(
                "example.com",
                Resolution.UNRESOLVED,
                Range.exact(6),
                ("resolution.insufficient_identity",),
            ),
        ),
    ),
    Case(
        "identity-unsubscribe",
        "identity",
        "One unsubscribe observation is unresolved.",
        (msg("identity-unsubscribe", NOW, unsubscribe=("leave.example.com",)),),
        suppressed=("example.com",),
        decisions=(
            Decision(
                "example.com",
                Resolution.UNRESOLVED,
                Range.exact(8),
                ("resolution.insufficient_identity",),
            ),
        ),
    ),
    Case(
        "identity-agreement",
        "identity",
        "Sender and authenticated evidence agree in one message.",
        (
            msg(
                "identity-agreement",
                NOW,
                sender="login.example.com",
                authenticated=("mail.example.com",),
            ),
        ),
        (
            finding(
                "example.com",
                80,
                NOW,
                NOW,
                1,
                identity_explanations=(
                    "identity.sender",
                    "identity.authenticated",
                    "identity.agreement.sender_auth",
                ),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(80)),),
    ),
    Case(
        "identity-repeated",
        "identity",
        "Independent sender observations receive diminishing credit.",
        (
            msg("identity-repeated-a", NOW, sender="mail.example.com"),
            msg("identity-repeated-b", _at(1), sender="mail.example.com"),
        ),
        (finding("example.com", 45, NOW, _at(1), 2),),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(45)),),
    ),
    Case(
        "identity-duplicate",
        "identity",
        "Duplicate observations inside one normalized message do not amplify.",
        (
            msg(
                "identity-duplicate",
                NOW,
                sender="mail.example.com",
                links=("portal.example.com", "portal.example.com"),
            ),
        ),
        (
            finding(
                "example.com",
                36,
                NOW,
                NOW,
                1,
                identity_explanations=("identity.sender", "identity.link"),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(36)),),
    ),
    Case(
        "identity-unrelated",
        "identity",
        "Unrelated registrable domains remain separate within one message.",
        (
            msg(
                "identity-unrelated",
                NOW,
                sender="mail.example.com",
                authenticated=("login.example.net",),
            ),
        ),
        (
            finding(
                "example.net",
                35,
                NOW,
                NOW,
                1,
                identity_explanations=("identity.authenticated",),
            ),
            finding("example.com", 30, NOW, NOW, 1),
        ),
        decisions=(
            Decision("example.com", Resolution.RESOLVED, Range.exact(30)),
            Decision("example.net", Resolution.RESOLVED, Range.exact(35)),
        ),
    ),
    Case(
        "identity-private",
        "identity",
        "Private suffix tenants are separate entities.",
        (
            msg("identity-private-a", NOW, sender="one.github.io"),
            msg("identity-private-b", _at(1), sender="two.github.io"),
        ),
        (
            finding("one.github.io", 30, NOW, NOW, 1),
            finding("two.github.io", 30, _at(1), _at(1), 1),
        ),
        decisions=(
            Decision("one.github.io", Resolution.RESOLVED, Range.exact(30)),
            Decision("two.github.io", Resolution.RESOLVED, Range.exact(30)),
        ),
    ),
    Case(
        "identity-wildcard",
        "identity",
        "A PSL wildcard rule preserves the registrable boundary.",
        (msg("identity-wildcard", NOW, sender="foo.bar.ck"),),
        (finding("foo.bar.ck", 30, NOW, NOW, 1),),
        decisions=(Decision("foo.bar.ck", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "identity-exception",
        "identity",
        "A PSL exception rule preserves its registrable boundary.",
        (msg("identity-exception", NOW, sender="www.ck"),),
        (finding("www.ck", 30, NOW, NOW, 1),),
        decisions=(Decision("www.ck", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "identity-unknown",
        "identity",
        "An unknown suffix is visible but confidence-capped.",
        (
            msg(
                "identity-unknown",
                NOW,
                sender="tenant.example",
                authenticated=("tenant.example",),
            ),
        ),
        (
            finding(
                "tenant.example",
                49,
                NOW,
                NOW,
                1,
                identity_explanations=(
                    "identity.sender",
                    "identity.authenticated",
                    "identity.agreement.sender_auth",
                    "identity.cap.prevailing_suffix",
                ),
            ),
        ),
        decisions=(Decision("tenant.example", Resolution.RESOLVED, Range.exact(49)),),
    ),
    Case(
        "identity-idna",
        "identity",
        "UTS 46 canonicalization produces a stable ASCII entity key.",
        (msg("identity-idna", NOW, sender="münich.example"),),
        (
            finding(
                "xn--mnich-kva.example",
                30,
                NOW,
                NOW,
                1,
                identity_explanations=("identity.sender", "identity.cap.prevailing_suffix"),
            ),
        ),
        decisions=(Decision("xn--mnich-kva.example", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "identity-malformed",
        "identity",
        "Malformed address hosts are removed by the parser.",
        (
            msg(
                "identity-malformed",
                NOW,
                raw=b"From: invalidlocal413@bad..example\r\nSubject: Synthetic control\r\n\r\nSynthetic body",
            ),
        ),
    ),
    Case(
        "identity-ip",
        "identity",
        "IP-literal addresses and URLs are removed by the parser.",
        (
            msg(
                "identity-ip",
                NOW,
                raw=(
                    b"From: iplocal527@127.0.0.1\r\nSubject: Synthetic control\r\n\r\n"
                    b"Visit http://127.0.0.1/private?token=synthetic"
                ),
            ),
        ),
    ),
    Case(
        "identity-local",
        "identity",
        "Local hostnames in addresses and URLs are removed by the parser.",
        (
            msg(
                "identity-local",
                NOW,
                raw=(
                    b"From: locallocal639@printer.local\r\nSubject: Synthetic control\r\n\r\n"
                    b"Visit https://printer.local/private?token=synthetic"
                ),
            ),
        ),
    ),
)
