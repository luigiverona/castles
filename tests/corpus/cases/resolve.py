from __future__ import annotations

from datetime import UTC, datetime, timedelta

from castles.core.entity import Resolution

from ..schema import Case, Decision, Range, finding, msg

NOW = datetime(2026, 7, 14, 14, tzinfo=UTC)
LATER = NOW + timedelta(minutes=1)

CASES = (
    Case(
        "resolve-one",
        "resolve",
        "One structural identity resolves one entity.",
        (msg("resolve-one", NOW, sender="mail.example.com"),),
        (finding("example.com", 30, NOW, NOW, 1),),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "resolve-unresolved",
        "resolve",
        "A single weak link candidate stays unresolved.",
        (msg("resolve-unresolved", NOW, links=("portal.example.com",)),),
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
        "resolve-ambiguous",
        "resolve",
        "Catalog ambiguity stays non-reportable.",
        (msg("resolve-ambiguous", NOW, sender="mailchi.mp"),),
        suppressed=("mailchi.mp",),
        decisions=(
            Decision(
                "mailchi.mp",
                Resolution.AMBIGUOUS,
                explanations=("infra.ambiguous.mailchimp",),
            ),
        ),
    ),
    Case(
        "resolve-conflicted",
        "resolve",
        "Competing domains stay distinct; the current resolver does not fabricate a conflict.",
        (
            msg(
                "resolve-conflicted",
                NOW,
                sender="mail.example.com",
                authenticated=("mail.example.net",),
                subject="Invoice available",
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
        "resolve-distinct",
        "resolve",
        "Two registrable domains never merge automatically.",
        (
            msg("resolve-distinct-a", NOW, sender="mail.example.com"),
            msg("resolve-distinct-b", LATER, sender="mail.example.net"),
        ),
        (
            finding("example.com", 30, NOW, NOW, 1),
            finding("example.net", 30, LATER, LATER, 1),
        ),
        decisions=(
            Decision("example.com", Resolution.RESOLVED, Range.exact(30)),
            Decision("example.net", Resolution.RESOLVED, Range.exact(30)),
        ),
    ),
    Case(
        "resolve-canonical",
        "resolve",
        "Subdomains canonicalize to one entity across messages.",
        (
            msg("resolve-canonical-a", NOW, sender="mail.example.org"),
            msg("resolve-canonical-b", LATER, sender="login.example.org"),
        ),
        (finding("example.org", 45, NOW, LATER, 2),),
        decisions=(Decision("example.org", Resolution.RESOLVED, Range.exact(45)),),
    ),
    Case(
        "resolve-display",
        "resolve",
        "Display-name similarity cannot merge unrelated domains.",
        (
            msg(
                "resolve-display",
                NOW,
                raw=(
                    b"From: Same Synthetic Name <displaylocal741@example.com>\r\n"
                    b"Reply-To: Same Synthetic Name <replylocal852@example.net>\r\n"
                    b"Subject: Synthetic control\r\n\r\nSynthetic body"
                ),
            ),
        ),
        (finding("example.com", 30, NOW, NOW, 1),),
        suppressed=("example.net",),
        decisions=(
            Decision("example.com", Resolution.RESOLVED, Range.exact(30)),
            Decision("example.net", Resolution.RESOLVED, Range.exact(14)),
        ),
    ),
    Case(
        "resolve-competing",
        "resolve",
        "Competing identities prevent relationship attribution.",
        (
            msg(
                "resolve-competing",
                NOW,
                sender="mail.example.com",
                authenticated=("mail.example.net",),
                text="Payment failed",
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
)
