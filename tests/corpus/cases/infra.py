from __future__ import annotations

from datetime import UTC, datetime

from castles.core.entity import Resolution

from ..schema import Case, Decision, Range, finding, msg

NOW = datetime(2026, 7, 14, 13, tzinfo=UTC)

CASES = (
    Case(
        "infra-exact",
        "infra",
        "An exact shared-mail rule is suppressed.",
        (msg("infra-exact", NOW, sender="pm.mtasv.net"),),
        suppressed=("pm.mtasv.net",),
    ),
    Case(
        "infra-subtree",
        "infra",
        "A tracking subtree is suppressed.",
        (msg("infra-subtree", NOW, sender="click.sendgrid.net"),),
        suppressed=("sendgrid.net",),
    ),
    Case(
        "infra-nearmiss",
        "infra",
        "Infrastructure matching respects label boundaries.",
        (msg("infra-nearmiss", NOW, sender="sendgrid.net.example"),),
        (
            finding(
                "net.example",
                30,
                NOW,
                NOW,
                1,
                identity_explanations=("identity.sender", "identity.cap.prevailing_suffix"),
            ),
        ),
        decisions=(Decision("net.example", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "infra-ambiguous",
        "infra",
        "Ambiguous infrastructure is represented but not reportable.",
        (msg("infra-ambiguous", NOW, sender="news.mandrillapp.com"),),
        suppressed=("mandrillapp.com",),
        decisions=(
            Decision(
                "mandrillapp.com",
                Resolution.AMBIGUOUS,
                explanations=("infra.ambiguous.mandrill",),
            ),
        ),
    ),
    Case(
        "infra-unlisted",
        "infra",
        "A reserved domain absent from the catalog remains eligible.",
        (msg("infra-unlisted", NOW, sender="service.example.org"),),
        (finding("example.org", 30, NOW, NOW, 1),),
        decisions=(Decision("example.org", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "infra-redirect",
        "infra",
        "A redirect or tracking host cannot become an entity.",
        (msg("infra-redirect", NOW, links=("u1.ct.sendgrid.net",)),),
        suppressed=("sendgrid.net",),
    ),
    Case(
        "infra-delivery",
        "infra",
        "A shared delivery host cannot become an entity.",
        (msg("infra-delivery", NOW, return_path="bounce.amazonses.com"),),
        suppressed=("amazonses.com",),
    ),
    Case(
        "infra-cdn",
        "infra",
        "A static CDN host cannot become an entity.",
        (msg("infra-cdn", NOW, links=("static.cloudfront.net",)),),
        suppressed=("cloudfront.net",),
    ),
)
