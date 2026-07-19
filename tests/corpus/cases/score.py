from __future__ import annotations

from datetime import UTC, datetime, timedelta

from castles.core.entity import Relationship, Resolution

from ..schema import Case, Decision, Range, finding, msg, relation

NOW = datetime(2026, 7, 14, 16, tzinfo=UTC)


def _at(index: int) -> datetime:
    return NOW + timedelta(minutes=index)


CAP_MESSAGES = tuple(
    msg(f"score-cap-{index}", _at(index), sender="mail.example.com") for index in range(50)
)
RELATION_CAP_MESSAGES = tuple(
    msg(
        f"score-relation-cap-{index}",
        _at(index),
        sender="mail.example.com",
        subject="Invoice available",
    )
    for index in range(56)
)
BAND_49_MESSAGES = (
    msg(
        "score-band-low-a",
        NOW,
        return_path="return.example.com",
        reply="reply.example.com",
        unsubscribe=("leave.example.com",),
        links=("portal.example.com",),
    ),
    msg("score-band-low-b", _at(1), links=("portal.example.com",)),
)
BAND_50_MESSAGES = (
    *BAND_49_MESSAGES,
    msg("score-band-medium-c", _at(2), links=("portal.example.com",)),
)
BAND_75_MESSAGES = (
    msg(
        "score-band-high-a",
        NOW,
        return_path="return.example.com",
        reply="reply.example.com",
        unsubscribe=("leave.example.com",),
        links=("portal.example.com",),
    ),
    msg(
        "score-band-high-b",
        _at(1),
        return_path="return.example.com",
        reply="reply.example.com",
        unsubscribe=("leave.example.com",),
        links=("portal.example.com",),
    ),
    msg(
        "score-band-high-c",
        _at(2),
        reply="reply.example.com",
        unsubscribe=("leave.example.com",),
        links=("portal.example.com",),
    ),
)

CASES = (
    Case(
        "score-documented",
        "score",
        "Documented sender and subject weights remain exact.",
        (msg("score-documented", NOW, sender="mail.example.com", subject="Invoice available"),),
        (
            finding(
                "example.com",
                30,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.BILLING, 26, "billing.event"),),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "score-cap",
        "score",
        "Identity confidence caps at 100.",
        CAP_MESSAGES,
        (finding("example.com", 100, NOW, _at(49), 50),),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(100)),),
    ),
    Case(
        "score-relation-cap",
        "score",
        "Relationship confidence caps at 100 independently.",
        RELATION_CAP_MESSAGES,
        (
            finding(
                "example.com",
                100,
                NOW,
                _at(55),
                56,
                relationships=(relation(Relationship.BILLING, 100, "billing.event"),),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(100)),),
    ),
    Case(
        "score-diminishing",
        "score",
        "Three sender observations produce the documented diminishing score.",
        tuple(
            msg(f"score-diminishing-{index}", _at(index), sender="mail.example.com")
            for index in range(3)
        ),
        (finding("example.com", 52, NOW, _at(2), 3),),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(52)),),
    ),
    Case(
        "score-permutation",
        "score",
        "Ordering does not affect entities, scores, evidence, or observations.",
        (
            msg("score-permutation-a", _at(2), sender="mail.example.com", text="Payment failed"),
            msg("score-permutation-b", NOW, sender="mail.example.com", subject="Invoice available"),
            msg("score-permutation-c", _at(1), sender="mail.example.net"),
        ),
        (
            finding(
                "example.com",
                45,
                NOW,
                _at(2),
                2,
                relationships=(relation(Relationship.BILLING, 38, "billing.event"),),
            ),
            finding("example.net", 30, _at(1), _at(1), 1),
        ),
        decisions=(
            Decision("example.com", Resolution.RESOLVED, Range.exact(45)),
            Decision("example.net", Resolution.RESOLVED, Range.exact(30)),
        ),
    ),
    Case(
        "score-duplicate",
        "score",
        "Duplicate normalized URL observations do not amplify identity.",
        (
            msg(
                "score-duplicate",
                NOW,
                sender="mail.example.com",
                links=("portal.example.com", "portal.example.com", "portal.example.com"),
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
        "score-independent",
        "score",
        "Relationship evidence changes no identity score.",
        (
            msg(
                "score-independent",
                NOW,
                sender="mail.example.com",
                authenticated=("login.example.com",),
                text="Payment failed",
            ),
        ),
        (
            finding(
                "example.com",
                80,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.BILLING, 12, "billing.event"),),
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
        "score-threshold",
        "score",
        "Identity 30 and relationship 12 are both reportable boundaries.",
        (msg("score-threshold", NOW, sender="mail.example.com", text="Support request"),),
        (
            finding(
                "example.com",
                30,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.SUPPORT, 12, "support.event"),),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
    ),
    Case(
        "score-band-low",
        "score",
        "The low confidence band ends at 49.",
        BAND_49_MESSAGES,
        (
            finding(
                "example.com",
                49,
                NOW,
                _at(1),
                2,
                identity_explanations=(
                    "identity.return",
                    "identity.reply",
                    "identity.unsubscribe",
                    "identity.link",
                ),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(49)),),
    ),
    Case(
        "score-band-medium",
        "score",
        "The medium confidence band begins at 50.",
        BAND_50_MESSAGES,
        (
            finding(
                "example.com",
                50,
                NOW,
                _at(2),
                3,
                identity_explanations=(
                    "identity.return",
                    "identity.reply",
                    "identity.unsubscribe",
                    "identity.link",
                ),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(50)),),
    ),
    Case(
        "score-band-high",
        "score",
        "The high confidence band begins at 75.",
        BAND_75_MESSAGES,
        (
            finding(
                "example.com",
                75,
                NOW,
                _at(2),
                3,
                identity_explanations=(
                    "identity.return",
                    "identity.reply",
                    "identity.unsubscribe",
                    "identity.link",
                ),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(75)),),
    ),
    Case(
        "score-unknown-cap",
        "score",
        "Prevailing-suffix confidence is capped at 49.",
        (
            msg(
                "score-unknown-cap",
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
        "score-same-message",
        "score",
        "Sender and authenticated agreement in one message receives its bonus.",
        (
            msg(
                "score-same-message",
                NOW,
                sender="mail.example.com",
                authenticated=("login.example.com",),
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
        "score-separate-message",
        "score",
        "Agreement across separate messages receives no same-message bonus.",
        (
            msg("score-separate-message-a", NOW, sender="mail.example.com"),
            msg("score-separate-message-b", _at(1), authenticated=("login.example.com",)),
        ),
        (
            finding(
                "example.com",
                65,
                NOW,
                _at(1),
                2,
                identity_explanations=("identity.sender", "identity.authenticated"),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(65)),),
    ),
)
