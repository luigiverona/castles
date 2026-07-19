from __future__ import annotations

from datetime import UTC, datetime, timedelta

from castles.core.entity import Relationship, Resolution

from ..schema import Case, Decision, Range, finding, msg, relation

NOW = datetime(2026, 7, 14, 15, tzinfo=UTC)
PHRASES = {
    Relationship.AUTHENTICATION: ("Verification code", "verification code", "auth.event"),
    Relationship.LIFECYCLE: ("Confirm your account", "account was created", "lifecycle.event"),
    Relationship.BILLING: ("Invoice available", "payment failed", "billing.event"),
    Relationship.SUBSCRIPTION: ("Subscription renewed", "trial is ending", "subscription.event"),
    Relationship.COMMERCE: ("Order confirmed", "order has shipped", "commerce.event"),
    Relationship.SUPPORT: ("Support request", "case received", "support.event"),
    Relationship.ACTIVITY: ("Activity summary", "recent activity", "activity.event"),
    Relationship.MARKETING: ("Special offer", "limited time offer", "marketing.event"),
}


def _cases(kind: Relationship) -> tuple[Case, ...]:
    subject, text, code = PHRASES[kind]
    prefix = f"relation-{kind.value}"
    repeated = tuple(
        msg(
            f"{prefix}-repeat-{index}",
            NOW + timedelta(minutes=index),
            sender="mail.example.com",
            subject=subject,
        )
        for index in range(3)
    )
    return (
        Case(
            f"{prefix}-subject",
            "relation",
            f"Subject language produces {kind.value} evidence.",
            (msg(f"{prefix}-subject", NOW, sender="mail.example.com", subject=subject),),
            (
                finding(
                    "example.com",
                    30,
                    NOW,
                    NOW,
                    1,
                    relationships=(relation(kind, 26, code),),
                ),
            ),
            decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
        ),
        Case(
            f"{prefix}-text",
            "relation",
            f"Bounded text produces {kind.value} evidence at the threshold.",
            (msg(f"{prefix}-text", NOW, sender="mail.example.com", text=text),),
            (
                finding(
                    "example.com",
                    30,
                    NOW,
                    NOW,
                    1,
                    relationships=(relation(kind, 12, code),),
                ),
            ),
            decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
        ),
        Case(
            f"{prefix}-repeated",
            "relation",
            f"Repeated independent {kind.value} evidence has diminishing returns.",
            repeated,
            (
                finding(
                    "example.com",
                    52,
                    NOW,
                    NOW + timedelta(minutes=2),
                    3,
                    relationships=(relation(kind, 45, code),),
                ),
            ),
            decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(52)),),
        ),
        Case(
            f"{prefix}-ambiguous",
            "relation",
            f"Unrelated entities prevent {kind.value} attribution.",
            (
                msg(
                    f"{prefix}-ambiguous",
                    NOW,
                    sender="mail.example.com",
                    authenticated=("mail.example.net",),
                    subject=subject,
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
            f"{prefix}-control",
            "relation",
            f"Generic language does not produce {kind.value} evidence.",
            (
                msg(
                    f"{prefix}-control",
                    NOW,
                    sender="mail.example.com",
                    subject="Synthetic status note",
                    text="This synthetic control contains no policy phrase.",
                ),
            ),
            (finding("example.com", 30, NOW, NOW, 1),),
            decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(30)),),
        ),
        Case(
            f"{prefix}-marketing",
            "relation",
            f"Marketing language alone does not imply {kind.value} ownership.",
            (msg(f"{prefix}-marketing", NOW, subject="Special offer"),),
        ),
    )


CASES = tuple(case for kind in Relationship for case in _cases(kind))
