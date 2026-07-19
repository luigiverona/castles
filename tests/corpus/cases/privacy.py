from __future__ import annotations

from datetime import UTC, datetime

from castles.core.entity import Relationship, Resolution

from ..schema import Case, Decision, Range, finding, msg, relation

NOW = datetime(2026, 7, 14, 17, tzinfo=UTC)

CASES = (
    Case(
        "privacy-raw",
        "privacy",
        "Raw addresses, subject, body, URL path, query, and message key never reach findings or exports.",
        (
            msg(
                "privacy-raw-secret",
                NOW,
                raw=(
                    b"From: Synthetic Person <origin@privacy.example.com>\r\n"
                    b"Reply-To: helper@support.example.com\r\n"
                    b"List-Unsubscribe: <https://leave.example.com/private/path?token=synthetic>\r\n"
                    b"Subject: Password reset synthetic subject\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                    b"Password reset synthetic body. Visit "
                    b"https://portal.example.com/account/private?token=synthetic"
                ),
            ),
        ),
        (
            finding(
                "example.com",
                58,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.AUTHENTICATION, 38, "auth.event"),),
                identity_explanations=(
                    "identity.sender",
                    "identity.reply",
                    "identity.unsubscribe",
                    "identity.link",
                ),
            ),
        ),
        decisions=(Decision("example.com", Resolution.RESOLVED, Range.exact(58)),),
    ),
    Case(
        "privacy-normalized",
        "privacy",
        "Normalized content and opaque keys stay outside findings and exports.",
        (
            msg(
                "privacy-normalized-secret",
                NOW,
                sender="mail.example.org",
                subject="Invoice available synthetic subject",
                text="Synthetic private body and payment failed",
                links=("portal.example.org",),
            ),
        ),
        (
            finding(
                "example.org",
                36,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.BILLING, 38, "billing.event"),),
                identity_explanations=("identity.sender", "identity.link"),
            ),
        ),
        decisions=(Decision("example.org", Resolution.RESOLVED, Range.exact(36)),),
    ),
    Case(
        "privacy-provider",
        "privacy",
        "Detection input and output remain provider-neutral and local.",
        (
            msg(
                "privacy-provider-secret",
                NOW,
                sender="mail.example.net",
                authenticated=("auth.example.net",),
                subject="Confirm your account",
            ),
        ),
        (
            finding(
                "example.net",
                80,
                NOW,
                NOW,
                1,
                relationships=(relation(Relationship.LIFECYCLE, 26, "lifecycle.event"),),
                identity_explanations=(
                    "identity.sender",
                    "identity.authenticated",
                    "identity.agreement.sender_auth",
                ),
            ),
        ),
        decisions=(Decision("example.net", Resolution.RESOLVED, Range.exact(80)),),
        private=("synthetic-owner@corpus.example", "synthetic-owner"),
    ),
)
