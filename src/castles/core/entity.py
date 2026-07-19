from __future__ import annotations

from enum import StrEnum


class Relationship(StrEnum):
    AUTHENTICATION = "authentication"
    LIFECYCLE = "lifecycle"
    BILLING = "billing"
    SUBSCRIPTION = "subscription"
    COMMERCE = "commerce"
    SUPPORT = "support"
    ACTIVITY = "activity"
    MARKETING = "marketing"


class Resolution(StrEnum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    CONFLICTED = "conflicted"
