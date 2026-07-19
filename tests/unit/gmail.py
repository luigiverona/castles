from __future__ import annotations

import base64
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

from castles.core.error import ParsingError, ProviderError, StaleCheckpointError
from castles.core.message import MessageRef
from castles.provider.gmail.client import Gmail, _execute
from castles.provider.port import MailboxQuery


class Request:
    def __init__(self, value: object) -> None:
        self.value = value

    def execute(self) -> object:
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class Resource:
    def __init__(self, pages: list[object]) -> None:
        self.pages = pages
        self.calls: list[dict[str, object]] = []

    def list(self, **kwargs: object) -> Request:
        self.calls.append(kwargs)
        return Request(self.pages.pop(0))

    def get(self, **kwargs: object) -> Request:
        del kwargs
        return Request(self.pages.pop(0))


class Users:
    def __init__(self, profile: object, messages: Resource, history: Resource) -> None:
        self.profile = profile
        self.message_resource = messages
        self.history_resource = history

    def getProfile(self, **kwargs: object) -> Request:
        del kwargs
        return Request(self.profile)

    def messages(self) -> Resource:
        return self.message_resource

    def history(self) -> Resource:
        return self.history_resource


class Api:
    def __init__(self, users: Users) -> None:
        self.resource = users

    def users(self) -> Users:
        return self.resource


DEFAULT_PROFILE = object()


def gmail(
    messages: list[object],
    history: list[object] | None = None,
    profile: object = DEFAULT_PROFILE,
) -> Gmail:
    api = Api(
        Users(
            (
                {"emailAddress": "Person@Example.com", "historyId": "42"}
                if profile is DEFAULT_PROFILE
                else profile
            ),
            Resource(messages),
            Resource(history or []),
        )
    )
    return Gmail(cast(Credentials, SimpleNamespace()), api)


def test_identity_checkpoint_and_validation() -> None:
    provider = gmail([])
    assert provider.identity().account_id == "person@example.com"
    assert provider.checkpoint() == "42"
    assert provider.checkpoint_kind() == "gmail_history"
    assert provider.validate().available


def test_enumeration_pages_deduplicate() -> None:
    provider = gmail(
        [
            {"messages": [{"id": "a"}, {"id": "a"}], "nextPageToken": "next"},
            {"messages": [{"id": "b"}]},
        ]
    )
    assert list(provider.enumerate(MailboxQuery())) == [MessageRef("a"), MessageRef("b")]
    assert provider.api.resource.message_resource.calls == [
        {"userId": "me", "includeSpamTrash": False, "maxResults": 500},
        {
            "userId": "me",
            "includeSpamTrash": False,
            "maxResults": 500,
            "pageToken": "next",
        },
    ]


def test_enumeration_applies_aware_since_query() -> None:
    provider = gmail([{"messages": []}])
    since = datetime(2026, 7, 1, tzinfo=UTC)
    assert list(provider.enumerate(MailboxQuery(since=since))) == []
    assert provider.api.resource.message_resource.calls[0]["q"] == (
        f"after:{int(since.timestamp())}"
    )


def test_history_enumeration() -> None:
    provider = gmail(
        [],
        [
            {
                "history": [{"messagesAdded": [{"message": {"id": "a"}}]}],
                "nextPageToken": "next",
            },
            {"history": [{"messagesAdded": [{"message": {"id": "b"}}]}]},
        ],
    )
    assert list(provider.enumerate(MailboxQuery(checkpoint="1"))) == [
        MessageRef("a"),
        MessageRef("b"),
    ]
    assert provider.api.resource.history_resource.calls == [
        {"userId": "me", "startHistoryId": "1", "historyTypes": ["messageAdded"]},
        {
            "userId": "me",
            "startHistoryId": "1",
            "historyTypes": ["messageAdded"],
            "pageToken": "next",
        },
    ]


def test_history_404_is_a_stale_checkpoint() -> None:
    error = HttpError(
        cast(Any, SimpleNamespace(status=404, reason="not found")), b"private response"
    )
    with pytest.raises(StaleCheckpointError, match="stale") as caught:
        list(gmail([], [error]).enumerate(MailboxQuery(checkpoint="1")))
    assert "private response" not in str(caught.value)


def test_nonstale_history_failure_remains_a_provider_error() -> None:
    error = HttpError(
        cast(Any, SimpleNamespace(status=500, reason="unavailable")), b"private response"
    )
    with pytest.raises(ProviderError, match="request failed"):
        list(gmail([], [error]).enumerate(MailboxQuery(checkpoint="1")))


@pytest.mark.parametrize(
    "content",
    [
        b"Authentication-Results: mx.google.com; dkim=pass header.d=forged.example\r\n\r\nbody",
        b"Authentication-Results: MX.GOOGLE.COM; spf=pass\r\n smtp.mailfrom=x@folded.example\r\n\r\nbody",
        b"Authentication-Results: mx.google.com; dkim=pass (header.d=comment.example)\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass header.d=second.example\r\n\r\nbody",
    ],
)
def test_fetch_does_not_trust_raw_authentication_headers(content: bytes) -> None:
    encoded = base64.urlsafe_b64encode(content).decode().rstrip("=")
    provider = gmail([{"id": "opaque", "raw": encoded, "internalDate": "1700000000000"}])
    result = provider.fetch(MessageRef("opaque"))
    assert result.authenticated == ()
    assert result.observed_at == datetime.fromtimestamp(1_700_000_000, tz=UTC)


def test_repeated_page_token_fails() -> None:
    provider = gmail(
        [
            {"messages": [], "nextPageToken": "same"},
            {"messages": [], "nextPageToken": "same"},
        ]
    )
    with pytest.raises(ProviderError, match="repeated"):
        list(provider.enumerate(MailboxQuery()))

    history = gmail(
        [],
        [
            {"history": [], "nextPageToken": "same"},
            {"history": [], "nextPageToken": "same"},
        ],
    )
    with pytest.raises(ProviderError, match="repeated"):
        list(history.enumerate(MailboxQuery(checkpoint="1")))


@pytest.mark.parametrize(
    "page",
    [
        None,
        {"messages": None},
        {"messages": [None]},
        {"messages": [{"id": 3}]},
        {"nextPageToken": 3},
    ],
)
def test_malformed_message_pages_are_typed(page: object) -> None:
    with pytest.raises(ProviderError, match="malformed"):
        list(gmail([page]).enumerate(MailboxQuery()))


@pytest.mark.parametrize(
    "page",
    [
        {"history": None},
        {"history": [{"messagesAdded": None}]},
        {"history": [{"messagesAdded": [{"message": None}]}]},
    ],
)
def test_malformed_history_pages_are_typed(page: object) -> None:
    with pytest.raises(ProviderError, match="malformed"):
        list(gmail([], [page]).enumerate(MailboxQuery(checkpoint="1")))


@pytest.mark.parametrize(
    "profile",
    [None, [], {"emailAddress": "bad\n@example.com", "historyId": "42"}],
)
def test_malformed_profiles_are_typed(profile: object) -> None:
    provider = gmail([], profile=profile)
    with pytest.raises(ProviderError):
        provider.identity()


def test_nonstring_profile_address_is_typed() -> None:
    with pytest.raises(ProviderError, match="mailbox address"):
        gmail([], profile={"emailAddress": 3, "historyId": "42"}).identity()


def test_missing_history_checkpoint_is_explicit() -> None:
    provider = gmail([], profile={"emailAddress": "person@example.com"})
    provider.identity()
    with pytest.raises(ProviderError, match="checkpoint"):
        provider.checkpoint()


def test_checkpoint_loads_profile_when_identity_was_not_requested() -> None:
    assert gmail([]).checkpoint() == "42"


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"id": "other", "raw": "YQ", "internalDate": "1700000000000"},
        {"id": "opaque", "raw": "%%%", "internalDate": "1700000000000"},
        {"id": "opaque", "raw": "", "internalDate": "1700000000000"},
        {"id": "opaque", "raw": "YQ", "internalDate": "not-a-time"},
    ],
)
def test_malformed_fetched_messages_are_typed(value: object) -> None:
    with pytest.raises((ParsingError, ProviderError)):
        gmail([value]).fetch(MessageRef("opaque"))


def test_fetch_enforces_encoded_size_before_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("castles.provider.gmail.client.MAX_ENCODED_BYTES", 1)
    value = {"id": "opaque", "raw": "YQ", "internalDate": "1700000000000"}
    with pytest.raises(ParsingError, match="safe byte limit"):
        gmail([value]).fetch(MessageRef("opaque"))


def test_execute_translates_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("castles.provider.gmail.client.time.sleep", lambda _: None)

    def fail() -> Any:
        raise OSError

    with pytest.raises(ProviderError):
        _execute(fail, attempts=2)


def test_execute_retries_only_transient_http_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("castles.provider.gmail.client.time.sleep", lambda _: None)
    calls = 0

    def transient() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise HttpError(
                cast(Any, SimpleNamespace(status=503, reason="unavailable")), b"private response"
            )
        return "ok"

    assert _execute(transient, attempts=4) == "ok"
    assert calls == 3

    calls = 0

    def denied() -> str:
        nonlocal calls
        calls += 1
        raise HttpError(
            cast(Any, SimpleNamespace(status=403, reason="forbidden")), b"private response"
        )

    with pytest.raises(ProviderError, match="request failed") as caught:
        _execute(denied, attempts=4)
    assert calls == 1
    assert "private response" not in str(caught.value)
