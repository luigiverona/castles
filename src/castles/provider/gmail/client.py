from __future__ import annotations

import base64
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, cast

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from castles.core.error import ParsingError, ProviderError, StaleCheckpointError
from castles.core.message import Mailbox, MessageRef, RawMessage
from castles.provider.port import MailboxQuery, ProviderCheck

MAX_ENCODED_BYTES = 34_952_540


def _page(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderError("Gmail returned a malformed API response")
    return value


def _records(page: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = page.get(name, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ProviderError("Gmail returned a malformed API response")
    return cast(list[dict[str, Any]], value)


def _token(page: dict[str, Any]) -> str | None:
    value = page.get("nextPageToken")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProviderError("Gmail returned a malformed pagination token")
    return value


def _pages(load: Callable[[str | None], dict[str, Any]], repeated: str) -> Iterable[dict[str, Any]]:
    token: str | None = None
    seen: set[str] = set()
    while True:
        page = load(token)
        yield page
        token = _token(page)
        if token is None:
            return
        if token in seen:
            raise ProviderError(repeated)
        seen.add(token)


def _execute[T](call: Callable[[], T], *, attempts: int = 4) -> T:
    for attempt in range(attempts):
        try:
            return call()
        except HttpError as exc:
            status = int(exc.resp.status)
            if status not in {429, 500, 502, 503, 504} or attempt + 1 == attempts:
                raise ProviderError("Gmail API request failed") from exc
        except OSError as exc:
            if attempt + 1 == attempts:
                raise ProviderError("Gmail API request could not complete") from exc
        time.sleep(min(2**attempt, 8))
    raise AssertionError("unreachable")


class Gmail:
    def __init__(self, credentials: Credentials, api: Any | None = None) -> None:
        self.api = api or build("gmail", "v1", credentials=credentials, cache_discovery=False)
        self._profile: dict[str, Any] | None = None

    def _get_profile(self) -> dict[str, Any]:
        return _page(_execute(lambda: self.api.users().getProfile(userId="me").execute()))

    def identity(self) -> Mailbox:
        self._profile = self._get_profile()
        address = self._profile.get("emailAddress")
        if not isinstance(address, str) or "@" not in address:
            raise ProviderError("Gmail profile did not include a mailbox address")
        normalized = address.casefold()
        try:
            return Mailbox("gmail", normalized, normalized)
        except ValueError:
            raise ProviderError("Gmail profile included a malformed mailbox address") from None

    def enumerate(self, query: MailboxQuery) -> Iterable[MessageRef]:
        if query.checkpoint:
            yield from self._history(query.checkpoint)
            return
        seen: set[str] = set()

        def load(token: str | None) -> dict[str, Any]:
            kwargs: dict[str, Any] = {"userId": "me", "includeSpamTrash": False, "maxResults": 500}
            if query.since:
                kwargs["q"] = f"after:{int(query.since.timestamp())}"
            if token:
                kwargs["pageToken"] = token
            return _page(_execute(self.api.users().messages().list(**kwargs).execute))

        for page in _pages(load, "Gmail pagination repeated a page token"):
            for item in _records(page, "messages"):
                key = item.get("id")
                if not isinstance(key, str) or not key:
                    raise ProviderError("Gmail returned a malformed message reference")
                if key not in seen:
                    seen.add(key)
                    yield MessageRef(key)

    def _history(self, checkpoint: str) -> Iterable[MessageRef]:
        seen: set[str] = set()

        def load(token: str | None) -> dict[str, Any]:
            kwargs: dict[str, Any] = {
                "userId": "me",
                "startHistoryId": checkpoint,
                "historyTypes": ["messageAdded"],
            }
            if token:
                kwargs["pageToken"] = token
            try:
                return _page(_execute(self.api.users().history().list(**kwargs).execute))
            except ProviderError as exc:
                if isinstance(exc.__cause__, HttpError) and int(exc.__cause__.resp.status) == 404:
                    raise StaleCheckpointError("Gmail history checkpoint is stale") from exc
                raise

        for page in _pages(load, "Gmail history pagination repeated a page token"):
            for event in _records(page, "history"):
                for added in _records(event, "messagesAdded"):
                    message = added.get("message")
                    if not isinstance(message, dict):
                        raise ProviderError("Gmail returned a malformed history record")
                    key = message.get("id")
                    if not isinstance(key, str) or not key:
                        raise ProviderError("Gmail returned a malformed message reference")
                    if key not in seen:
                        seen.add(key)
                        yield MessageRef(key)

    def fetch(self, ref: MessageRef) -> RawMessage:
        result = _page(
            _execute(
                lambda: (
                    self.api.users().messages().get(userId="me", id=ref.key, format="raw").execute()
                )
            )
        )
        try:
            if result.get("id") != ref.key:
                raise ParsingError("Gmail returned a mismatched message")
            encoded = result["raw"]
            if not isinstance(encoded, str) or len(encoded) > MAX_ENCODED_BYTES:
                raise ParsingError("Gmail message exceeds the safe byte limit")
            payload = base64.b64decode(
                (encoded + "=" * (-len(encoded) % 4)).encode("ascii"), altchars=b"-_", validate=True
            )
            timestamp = result["internalDate"]
            if not isinstance(timestamp, str) or not timestamp.isdecimal():
                raise ValueError
            observed = datetime.fromtimestamp(int(timestamp) / 1000, tz=UTC)
            if not payload:
                raise ValueError
        except ParsingError:
            raise
        except (KeyError, ValueError, TypeError, UnicodeError, OverflowError):
            raise ParsingError("Gmail returned a malformed message") from None
        # Raw RFC fields have no per-header provenance in this response. A sender can inject an
        # Authentication-Results field naming mx.google.com, so none are trusted here.
        return RawMessage(ref, payload, observed)

    def checkpoint(self) -> str | None:
        if self._profile is None:
            self._profile = self._get_profile()
        value = self._profile.get("historyId")
        if not isinstance(value, str) or not value.isdecimal():
            raise ProviderError("Gmail profile did not include a valid history checkpoint")
        return value

    def checkpoint_kind(self) -> str:
        return "gmail_history"

    def validate(self) -> ProviderCheck:
        self.identity()
        return ProviderCheck(True, "Gmail read-only profile is available")
