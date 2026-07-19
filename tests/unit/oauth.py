from __future__ import annotations

import http.client
import json
import os
import socket
import stat
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest
from google.auth.exceptions import RefreshError, TransportError
from google.oauth2.credentials import Credentials
from oauthlib.oauth2 import OAuth2Error

from castles.config.setting import TokenStore
from castles.core.error import AuthorizationError
from castles.provider.gmail.auth import SCOPE, authorize, load, parse
from castles.provider.gmail.client import Gmail
from castles.provider.gmail.loopback import HOST, MAX_IGNORED, OAuthFlow, run

STATE = "expected-state"
URL = "https://accounts.example/authorize"


def client(path: Path) -> Path:
    path.write_text(
        '{"installed":{"client_id":"id","client_secret":"secret","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}}'
    )
    return path


def credential(
    *, valid: bool = True, expired: bool = False, refresh: str | None = "refresh"
) -> MagicMock:
    value = MagicMock()
    value.valid = valid
    value.expired = expired
    value.refresh_token = refresh
    value.to_json.return_value = '{"token":"private"}'
    return value


class RefreshResponse:
    def __init__(self, status: int, value: dict[str, object]) -> None:
        self.status = status
        self.data = json.dumps(value).encode()
        self.headers: dict[str, str] = {}


class RefreshTransport:
    def __init__(
        self,
        value: dict[str, object] | None = None,
        *,
        status: int = 200,
        failure: Exception | None = None,
    ) -> None:
        self.value = value or {}
        self.status = status
        self.failure = failure
        self.calls = 0

    def __call__(self, **kwargs: object) -> RefreshResponse:
        self.calls += 1
        assert kwargs["method"] == "POST"
        assert kwargs["url"] == "https://oauth2.googleapis.com/token"
        if self.failure:
            raise self.failure
        return RefreshResponse(self.status, self.value)


def saved_credentials(*, expired: bool) -> Credentials:
    now = datetime.now(UTC)
    return Credentials(  # type: ignore[no-untyped-call]
        token="synthetic-access-before",
        refresh_token="synthetic-refresh-before",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client",
        client_secret="synthetic-client-secret",
        scopes=(SCOPE,),
        expiry=now - timedelta(hours=1) if expired else now + timedelta(hours=1),
    )


def fingerprint(value: str | None) -> str:
    assert value is not None
    return sha256(value.encode()).hexdigest()


def test_scope_parse_and_existing_authorization(tmp_path: Path) -> None:
    assert SCOPE == "https://www.googleapis.com/auth/gmail.readonly"
    with pytest.raises(AuthorizationError, match="invalid"):
        parse("not json")
    current = credential()
    store = TokenStore(tmp_path / "token.json")
    store.save("{}")
    with patch(
        "castles.provider.gmail.auth.Credentials.from_authorized_user_info",
        return_value=current,
    ):
        assert authorize(client(tmp_path / "client.json"), store) is current
        assert store.load() == '{"token":"private"}'
        assert load(store) is current


def test_unexpired_authorization_skips_refresh_and_provider_proceeds(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "token.json")
    store.save(saved_credentials(expired=False).to_json())  # type: ignore[no-untyped-call]
    transport = RefreshTransport(failure=AssertionError("refresh must not run"))
    api = MagicMock()
    api.users.return_value.getProfile.return_value.execute.return_value = {
        "emailAddress": "person@example.com",
        "historyId": "42",
    }

    with patch("castles.provider.gmail.auth.Request", return_value=transport):
        credentials = load(store)
        assert Gmail(credentials, api).validate().available

    assert transport.calls == 0


@pytest.mark.parametrize("rotated", [False, True])
def test_expired_authorization_refreshes_once_and_persists_atomically(
    tmp_path: Path, rotated: bool
) -> None:
    path = tmp_path / "token.json"
    store = TokenStore(path)
    original = saved_credentials(expired=True)
    store.save(original.to_json())  # type: ignore[no-untyped-call]
    value: dict[str, object] = {
        "access_token": "synthetic-access-after",
        "expires_in": 3600,
        "scope": SCOPE,
        "token_type": "Bearer",
    }
    if rotated:
        value["refresh_token"] = "synthetic-refresh-after"
    transport = RefreshTransport(value)
    api = MagicMock()
    api.users.return_value.getProfile.return_value.execute.return_value = {
        "emailAddress": "person@example.com",
        "historyId": "42",
    }

    with (
        patch("castles.provider.gmail.auth.Request", return_value=transport),
        patch("castles.config.setting.os.replace", wraps=os.replace) as replace,
    ):
        credentials = load(store)
        assert Gmail(credentials, api).validate().available
        assert load(store).valid

    persisted = parse(cast(str, store.load()))
    assert transport.calls == 1
    assert replace.call_count == 1
    assert fingerprint(persisted.token) == fingerprint("synthetic-access-after")
    expected_refresh = "synthetic-refresh-after" if rotated else "synthetic-refresh-before"
    assert fingerprint(persisted.refresh_token) == fingerprint(expected_refresh)
    assert path.is_file() and not path.is_symlink()
    assert stat.S_ISREG(path.lstat().st_mode)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("transport", "message"),
    [
        (
            RefreshTransport(
                {
                    "error": "invalid_grant",
                    "error_description": "synthetic-private-provider-detail",
                },
                status=400,
            ),
            "revoked",
        ),
        (
            RefreshTransport(
                failure=TransportError(  # type: ignore[no-untyped-call]
                    "synthetic-private-transport-detail"
                )
            ),
            "could not reach Google",
        ),
    ],
)
def test_real_refresh_failures_leave_credentials_unchanged_and_sanitized(
    tmp_path: Path, transport: RefreshTransport, message: str
) -> None:
    path = tmp_path / "token.json"
    store = TokenStore(path)
    store.save(saved_credentials(expired=True).to_json())  # type: ignore[no-untyped-call]
    original = path.read_bytes()
    api = MagicMock()

    with (
        patch("castles.provider.gmail.auth.Request", return_value=transport),
        pytest.raises(AuthorizationError, match=message) as caught,
    ):
        Gmail(load(store), api).validate()

    rendered = str(caught.value)
    assert transport.calls == 1
    assert path.read_bytes() == original
    assert api.mock_calls == []
    assert "invalid_grant" not in rendered
    assert "synthetic-private" not in rendered
    assert "synthetic-access" not in rendered
    assert "synthetic-refresh" not in rendered


def test_new_authorization_uses_pkce_and_no_browser(tmp_path: Path) -> None:
    flow = MagicMock()
    fresh = credential()
    store = TokenStore(tmp_path / "token.json")
    with (
        patch(
            "castles.provider.gmail.auth.InstalledAppFlow.from_client_secrets_file",
            return_value=flow,
        ) as factory,
        patch("castles.provider.gmail.auth.run", return_value=fresh) as callback,
    ):
        assert (
            authorize(client(tmp_path / "client.json"), store, force=True, no_browser=True) is fresh
        )
    assert factory.call_args.kwargs == {
        "scopes": (SCOPE,),
        "autogenerate_code_verifier": True,
    }
    callback.assert_called_once_with(flow, no_browser=True)


def test_authorization_config_and_load_failures(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "token.json")
    with pytest.raises(AuthorizationError, match="not authorized"):
        load(store)
    store.save("{}")
    with (
        patch(
            "castles.provider.gmail.auth.Credentials.from_authorized_user_info",
            side_effect=ValueError,
        ),
        pytest.raises(AuthorizationError, match="invalid"),
    ):
        load(store)
    with (
        patch(
            "castles.provider.gmail.auth.InstalledAppFlow.from_client_secrets_file",
            side_effect=ValueError,
        ),
        pytest.raises(AuthorizationError, match="client JSON"),
    ):
        authorize(client(tmp_path / "client.json"), store, force=True)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (RefreshError("invalid_grant"), "revoked"),  # type: ignore[no-untyped-call]
        (RefreshError("temporary"), "refresh failed"),  # type: ignore[no-untyped-call]
        (TransportError("offline"), "could not reach"),  # type: ignore[no-untyped-call]
    ],
)
def test_refresh_failures_are_sanitized(tmp_path: Path, failure: Exception, message: str) -> None:
    current = credential(valid=False, expired=True)
    current.refresh.side_effect = failure
    store = TokenStore(tmp_path / "token.json")
    store.save("{}")
    with (
        patch(
            "castles.provider.gmail.auth.Credentials.from_authorized_user_info",
            return_value=current,
        ),
        pytest.raises(AuthorizationError, match=message) as caught,
    ):
        load(store)
    assert "invalid_grant" not in str(caught.value)


def test_invalid_unrefreshable_credentials(tmp_path: Path) -> None:
    current = credential(valid=False, expired=False, refresh=None)
    store = TokenStore(tmp_path / "token.json")
    store.save("{}")
    with (
        patch(
            "castles.provider.gmail.auth.Credentials.from_authorized_user_info",
            return_value=current,
        ),
        pytest.raises(AuthorizationError, match="invalid"),
    ):
        load(store)


class Flow:
    def __init__(self, error: Exception | None = None) -> None:
        self.redirect_uri = ""
        self.ready = threading.Event()
        self.error = error
        self.response: str | None = None
        self.fetches = 0
        self._credentials = cast(Credentials, object())

    @property
    def credentials(self) -> Credentials:
        return self._credentials

    def authorization_url(self, **kwargs: object) -> tuple[str, str]:
        assert kwargs == {"access_type": "offline", "prompt": "consent"}
        self.ready.set()
        return URL, STATE

    def fetch_token(self, **kwargs: object) -> Mapping[str, str]:
        self.fetches += 1
        self.response = cast(str, kwargs["authorization_response"])
        if self.error:
            raise self.error
        return {}


class Outcome:
    value: Credentials | None = None
    error: BaseException | None = None


def start(
    flow: Flow,
    *,
    no_browser: bool = True,
    browser: Callable[[str], bool] | None = None,
) -> tuple[threading.Thread, Outcome]:
    outcome = Outcome()

    def target() -> None:
        try:
            kwargs: dict[str, object] = {
                "no_browser": no_browser,
                "timeout": 2.0,
                "report": lambda _: None,
            }
            if browser:
                kwargs["open_browser"] = browser
            outcome.value = run(cast(OAuthFlow, flow), **kwargs)  # type: ignore[arg-type]
        except BaseException as exc:
            outcome.error = exc

    thread = threading.Thread(target=target)
    thread.start()
    assert flow.ready.wait(5), f"loopback start failed: {type(outcome.error).__name__}"
    return thread, outcome


def request(
    flow: Flow, method: str, path: str, *, timeout: float = 1
) -> tuple[int, dict[str, str], str]:
    target = urlsplit(flow.redirect_uri)
    connection = http.client.HTTPConnection(HOST, target.port, timeout=timeout)
    connection.request(method, path)
    response = connection.getresponse()
    result = (
        response.status,
        {key.casefold(): value for key, value in response.getheaders()},
        response.read().decode(),
    )
    connection.close()
    return result


def finish(thread: threading.Thread, outcome: Outcome) -> Outcome:
    thread.join(2)
    assert not thread.is_alive()
    return outcome


def test_loopback_ignores_probes_then_accepts_exact_callback() -> None:
    flow = Flow()
    thread, outcome = start(flow)
    status, _, _ = request(flow, "GET", "/favicon.ico")
    assert status == 404
    status, headers, body = request(flow, "GET", f"/?state={STATE}&code=code")
    finish(thread, outcome)
    assert status == 200
    assert body == "Authorization received. Return to Castles."
    assert headers["cache-control"] == "no-store"
    assert headers["pragma"] == "no-cache"
    assert outcome.value is flow.credentials
    assert flow.response and flow.response.startswith("https://127.0.0.1")
    assert flow.fetches == 1


def test_loopback_fixed_host_does_not_require_reverse_dns() -> None:
    flow = Flow()
    with patch("http.server.socket.getfqdn", side_effect=OSError("unavailable")):
        thread, outcome = start(flow)
        assert request(flow, "GET", f"/?state={STATE}&code=code")[0] == 200
        finish(thread, outcome)
    assert outcome.value is flow.credentials


def test_blocking_browser_launch_cannot_block_valid_callback() -> None:
    flow = Flow()
    launched = threading.Event()
    release = threading.Event()

    def browser(_: str) -> bool:
        launched.set()
        release.wait(2)
        return True

    thread, outcome = start(flow, no_browser=False, browser=browser)
    assert launched.wait(1)
    try:
        status, _, _ = request(flow, "GET", f"/?state={STATE}&code=code", timeout=2)
    finally:
        release.set()
        finish(thread, outcome)
    assert status == 200
    assert outcome.error is None
    assert flow.fetches == 1


def test_incomplete_connection_cannot_block_valid_callback() -> None:
    flow = Flow()
    thread, outcome = start(flow)
    target = urlsplit(flow.redirect_uri)
    incomplete = socket.create_connection((HOST, cast(int, target.port)), timeout=1)
    try:
        # Give the single callback worker time to accept the connection without receiving a request.
        threading.Event().wait(0.1)
        status, _, _ = request(flow, "GET", f"/?state={STATE}&code=code", timeout=2)
    finally:
        incomplete.close()
        finish(thread, outcome)
    assert status == 200
    assert outcome.error is None
    assert flow.fetches == 1


@pytest.mark.parametrize(
    "path",
    [
        f"/?state={STATE}&code=one&code=two",
        f"/?state={STATE}&code=%ZZ",
        "/?" + "&".join(f"x{index}=y" for index in range(21)),
    ],
)
def test_loopback_rejects_malformed_callbacks(path: str) -> None:
    flow = Flow()
    thread, outcome = start(flow)
    assert request(flow, "GET", path)[0] == 400
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert flow.response is None


def test_loopback_state_mismatch_guides_away_from_stale_tabs() -> None:
    flow = Flow()
    thread, outcome = start(flow)
    assert request(flow, "GET", "/?state=wrong&code=code")[0] == 400
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert "state did not match" in str(outcome.error)
    assert "close stale authorization tabs" in str(outcome.error)
    assert STATE not in str(outcome.error)


def test_loopback_denial_and_request_limit() -> None:
    flow = Flow()
    thread, outcome = start(flow)
    assert request(flow, "GET", f"/?state={STATE}&error=access_denied")[0] == 200
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert "denied" in str(outcome.error)
    assert "read-only" in str(outcome.error)

    failed = Flow()
    thread, outcome = start(failed)
    assert request(failed, "GET", f"/?state={STATE}&error=server_error")[0] == 200
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert "failed at Google" in str(outcome.error)
    assert "newest tab" in str(outcome.error)

    limited = Flow()
    thread, outcome = start(limited)
    for index in range(MAX_IGNORED):
        request(limited, "GET", f"/probe-{index}")
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert "unrelated" in str(outcome.error)


def test_loopback_timeout_browser_bind_and_exchange_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = Flow()
    moments = iter((10.0, 311.0))
    with pytest.raises(AuthorizationError, match="five minutes") as caught:
        run(
            cast(OAuthFlow, flow),
            no_browser=True,
            timeout=300,
            monotonic=lambda: next(moments),
            report=lambda _: None,
        )
    assert "Google page stalled" in str(caught.value)
    assert "clean Firefox or Chromium" in str(caught.value)
    assert "localhost failed" in str(caught.value)
    assert "--no-browser" in str(caught.value)

    release = threading.Event()
    moments = iter((10.0, 311.0))

    def blocking_browser(_: str) -> bool:
        release.wait(1)
        return True

    try:
        with pytest.raises(AuthorizationError, match="five minutes"):
            run(
                cast(OAuthFlow, Flow()),
                no_browser=False,
                timeout=300,
                monotonic=lambda: next(moments),
                open_browser=blocking_browser,
                report=lambda _: None,
            )
    finally:
        release.set()
    with pytest.raises(AuthorizationError, match="browser"):
        run(
            cast(OAuthFlow, Flow()),
            no_browser=False,
            open_browser=lambda _: False,
            report=lambda _: None,
        )
    with pytest.raises(AuthorizationError, match="browser") as browser_failure:
        run(
            cast(OAuthFlow, Flow()),
            no_browser=False,
            open_browser=lambda _: (_ for _ in ()).throw(
                RuntimeError("synthetic-private-browser-detail")
            ),
            report=lambda _: None,
        )
    assert "synthetic-private" not in str(browser_failure.value)
    with (
        monkeypatch.context() as current,
        pytest.raises(AuthorizationError, match=r"listener on 127\.0\.0\.1"),
    ):
        current.setattr(
            "castles.provider.gmail.loopback.make_server",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("private")),
        )
        run(cast(OAuthFlow, Flow()), no_browser=True, report=lambda _: None)

    failed = Flow(OAuth2Error("private"))
    thread, outcome = start(failed)
    request(failed, "GET", f"/?state={STATE}&code=code")
    finish(thread, outcome)
    assert isinstance(outcome.error, AuthorizationError)
    assert "private" not in str(outcome.error)
    assert "newest authorization tab" in str(outcome.error)


def test_loopback_browser_success() -> None:
    flow = Flow()
    reports: list[str] = []
    outcome = Outcome()

    def browser(url: str) -> bool:
        assert url == URL
        return True

    def target() -> None:
        try:
            outcome.value = run(
                cast(OAuthFlow, flow),
                no_browser=False,
                timeout=2,
                open_browser=browser,
                report=reports.append,
            )
        except BaseException as exc:
            outcome.error = exc

    thread = threading.Thread(target=target)
    thread.start()
    assert flow.ready.wait(1)
    request(flow, "GET", f"/?state={STATE}&code=code")
    finish(thread, outcome)
    assert outcome.error is None
    assert reports == [
        "Waiting up to five minutes for Gmail authorization in your browser. Use the newest "
        "Castles tab; tabs from earlier setup attempts will not work."
    ]


def test_loopback_no_browser_marks_url_sensitive_and_current() -> None:
    flow = Flow()
    reports: list[str] = []
    outcome = Outcome()

    def target() -> None:
        try:
            outcome.value = run(
                cast(OAuthFlow, flow), no_browser=True, timeout=2, report=reports.append
            )
        except BaseException as exc:
            outcome.error = exc

    thread = threading.Thread(target=target)
    thread.start()
    assert flow.ready.wait(1)
    request(flow, "GET", f"/?state={STATE}&code=code")
    finish(thread, outcome)
    assert outcome.error is None
    assert len(reports) == 1
    assert reports[0].startswith("Open this newest authorization URL (sensitive; do not share it):")
    assert reports[0].endswith(
        "Waiting up to five minutes for Google to return to Castles on 127.0.0.1."
    )


def test_loopback_server_closes() -> None:
    flow = Flow()
    thread, outcome = start(flow)
    request(flow, "GET", f"/?state={STATE}&code=code")
    finish(thread, outcome)
    target = urlsplit(flow.redirect_uri)
    with pytest.raises(OSError):
        socket.create_connection((HOST, cast(int, target.port)), timeout=0.1)
