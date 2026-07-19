from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from google.auth.exceptions import TransportError
from google.oauth2.credentials import Credentials

from castles import wiring
from castles.app.doctor import Health
from castles.app.scan import ScanRequest
from castles.config.path import Paths
from castles.config.setting import TokenStore
from castles.core.error import AuthorizationError
from castles.core.message import Mailbox, MessageRef, RawMessage
from castles.provider.gmail import auth as gmail_auth
from castles.provider.gmail.auth import SCOPE
from castles.provider.port import MailboxQuery, ProviderCheck

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def client(path: Path) -> Path:
    path.write_text(
        '{"installed":{"client_id":"id","client_secret":"secret","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}}'
    )
    return path


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Paths:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("WIN_PD_OVERRIDE_APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("WIN_PD_OVERRIDE_LOCAL_APPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    return Paths.system()


class Provider:
    def identity(self) -> Mailbox:
        return Mailbox("gmail", "person@example.com", "person@example.com")

    def enumerate(self, query: MailboxQuery) -> Iterable[MessageRef]:
        assert query.since is not None
        return (MessageRef("opaque"),)

    def fetch(self, ref: MessageRef) -> RawMessage:
        return RawMessage(
            ref,
            b"From: Billing <billing@unknown-saas.example>\r\nSubject: Invoice available\r\n\r\nbody",
            NOW,
        )

    def checkpoint(self) -> str | None:
        return "42"

    def checkpoint_kind(self) -> str:
        return "history"

    def validate(self) -> ProviderCheck:
        return ProviderCheck(True, "available")


class RefreshResponse:
    def __init__(self, status: int = 200, value: dict[str, object] | None = None) -> None:
        self.status = status
        self.data = json.dumps(
            value
            or {
                "access_token": "synthetic-access-after",
                "expires_in": 3600,
                "scope": SCOPE,
                "token_type": "Bearer",
            }
        ).encode()
        self.headers: dict[str, str] = {}


class RefreshTransport:
    def __init__(self, *, invalid: bool = False, failure: Exception | None = None) -> None:
        self.invalid = invalid
        self.failure = failure
        self.calls = 0

    def __call__(self, **kwargs: object) -> RefreshResponse:
        del kwargs
        self.calls += 1
        if self.failure:
            raise self.failure
        if self.invalid:
            return RefreshResponse(
                400,
                {
                    "error": "invalid_grant",
                    "error_description": "synthetic-private-provider-detail",
                },
            )
        return RefreshResponse()


def expired_credentials() -> Credentials:
    return Credentials(  # type: ignore[no-untyped-call]
        token="synthetic-access-before",
        refresh_token="synthetic-refresh-before",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client",
        client_secret="synthetic-client-secret",
        scopes=(SCOPE,),
        expiry=datetime.now(UTC) - timedelta(hours=1),
    )


def test_setup_usecase_copies_private_client(
    isolated: Paths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = client(tmp_path / "source.json")
    credentials = cast(Credentials, SimpleNamespace())
    monkeypatch.setattr(wiring, "authorize", lambda *args, **kwargs: credentials)
    monkeypatch.setattr(wiring, "Gmail", lambda _: Provider())
    mailbox = wiring.setup_usecase().execute(source, force=True, no_browser=True)
    assert mailbox.address == "person@example.com"
    assert isolated.client.is_file()
    assert "client_secret" not in isolated.client.name


def test_scan_and_local_results_through_composition(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "load", lambda _: cast(Credentials, SimpleNamespace()))
    monkeypatch.setattr(wiring, "Gmail", lambda _: Provider())
    result = wiring.scan(ScanRequest())
    assert result.finding_count == 1
    local = wiring.local_results()
    assert local[0].findings[0].entity == "unknown-saas.example"


def test_empty_results_and_find_client(isolated: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    assert wiring.local_results() == ()
    expected = isolated.config / "source.json"
    monkeypatch.setattr(wiring, "discover_client", lambda _: expected)
    assert wiring.find_client() == expected


def test_doctor_complete_and_provider_checks(
    isolated: Paths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated.prepare()
    isolated.client.write_text(client(tmp_path / "source.json").read_text())
    TokenStore(isolated.token).save("private")
    monkeypatch.setattr(wiring, "load", lambda _: cast(Credentials, SimpleNamespace()))
    monkeypatch.setattr(wiring, "Gmail", lambda _: Provider())
    checks = wiring.doctor(provider=True)
    assert all(check.health is Health.OK for check in checks if check.name != "database")
    assert next(check for check in checks if check.name == "Gmail provider").health is Health.OK


def test_doctor_and_scan_share_one_persisted_refresh_path(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated.prepare()
    TokenStore(isolated.token).save(
        expired_credentials().to_json()  # type: ignore[no-untyped-call]
    )
    transport = RefreshTransport()
    monkeypatch.setattr(gmail_auth, "Request", lambda: transport)
    monkeypatch.setattr(wiring, "Gmail", lambda _: Provider())

    checks = wiring.doctor(provider=True)
    result = wiring.scan(ScanRequest())

    assert next(check for check in checks if check.name == "Gmail provider").health is Health.OK
    assert result.finding_count == 1
    assert transport.calls == 1
    assert gmail_auth.parse(cast(str, TokenStore(isolated.token).load())).valid


def test_invalid_refresh_prevents_provider_access_and_preserves_offline_findings(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    production_load = gmail_auth.load
    monkeypatch.setattr(wiring, "load", lambda _: cast(Credentials, SimpleNamespace()))
    monkeypatch.setattr(wiring, "Gmail", lambda _: Provider())
    assert wiring.scan(ScanRequest()).finding_count == 1

    monkeypatch.setattr(wiring, "load", production_load)
    TokenStore(isolated.token).save(
        expired_credentials().to_json()  # type: ignore[no-untyped-call]
    )
    original = isolated.token.read_bytes()
    transport = RefreshTransport(invalid=True)
    monkeypatch.setattr(gmail_auth, "Request", lambda: transport)

    constructed = False

    class Forbidden:
        def __init__(self, _: Credentials) -> None:
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(wiring, "Gmail", Forbidden)
    with pytest.raises(AuthorizationError, match="revoked") as caught:
        wiring.scan(ScanRequest())

    assert not constructed
    assert transport.calls == 1
    assert isolated.token.read_bytes() == original
    assert wiring.local_results()[0].findings[0].entity == "unknown-saas.example"
    assert "synthetic-private" not in str(caught.value)


def test_refresh_transport_failure_is_safe_in_provider_doctor(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated.prepare()
    TokenStore(isolated.token).save(
        expired_credentials().to_json()  # type: ignore[no-untyped-call]
    )
    original = isolated.token.read_bytes()
    transport = RefreshTransport(
        failure=TransportError(  # type: ignore[no-untyped-call]
            "synthetic-private-transport-detail"
        )
    )
    monkeypatch.setattr(gmail_auth, "Request", lambda: transport)

    checks = wiring.doctor(provider=True)
    provider = next(check for check in checks if check.name == "Gmail provider")

    assert provider.health is Health.FAIL
    assert provider.detail == "provider validation failed"
    assert transport.calls == 1
    assert isolated.token.read_bytes() == original
    assert "synthetic-private" not in provider.detail


def test_doctor_invalid_client_and_provider_failure(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated.prepare()
    isolated.client.write_text("{}")
    monkeypatch.setattr(wiring, "load", lambda _: (_ for _ in ()).throw(RuntimeError("private")))
    checks = wiring.doctor(provider=True)
    assert next(check for check in checks if check.name == "OAuth client").health is Health.FAIL
    assert next(check for check in checks if check.name == "Gmail provider").health is Health.FAIL


def test_doctor_reports_unsafe_authorization_file(isolated: Paths, tmp_path: Path) -> None:
    isolated.prepare()
    target = tmp_path / "target"
    target.write_text("private")
    isolated.token.symlink_to(target)
    checks = wiring.doctor()
    authorization = next(check for check in checks if check.name == "Gmail authorization")
    assert authorization.health is Health.FAIL
