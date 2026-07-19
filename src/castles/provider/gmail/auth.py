from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from castles.config.setting import TokenStore, validate_client
from castles.core.error import (
    AuthorizationError,
    ConfigurationError,
    MalformedCredentialsError,
    MissingScopeError,
    TokenPersistenceError,
    UnexpectedScopeError,
)
from castles.provider.gmail.loopback import run

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SCOPES = (SCOPE,)


def parse(value: str) -> Credentials:
    try:
        credentials = cast(
            Credentials,
            Credentials.from_authorized_user_info(json.loads(value), SCOPES),  # type: ignore[no-untyped-call]
        )
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise MalformedCredentialsError("saved Gmail authorization is invalid") from None
    _validate_credentials(credentials, require_valid=False)
    return credentials


def _validate_credentials(credentials: Credentials, *, require_valid: bool = True) -> None:
    granted = credentials.granted_scopes
    configured = credentials.scopes
    values = granted if granted is not None else configured
    if values is None or isinstance(values, str):
        raise MalformedCredentialsError("Gmail authorization credentials are malformed")
    try:
        scopes = set(values)
    except TypeError:
        raise MalformedCredentialsError("Gmail authorization credentials are malformed") from None
    if SCOPE not in scopes:
        raise MissingScopeError(
            "Google did not grant the required Gmail read-only scope; retry setup and approve "
            "read-only access"
        )
    if scopes != {SCOPE}:
        raise UnexpectedScopeError(
            "Google returned authorization with an unexpected scope; Castles did not save it"
        )
    if (
        (require_valid and not credentials.valid)
        or not isinstance(credentials.token, str)
        or not credentials.token
    ):
        raise MalformedCredentialsError("Gmail authorization credentials are malformed")


def _refresh(credentials: Credentials) -> None:
    try:
        credentials.refresh(Request())  # type: ignore[no-untyped-call]
    except RefreshError as exc:
        reason = str(exc).casefold()
        if "invalid_grant" in reason or "revoked" in reason:
            raise AuthorizationError("Gmail authorization was revoked; run setup again") from None
        raise AuthorizationError("Gmail authorization refresh failed") from None
    except TransportError:
        raise AuthorizationError("Gmail authorization refresh could not reach Google") from None


def authorize(
    client: Path, store: TokenStore, *, force: bool = False, no_browser: bool = False
) -> Credentials:
    validate_client(client)
    current = None if force else store.load()
    credentials = parse(current) if current else None
    if credentials and credentials.expired and credentials.refresh_token:
        _refresh(credentials)
    if not credentials or not credentials.valid:
        try:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(client), scopes=SCOPES, autogenerate_code_verifier=True
            )
        except (OSError, ValueError, KeyError):
            raise AuthorizationError("Google OAuth client JSON is invalid") from None
        credentials = run(flow, no_browser=no_browser)
    _validate_credentials(credentials)
    try:
        store.save(credentials.to_json())  # type: ignore[no-untyped-call]
    except ConfigurationError:
        raise TokenPersistenceError(
            "Gmail authorization could not be saved safely; any previous authorization was "
            "preserved"
        ) from None
    return credentials


def load(store: TokenStore) -> Credentials:
    current = store.load()
    if not current:
        raise AuthorizationError("Gmail is not authorized; run `castles setup`")
    credentials = parse(current)
    if credentials.expired and credentials.refresh_token:
        _refresh(credentials)
        _validate_credentials(credentials)
        try:
            store.save(credentials.to_json())  # type: ignore[no-untyped-call]
        except ConfigurationError:
            raise TokenPersistenceError(
                "refreshed Gmail authorization could not be saved safely; the prior file was "
                "preserved"
            ) from None
    if not credentials.valid:
        raise AuthorizationError("Gmail authorization is invalid; run `castles setup`")
    return credentials
