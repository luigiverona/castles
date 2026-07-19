from __future__ import annotations

import sys
import time
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from socket import socket
from socketserver import TCPServer
from threading import Event, Thread
from typing import Protocol, cast
from urllib.parse import parse_qsl
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from google.oauth2.credentials import Credentials
from oauthlib.oauth2 import OAuth2Error

from castles.app.setup import GUIDE_URL
from castles.core.error import (
    AuthorizationDeniedError,
    AuthorizationError,
    BrowserOpenError,
    CallbackTimeoutError,
    StaleCallbackError,
    TokenExchangeError,
)

HOST = "127.0.0.1"
PATH = "/"
MAX_QUERY_BYTES = 8192
MAX_PARAMETERS = 20
MAX_IGNORED = 20
POLL_SECONDS = 0.1
CONNECTION_SECONDS = 1.0


class OAuthFlow(Protocol):
    redirect_uri: str

    @property
    def credentials(self) -> Credentials: ...

    def authorization_url(self, **kwargs: object) -> tuple[str, str]: ...

    def fetch_token(self, **kwargs: object) -> Mapping[str, str]: ...


@dataclass(slots=True)
class Callback:
    expected: str = ""
    response: str | None = None
    error: AuthorizationError | None = None
    ignored: int = 0


class Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        del format, args


class Server(WSGIServer):
    connection_timeout: float = CONNECTION_SECONDS

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = HOST
        self.server_port = int(self.server_address[1])
        self.setup_environ()

    def get_request(self) -> tuple[socket, object]:
        connection, address = super().get_request()
        connection.settimeout(self.connection_timeout)
        return connection, address

    def handle_error(self, request: object, client_address: object) -> None:
        del request, client_address


def _percent(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] == "%":
            if index + 2 >= len(value) or any(
                char not in "0123456789abcdefABCDEF" for char in value[index + 1 : index + 3]
            ):
                return False
            index += 3
        else:
            index += 1
    return True


class Application:
    def __init__(self, state: Callback, redirect: str) -> None:
        self.state = state
        self.redirect = redirect

    def __call__(
        self,
        environ: Mapping[str, object],
        start: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", ""))
        path = str(environ.get("PATH_INFO", ""))
        query = str(environ.get("QUERY_STRING", ""))
        if method != "GET" or path != PATH or not query:
            self.state.ignored += 1
            if self.state.ignored >= MAX_IGNORED:
                self.state.error = AuthorizationError("too many unrelated OAuth callback requests")
            status = HTTPStatus.METHOD_NOT_ALLOWED if method != "GET" else HTTPStatus.NOT_FOUND
            return self._respond(start, status, "Not an OAuth callback.", method == "HEAD")
        if len(query.encode(errors="replace")) > MAX_QUERY_BYTES or not _percent(query):
            return self._fail(start, "Gmail OAuth callback was malformed")
        try:
            pairs = parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_PARAMETERS,
            )
        except ValueError:
            return self._fail(start, "Gmail OAuth callback was malformed")
        grouped: dict[str, list[str]] = {}
        for key, value in pairs:
            grouped.setdefault(key, []).append(value)
        states, codes, errors = (
            grouped.get("state", []),
            grouped.get("code", []),
            grouped.get("error", []),
        )
        if len(states) != 1 or states[0] != self.state.expected:
            return self._fail(
                start,
                "Gmail OAuth callback state did not match; close stale authorization tabs and "
                "retry setup",
                StaleCallbackError,
            )
        if (len(codes) == 1) == (len(errors) == 1) or (codes and not codes[0]):
            return self._fail(start, "Gmail OAuth callback was malformed")
        if errors:
            self.state.error = (
                AuthorizationDeniedError(
                    "Google returned an authorization denial. Castles cannot determine whether the "
                    "cause was Deny, the Testing user list, browser controls, or a Google policy "
                    "decision. Review the Testing guidance and retry.\n\n"
                    f"Guide:\n{GUIDE_URL}#testing-or-in-production"
                )
                if errors[0] == "access_denied"
                else AuthorizationError(
                    "Gmail authorization failed at Google; retry setup using the newest tab"
                )
            )
        self.state.response = f"{self.redirect}?{query}"
        return self._respond(start, HTTPStatus.OK, "Authorization received. Return to Castles.")

    def _fail(
        self,
        start: Callable[[str, list[tuple[str, str]]], object],
        message: str,
        error: type[AuthorizationError] = AuthorizationError,
    ) -> list[bytes]:
        self.state.error = error(message)
        return self._respond(start, HTTPStatus.BAD_REQUEST, "Invalid OAuth callback.")

    @staticmethod
    def _respond(
        start: Callable[[str, list[tuple[str, str]]], object],
        status: HTTPStatus,
        message: str,
        head: bool = False,
    ) -> list[bytes]:
        body = message.encode()
        start(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("Pragma", "no-cache"),
                ("Content-Security-Policy", "default-src 'none'"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        return [] if head else [body]


def run(
    flow: OAuthFlow,
    *,
    no_browser: bool = False,
    timeout: float = 300,
    monotonic: Callable[[], float] = time.monotonic,
    open_browser: Callable[[str], bool] = webbrowser.open,
    report: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> Credentials:
    state = Callback()
    server: Server | None = None
    try:
        try:
            server = make_server(
                HOST, 0, lambda environ, start: [], server_class=Server, handler_class=Quiet
            )
        except OSError:
            raise AuthorizationError(
                "Castles could not start the OAuth listener on 127.0.0.1; check local firewall "
                "or security controls and retry"
            ) from None
        redirect = f"http://{HOST}:{server.server_port}{PATH}"
        flow.redirect_uri = redirect
        url, state.expected = flow.authorization_url(access_type="offline", prompt="consent")
        server.set_app(Application(state, redirect))
        deadline = monotonic() + timeout
        browser_done = Event()
        browser_opened: bool | None = None

        def launch_browser() -> None:
            nonlocal browser_opened
            try:
                browser_opened = open_browser(url)
            except Exception:
                browser_opened = False
            finally:
                browser_done.set()

        if no_browser:
            report(
                f"Open this newest authorization URL (sensitive; do not share it):\n{url}\n"
                "Waiting up to five minutes for Google to return to Castles on 127.0.0.1."
            )
        else:
            Thread(target=launch_browser, name="castles-browser", daemon=True).start()
            report(
                "Waiting up to five minutes for Gmail authorization in your browser. Use the "
                "newest Castles tab; tabs from earlier setup attempts will not work."
            )
        while state.response is None and state.error is None:
            if not no_browser and browser_done.is_set() and not browser_opened:
                raise BrowserOpenError("browser could not open; retry setup with --no-browser")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise CallbackTimeoutError(
                    "Google authorization did not return to Castles within five minutes. Possible "
                    "causes include: authorization was not completed; an old browser tab was used; "
                    "browser controls blocked the loopback redirect; the project is in Testing and "
                    "the account is not allowed; or Google denied the application before callback. "
                    f"Retry with the newest tab.\n\nGuide:\n{GUIDE_URL}#troubleshooting"
                )
            server.timeout = min(POLL_SECONDS, remaining)
            server.connection_timeout = min(CONNECTION_SECONDS, remaining)
            server.handle_request()
        if state.error:
            raise state.error
        response = cast(str, state.response).replace("http://", "https://", 1)
        try:
            flow.fetch_token(authorization_response=response)
        except (OSError, ValueError, OAuth2Error):
            raise TokenExchangeError(
                "Gmail token exchange failed; retry setup using the newest authorization tab"
            ) from None
        return flow.credentials
    finally:
        if server is not None:
            server.server_close()
