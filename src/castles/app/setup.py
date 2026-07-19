from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from castles.app.port import SetupTerminal
from castles.core.error import (
    DownloadsUnavailableError,
    MultipleClientCandidatesError,
    NoClientCandidateError,
    NoManagedClientError,
    SetupCancelledError,
)
from castles.core.message import Mailbox

GUIDE_URL = "https://castles.luigiverona.dev/setup.html"

OVERVIEW = f"""Castles needs a Google Desktop OAuth client.

The client belongs to your Google Cloud project and remains under your control.
Castles requests read-only Gmail access and processes mailbox data locally.

Setup overview:
  1. Create or select a dedicated Google Cloud project
  2. Enable the Gmail API
  3. Configure an External OAuth application
  4. Add only Gmail read-only access
  5. Create a Desktop app OAuth client
  6. Download the client JSON

Guide:
{GUIDE_URL}"""

NON_INTERACTIVE = f"""No Google Desktop OAuth client is configured.

Run:
  castles setup /path/to/google-desktop-client.json

Guide:
  {GUIDE_URL}"""

BEFORE_AUTHORIZATION = """The Google Desktop client belongs to your project and remains under your control.
Castles requests read-only Gmail access and processes mailbox data locally.
Setup authorizes access but does not scan. Start analysis later with `castles scan`.
Remove local authorization with `castles logout`; revoke the grant separately in your Google Account."""

IMPORTED = """Castles stored a private managed copy of the Google Desktop client.
Castles did not delete the source. The original copy is no longer required by Castles and may be
deleted manually after setup succeeds."""


@dataclass(frozen=True, slots=True)
class DesktopClient:
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    auth_uri: str = field(repr=False)
    token_uri: str = field(repr=False)
    redirect_uris: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ClientCandidate:
    path: Path = field(repr=False)
    label: str
    client: DesktopClient = field(repr=False)


@dataclass(frozen=True, slots=True)
class ClientDiscovery:
    downloads_available: bool
    candidates: tuple[ClientCandidate, ...]
    bounded: bool = False


@dataclass(frozen=True, slots=True)
class Setup:
    managed: Path
    inspect: Callable[[Path], DesktopClient]
    import_client: Callable[[DesktopClient], None]
    discover: Callable[[], ClientDiscovery]
    authorize: Callable[[bool, bool], Mailbox]
    terminal: SetupTerminal

    def execute(
        self,
        source: Path | None = None,
        *,
        force: bool = False,
        no_browser: bool = False,
        non_interactive: bool = False,
    ) -> Mailbox:
        selected: DesktopClient | None = None
        imported = False

        if source is not None:
            selected = self.inspect(source)
            self.import_client(selected)
            imported = True
        elif self.managed.exists() or self.managed.is_symlink():
            self.inspect(self.managed)
        else:
            interactive = not non_interactive and self.terminal.interactive()
            discovery = self.discover()
            if not interactive:
                if not discovery.downloads_available:
                    raise DownloadsUnavailableError(NON_INTERACTIVE)
                if not discovery.candidates:
                    raise NoClientCandidateError(NON_INTERACTIVE)
                if len(discovery.candidates) > 1:
                    raise MultipleClientCandidatesError(NON_INTERACTIVE)
                raise NoManagedClientError(NON_INTERACTIVE)
            self.terminal.write(OVERVIEW)
            selected = self._choose(discovery)
            self.import_client(selected)
            imported = True

        if imported:
            self.terminal.write(IMPORTED)
        self.terminal.write(BEFORE_AUTHORIZATION)
        return self.authorize(force, no_browser)

    def _choose(self, discovery: ClientDiscovery) -> DesktopClient:
        candidates = discovery.candidates
        if len(candidates) == 1:
            candidate = candidates[0]
            self.terminal.write(f"Found a valid Google Desktop client:\n\n  {candidate.label}")
            answer = self.terminal.confirm("Use this file?", default=True)
            if answer:
                return candidate.client
            if answer is None:
                raise SetupCancelledError("Google Desktop client setup was cancelled")
            return self._ask_path()
        if len(candidates) > 1:
            choice = self.terminal.select(
                "Choose a Google Desktop client:",
                tuple(candidate.label for candidate in candidates),
            )
            if choice is None:
                raise SetupCancelledError("Google Desktop client setup was cancelled")
            if choice < 0 or choice >= len(candidates):
                raise MultipleClientCandidatesError(
                    "No Google Desktop client was selected; retry setup and choose one file"
                )
            return candidates[choice].client
        return self._ask_path()

    def _ask_path(self) -> DesktopClient:
        source = self.terminal.path(
            "Path to the downloaded Google Desktop client JSON (blank to cancel):"
        )
        if source is None:
            raise SetupCancelledError("Google Desktop client setup was cancelled")
        return self.inspect(source)
