from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO, cast

import pytest
from rich.console import Console

from castles.app.setup import (
    BEFORE_AUTHORIZATION,
    GUIDE_URL,
    OVERVIEW,
    ClientCandidate,
    ClientDiscovery,
    DesktopClient,
    Setup,
)
from castles.cli.setup import MAX_ATTEMPTS, Terminal
from castles.core.error import (
    DownloadsUnavailableError,
    MultipleClientCandidatesError,
    NoClientCandidateError,
    NoManagedClientError,
    SetupCancelledError,
)
from castles.core.message import Mailbox


def client(value: str = "one") -> DesktopClient:
    return DesktopClient(
        f"synthetic-{value}.apps.googleusercontent.com",
        f"synthetic-{value}-secret",
        "https://accounts.google.com/o/oauth2/auth",
        "https://oauth2.googleapis.com/token",
        ("http://localhost",),
    )


@dataclass
class FakeTerminal:
    tty: bool = True
    confirmation: bool | None = True
    selection: int | None = 0
    supplied_path: Path | None = None
    messages: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)

    def interactive(self) -> bool:
        return self.tty

    def write(self, message: str) -> None:
        self.messages.append(message)

    def confirm(self, prompt: str, *, default: bool = True) -> bool | None:
        del default
        self.prompts.append(prompt)
        return self.confirmation

    def select(self, prompt: str, choices: tuple[str, ...]) -> int | None:
        self.prompts.extend((prompt, *choices))
        return self.selection

    def path(self, prompt: str) -> Path | None:
        self.prompts.append(prompt)
        return self.supplied_path


def usecase(
    tmp_path: Path,
    terminal: FakeTerminal,
    *,
    discovery: ClientDiscovery = ClientDiscovery(True, ()),
) -> tuple[Setup, list[object]]:
    managed = tmp_path / "managed.json"
    calls: list[object] = []
    values: dict[Path, DesktopClient] = {}

    def inspect(path: Path) -> DesktopClient:
        calls.append(("inspect", path))
        return values.get(path, client(path.stem))

    def store(value: DesktopClient) -> None:
        calls.append(("import", value.client_id))
        managed.write_text("managed")

    def discover() -> ClientDiscovery:
        calls.append("discover")
        return discovery

    def authorize(force: bool, no_browser: bool) -> Mailbox:
        calls.append(("authorize", force, no_browser))
        return Mailbox("gmail", "synthetic@example.com", "synthetic@example.com")

    return Setup(managed, inspect, store, discover, authorize, terminal), calls


def candidate(tmp_path: Path, name: str) -> ClientCandidate:
    return ClientCandidate(
        tmp_path / f"client_secret_{name}.json",
        f"~/Downloads/client_secret_….json (modified 2026-07-19 12:00:0{name} UTC)",
        client(name),
    )


def test_explicit_path_wins_and_never_prompts(tmp_path: Path) -> None:
    terminal = FakeTerminal(tty=True)
    current, calls = usecase(tmp_path, terminal)
    current.managed.write_text("existing")
    source = tmp_path / "explicit.json"

    mailbox = current.execute(source, force=True, no_browser=True)

    assert mailbox.provider == "gmail"
    assert calls == [
        ("inspect", source),
        ("import", "synthetic-explicit.apps.googleusercontent.com"),
        ("authorize", True, True),
    ]
    assert terminal.prompts == []
    assert BEFORE_AUTHORIZATION in terminal.messages


def test_managed_client_is_reused_before_discovery(tmp_path: Path) -> None:
    terminal = FakeTerminal()
    current, calls = usecase(tmp_path, terminal)
    current.managed.write_text("existing")

    current.execute()

    assert calls == [("inspect", current.managed), ("authorize", False, False)]
    assert terminal.prompts == []


def test_one_download_candidate_requires_confirmation(tmp_path: Path) -> None:
    terminal = FakeTerminal(confirmation=True)
    found = candidate(tmp_path, "1")
    current, calls = usecase(tmp_path, terminal, discovery=ClientDiscovery(True, (found,)))

    current.execute()

    assert "discover" in calls
    assert ("import", found.client.client_id) in calls
    assert terminal.prompts == ["Use this file?"]
    rendered = "\n".join(terminal.messages)
    assert OVERVIEW in rendered
    assert "synthetic-1" not in rendered


def test_rejected_download_candidate_accepts_an_explicit_path(tmp_path: Path) -> None:
    source = tmp_path / "chosen.json"
    terminal = FakeTerminal(confirmation=False, supplied_path=source)
    current, calls = usecase(
        tmp_path, terminal, discovery=ClientDiscovery(True, (candidate(tmp_path, "1"),))
    )

    current.execute()

    assert ("inspect", source) in calls
    assert ("import", "synthetic-chosen.apps.googleusercontent.com") in calls


def test_multiple_candidates_require_selection(tmp_path: Path) -> None:
    terminal = FakeTerminal(selection=1)
    first = candidate(tmp_path, "1")
    second = candidate(tmp_path, "2")
    current, calls = usecase(tmp_path, terminal, discovery=ClientDiscovery(True, (first, second)))

    current.execute()

    assert ("import", second.client.client_id) in calls
    assert ("import", first.client.client_id) not in calls


def test_invalid_candidate_selection_is_typed(tmp_path: Path) -> None:
    terminal = FakeTerminal(selection=8)
    current, _ = usecase(
        tmp_path,
        terminal,
        discovery=ClientDiscovery(True, (candidate(tmp_path, "1"), candidate(tmp_path, "2"))),
    )
    with pytest.raises(MultipleClientCandidatesError, match="No Google Desktop"):
        current.execute()


def test_no_candidate_guides_and_accepts_a_path(tmp_path: Path) -> None:
    source = tmp_path / "chosen.json"
    terminal = FakeTerminal(supplied_path=source)
    current, calls = usecase(tmp_path, terminal)

    current.execute()

    assert ("inspect", source) in calls
    assert GUIDE_URL in "\n".join(terminal.messages)


@pytest.mark.parametrize("tty", [False, True])
def test_non_interactive_never_discovers_or_prompts(tmp_path: Path, tty: bool) -> None:
    terminal = FakeTerminal(tty=tty)
    current, calls = usecase(
        tmp_path, terminal, discovery=ClientDiscovery(True, (candidate(tmp_path, "1"),))
    )
    with pytest.raises(NoManagedClientError) as caught:
        current.execute(non_interactive=tty)
    assert "castles setup /path/to/google-desktop-client.json" in str(caught.value)
    assert GUIDE_URL in str(caught.value)
    assert calls == ["discover"]
    assert terminal.prompts == []


@pytest.mark.parametrize(
    ("discovery", "error"),
    [
        (ClientDiscovery(False, ()), DownloadsUnavailableError),
        (ClientDiscovery(True, ()), NoClientCandidateError),
        (
            ClientDiscovery(
                True,
                (
                    ClientCandidate(Path("one"), "one", client("one")),
                    ClientCandidate(Path("two"), "two", client("two")),
                ),
            ),
            MultipleClientCandidatesError,
        ),
        (
            ClientDiscovery(True, (ClientCandidate(Path("one"), "one", client("one")),)),
            NoManagedClientError,
        ),
    ],
)
def test_non_interactive_error_taxonomy(
    tmp_path: Path, discovery: ClientDiscovery, error: type[NoManagedClientError]
) -> None:
    terminal = FakeTerminal(tty=False)
    current, _ = usecase(tmp_path, terminal, discovery=discovery)
    with pytest.raises(error) as caught:
        current.execute()
    rendered = str(caught.value)
    assert "castles setup /path/to/google-desktop-client.json" in rendered
    assert GUIDE_URL in rendered
    assert "synthetic-one-secret" not in rendered


@pytest.mark.parametrize(
    "terminal",
    [
        FakeTerminal(confirmation=None),
        FakeTerminal(selection=None),
        FakeTerminal(supplied_path=None),
    ],
)
def test_cancellation_is_clean(tmp_path: Path, terminal: FakeTerminal) -> None:
    discovery = (
        ClientDiscovery(True, (candidate(tmp_path, "1"),))
        if terminal.confirmation is None
        else ClientDiscovery(True, (candidate(tmp_path, "1"), candidate(tmp_path, "2")))
        if terminal.selection is None
        else ClientDiscovery(True, ())
    )
    current, calls = usecase(tmp_path, terminal, discovery=discovery)
    with pytest.raises(SetupCancelledError, match="cancelled"):
        current.execute()
    assert not any(isinstance(call, tuple) and call[0] == "authorize" for call in calls)


class TTYInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class TTYOutput(io.StringIO):
    def isatty(self) -> bool:
        return True


class FailedInput:
    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        raise OSError("synthetic input failure")


def test_terminal_prompts_only_with_tty_boundaries() -> None:
    output = TTYOutput()
    current = Terminal(Console(file=output, force_terminal=False), TTYInput("\n"), output)
    assert current.interactive()
    assert current.confirm("Use this file?")

    assert not Terminal(Console(file=io.StringIO()), TTYInput(), io.StringIO()).interactive()
    assert not Terminal(Console(file=io.StringIO()), io.StringIO(), TTYOutput()).interactive()


def test_terminal_invalid_input_is_bounded_and_eof_does_not_loop() -> None:
    output = TTYOutput()
    values = "\n".join("invalid" for _ in range(MAX_ATTEMPTS)) + "\n"
    current = Terminal(Console(file=output, force_terminal=False), TTYInput(values), output)
    assert current.select("Choose:", ("one", "two")) is None
    assert output.getvalue().count("Enter a number") == MAX_ATTEMPTS

    eof = Terminal(Console(file=TTYOutput(), force_terminal=False), TTYInput(""), TTYOutput())
    assert eof.confirm("Use this file?") is None


def test_terminal_delivery_paths_are_bounded_and_deterministic() -> None:
    output = TTYOutput()
    console = Console(file=output, force_terminal=False)
    Terminal(console, TTYInput(), output).write("Guide text")
    assert "Guide text" in output.getvalue()

    assert Terminal(console, TTYInput("yes\n"), output).confirm("Use?") is True
    assert Terminal(console, TTYInput("no\n"), output).confirm("Use?") is False
    assert Terminal(console, TTYInput("\n"), output).confirm("Use?", default=False) is False
    invalid = "\n".join("maybe" for _ in range(MAX_ATTEMPTS)) + "\n"
    assert Terminal(console, TTYInput(invalid), output).confirm("Use?") is None

    assert Terminal(console, TTYInput("2\n"), output).select("Choose:", ("one", "two")) == 1
    assert Terminal(console, TTYInput("\n"), output).select("Choose:", ("one",)) is None
    assert (
        Terminal(console, TTYInput("~/client.json\n"), output).path("Path:")
        == Path("~/client.json").expanduser()
    )
    assert Terminal(console, cast(TextIO, FailedInput()), output).path("Path:") is None
