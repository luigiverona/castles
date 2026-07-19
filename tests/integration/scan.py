from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import pytest

from castles.app.scan import OVERLAP_DAYS, Scan, ScanRequest
from castles.core.error import (
    CorruptionError,
    LockingError,
    ParsingError,
    ProviderError,
    StaleCheckpointError,
)
from castles.core.finding import Finding
from castles.core.message import Mailbox, MessageRef, NormalizedMessage, RawMessage
from castles.core.scan import ScanMode, ScanStatus
from castles.core.signal import MessageSignals
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.parse import html as html_parser
from castles.parse.mime import parse as parse_message
from castles.provider.port import MailboxQuery, ProviderCheck
from castles.store.lock import FileLocks
from castles.store.sqlite import SQLite

NOW = datetime(2026, 7, 14, tzinfo=UTC)


class Provider:
    def __init__(self, keys: tuple[str, ...], *, checkpoint: str = "42") -> None:
        self.keys = keys
        self.checkpoint_value = checkpoint
        self.queries: list[MailboxQuery] = []
        self.stale = False
        self.failure = False
        self.fetch_failure: Exception | None = None
        self.fail_after: int | None = None

    def identity(self) -> Mailbox:
        return Mailbox("fake", "person@example.com", "person@example.com")

    def enumerate(self, query: MailboxQuery) -> Iterable[MessageRef]:
        self.queries.append(query)
        if self.failure:
            raise ProviderError("provider failed")
        if self.stale and query.checkpoint:
            raise StaleCheckpointError("stale")
        for index, key in enumerate(self.keys):
            if self.fail_after is not None and index == self.fail_after:
                raise ProviderError("provider interrupted")
            yield MessageRef(key)

    def fetch(self, ref: MessageRef) -> RawMessage:
        if self.fetch_failure:
            raise self.fetch_failure
        return RawMessage(
            ref,
            b"synthetic",
            NOW + timedelta(minutes=int(ref.key[-1]) if ref.key[-1].isdigit() else 0),
        )

    def checkpoint(self) -> str | None:
        return self.checkpoint_value

    def checkpoint_kind(self) -> str:
        return "fake_cursor"

    def validate(self) -> ProviderCheck:
        return ProviderCheck(True, "fake available")


class Locks:
    def acquire(self, account: str) -> AbstractContextManager[None]:
        del account
        return nullcontext()


def parser(raw: RawMessage) -> NormalizedMessage:
    if raw.ref.key.startswith("bad"):
        raise ParsingError("synthetic parse failure")
    domain = "spotify.com" if raw.ref.key.startswith("new") else "unknown-saas.example"
    return NormalizedMessage(
        raw.ref.key,
        raw.observed_at,
        domain,
        None,
        None,
        (),
        "Invoice available",
        "",
        ("u.ct.sendgrid.net",),
        (),
    )


@pytest.fixture
def setup(tmp_path: Path) -> Iterator[tuple[SQLite, Path]]:
    store = SQLite(tmp_path / "castles.db")
    store.migrate()
    yield store, tmp_path
    store.close()


def scanner(
    provider: Provider,
    store: SQLite,
    tmp_path: Path,
    discovery: Callable[[tuple[MessageSignals, ...]], tuple[Finding, ...]] = discover,
) -> Scan:
    return Scan(provider, store, parser, extract, discovery, Locks(), now=lambda: NOW)


def test_initial_and_incremental_recompute(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    initial = scanner(provider, store, path).execute(ScanRequest())
    assert initial.mode is ScanMode.INITIAL
    assert (initial.discovered, initial.processed, initial.skipped) == (1, 1, 0)
    provider.keys = ("msg1", "msg2")
    provider.checkpoint_value = "43"
    incremental = scanner(provider, store, path).execute(ScanRequest())
    assert incremental.mode is ScanMode.INCREMENTAL
    assert (incremental.discovered, incremental.processed, incremental.skipped) == (2, 1, 1)
    account = store.accounts()[0][0]
    assert store.findings(account)[0].message_count == 2
    assert store.checkpoint(account).value == "43"  # type: ignore[union-attr]


def test_duplicate_enumeration_does_not_inflate_counts(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    result = scanner(Provider(("msg1", "msg1", "msg1")), store, path).execute(ScanRequest())
    assert (result.discovered, result.processed, result.skipped) == (1, 1, 0)
    account = store.accounts()[0][0]
    assert store.findings(account)[0].message_count == 1


def test_since_scan(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    since = NOW - timedelta(days=10)
    provider = Provider(("msg1",))
    result = scanner(provider, store, path).execute(ScanRequest(since=since))
    assert result.mode is ScanMode.SINCE
    assert provider.queries == [MailboxQuery(since=since)]


def test_stale_checkpoint_fallback(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    scanner(provider, store, path).execute(ScanRequest())
    provider.stale = True
    result = scanner(provider, store, path).execute(ScanRequest())
    assert result.stale_fallback
    assert provider.queries[-1].since == NOW - timedelta(days=OVERLAP_DAYS)


@pytest.mark.parametrize("field", ["provider", "kind"])
def test_corrupted_checkpoint_identity_is_rejected(setup: tuple[SQLite, Path], field: str) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    statement = (
        "UPDATE checkpoints SET provider='other' WHERE account_id=?"
        if field == "provider"
        else "UPDATE checkpoints SET kind='other' WHERE account_id=?"
    )
    store.connection.execute(statement, (account,))
    store.connection.commit()
    scans = store.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    with pytest.raises(CorruptionError, match="does not match"):
        scanner(provider, store, path).execute(ScanRequest())

    assert store.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == scans


def test_successful_full_replacement(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    scanner(provider, store, path).execute(ScanRequest())
    provider.keys = ("new1",)
    result = scanner(provider, store, path).execute(ScanRequest(full=True))
    account = store.accounts()[0][0]
    assert result.mode is ScanMode.FULL
    assert store.findings(account)[0].entity == "spotify.com"
    assert [value.message_key for value in store.signals(account)] == ["new1"]


def test_partial_full_preserves_active(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    before = store.findings(account)
    checkpoint = store.checkpoint(account)
    provider.keys = ("new1", "bad2")
    result = scanner(provider, store, path).execute(ScanRequest(full=True))
    assert result.status is ScanStatus.PARTIAL
    assert store.findings(account) == before
    assert store.checkpoint(account) == checkpoint
    assert (
        store.connection.execute(
            "SELECT COUNT(*) FROM messages WHERE generation != 'active'"
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize("failure", ["provider", "detector"])
def test_failed_scan_is_recorded_and_active_preserved(
    setup: tuple[SQLite, Path], failure: str
) -> None:
    store, path = setup
    provider = Provider(("msg1",))
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    before = store.findings(account)
    provider.keys = ("new1",)
    if failure == "provider":
        provider.failure = True
        current = scanner(provider, store, path)
    else:

        def broken(_values: tuple[MessageSignals, ...]) -> tuple[Finding, ...]:
            raise RuntimeError("detector failed")

        current = scanner(provider, store, path, broken)
    with pytest.raises((ProviderError, RuntimeError)):
        current.execute(ScanRequest(full=True))
    assert store.findings(account) == before
    row = store.connection.execute(
        "SELECT status FROM scans ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    assert row[0] == "failed"


def test_parser_skip_marks_partial_nonfull(setup: tuple[SQLite, Path]) -> None:
    store, path = setup
    result = scanner(Provider(("msg1", "bad2")), store, path).execute(ScanRequest())
    assert result.status is ScanStatus.PARTIAL
    assert (result.processed, result.skipped) == (1, 1)
    account = store.accounts()[0][0]
    assert store.checkpoint(account) is not None


def test_real_mime_parser_rejection_keeps_scanning_valid_html(
    setup: tuple[SQLite, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = setup
    marker = "synthetic-parser-rejection"

    class HTMLProvider(Provider):
        def fetch(self, ref: MessageRef) -> RawMessage:
            message = EmailMessage()
            if ref.key == "opaque-a":
                message["From"] = "alerts@first-service.example"
                content = (
                    '<div style="display:none"><span style="color:red">secret</span>'
                    '<a href="https://hidden.example/private">hidden</a></div>'
                    '<p>visible first</p><a href="https://first-service.example/path">first</a>'
                )
            elif ref.key == "opaque-b":
                message["From"] = "alerts@rejected-service.example"
                content = f"<p>{marker}</p>"
            else:
                message["From"] = "alerts@second-service.example"
                content = (
                    '<p>visible last</p><a href="https://second-service.example/path">second</a>'
                )
            message.add_alternative(content, subtype="html")
            return RawMessage(ref, message.as_bytes(), NOW)

    production_extract = html_parser._extract

    def rejecting(value: str) -> tuple[str, tuple[str, ...]]:
        if marker in value:
            raise AttributeError("synthetic private parser detail")
        return production_extract(value)

    monkeypatch.setattr(html_parser, "_extract", rejecting)
    provider = HTMLProvider(("opaque-a", "opaque-b", "opaque-c"))
    result = Scan(
        provider,
        store,
        parse_message,
        extract,
        discover,
        Locks(),
        now=lambda: NOW,
    ).execute(ScanRequest())

    assert result.status is ScanStatus.PARTIAL
    assert (result.discovered, result.processed, result.skipped) == (3, 2, 1)
    account = store.accounts()[0][0]
    assert {value.message_key for value in store.signals(account)} == {"opaque-a", "opaque-c"}
    assert {value.entity for value in store.findings(account)} == {
        "first-service.example",
        "second-service.example",
    }
    assert store.checkpoint(account) is not None
    assert store.scan(account).status is ScanStatus.PARTIAL  # type: ignore[union-attr]


def test_fetch_transport_failure_fails_without_advancing_checkpoint(
    setup: tuple[SQLite, Path],
) -> None:
    store, path = setup
    provider = Provider(("msg1",), checkpoint="42")
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    checkpoint = store.checkpoint(account)
    provider.keys = ("msg2",)
    provider.checkpoint_value = "43"
    provider.fetch_failure = OSError("private transport detail")

    with pytest.raises(OSError, match="private transport detail"):
        scanner(provider, store, path).execute(ScanRequest())

    assert store.checkpoint(account) == checkpoint
    assert store.scan(account).status is ScanStatus.FAILED  # type: ignore[union-attr]


def test_incremental_provider_interruption_reuses_committed_signals(
    setup: tuple[SQLite, Path],
) -> None:
    store, path = setup
    provider = Provider(("msg1",), checkpoint="42")
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    checkpoint = store.checkpoint(account)
    provider.keys = ("new1", "new2")
    provider.checkpoint_value = "43"
    provider.fail_after = 1

    with pytest.raises(ProviderError, match="interrupted"):
        scanner(provider, store, path).execute(ScanRequest())

    assert store.checkpoint(account) == checkpoint
    assert {value.message_key for value in store.signals(account)} == {"msg1", "new1"}
    provider.fail_after = None
    result = scanner(provider, store, path).execute(ScanRequest())
    assert (result.processed, result.skipped) == (1, 1)
    assert {value.message_key for value in store.signals(account)} == {"msg1", "new1", "new2"}


def test_incremental_discovery_failure_recomputes_committed_signals_on_retry(
    setup: tuple[SQLite, Path],
) -> None:
    store, path = setup
    provider = Provider(("msg1",), checkpoint="42")
    scanner(provider, store, path).execute(ScanRequest())
    account = store.accounts()[0][0]
    checkpoint = store.checkpoint(account)
    provider.keys = ("new1",)

    def broken(_values: tuple[MessageSignals, ...]) -> tuple[Finding, ...]:
        raise RuntimeError("discovery interrupted")

    with pytest.raises(RuntimeError, match="discovery"):
        scanner(provider, store, path, broken).execute(ScanRequest())
    assert store.checkpoint(account) == checkpoint
    assert {value.message_key for value in store.signals(account)} == {"msg1", "new1"}

    result = scanner(provider, store, path).execute(ScanRequest())
    assert (result.processed, result.skipped) == (0, 1)
    assert {finding.entity for finding in store.findings(account)} == {
        "spotify.com",
        "unknown-saas.example",
    }


def test_request_validation() -> None:
    with pytest.raises(ValueError):
        ScanRequest(full=True, since=NOW)
    with pytest.raises(ValueError):
        ScanRequest(since=datetime(2026, 1, 1))


def test_file_lock_contention_and_release(tmp_path: Path) -> None:
    first = FileLocks(tmp_path, timeout=0.01)
    second = FileLocks(tmp_path, timeout=0.01)
    with (
        first.acquire("one"),
        pytest.raises(LockingError, match="already running"),
        second.acquire("two"),
    ):
        pass
    with second.acquire("two"):
        assert (tmp_path / "scan.lock").exists()
    assert not (tmp_path / "scan.lock").exists()


def test_file_lock_rejects_symlink_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(LockingError, match="unsafe"), FileLocks(linked).acquire("one"):
        pass
    assert not (target / "scan.lock").exists()
