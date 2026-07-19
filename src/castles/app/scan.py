from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from castles.app.port import Discovery, Extractor, Parser
from castles.core.error import CorruptionError, ParsingError, StaleCheckpointError
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.provider.port import MailboxProvider, MailboxQuery
from castles.store.port import Checkpoint, Locks, Store

INITIAL_DAYS = 365
OVERLAP_DAYS = 7


@dataclass(frozen=True, slots=True)
class ScanRequest:
    full: bool = False
    since: datetime | None = None

    def __post_init__(self) -> None:
        if self.full and self.since is not None:
            raise ValueError("full and since scans are mutually exclusive")
        if self.since is not None and (self.since.tzinfo is None or self.since.utcoffset() is None):
            raise ValueError("since must be timezone-aware")


class Scan:
    def __init__(
        self,
        provider: MailboxProvider,
        store: Store,
        parser: Parser,
        extractor: Extractor,
        discovery: Discovery,
        locks: Locks,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.provider = provider
        self.store = store
        self.parser = parser
        self.extractor = extractor
        self.discovery = discovery
        self.locks = locks
        self.now = now

    def execute(self, request: ScanRequest) -> ScanResult:
        mailbox = self.provider.identity()
        with self.locks.acquire(mailbox.account_id):
            account = self.store.account(mailbox)
            checkpoint = self.store.checkpoint(account)
            checkpoint_kind = self.provider.checkpoint_kind()
            if checkpoint and (
                checkpoint.provider != mailbox.provider or checkpoint.kind != checkpoint_kind
            ):
                raise CorruptionError("stored checkpoint does not match the mailbox provider")
            mode = (
                ScanMode.FULL
                if request.full
                else ScanMode.SINCE
                if request.since
                else ScanMode.INCREMENTAL
                if checkpoint
                else ScanMode.INITIAL
            )
            started = self.now().astimezone(UTC)
            scan_id = uuid4().hex
            generation = scan_id if mode is ScanMode.FULL else "active"
            self.store.begin(scan_id, account, mode, generation, started)
            discovered = processed = skipped = rejected = 0
            stale = False
            enumerated: set[str] = set()

            def process(query: MailboxQuery) -> None:
                nonlocal discovered, processed, skipped, rejected
                for ref in self.provider.enumerate(query):
                    if ref.key in enumerated:
                        continue
                    enumerated.add(ref.key)
                    discovered += 1
                    if mode is not ScanMode.FULL and self.store.seen(account, ref.key):
                        skipped += 1
                        continue
                    try:
                        normalized = self.parser(self.provider.fetch(ref))
                    except ParsingError:
                        skipped += 1
                        rejected += 1
                        continue
                    signals = self.extractor(normalized)
                    if self.store.put(account, generation, signals):
                        processed += 1

            try:
                query = MailboxQuery()
                if mode is ScanMode.INITIAL:
                    query = MailboxQuery(since=started - timedelta(days=INITIAL_DAYS))
                elif mode is ScanMode.SINCE:
                    query = MailboxQuery(since=request.since)
                elif mode is ScanMode.INCREMENTAL and checkpoint:
                    query = MailboxQuery(checkpoint=checkpoint.value)
                try:
                    process(query)
                except StaleCheckpointError:
                    if mode is not ScanMode.INCREMENTAL or checkpoint is None:
                        raise
                    stale = True
                    process(
                        MailboxQuery(since=checkpoint.successful_at - timedelta(days=OVERLAP_DAYS))
                    )
                values = self.store.signals(account, generation)
                findings = self.discovery(values)
                completed = self.now().astimezone(UTC)
                status = ScanStatus.PARTIAL if rejected else ScanStatus.COMPLETE
                result = ScanResult(
                    scan_id,
                    mode,
                    status,
                    started,
                    completed,
                    discovered,
                    processed,
                    skipped,
                    len(findings),
                    stale,
                )
                if mode is ScanMode.FULL and rejected:
                    self.store.discard(account, result, generation)
                    return replace(result, finding_count=len(self.store.findings(account)))
                value = self.provider.checkpoint()
                next_checkpoint = (
                    Checkpoint(mailbox.provider, checkpoint_kind, value, completed)
                    if value is not None
                    else None
                )
                self.store.complete(
                    account, result, generation, findings, next_checkpoint, mode is ScanMode.FULL
                )
                return result
            except Exception:
                self.store.fail(scan_id, account, generation, self.now().astimezone(UTC))
                raise
