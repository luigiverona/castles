from __future__ import annotations

import os
import sqlite3
import stat
from datetime import UTC, datetime
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote

from castles.core.error import CorruptionError, StorageError
from castles.core.finding import Finding
from castles.core.message import Mailbox
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.core.signal import MessageSignals
from castles.store.codec import decode_finding, decode_signals, encode_finding, encode_signals
from castles.store.port import Checkpoint

ACTIVE = "active"
SCHEMA_VERSION = 1
MIGRATION_SHA256 = "1d99d3e748ccf9bf155c75e14eb47f267b71417f01b08b8d65acc443794eae84"
_COLUMNS = {
    "schema_migrations": {"version", "applied_at"},
    "accounts": {"id", "provider", "account_id", "address"},
    "checkpoints": {"account_id", "provider", "kind", "value", "successful_at"},
    "scans": {
        "scan_id",
        "account_id",
        "mode",
        "status",
        "generation",
        "started_at",
        "completed_at",
        "discovered",
        "processed",
        "skipped",
    },
    "messages": {
        "account_id",
        "generation",
        "message_key",
        "observed_at",
        "payload",
        "fingerprint",
    },
    "findings": {"account_id", "generation", "entity_key", "payload", "fingerprint"},
}


class SQLite:
    def __init__(self, path: Path, *, readonly: bool = False) -> None:
        self.path = path
        try:
            parent = path.parent.lstat()
            if not stat.S_ISDIR(parent.st_mode):
                raise StorageError("Castles database directory is not a regular directory")
            current = path.lstat()
        except FileNotFoundError:
            current = None
        except OSError as exc:
            raise StorageError("Castles database path could not be inspected") from exc
        if current is not None and not stat.S_ISREG(current.st_mode):
            raise StorageError("Castles database path is not a regular file")
        if readonly:
            uri = f"file:{quote(str(path.resolve()))}?mode=ro"
            try:
                self.connection = sqlite3.connect(uri, uri=True)
            except sqlite3.Error as exc:
                raise StorageError("Castles database could not be opened read-only") from exc
        else:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                self.connection = sqlite3.connect(path)
                if os.name == "posix":
                    path.chmod(0o600)
            except (OSError, sqlite3.Error) as exc:
                raise StorageError("Castles database could not be opened") from exc
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.connection.close()

    @staticmethod
    def _migration() -> str:
        try:
            data = files("castles.store").joinpath("sql/001_init.sql").read_bytes()
        except (OSError, UnicodeError) as exc:
            raise StorageError("bundled database migration could not be read") from exc
        if sha256(data).hexdigest() != MIGRATION_SHA256:
            raise StorageError("bundled database migration checksum does not match")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise StorageError("bundled database migration is not UTF-8") from None

    def _validate_schema(self) -> None:
        self._migration()
        for table, expected in _COLUMNS.items():
            rows = self.connection.execute(f"PRAGMA table_info({table})").fetchall()
            if {str(row[1]) for row in rows} != expected:
                raise StorageError("Castles database schema is incomplete or modified")

    def migrate(self) -> None:
        try:
            table = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone()
            applied = (
                {row[0] for row in self.connection.execute("SELECT version FROM schema_migrations")}
                if table
                else set()
            )
            if any(version > SCHEMA_VERSION for version in applied):
                raise StorageError("Castles database schema is newer than this application")
            if 1 not in applied:
                script = self._migration()
                statements: list[str] = []
                current = ""
                for line in script.splitlines(keepends=True):
                    current += line
                    if sqlite3.complete_statement(current):
                        statements.append(current)
                        current = ""
                if current.strip():
                    raise StorageError("bundled database migration is incomplete")
                with self.connection:
                    for statement in statements:
                        self.connection.execute(statement)
                    self.connection.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (1, datetime.now(UTC).isoformat()),
                    )
            self._validate_schema()
        except StorageError:
            raise
        except (OSError, UnicodeError, sqlite3.Error) as exc:
            raise StorageError("Castles database migration failed") from exc

    def schema(self) -> int:
        try:
            row = self.connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        except sqlite3.Error as exc:
            raise StorageError("Castles database schema could not be read") from exc
        version = int(row[0] or 0)
        if version == SCHEMA_VERSION:
            self._validate_schema()
        return version

    def integrity(self) -> bool:
        try:
            row = self.connection.execute("PRAGMA integrity_check").fetchone()
            return bool(row and row[0] == "ok")
        except sqlite3.Error as exc:
            raise CorruptionError("Castles database integrity check failed") from exc

    def account(self, mailbox: Mailbox) -> int:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO accounts(provider, account_id, address) VALUES (?, ?, ?) ON CONFLICT(provider, account_id) DO UPDATE SET address=excluded.address",
                    (mailbox.provider, mailbox.account_id, mailbox.address),
                )
                row = self.connection.execute(
                    "SELECT id FROM accounts WHERE provider=? AND account_id=?",
                    (mailbox.provider, mailbox.account_id),
                ).fetchone()
            if row is None:
                raise StorageError("Castles account could not be stored")
            return int(row[0])
        except sqlite3.Error as exc:
            raise StorageError("Castles account could not be stored") from exc

    def accounts(self) -> tuple[tuple[int, str, str], ...]:
        try:
            rows = self.connection.execute(
                "SELECT id, provider, address FROM accounts ORDER BY provider, address"
            ).fetchall()
            return tuple((int(row[0]), str(row[1]), str(row[2])) for row in rows)
        except sqlite3.Error as exc:
            raise StorageError("Castles accounts could not be read") from exc

    def checkpoint(self, account: int) -> Checkpoint | None:
        try:
            row = self.connection.execute(
                "SELECT provider, kind, value, successful_at FROM checkpoints WHERE account_id=?",
                (account,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("Castles checkpoint could not be read") from exc
        if row is None:
            return None
        try:
            timestamp = datetime.fromisoformat(row[3])
            if timestamp.tzinfo is None:
                raise ValueError
            return Checkpoint(str(row[0]), str(row[1]), str(row[2]), timestamp)
        except (TypeError, ValueError):
            raise CorruptionError("stored checkpoint is malformed") from None

    def begin(
        self, scan_id: str, account: int, mode: ScanMode, generation: str, started: datetime
    ) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO scans(scan_id, account_id, mode, status, generation, started_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        account,
                        mode.value,
                        ScanStatus.RUNNING.value,
                        generation,
                        started.isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError("Castles scan could not start") from exc

    def seen(self, account: int, message_key: str) -> bool:
        try:
            row = self.connection.execute(
                "SELECT 1 FROM messages WHERE account_id=? AND generation=? AND message_key=?",
                (account, ACTIVE, message_key),
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise StorageError("Castles message state could not be read") from exc

    def put(self, account: int, generation: str, message: MessageSignals) -> bool:
        payload, digest = encode_signals(message)
        try:
            with self.connection:
                row = self.connection.execute(
                    "SELECT fingerprint FROM messages WHERE account_id=? AND generation=? AND message_key=?",
                    (account, generation, message.message_key),
                ).fetchone()
                if row is not None:
                    if row[0] != digest:
                        raise CorruptionError("conflicting message signal payload already exists")
                    return False
                self.connection.execute(
                    "INSERT INTO messages(account_id, generation, message_key, observed_at, payload, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account,
                        generation,
                        message.message_key,
                        message.observed_at.astimezone(UTC).isoformat(),
                        payload,
                        digest,
                    ),
                )
            return True
        except CorruptionError:
            raise
        except sqlite3.Error as exc:
            raise StorageError("Castles message signals could not be stored") from exc

    def signals(self, account: int, generation: str = ACTIVE) -> tuple[MessageSignals, ...]:
        try:
            rows = self.connection.execute(
                "SELECT message_key, observed_at, payload, fingerprint FROM messages WHERE account_id=? AND generation=? ORDER BY observed_at, message_key",
                (account, generation),
            ).fetchall()
            return tuple(
                self._decode_signals(str(row[0]), str(row[1]), str(row[2]), str(row[3]))
                for row in rows
            )
        except sqlite3.Error as exc:
            raise StorageError("Castles message signals could not be read") from exc

    @staticmethod
    def _decode_signals(
        message_key: str, observed_at: str, payload: str, digest: str
    ) -> MessageSignals:
        value = decode_signals(message_key, payload, digest)
        try:
            stored = datetime.fromisoformat(observed_at)
        except ValueError:
            raise CorruptionError("stored message observation time is malformed") from None
        if stored.tzinfo is None or stored.utcoffset() is None or stored != value.observed_at:
            raise CorruptionError("stored message observation time does not match its payload")
        return value

    def findings(self, account: int) -> tuple[Finding, ...]:
        try:
            rows = self.connection.execute(
                "SELECT entity_key, payload, fingerprint FROM findings WHERE account_id=? AND generation=? ORDER BY entity_key",
                (account, ACTIVE),
            ).fetchall()
            return tuple(
                sorted(
                    (self._decode_finding(str(row[0]), str(row[1]), str(row[2])) for row in rows),
                    key=lambda item: item.sort_key,
                )
            )
        except sqlite3.Error as exc:
            raise StorageError("Castles findings could not be read") from exc

    @staticmethod
    def _decode_finding(entity: str, payload: str, digest: str) -> Finding:
        finding = decode_finding(payload, digest)
        if finding.entity != entity:
            raise CorruptionError("stored finding entity key does not match its payload")
        return finding

    def scan(self, account: int) -> ScanResult | None:
        try:
            row = self.connection.execute(
                "SELECT scan_id, mode, status, started_at, completed_at, discovered, processed, skipped FROM scans WHERE account_id=? AND status != 'running' ORDER BY started_at DESC, rowid DESC LIMIT 1",
                (account,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("Castles scan metadata could not be read") from exc
        if row is None:
            return None
        try:
            completed = datetime.fromisoformat(row[4])
            return ScanResult(
                str(row[0]),
                ScanMode(row[1]),
                ScanStatus(row[2]),
                datetime.fromisoformat(row[3]),
                completed,
                int(row[5]),
                int(row[6]),
                int(row[7]),
                len(self.findings(account)),
                False,
            )
        except (TypeError, ValueError):
            raise CorruptionError("stored scan metadata is malformed") from None

    def complete(
        self,
        account: int,
        result: ScanResult,
        generation: str,
        findings: tuple[Finding, ...],
        checkpoint: Checkpoint | None,
        promote: bool,
    ) -> None:
        try:
            with self.connection:
                if promote and (generation == ACTIVE or result.mode is not ScanMode.FULL):
                    raise CorruptionError("full scan promotion metadata is inconsistent")
                if result.status not in {ScanStatus.COMPLETE, ScanStatus.PARTIAL}:
                    raise CorruptionError("scan completion status is inconsistent")
                if checkpoint is not None:
                    provider = self.connection.execute(
                        "SELECT provider FROM accounts WHERE id=?", (account,)
                    ).fetchone()
                    if provider is None or str(provider[0]) != checkpoint.provider:
                        raise CorruptionError("checkpoint provider does not match its account")
                self.connection.execute(
                    "DELETE FROM findings WHERE account_id=? AND generation=?",
                    (account, generation),
                )
                for finding in findings:
                    payload, digest = encode_finding(finding)
                    self.connection.execute(
                        "INSERT INTO findings(account_id, generation, entity_key, payload, fingerprint) VALUES (?, ?, ?, ?, ?)",
                        (account, generation, finding.entity, payload, digest),
                    )
                if promote:
                    self.connection.execute(
                        "DELETE FROM messages WHERE account_id=? AND generation=?",
                        (account, ACTIVE),
                    )
                    self.connection.execute(
                        "DELETE FROM findings WHERE account_id=? AND generation=?",
                        (account, ACTIVE),
                    )
                    self.connection.execute(
                        "UPDATE messages SET generation=? WHERE account_id=? AND generation=?",
                        (ACTIVE, account, generation),
                    )
                    self.connection.execute(
                        "UPDATE findings SET generation=? WHERE account_id=? AND generation=?",
                        (ACTIVE, account, generation),
                    )
                if checkpoint is not None:
                    self.connection.execute(
                        "INSERT INTO checkpoints(account_id, provider, kind, value, successful_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET provider=excluded.provider, kind=excluded.kind, value=excluded.value, successful_at=excluded.successful_at",
                        (
                            account,
                            checkpoint.provider,
                            checkpoint.kind,
                            checkpoint.value,
                            checkpoint.successful_at.isoformat(),
                        ),
                    )
                updated = self.connection.execute(
                    "UPDATE scans SET status=?, completed_at=?, discovered=?, processed=?, skipped=? WHERE scan_id=? AND account_id=? AND generation=? AND status=?",
                    (
                        result.status.value,
                        result.completed_at.isoformat(),
                        result.discovered,
                        result.processed,
                        result.skipped,
                        result.scan_id,
                        account,
                        generation,
                        ScanStatus.RUNNING.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise CorruptionError("scan completion does not match a running scan")
        except CorruptionError:
            raise
        except sqlite3.Error as exc:
            raise StorageError("Castles scan completion could not be committed") from exc

    def discard(self, account: int, result: ScanResult, generation: str) -> None:
        try:
            with self.connection:
                if (
                    generation == ACTIVE
                    or result.mode is not ScanMode.FULL
                    or result.status is not ScanStatus.PARTIAL
                ):
                    raise CorruptionError("full scan discard metadata is inconsistent")
                self.connection.execute(
                    "DELETE FROM messages WHERE account_id=? AND generation=?",
                    (account, generation),
                )
                self.connection.execute(
                    "DELETE FROM findings WHERE account_id=? AND generation=?",
                    (account, generation),
                )
                updated = self.connection.execute(
                    "UPDATE scans SET status=?, completed_at=?, discovered=?, processed=?, skipped=? WHERE scan_id=? AND account_id=? AND generation=? AND status=?",
                    (
                        result.status.value,
                        result.completed_at.isoformat(),
                        result.discovered,
                        result.processed,
                        result.skipped,
                        result.scan_id,
                        account,
                        generation,
                        ScanStatus.RUNNING.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise CorruptionError("scan discard does not match a running scan")
        except CorruptionError:
            raise
        except sqlite3.Error as exc:
            raise StorageError("Castles full scan stage could not be discarded") from exc

    def fail(self, scan_id: str, account: int, generation: str, completed: datetime) -> None:
        try:
            with self.connection:
                if generation != ACTIVE:
                    self.connection.execute(
                        "DELETE FROM messages WHERE account_id=? AND generation=?",
                        (account, generation),
                    )
                    self.connection.execute(
                        "DELETE FROM findings WHERE account_id=? AND generation=?",
                        (account, generation),
                    )
                updated = self.connection.execute(
                    "UPDATE scans SET status=?, completed_at=? WHERE scan_id=? AND account_id=? AND generation=? AND status=?",
                    (
                        ScanStatus.FAILED.value,
                        completed.isoformat(),
                        scan_id,
                        account,
                        generation,
                        ScanStatus.RUNNING.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise CorruptionError("scan failure does not match a running scan")
        except CorruptionError:
            raise
        except sqlite3.Error as exc:
            raise StorageError("Castles failed scan could not be recorded") from exc
