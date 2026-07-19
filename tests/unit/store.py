from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from castles.core.error import CorruptionError, StorageError
from castles.core.message import Mailbox, NormalizedMessage
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.core.signal import MessageSignals, SignalKind
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.store.codec import (
    MAX_PAYLOAD_BYTES,
    decode_finding,
    decode_signals,
    encode_finding,
    encode_signals,
    fingerprint,
)
from castles.store.port import Checkpoint
from castles.store.sqlite import ACTIVE, SQLite

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def signals(key: str, domain: str = "github.com") -> MessageSignals:
    return extract(
        NormalizedMessage(key, NOW, domain, None, None, (), "Invoice available", "", (), ())
    )


def result(
    scan_id: str, mode: ScanMode = ScanMode.INITIAL, status: ScanStatus = ScanStatus.COMPLETE
) -> ScanResult:
    return ScanResult(scan_id, mode, status, NOW, NOW, 1, 1, 0, 1)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[SQLite]:
    store = SQLite(tmp_path / "castles.db")
    store.migrate()
    yield store
    store.close()


def test_fresh_schema_and_atomic_idempotent_migration(database: SQLite) -> None:
    assert database.schema() == 1
    database.migrate()
    tables = {
        row[0]
        for row in database.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"accounts", "checkpoints", "scans", "messages", "findings"}.issubset(tables)


def test_newer_schema_is_rejected(database: SQLite) -> None:
    database.connection.execute("INSERT INTO schema_migrations VALUES (2, ?)", (NOW.isoformat(),))
    database.connection.commit()
    with pytest.raises(StorageError, match="newer"):
        database.migrate()


def test_incomplete_schema_and_modified_migration_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incomplete = SQLite(tmp_path / "incomplete.db")
    incomplete.connection.execute(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    incomplete.connection.execute("INSERT INTO schema_migrations VALUES (1, ?)", (NOW.isoformat(),))
    incomplete.connection.commit()
    with pytest.raises(StorageError, match="incomplete or modified"):
        incomplete.migrate()
    incomplete.close()

    monkeypatch.setattr("castles.store.sqlite.MIGRATION_SHA256", "0" * 64)
    modified = SQLite(tmp_path / "modified.db")
    with pytest.raises(StorageError, match="checksum"):
        modified.migrate()
    modified.close()


def test_account_isolation_and_upsert(database: SQLite) -> None:
    first = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    same = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    second = database.account(Mailbox("gmail", "two@example.com", "two@example.com"))
    assert first == same
    assert first != second
    database.put(first, ACTIVE, signals("same", "github.com"))
    database.put(second, ACTIVE, signals("same", "spotify.com"))
    first_signal = next(
        item for item in database.signals(first)[0].signals if item.kind is SignalKind.SENDER
    )
    second_signal = next(
        item for item in database.signals(second)[0].signals if item.kind is SignalKind.SENDER
    )
    assert first_signal.value == "github.com"
    assert second_signal.value == "spotify.com"


def test_canonical_payload_round_trip_and_strict_fields() -> None:
    value = signals("opaque")
    payload, digest = encode_signals(value)
    assert decode_signals("opaque", payload, digest) == value
    finding = discover((value,))[0]
    finding_payload, finding_digest = encode_finding(finding)
    assert decode_finding(finding_payload, finding_digest) == finding
    with pytest.raises(CorruptionError, match="fingerprint"):
        decode_signals("opaque", payload, "0" * 64)
    with pytest.raises(CorruptionError, match="unexpected fields"):
        decode_signals(
            "opaque",
            payload[:-1] + ',"extra":1}',
            __import__("hashlib").sha256((payload[:-1] + ',"extra":1}').encode()).hexdigest(),
        )

    offset = value.__class__(
        value.message_key,
        value.observed_at.astimezone(timezone(-timedelta(hours=3))),
        value.signals,
    )
    assert encode_signals(offset) == encode_signals(value)


def test_codec_rejects_noncanonical_json_and_nonstandard_numbers() -> None:
    finding_payload, _ = encode_finding(discover((signals("opaque"),))[0])
    duplicate = finding_payload[:-1] + ',"schema":1}'
    with pytest.raises(CorruptionError):
        decode_finding(duplicate, fingerprint(duplicate))

    document = json.loads(finding_payload)
    document["message_count"] = float("nan")
    nonstandard = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CorruptionError):
        decode_finding(nonstandard, fingerprint(nonstandard))

    spaced = finding_payload.replace(":", ": ", 1)
    with pytest.raises(CorruptionError):
        decode_finding(spaced, fingerprint(spaced))

    reordered = json.loads(finding_payload)
    reordered["explanations"] = [
        "resolution.domain_evidence",
        "resolution.domain_evidence",
    ]
    reordered_payload = json.dumps(reordered, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CorruptionError, match="canonical"):
        decode_finding(reordered_payload, fingerprint(reordered_payload))

    with pytest.raises(CorruptionError, match="safe limit"):
        decode_finding("x" * (MAX_PAYLOAD_BYTES + 1), "0" * 64)


def test_signal_list_order_is_strictly_canonical() -> None:
    value = extract(
        NormalizedMessage(
            "opaque",
            NOW,
            "example.com",
            "reply.example",
            None,
            (),
            "",
            "",
            (),
            (),
        )
    )
    payload, _ = encode_signals(value)
    document = json.loads(payload)
    document["signals"].reverse()
    reordered = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CorruptionError, match="canonical"):
        decode_signals("opaque", reordered, fingerprint(reordered))


@pytest.mark.parametrize(
    "change",
    [
        {"schema": 2},
        {"policy": 3},
        {"policy": "extract-v2"},
        {"observed_at": 3},
        {"observed_at": "not-a-time"},
        {"observed_at": "2026-01-01T00:00:00"},
        {"signals": {}},
        {
            "signals": [
                {"kind": "unknown", "source": "url", "value": "x", "strength": "weak", "code": "x"}
            ]
        },
        {"signals": [{"kind": "link"}]},
    ],
)
def test_signal_codec_rejects_corruption(change: dict[str, object]) -> None:
    payload, _ = encode_signals(signals("opaque"))
    document = json.loads(payload)
    document.update(change)
    corrupted = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CorruptionError):
        decode_signals("opaque", corrupted, fingerprint(corrupted))
    with pytest.raises(CorruptionError):
        decode_signals("opaque", "not json", fingerprint("not json"))


@pytest.mark.parametrize(
    "change",
    [
        {"schema": 2},
        {"policy": "report-v2"},
        {"relationships": {}},
        {"explanations": [3]},
        {"identity": {}},
        {"first_seen": "not-a-time"},
        {"message_count": 0},
        {"relationships": [{"kind": "unknown", "confidence": {}}]},
        {"relationships": [{"kind": "billing"}]},
    ],
)
def test_finding_codec_rejects_corruption(change: dict[str, object]) -> None:
    payload, _ = encode_finding(discover((signals("opaque"),))[0])
    document = json.loads(payload)
    document.update(change)
    corrupted = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CorruptionError):
        decode_finding(corrupted, fingerprint(corrupted))


def test_duplicate_idempotency_and_conflict(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    assert database.put(account, ACTIVE, signals("same", "github.com"))
    assert not database.put(account, ACTIVE, signals("same", "github.com"))
    with pytest.raises(CorruptionError, match="conflicting"):
        database.put(account, ACTIVE, signals("same", "spotify.com"))


def test_checkpoint_and_scan_round_trip(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    value = signals("one")
    finding = discover((value,))
    database.begin("scan", account, ScanMode.INITIAL, ACTIVE, NOW)
    database.put(account, ACTIVE, value)
    checkpoint = Checkpoint("gmail", "gmail_history", "42", NOW)
    database.complete(account, result("scan"), ACTIVE, finding, checkpoint, False)
    assert database.checkpoint(account) == checkpoint
    assert database.findings(account) == finding
    assert database.scan(account) is not None
    assert database.scan(account).status is ScanStatus.COMPLETE  # type: ignore[union-attr]


def test_full_stage_promotion(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    old = signals("old", "github.com")
    database.put(account, ACTIVE, old)
    database.begin("full", account, ScanMode.FULL, "full", NOW)
    new = signals("new", "spotify.com")
    database.put(account, "full", new)
    findings = discover((new,))
    database.complete(account, result("full", ScanMode.FULL), "full", findings, None, True)
    assert database.signals(account) == (new,)
    assert database.findings(account) == findings
    assert (
        database.connection.execute(
            "SELECT COUNT(*) FROM messages WHERE generation='full'"
        ).fetchone()[0]
        == 0
    )


def test_scan_completion_is_bound_to_account_and_generation(database: SQLite) -> None:
    first = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    second = database.account(Mailbox("gmail", "two@example.com", "two@example.com"))
    database.begin("first-scan", first, ScanMode.FULL, "first-stage", NOW)
    database.begin("second-scan", second, ScanMode.FULL, "second-stage", NOW)
    database.put(first, "first-stage", signals("first", "github.com"))
    before = database.signals(first, "first-stage")

    mismatched = result("second-scan", ScanMode.FULL)
    with pytest.raises(CorruptionError, match="running scan"):
        database.complete(
            first,
            mismatched,
            "first-stage",
            discover(before),
            None,
            True,
        )

    assert database.signals(first, "first-stage") == before
    assert (
        database.connection.execute(
            "SELECT status FROM scans WHERE scan_id='second-scan'"
        ).fetchone()[0]
        == ScanStatus.RUNNING.value
    )

    partial = result("second-scan", ScanMode.FULL, ScanStatus.PARTIAL)
    with pytest.raises(CorruptionError, match="running scan"):
        database.discard(first, partial, "first-stage")
    with pytest.raises(CorruptionError, match="running scan"):
        database.fail("second-scan", first, "first-stage", NOW)
    assert database.signals(first, "first-stage") == before


def test_promotion_and_checkpoint_metadata_are_validated(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    database.begin("scan", account, ScanMode.INITIAL, ACTIVE, NOW)
    value = signals("one")
    with pytest.raises(CorruptionError, match="promotion"):
        database.complete(account, result("scan"), ACTIVE, discover((value,)), None, True)
    with pytest.raises(CorruptionError, match="checkpoint provider"):
        database.complete(
            account,
            result("scan"),
            ACTIVE,
            discover((value,)),
            Checkpoint("other", "cursor", "1", NOW),
            False,
        )


def test_partial_discard_and_failure_preserve_active(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    old = signals("old")
    database.put(account, ACTIVE, old)
    for scan_id, action in (("partial", "discard"), ("failed", "fail")):
        database.begin(scan_id, account, ScanMode.FULL, scan_id, NOW)
        database.put(account, scan_id, signals(scan_id, "spotify.com"))
        if action == "discard":
            database.discard(account, result(scan_id, ScanMode.FULL, ScanStatus.PARTIAL), scan_id)
        else:
            database.fail(scan_id, account, scan_id, NOW)
        assert database.signals(account) == (old,)
        assert (
            database.connection.execute(
                "SELECT COUNT(*) FROM messages WHERE generation=?", (scan_id,)
            ).fetchone()[0]
            == 0
        )


def test_failed_stage_cleanup_is_account_scoped(database: SQLite) -> None:
    first = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    second = database.account(Mailbox("gmail", "two@example.com", "two@example.com"))
    generation = "shared-generation"
    database.begin("first-scan", first, ScanMode.FULL, generation, NOW)
    database.put(first, generation, signals("first", "github.com"))
    database.put(second, generation, signals("second", "spotify.com"))

    database.fail("first-scan", first, generation, NOW)

    assert database.signals(first, generation) == ()
    assert database.signals(second, generation) == (signals("second", "spotify.com"),)


def test_corruption_detection(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    database.put(account, ACTIVE, signals("one"))
    database.connection.execute("UPDATE messages SET payload='{}'")
    database.connection.commit()
    with pytest.raises(CorruptionError, match="fingerprint"):
        database.signals(account)
    database.connection.execute("DELETE FROM messages")
    database.connection.commit()

    payload, digest = encode_signals(signals("two"))
    database.connection.execute(
        "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?)",
        (account, ACTIVE, "two", NOW.isoformat(), payload, digest),
    )
    database.connection.execute(
        "UPDATE messages SET observed_at=? WHERE message_key='two'",
        ((NOW + timedelta(days=1)).isoformat(),),
    )
    database.connection.commit()
    with pytest.raises(CorruptionError, match="observation time"):
        database.signals(account)


def test_finding_index_must_match_payload(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    value = signals("one")
    database.begin("scan", account, ScanMode.INITIAL, ACTIVE, NOW)
    database.complete(account, result("scan"), ACTIVE, discover((value,)), None, False)
    database.connection.execute("UPDATE findings SET entity_key='other.example'")
    database.connection.commit()
    with pytest.raises(CorruptionError, match="entity key"):
        database.findings(account)


def test_read_only_access_and_integrity(tmp_path: Path) -> None:
    path = tmp_path / "castles.db"
    writer = SQLite(path)
    writer.migrate()
    account = writer.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    writer.put(account, ACTIVE, signals("one"))
    writer.close()
    reader = SQLite(path, readonly=True)
    assert reader.integrity()
    assert reader.signals(account)
    with pytest.raises(sqlite3.OperationalError):
        reader.connection.execute("DELETE FROM messages")
    reader.close()


def test_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    writer = SQLite(target)
    writer.migrate()
    writer.close()
    linked = tmp_path / "linked.db"
    linked.symlink_to(target)
    with pytest.raises(StorageError, match="regular file"):
        SQLite(linked, readonly=True)


def test_database_contains_no_raw_content(database: SQLite) -> None:
    account = database.account(Mailbox("gmail", "one@example.com", "one@example.com"))
    database.put(account, ACTIVE, signals("opaque"))
    payload = database.connection.execute("SELECT payload FROM messages").fetchone()[0]
    for private in ("Invoice available", "raw body", "https://github.com/private?q=secret"):
        assert private not in payload
