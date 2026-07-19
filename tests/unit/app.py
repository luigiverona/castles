from __future__ import annotations

import csv
import io
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from castles.app.doctor import Check, Health, healthy
from castles.app.export import CSV_COLUMNS, csv_export, json_export, write
from castles.app.results import ResultSet
from castles.app.show import show
from castles.core.message import NormalizedMessage
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.detect.build import discover
from castles.detect.extract import extract

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def values() -> tuple[ResultSet, ...]:
    finding = discover(
        (
            extract(
                NormalizedMessage(
                    "opaque",
                    NOW,
                    "github.com",
                    None,
                    None,
                    ("github.com",),
                    "Invoice available",
                    "",
                    (),
                    (),
                )
            ),
        )
    )
    scan = ScanResult("scan", ScanMode.INITIAL, ScanStatus.COMPLETE, NOW, NOW, 1, 1, 0, 1)
    return (ResultSet("gmail", "person@example.com", scan, finding),)


def test_json_export_schema_and_privacy() -> None:
    document = json.loads(json_export(values(), NOW))
    assert document["schema_version"] == 1
    assert document["generated_at"] == NOW.isoformat()
    assert document["mailboxes"][0]["provider"] == "gmail"
    assert document["mailboxes"][0]["findings"][0]["entity"] == "github.com"
    rendered = json.dumps(document)
    assert "person@example.com" not in rendered
    assert "opaque" not in rendered
    assert "scan_id" not in rendered


def test_csv_fixed_contract() -> None:
    content = csv_export(values())
    rows = list(csv.DictReader(io.StringIO(content)))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert rows[0]["entity"] == "github.com"
    assert rows[0]["relationships"].startswith("billing:26:low")


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_neutralizes_formulas_in_explanations(prefix: str) -> None:
    result = values()[0]
    finding = replace(result.findings[0], explanations=(prefix + "formula",))
    content = csv_export((replace(result, findings=(finding,)),))
    row = next(csv.DictReader(io.StringIO(content)))
    assert row["explanations"] == "'" + prefix + "formula"


def test_atomic_export_write(tmp_path: Path) -> None:
    destination = tmp_path / "out.json"
    write(destination, "private\n")
    assert destination.read_text() == "private\n"
    assert not destination.with_suffix(".json.tmp").exists()


def test_export_does_not_follow_predictable_temporary_symlink(tmp_path: Path) -> None:
    destination = tmp_path / "out.json"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    destination.with_suffix(".json.tmp").symlink_to(victim)

    write(destination, "private\n")

    assert destination.read_text() == "private\n"
    assert victim.read_text() == "unchanged"


def test_show_and_health() -> None:
    assert show(values(), "GITHUB.COM.")[0].entity == "github.com"
    assert show(values(), "missing.example") == ()
    assert healthy((Check("one", Health.OK, "ok"), Check("two", Health.WARN, "missing")))
    assert not healthy((Check("one", Health.FAIL, "bad"),))
