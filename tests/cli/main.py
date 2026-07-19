from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from castles import __version__, wiring
from castles.app.doctor import Check, Health
from castles.cli.main import app
from castles.config.path import Paths
from castles.config.setting import TokenStore
from castles.core.error import ConfigurationError
from castles.core.message import Mailbox, NormalizedMessage
from castles.core.scan import ScanMode, ScanResult, ScanStatus
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.store.port import Checkpoint
from castles.store.sqlite import ACTIVE, SQLite

NOW = datetime(2026, 7, 14, tzinfo=UTC)
runner = CliRunner()


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Paths:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("WIN_PD_OVERRIDE_APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("WIN_PD_OVERRIDE_LOCAL_APPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    return Paths.system()


def seed(paths: Paths) -> None:
    paths.prepare()
    store = SQLite(paths.database)
    store.migrate()
    account = store.account(Mailbox("gmail", "person@example.com", "person@example.com"))
    signals = extract(
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
    )
    store.begin("scan", account, ScanMode.INITIAL, ACTIVE, NOW)
    store.put(account, ACTIVE, signals)
    findings = discover((signals,))
    result = ScanResult("scan", ScanMode.INITIAL, ScanStatus.COMPLETE, NOW, NOW, 1, 1, 0, 1)
    store.complete(
        account, result, ACTIVE, findings, Checkpoint("gmail", "history", "42", NOW), False
    )
    store.close()


def test_help_and_version() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("setup", "scan", "results", "show", "export", "doctor", "logout"):
        assert command in result.stdout
    assert runner.invoke(app, ["--version"]).stdout.startswith(f"Castles {__version__}")


def test_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "client.json"
    source.write_text("{}")
    usecase = SimpleNamespace(
        execute=lambda path, force, no_browser: Mailbox(
            "gmail", "person@example.com", "person@example.com"
        )
    )
    monkeypatch.setattr(wiring, "setup_usecase", lambda: usecase)
    result = runner.invoke(app, ["setup", str(source), "--force", "--no-browser"])
    assert result.exit_code == 0
    assert "read-only" in result.stdout
    assert "castles scan" in result.stdout
    assert "person@example.com" not in result.stdout


def test_setup_requires_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring, "find_client", lambda: None)
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 1
    assert "desktop OAuth client" in result.stderr


def test_scan_output_and_since_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    value = ScanResult(
        "scan", ScanMode.INCREMENTAL, ScanStatus.COMPLETE, NOW, NOW, 2, 1, 1, 1, True
    )
    monkeypatch.setattr(wiring, "scan", lambda request: value)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "2 discovered, 1 processed, 1 skipped" in result.stdout
    assert "checkpoint was stale" in result.stdout
    invalid = runner.invoke(app, ["scan", "--since", "2026-01-01"])
    assert invalid.exit_code == 1
    assert "timezone" in invalid.stderr


def test_results_show_and_narrow_terminal(isolated: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(isolated)
    monkeypatch.setenv("COLUMNS", "40")
    result = runner.invoke(app, ["results"])
    assert result.exit_code == 0
    assert "github.com" in result.stdout
    assert "billing" in result.stdout
    assert "person@example.com" not in result.stdout
    shown = runner.invoke(app, ["show", "GITHUB.COM."])
    assert shown.exit_code == 0
    assert "Identity evidence" in shown.stdout
    missing = runner.invoke(app, ["show", "missing.example"])
    assert missing.exit_code == 1


def test_results_are_offline(isolated: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(isolated)

    def blocked(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise AssertionError("network attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    assert runner.invoke(app, ["results"]).exit_code == 0
    assert runner.invoke(app, ["show", "github.com"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            ["export", "--output", str(isolated.state / "offline.json")],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["doctor"]).exit_code == 0


@pytest.mark.parametrize("format", ["json", "csv"])
def test_export(isolated: Paths, tmp_path: Path, format: str) -> None:
    seed(isolated)
    destination = tmp_path / f"out.{format}"
    result = runner.invoke(app, ["export", "--format", format, "--output", str(destination)])
    assert result.exit_code == 0
    assert destination.is_file()
    if format == "json":
        assert json.loads(destination.read_text())["schema_version"] == 1
    else:
        assert destination.read_text().startswith("entity,identity_score")


def test_export_rejects_format() -> None:
    result = runner.invoke(app, ["export", "--format", "xml"])
    assert result.exit_code == 1
    assert "json or csv" in result.stderr


def test_doctor_offline_does_not_construct_gmail(
    isolated: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Forbidden:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("Gmail constructed")

    monkeypatch.setattr(wiring, "Gmail", Forbidden)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Public Suffix List" in result.stdout
    assert not isolated.state.exists()


def test_doctor_failure_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring, "doctor", lambda provider: (Check("bad", Health.FAIL, "failed"),))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "failed" in result.stdout


def test_logout_only_removes_token(isolated: Paths) -> None:
    isolated.prepare()
    TokenStore(isolated.token).save("private")
    isolated.database.write_bytes(b"database")
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert not isolated.token.exists()
    assert isolated.database.read_bytes() == b"database"


def test_sanitized_expected_and_unexpected_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        wiring, "local_results", lambda: (_ for _ in ()).throw(ConfigurationError("safe failure"))
    )
    expected = runner.invoke(app, ["results"])
    assert expected.exit_code == 1
    assert "safe failure" in expected.stderr
    monkeypatch.setattr(
        wiring, "local_results", lambda: (_ for _ in ()).throw(RuntimeError("secret detail"))
    )
    unexpected = runner.invoke(app, ["results"])
    assert unexpected.exit_code == 1
    assert "unexpected failure" in unexpected.stderr
    assert "secret detail" not in unexpected.output
