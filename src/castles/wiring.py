from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from castles.app.doctor import Check, Health
from castles.app.export import csv_export, json_export, write
from castles.app.port import SetupTerminal
from castles.app.results import ResultSet, results
from castles.app.scan import Scan, ScanRequest
from castles.app.setup import DesktopClient, Setup
from castles.config.path import Paths, private
from castles.config.setting import (
    TokenStore,
    discover_clients,
    import_client,
    validate_client,
)
from castles.core.error import ConfigurationError, StorageError
from castles.core.message import Mailbox
from castles.core.scan import ScanResult
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.detect.infra import CATALOG_ID, Infrastructure
from castles.detect.suffix import SNAPSHOT_ID, Suffixes
from castles.parse.mime import parse
from castles.provider.gmail.auth import authorize, load
from castles.provider.gmail.client import Gmail
from castles.store.lock import FileLocks
from castles.store.sqlite import SQLite


def _paths() -> Paths:
    return Paths.system()


def setup_usecase(terminal: SetupTerminal) -> Setup:
    paths = _paths()
    store = TokenStore(paths.token)

    def configure(client: DesktopClient) -> None:
        paths.prepare()
        import_client(paths.client, client)

    def authentication(force: bool, no_browser: bool) -> Mailbox:
        credentials = authorize(paths.client, store, force=force, no_browser=no_browser)
        return Gmail(credentials).identity()

    return Setup(
        paths.client,
        validate_client,
        configure,
        lambda: discover_clients(Path.home()),
        authentication,
        terminal,
    )


def scan(request: ScanRequest) -> ScanResult:
    paths = _paths()
    paths.prepare()
    database = SQLite(paths.database)
    try:
        database.migrate()
        provider = Gmail(load(TokenStore(paths.token)))
        return Scan(
            provider,
            database,
            parse,
            extract,
            discover,
            FileLocks(paths.state),
        ).execute(request)
    finally:
        database.close()


def local_results() -> tuple[ResultSet, ...]:
    path = _paths().database
    if not path.is_file():
        return ()
    database = SQLite(path, readonly=True)
    try:
        if database.schema() != 1:
            raise StorageError("Castles database schema is unsupported")
        return results(database)
    finally:
        database.close()


def export(path: Path, format: str) -> None:
    values = local_results()
    content = json_export(values, datetime.now(UTC)) if format == "json" else csv_export(values)
    write(path, content)


def logout() -> bool:
    return TokenStore(_paths().token).remove()


def doctor(*, provider: bool = False) -> tuple[Check, ...]:
    paths = _paths()
    checks: list[Check] = []
    for name, path in (("configuration directory", paths.config), ("state directory", paths.state)):
        if not path.exists():
            checks.append(Check(name, Health.WARN, "not created yet"))
        elif private(path):
            checks.append(Check(name, Health.OK, "private local permissions"))
        else:
            checks.append(Check(name, Health.FAIL, "permissions allow access by other local users"))
    if paths.client.is_file():
        try:
            validate_client(paths.client)
            checks.append(Check("OAuth client", Health.OK, "desktop client configuration is valid"))
        except ConfigurationError as exc:
            checks.append(Check("OAuth client", Health.FAIL, str(exc)))
    else:
        checks.append(Check("OAuth client", Health.WARN, "not configured"))
    if not paths.token.exists() and not paths.token.is_symlink():
        checks.append(Check("Gmail authorization", Health.WARN, "not authorized"))
    elif private(paths.token):
        checks.append(Check("Gmail authorization", Health.OK, "saved in a private regular file"))
    else:
        checks.append(Check("Gmail authorization", Health.FAIL, "authorization file is unsafe"))
    if paths.database.is_file():
        database: SQLite | None = None
        try:
            database = SQLite(paths.database, readonly=True)
            schema = database.schema()
            integrity = database.integrity()
            checks.append(
                Check(
                    "database schema",
                    Health.OK if schema == 1 else Health.FAIL,
                    f"schema {schema}",
                )
            )
            checks.append(
                Check(
                    "SQLite integrity",
                    Health.OK if integrity else Health.FAIL,
                    "ok" if integrity else "integrity failure",
                )
            )
            checks.append(
                Check(
                    "database permissions",
                    Health.OK if private(paths.database) else Health.FAIL,
                    "private regular file"
                    if private(paths.database)
                    else "database file is unsafe",
                )
            )
        except StorageError as exc:
            checks.append(Check("database", Health.FAIL, str(exc)))
        finally:
            if database is not None:
                database.close()
    elif paths.database.exists() or paths.database.is_symlink():
        checks.append(Check("database", Health.FAIL, "database path is unsafe"))
    else:
        checks.append(Check("database", Health.WARN, "not created yet"))
    try:
        Suffixes().boundary("example.com")
        checks.append(Check("Public Suffix List", Health.OK, SNAPSHOT_ID))
    except Exception:
        checks.append(Check("Public Suffix List", Health.FAIL, "packaged resource is invalid"))
    try:
        Infrastructure().classify("example.com")
        checks.append(Check("infrastructure catalog", Health.OK, CATALOG_ID))
    except Exception:
        checks.append(Check("infrastructure catalog", Health.FAIL, "packaged resource is invalid"))
    if provider:
        try:
            value = Gmail(load(TokenStore(paths.token))).validate()
            checks.append(
                Check("Gmail provider", Health.OK if value.available else Health.FAIL, value.detail)
            )
        except Exception:
            checks.append(Check("Gmail provider", Health.FAIL, "provider validation failed"))
    return tuple(checks)
