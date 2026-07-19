from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from castles.app.setup import GUIDE_URL, ClientCandidate, ClientDiscovery, DesktopClient
from castles.core.error import (
    ClientEndpointError,
    ClientFileNotFoundError,
    ClientMalformedError,
    ClientOversizedError,
    ClientPersistenceError,
    ClientRedirectError,
    ClientTypeError,
    ClientUnreadableError,
    ConfigurationError,
)

MAX_CLIENT_BYTES = 128 * 1024
MAX_TOKEN_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 128
MAX_JSON_STRING = 8192
MAX_DIRECTORY_ENTRIES = 1000
MAX_CLIENT_CANDIDATES = 25
GOOGLE_AUTH_URIS = {
    "https://accounts.google.com/o/oauth2/auth",
    "https://accounts.google.com/o/oauth2/v2/auth",
}
GOOGLE_EXCHANGE_URI = "https://oauth2.googleapis.com/token"
CLIENT_ID = re.compile(r"[A-Za-z0-9._-]{6,200}\.apps\.googleusercontent\.com")


class _StructureError(ValueError):
    pass


def _directory(path: Path, message: str) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ConfigurationError(message) from None
    if not stat.S_ISDIR(current.st_mode):
        raise ConfigurationError(message)
    return True


def _read_regular(path: Path, limit: int, message: str) -> str:
    descriptor = -1
    try:
        if not _directory(path.parent, message):
            raise OSError
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size > limit
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise OSError
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            value = stream.read(limit + 1)
        if len(value.encode("utf-8")) > limit:
            raise OSError
        return value
    except (OSError, UnicodeError):
        raise ConfigurationError(message) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_client(path: Path) -> str:
    descriptor = -1
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise ClientFileNotFoundError(
            f"Google Desktop OAuth client file was not found.\n\nGuide:\n{GUIDE_URL}"
        ) from None
    except OSError:
        raise ClientUnreadableError(
            f"Google Desktop OAuth client file could not be inspected safely.\n\nGuide:\n{GUIDE_URL}"
        ) from None
    if not stat.S_ISREG(before.st_mode):
        raise ClientUnreadableError(
            f"Google Desktop OAuth client must be a regular, non-symlink file.\n\nGuide:\n{GUIDE_URL}"
        )
    if before.st_size > MAX_CLIENT_BYTES:
        raise ClientOversizedError(
            f"Google Desktop OAuth client file is too large.\n\nGuide:\n{GUIDE_URL}"
        )
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size > MAX_CLIENT_BYTES
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise OSError
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            content = stream.read(MAX_CLIENT_BYTES + 1)
        if len(content.encode("utf-8")) > MAX_CLIENT_BYTES:
            raise ClientOversizedError(
                f"Google Desktop OAuth client file is too large.\n\nGuide:\n{GUIDE_URL}"
            )
        return content
    except ClientOversizedError:
        raise
    except (OSError, UnicodeError):
        raise ClientUnreadableError(
            f"Google Desktop OAuth client file could not be read safely.\n\nGuide:\n{GUIDE_URL}"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    if len(values) > MAX_JSON_NODES:
        raise _StructureError
    result: dict[str, object] = {}
    for key, value in values:
        if key in result or len(key) > MAX_JSON_STRING:
            raise _StructureError
        result[key] = value
    return result


def _bounded(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        raise _StructureError
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING:
            raise _StructureError
    elif isinstance(value, dict):
        for key, child in value.items():
            _bounded(key, depth=depth + 1, count=count)
            _bounded(child, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for child in value:
            _bounded(child, depth=depth + 1, count=count)


def _redirect(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and (port is None or 1 <= port <= 65535)
    )


def validate_client(path: Path) -> DesktopClient:
    content = _read_client(path)
    try:
        document = json.loads(content, object_pairs_hook=_pairs)
        _bounded(document)
    except (json.JSONDecodeError, UnicodeError, _StructureError, RecursionError):
        raise ClientMalformedError(
            f"The supplied file is not valid bounded JSON.\n\nGuide:\n{GUIDE_URL}"
        ) from None
    wrong_category = {"web", "type", "api_key", "token", "access_token", "refresh_token"}
    if (
        not isinstance(document, dict)
        or wrong_category.intersection(document)
        or not isinstance(document.get("installed"), dict)
    ):
        raise ClientTypeError(
            "The supplied file is not a Google Desktop OAuth client.\n\n"
            "Create an OAuth client whose application type is Desktop app, download its JSON "
            f"file, and retry.\n\nGuide:\n{GUIDE_URL}"
        )
    installed = cast(dict[str, object], document["installed"])
    client_id = installed.get("client_id")
    client_secret = installed.get("client_secret")
    auth_uri = installed.get("auth_uri")
    token_uri = installed.get("token_uri")
    redirect_uris = installed.get("redirect_uris")
    if (
        not isinstance(client_id, str)
        or CLIENT_ID.fullmatch(client_id) is None
        or not isinstance(client_secret, str)
        or not 1 <= len(client_secret) <= 512
    ):
        raise ClientTypeError(
            "The supplied file is not a Google Desktop OAuth client.\n\n"
            "Create an OAuth client whose application type is Desktop app, download its JSON "
            f"file, and retry.\n\nGuide:\n{GUIDE_URL}"
        )
    if (
        not isinstance(auth_uri, str)
        or auth_uri not in GOOGLE_AUTH_URIS
        or not isinstance(token_uri, str)
        or token_uri != GOOGLE_EXCHANGE_URI
    ):
        raise ClientEndpointError(
            f"The Google Desktop OAuth client contains unsupported authorization endpoints.\n\nGuide:\n{GUIDE_URL}"
        )
    if (
        not isinstance(redirect_uris, list)
        or not 1 <= len(redirect_uris) <= 8
        or any(not isinstance(uri, str) or not _redirect(uri) for uri in redirect_uris)
    ):
        raise ClientRedirectError(
            "The Google Desktop OAuth client does not support the local loopback redirect used "
            f"by Castles.\n\nGuide:\n{GUIDE_URL}"
        )
    return DesktopClient(
        client_id,
        client_secret,
        auth_uri,
        token_uri,
        tuple(cast(list[str], redirect_uris)),
    )


def _client_document(client: DesktopClient) -> dict[str, object]:
    return {
        "installed": {
            "auth_uri": client.auth_uri,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uris": list(client.redirect_uris),
            "token_uri": client.token_uri,
        }
    }


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _directory(path.parent, "private Castles configuration directory is unsafe")
    if os.name == "posix":
        try:
            path.parent.chmod(0o700)
        except OSError:
            raise ConfigurationError(
                "private Castles directory permissions could not be set"
            ) from None
    try:
        current = path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise ConfigurationError("private Castles configuration could not be inspected") from None
    else:
        if not stat.S_ISREG(current.st_mode):
            raise ConfigurationError("private Castles configuration is not a regular file")

    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise ConfigurationError("could not write private Castles configuration") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def import_client(path: Path, client: DesktopClient) -> None:
    content = json.dumps(_client_document(client), ensure_ascii=False, sort_keys=True) + "\n"
    if len(content.encode()) > MAX_CLIENT_BYTES:
        raise ClientPersistenceError("Google Desktop OAuth client could not be stored safely")
    try:
        write_private(path, content)
    except ConfigurationError:
        raise ClientPersistenceError(
            "Google Desktop OAuth client could not be stored safely; any previous managed client "
            "was preserved"
        ) from None


def _candidate_label(path: Path, modified: float) -> str:
    name = "client_secret_….json" if path.name.startswith("client_secret_") else path.name
    timestamp = datetime.fromtimestamp(modified).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    return f"~/Downloads/{name} (modified {timestamp})"


def discover_clients(home: Path) -> ClientDiscovery:
    downloads = home / "Downloads"
    try:
        current = downloads.lstat()
    except (FileNotFoundError, OSError):
        return ClientDiscovery(False, ())
    if not stat.S_ISDIR(current.st_mode):
        return ClientDiscovery(False, ())

    paths: list[tuple[Path, float]] = []
    bounded = False
    try:
        for entry_count, path in enumerate(downloads.iterdir(), start=1):
            if entry_count > MAX_DIRECTORY_ENTRIES:
                bounded = True
                break
            if path.suffix.casefold() != ".json" or not (
                path.name.startswith("client_secret_") or path.name == "credentials.json"
            ):
                continue
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            paths.append((path, metadata.st_mtime))
    except OSError:
        return ClientDiscovery(False, ())

    paths.sort(key=lambda value: value[0].name.casefold())
    if len(paths) > MAX_CLIENT_CANDIDATES:
        paths = paths[:MAX_CLIENT_CANDIDATES]
        bounded = True
    candidates: list[ClientCandidate] = []
    for path, modified in paths:
        try:
            client = validate_client(path)
        except ConfigurationError:
            continue
        candidates.append(ClientCandidate(path, _candidate_label(path, modified), client))
    return ClientDiscovery(True, tuple(candidates), bounded)


class TokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> str | None:
        if not _directory(
            self.path.parent, "saved Gmail authorization directory could not be read safely"
        ):
            return None
        try:
            self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise ConfigurationError("saved Gmail authorization could not be inspected") from None
        return _read_regular(
            self.path, MAX_TOKEN_BYTES, "saved Gmail authorization could not be read safely"
        )

    def save(self, value: str) -> None:
        if len(value.encode()) > MAX_TOKEN_BYTES:
            raise ConfigurationError("saved Gmail authorization is too large")
        write_private(self.path, value)

    def remove(self) -> bool:
        if not _directory(
            self.path.parent, "saved Gmail authorization directory could not be modified safely"
        ):
            return False
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ConfigurationError("saved Gmail authorization could not be inspected") from exc
        if not stat.S_ISREG(current.st_mode):
            raise ConfigurationError("saved Gmail authorization is not a regular file")
        try:
            self.path.unlink()
            return True
        except OSError as exc:
            raise ConfigurationError("saved Gmail authorization could not be removed") from exc
