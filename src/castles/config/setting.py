from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import cast

from castles.core.error import ConfigurationError

MAX_CLIENT_BYTES = 128 * 1024
MAX_TOKEN_BYTES = 1024 * 1024
GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_EXCHANGE_URI = "https://oauth2.googleapis.com/token"


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
        if not stat.S_ISREG(before.st_mode):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (
            after.st_dev,
            after.st_ino,
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


def validate_client(path: Path) -> dict[str, object]:
    try:
        document = json.loads(
            _read_regular(
                path,
                MAX_CLIENT_BYTES,
                "Google OAuth client JSON must be a regular private file",
            )
        )
        installed = document["installed"]
        if not isinstance(installed, dict):
            raise TypeError
        required = ("client_id", "client_secret", "auth_uri", "token_uri")
        if any(not isinstance(installed.get(key), str) or not installed[key] for key in required):
            raise ValueError
        if (
            installed["auth_uri"] != GOOGLE_AUTH_URI
            or installed["token_uri"] != GOOGLE_EXCHANGE_URI
        ):
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ConfigurationError(
            "Google OAuth client JSON must describe a desktop application"
        ) from None
    return cast(dict[str, object], document)


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _directory(path.parent, "private Castles configuration directory is unsafe")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(0o600)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ConfigurationError("could not write private Castles configuration") from exc


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


def discover_client(home: Path) -> Path | None:
    downloads = home / "Downloads"
    if not downloads.is_dir():
        return None
    try:
        candidates = sorted(
            (
                path
                for path in downloads.iterdir()
                if path.is_file()
                and path.suffix.casefold() == ".json"
                and (path.name.startswith("client_secret_") or path.name == "credentials.json")
            ),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )[:100]
    except OSError:
        return None
    for candidate in candidates:
        try:
            validate_client(candidate)
            return candidate
        except ConfigurationError:
            continue
    return None
