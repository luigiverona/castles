from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from castles.core.error import LockingError


class FileLocks:
    def __init__(self, directory: Path, *, timeout: float = 5.0) -> None:
        self.directory = directory
        self.timeout = timeout

    def _path(self, account: str) -> Path:
        # The account is intentionally not included in the filename.
        del account
        return self.directory / "scan.lock"

    @contextmanager
    def acquire(self, account: str) -> Iterator[None]:
        try:
            current = self.directory.lstat()
            if not stat.S_ISDIR(current.st_mode):
                raise LockingError("Castles scan lock directory is unsafe")
        except FileNotFoundError:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as exc:
            raise LockingError("Castles scan lock directory could not be inspected") from exc
        path = self._path(account)
        token = uuid4().hex
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    json.dump({"pid": os.getpid(), "token": token, "created": time.time()}, stream)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise LockingError("another Castles scan is already running") from None
                time.sleep(0.05)
            except OSError as exc:
                raise LockingError("Castles scan lock could not be created") from exc
        try:
            yield
        finally:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("token") == token:
                    path.unlink(missing_ok=True)
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
