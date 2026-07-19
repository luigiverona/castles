from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from platformdirs import PlatformDirs

from castles.core.error import ConfigurationError


@dataclass(frozen=True, slots=True)
class Paths:
    config: Path
    state: Path

    @classmethod
    def system(cls) -> Paths:
        dirs = PlatformDirs("castles", appauthor=False)
        return cls(Path(dirs.user_config_dir), Path(dirs.user_state_dir))

    @property
    def database(self) -> Path:
        return self.state / "castles.db"

    @property
    def client(self) -> Path:
        return self.config / "google.json"

    @property
    def token(self) -> Path:
        return self.state / "gmail.json"

    def prepare(self) -> None:
        for directory in (self.config, self.state):
            try:
                current = directory.lstat()
                if not stat.S_ISDIR(current.st_mode):
                    raise ConfigurationError("Castles local directory is not a regular directory")
            except FileNotFoundError:
                directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            if os.name == "posix":
                directory.chmod(0o700)


def private(path: Path) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    regular = stat.S_ISREG(current.st_mode) or stat.S_ISDIR(current.st_mode)
    return regular and (os.name != "posix" or current.st_mode & 0o077 == 0)
