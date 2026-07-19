from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from rich.console import Console

MAX_ATTEMPTS = 3


@dataclass(slots=True)
class Terminal:
    console: Console
    input: TextIO = field(default_factory=lambda: sys.stdin)
    output: TextIO = field(default_factory=lambda: sys.stdout)

    def interactive(self) -> bool:
        return self.input.isatty() and self.output.isatty()

    def write(self, message: str) -> None:
        self.console.print(message)

    def _read(self, prompt: str) -> str | None:
        self.console.print(prompt, end=" ")
        try:
            value = self.input.readline()
        except (EOFError, OSError):
            return None
        if value == "":
            return None
        return value.strip()

    def confirm(self, prompt: str, *, default: bool = True) -> bool | None:
        marker = "[Y/n]" if default else "[y/N]"
        for _ in range(MAX_ATTEMPTS):
            value = self._read(f"{prompt} {marker}")
            if value is None:
                return None
            if value == "":
                return default
            if value.casefold() in {"y", "yes"}:
                return True
            if value.casefold() in {"n", "no"}:
                return False
            self.console.print("Enter y or n.")
        return None

    def select(self, prompt: str, choices: tuple[str, ...]) -> int | None:
        self.console.print(prompt)
        for index, choice in enumerate(choices, start=1):
            self.console.print(f"  {index}. {choice}")
        for _ in range(MAX_ATTEMPTS):
            value = self._read("Selection (blank to cancel):")
            if value is None or value == "":
                return None
            try:
                selected = int(value)
            except ValueError:
                selected = 0
            if 1 <= selected <= len(choices):
                return selected - 1
            self.console.print(f"Enter a number from 1 to {len(choices)}.")
        return None

    def path(self, prompt: str) -> Path | None:
        value = self._read(prompt)
        if value is None or value == "":
            return None
        return Path(value).expanduser()
