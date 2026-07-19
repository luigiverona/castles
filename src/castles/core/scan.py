from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from castles.core.message import _aware


class ScanMode(StrEnum):
    INITIAL = "initial"
    INCREMENTAL = "incremental"
    SINCE = "since"
    FULL = "full"


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScanResult:
    scan_id: str
    mode: ScanMode
    status: ScanStatus
    started_at: datetime
    completed_at: datetime
    discovered: int
    processed: int
    skipped: int
    finding_count: int
    stale_fallback: bool = False

    def __post_init__(self) -> None:
        _aware(self.started_at, "started_at")
        _aware(self.completed_at, "completed_at")
        if self.started_at > self.completed_at:
            raise ValueError("scan completion must follow start")
        if min(self.discovered, self.processed, self.skipped, self.finding_count) < 0:
            raise ValueError("scan counts must not be negative")
