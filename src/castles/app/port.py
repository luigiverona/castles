from __future__ import annotations

from collections.abc import Callable

from castles.core.finding import Finding
from castles.core.message import NormalizedMessage, RawMessage
from castles.core.signal import MessageSignals

Parser = Callable[[RawMessage], NormalizedMessage]
Extractor = Callable[[NormalizedMessage], MessageSignals]
Discovery = Callable[[tuple[MessageSignals, ...]], tuple[Finding, ...]]
