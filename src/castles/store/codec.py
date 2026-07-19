from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, cast

from castles.core.entity import Relationship
from castles.core.error import CorruptionError
from castles.core.finding import FINDING_SCHEMA_VERSION, Finding, RelationshipFinding
from castles.core.score import Band, Confidence
from castles.core.signal import (
    SIGNAL_SCHEMA_VERSION,
    MessageSignals,
    Signal,
    SignalKind,
    SignalSource,
    Strength,
)

MAX_PAYLOAD_BYTES = 1024 * 1024


def _oversized(payload: str) -> bool:
    return len(payload) > MAX_PAYLOAD_BYTES or len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES


def _time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise CorruptionError("stored timestamp has an invalid type")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise CorruptionError("stored timestamp is malformed") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise CorruptionError("stored timestamp is not timezone-aware")
    return result


def _json(value: dict[str, object]) -> str:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def fingerprint(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()


def encode_signals(value: MessageSignals) -> tuple[str, str]:
    document: dict[str, object] = {
        "schema": value.schema,
        "policy": value.policy,
        "observed_at": _time(value.observed_at),
        "signals": [
            {
                "kind": signal.kind.value,
                "source": signal.source.value,
                "value": signal.value,
                "strength": signal.strength.value,
                "code": signal.code,
            }
            for signal in value.signals
        ],
    }
    payload = _json(document)
    return payload, fingerprint(payload)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    del value
    raise ValueError("nonstandard JSON constant")


def _object(payload: str, fields: set[str]) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
        canonical = _json(value)
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError):
        raise CorruptionError("stored canonical payload is malformed") from None
    if not isinstance(value, dict) or set(value) != fields or canonical != payload:
        raise CorruptionError("stored canonical payload has unexpected fields")
    return cast(dict[str, Any], value)


def decode_signals(message_key: str, payload: str, expected: str) -> MessageSignals:
    if _oversized(payload):
        raise CorruptionError("stored message signal payload exceeds the safe limit")
    if fingerprint(payload) != expected:
        raise CorruptionError("stored message signal fingerprint does not match")
    document = _object(payload, {"schema", "policy", "observed_at", "signals"})
    if document["schema"] != SIGNAL_SCHEMA_VERSION or not isinstance(document["policy"], str):
        raise CorruptionError("stored message signal schema is unsupported")
    raw_signals = document["signals"]
    if not isinstance(raw_signals, list):
        raise CorruptionError("stored message signals are malformed")
    try:
        signals = tuple(
            Signal(
                SignalKind(item["kind"]),
                SignalSource(item["source"]),
                item["value"],
                Strength(item["strength"]),
                item["code"],
            )
            for item in raw_signals
            if isinstance(item, dict)
            and set(item) == {"kind", "source", "value", "strength", "code"}
        )
    except (KeyError, TypeError, ValueError):
        raise CorruptionError("stored message signals are malformed") from None
    if len(signals) != len(raw_signals):
        raise CorruptionError("stored message signals have unexpected fields")
    try:
        value = MessageSignals(
            message_key,
            _parse_time(document["observed_at"]),
            signals,
            document["policy"],
            document["schema"],
        )
        if encode_signals(value)[0] != payload:
            raise CorruptionError("stored message signals are not canonical")
        return value
    except (TypeError, ValueError):
        raise CorruptionError("stored message signals violate invariants") from None


def _encode_confidence(value: Confidence) -> dict[str, object]:
    return {
        "score": value.score,
        "band": value.band.value,
        "explanations": list(value.explanations),
        "policy": value.policy,
    }


def _decode_confidence(value: object) -> Confidence:
    if not isinstance(value, dict) or set(value) != {"score", "band", "explanations", "policy"}:
        raise CorruptionError("stored confidence is malformed")
    try:
        explanations = value["explanations"]
        if not isinstance(explanations, list) or any(
            not isinstance(item, str) for item in explanations
        ):
            raise TypeError
        return Confidence(value["score"], Band(value["band"]), tuple(explanations), value["policy"])
    except (KeyError, TypeError, ValueError):
        raise CorruptionError("stored confidence violates invariants") from None


def encode_finding(value: Finding) -> tuple[str, str]:
    document: dict[str, object] = {
        "schema": value.schema,
        "policy": value.policy,
        "entity": value.entity,
        "identity": _encode_confidence(value.identity),
        "relationships": [
            {"kind": item.kind.value, "confidence": _encode_confidence(item.confidence)}
            for item in value.relationships
        ],
        "first_seen": _time(value.first_seen),
        "last_seen": _time(value.last_seen),
        "message_count": value.message_count,
        "explanations": list(value.explanations),
    }
    payload = _json(document)
    return payload, fingerprint(payload)


def decode_finding(payload: str, expected: str) -> Finding:
    if _oversized(payload):
        raise CorruptionError("stored finding payload exceeds the safe limit")
    if fingerprint(payload) != expected:
        raise CorruptionError("stored finding fingerprint does not match")
    document = _object(
        payload,
        {
            "schema",
            "policy",
            "entity",
            "identity",
            "relationships",
            "first_seen",
            "last_seen",
            "message_count",
            "explanations",
        },
    )
    if document["schema"] != FINDING_SCHEMA_VERSION:
        raise CorruptionError("stored finding schema is unsupported")
    relationships = document["relationships"]
    explanations = document["explanations"]
    if (
        not isinstance(relationships, list)
        or not isinstance(explanations, list)
        or any(not isinstance(item, str) for item in explanations)
    ):
        raise CorruptionError("stored finding is malformed")
    try:
        values = tuple(
            RelationshipFinding(Relationship(item["kind"]), _decode_confidence(item["confidence"]))
            for item in relationships
            if isinstance(item, dict) and set(item) == {"kind", "confidence"}
        )
        if len(values) != len(relationships):
            raise ValueError
        value = Finding(
            document["entity"],
            _decode_confidence(document["identity"]),
            values,
            _parse_time(document["first_seen"]),
            _parse_time(document["last_seen"]),
            document["message_count"],
            tuple(explanations),
            document["policy"],
            document["schema"],
        )
        if encode_finding(value)[0] != payload:
            raise CorruptionError("stored finding is not canonical")
        return value
    except (KeyError, TypeError, ValueError):
        raise CorruptionError("stored finding violates invariants") from None
