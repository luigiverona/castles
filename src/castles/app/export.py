from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from castles.app.results import ResultSet
from castles.core.error import ExportError

EXPORT_SCHEMA = 1
CSV_COLUMNS = (
    "entity",
    "identity_score",
    "identity_band",
    "relationships",
    "first_seen",
    "last_seen",
    "message_count",
    "identity_policy",
    "relationship_policies",
    "explanations",
)


def json_export(values: tuple[ResultSet, ...], generated: datetime) -> str:
    document: dict[str, object] = {
        "schema_version": EXPORT_SCHEMA,
        "generated_at": generated.isoformat(),
        "mailboxes": [
            {
                "provider": value.provider,
                "scan": (
                    {
                        "mode": value.scan.mode.value,
                        "status": value.scan.status.value,
                        "completed_at": value.scan.completed_at.isoformat(),
                        "discovered": value.scan.discovered,
                        "processed": value.scan.processed,
                        "skipped": value.scan.skipped,
                    }
                    if value.scan
                    else None
                ),
                "findings": [
                    {
                        "entity": finding.entity,
                        "identity": {
                            "score": finding.identity.score,
                            "band": finding.identity.band.value,
                            "policy": finding.identity.policy,
                            "explanations": list(finding.identity.explanations),
                        },
                        "relationships": [
                            {
                                "kind": relationship.kind.value,
                                "score": relationship.confidence.score,
                                "band": relationship.confidence.band.value,
                                "policy": relationship.confidence.policy,
                                "explanations": list(relationship.confidence.explanations),
                            }
                            for relationship in finding.relationships
                        ],
                        "first_seen": finding.first_seen.isoformat(),
                        "last_seen": finding.last_seen.isoformat(),
                        "message_count": finding.message_count,
                        "policy": finding.policy,
                        "explanations": list(finding.explanations),
                    }
                    for finding in value.findings
                ],
            }
            for value in values
        ],
    }
    return (
        json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n"
    )


def _safe(value: str) -> str:
    return "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


def csv_export(values: tuple[ResultSet, ...]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for value in values:
        for finding in value.findings:
            writer.writerow(
                {
                    "entity": _safe(finding.entity),
                    "identity_score": finding.identity.score,
                    "identity_band": _safe(finding.identity.band.value),
                    "relationships": _safe(
                        ";".join(
                            f"{item.kind.value}:{item.confidence.score}:{item.confidence.band.value}"
                            for item in finding.relationships
                        )
                    ),
                    "first_seen": _safe(finding.first_seen.isoformat()),
                    "last_seen": _safe(finding.last_seen.isoformat()),
                    "message_count": finding.message_count,
                    "identity_policy": _safe(finding.identity.policy),
                    "relationship_policies": _safe(
                        ";".join(sorted({item.confidence.policy for item in finding.relationships}))
                    ),
                    "explanations": _safe(";".join(finding.explanations)),
                }
            )
    return stream.getvalue()


def write(path: Path, content: str) -> None:
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ExportError("export could not be written") from exc
