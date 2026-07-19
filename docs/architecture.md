# Architecture

Castles has one production path:

```text
mailbox provider -> bounded parser -> signal extraction -> entity discovery
-> evidence and confidence -> findings -> SQLite -> CLI or export
```

`core` owns immutable provider-neutral values. `parse` bounds and normalizes mailbox content.
`detect` implements open-world discovery. `provider` defines one static mailbox boundary and the
Gmail adapter. `store` owns persistence. `app` orchestrates use cases. `cli` renders with Typer and
Rich. `config` calculates private local paths. `wiring.py` is the composition root.

Dependencies point inward toward `core` and narrow protocols. Detection, confidence, findings,
storage, results, and exports do not depend on Gmail.

The provider contract lives in `provider/port.py`; application callables and storage protocols are
the only narrow abstractions. `wiring.py` is the sole normal composition root. Import Linter enforces
core independence, prevents application imports of concrete adapters, and prevents CLI access to
Gmail, SQLite, parsing, detection, and configuration adapters except through composition.

Parsing limits are 25 MiB raw bytes, 200 MIME parts, depth 12, 512 KiB per decoded text payload,
256 KiB combined normalized text, 1,000 subject characters, 200 URLs, and 4,096 characters per URL.
Attachments and active or hidden HTML elements are excluded. Only URL hostnames leave parsing.

## Design constraints

| Responsibility | Castles constraint |
|---|---|
| OAuth and Gmail API | Installed-application loopback flow, exact read-only scope, bounded requests |
| MIME, HTML, and URLs | Bounded local parsing; complete URLs and raw content are never persisted |
| Domain boundaries | UTS 46 normalization and a reviewed offline Public Suffix List snapshot |
| Infrastructure | Small exact/subtree technical catalog, never a company catalog |
| Detection | One deterministic signal, resolution, confidence, and finding path |
| Local state | Private paths, separate credentials, file locking, and canonical SQLite payloads |
| Storage lifecycle | One schema from `001_init.sql`; staged full scans and atomic promotion |
| Delivery | One Typer/Rich CLI, fixed exports, packaged runtime resources, and no hosted backend |
| Compatibility | Isolated Castles state with no foreign schema, token, or import compatibility layer |
