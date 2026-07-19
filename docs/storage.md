# Storage

Castles starts at `001_init.sql`; it does not read or migrate another product's database. The
tables are `schema_migrations`, `accounts`, `checkpoints`, `scans`, `messages`, and `findings`.
Account and generation are part of every mailbox-derived primary key.

`messages.payload` is canonical UTF-8 JSON schema 1 containing extraction policy, aware observation
time, and sorted privacy-minimized signals. `findings.payload` is canonical JSON schema 1 containing
the final entity, identity strength, sorted relationships, first/last seen, message count,
explanations, and policy versions. JSON uses sorted keys, fixed separators, stable enum strings,
aware ISO-8601 times, and no NaN. SHA-256 fingerprints detect conflicting duplicates and
corruption. Readers reject unknown fields.

Initial, since, and incremental scans ingest into `active`, then load the complete active signal set,
recompute every finding, and atomically replace active findings with checkpoint and scan metadata.
Bounded message commits can survive a failed non-full scan; the unchanged checkpoint causes a safe
retry and complete recomputation.

A deterministic parser rejection makes a non-full scan partial, but successfully accepted messages
and the provider checkpoint are committed. The rejected message is not persisted and is not retried
after the provider moves beyond it. Transport and provider failures fail the scan instead; they are
never classified as malformed-message skips.

Full scans stage messages and findings under the scan ID. Successful completion atomically deletes
the old active generation, promotes the stage, updates the checkpoint, and completes scan metadata.
A partial or failed full scan deletes its stage and preserves active messages, findings, and
checkpoint.

Only one local scan can hold the database-level scan lock. Read-only commands use SQLite `mode=ro`
and remain available when SQLite permits safe concurrent reads.
